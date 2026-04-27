package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"crypto/ed25519"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/chain"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/config"
	"github.com/shadowai/backend/internal/dashboard"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/embedding"
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/internaldb"
	"github.com/shadowai/backend/internal/metrics"
	mw "github.com/shadowai/backend/internal/middleware"
	"github.com/shadowai/backend/internal/platform/postgres"
	rdb "github.com/shadowai/backend/internal/platform/redis"
	"github.com/shadowai/backend/internal/policy"
	"github.com/shadowai/backend/internal/proxy"
	"github.com/shadowai/backend/internal/health"
)

func main() {
	cfg := config.Load()
	if err := cfg.ValidateStartupConfig(); err != nil {
		log.Fatalf("config validation failed: %v", err)
	}
	if !cfg.IsProduction() && len(cfg.JWTSecret) < 32 {
		log.Printf("warning: JWT_SECRET is shorter than 32 chars; set a strong secret in production")
	}
	mw.ConfigureTrustedProxies(cfg.TrustedProxyCIDRs)

	db, err := postgres.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer db.Close()

	redisClient, err := rdb.Connect(cfg.RedisURL)
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer redisClient.Close()

	// Repositories
	authRepo := auth.NewRepository(db)
	auditRepo := audit.NewRepository(db).WithChainSecret(cfg.AuditChainSecret)
	policyRepo := policy.NewRepository(db)
	budgetRepo := budget.NewRepository(db)
	internalDBRepo := internaldb.NewRepository(db)

	// Services
	var authOpts []auth.ServiceOption
	if cfg.AdminMFARequired {
		authOpts = append(authOpts, auth.WithAdminMFARequired())
	}
	authSvc := auth.NewService(authRepo, cfg.JWTSecret, authOpts...)
	auditSvc := audit.NewService(auditRepo)
	policySvc := policy.NewService(policyRepo)
	budgetSvc := budget.NewService(budgetRepo, redisClient)
	internalDBManager, err := internaldb.NewManager(internalDBRepo, cfg.InternalDBSources, cfg.InternalDBQueryTimeout)
	if err != nil {
		log.Printf("internal DB sources: %v", err)
	}
	if internalDBManager != nil && cfg.InternalDBRefreshInterval > 0 {
		refreshStop := make(chan struct{})
		defer close(refreshStop)
		refreshTicker := time.NewTicker(cfg.InternalDBRefreshInterval)
		go func() {
			defer refreshTicker.Stop()
			for {
				select {
				case <-refreshTicker.C:
					if err := internalDBManager.RefreshSources(context.Background()); err != nil {
						log.Printf("internal DB refresh: %v", err)
					}
				case <-refreshStop:
					return
				}
			}
		}()
	}
	defer func() {
		if internalDBManager != nil {
			if err := internalDBManager.Close(); err != nil {
				log.Printf("internal DB close: %v", err)
			}
		}
	}()
	dlpSvc := dlp.NewService(cfg.DLPMode)

	// Firewall Pipeline
	var firewallPipeline *firewall.Pipeline
	if cfg.FirewallEnabled {
		// PR-4: inspector modes. Читаем FIREWALL_MODE_DEFAULT и
		// FIREWALL_MODE_<NAME> из env; каждый Register ниже резолвит
		// свой mode по Inspector.Name().
		inspectorModes := firewall.LoadInspectorModesFromEnv()
		firewallPipeline = firewall.NewPipelineWithModes(inspectorModes)
		firewallPipeline.Register(firewall.NewPIIInspector())
		firewallPipeline.Register(firewall.NewDLPInspector(dlpSvc))
		firewallPipeline.Register(firewall.NewPolicyInspector(policySvc.Engine))

		var judge *firewall.Judge
		if cfg.FirewallJudgeEnabled {
			judge = firewall.NewJudge(firewall.JudgeConfig{
				Provider: cfg.FirewallJudgeProvider,
				Model:    cfg.FirewallJudgeModel,
				Endpoint: cfg.FirewallJudgeEndpoint,
				APIKey:   cfg.FirewallJudgeAPIKey,
				Timeout:  cfg.FirewallJudgeTimeout,
				Enabled:  true,
			})
		}

		firewallPipeline.Register(firewall.NewPromptInjectionInspector(firewall.PromptInjectionConfig{
			Enabled:            cfg.FirewallPIEnabled,
			HeuristicThreshold: cfg.FirewallPIHeuristicThreshold,
			JudgeThreshold:     cfg.FirewallPIJudgeThreshold,
		}, judge))
		firewallPipeline.Register(firewall.NewJailbreakInspector(firewall.JailbreakConfig{
			Enabled:            cfg.FirewallJBEnabled,
			HeuristicThreshold: cfg.FirewallJBHeuristicThreshold,
			JudgeThreshold:     cfg.FirewallJBJudgeThreshold,
		}, judge))
		firewallPipeline.Register(firewall.NewContentModerationInspector(firewall.ContentModerationConfig{
			Enabled:            cfg.FirewallCMEnabled,
			HeuristicThreshold: cfg.FirewallCMHeuristicThreshold,
			JudgeThreshold:     cfg.FirewallCMJudgeThreshold,
		}, judge))
		firewallPipeline.Register(firewall.NewOutputValidationInspector(firewall.OutputValidationConfig{
			Enabled:            cfg.FirewallOVEnabled,
			HeuristicThreshold: cfg.FirewallOVHeuristicThreshold,
		}))
		firewallPipeline.Register(firewall.NewContentRateLimiter(firewall.ContentRateLimitConfig{
			Enabled:           cfg.FirewallRLEnabled,
			MaxCharsPerMinute: cfg.FirewallRLMaxCharsPerMinute,
			MaxFlagsPerMinute: cfg.FirewallRLMaxFlagsPerMinute,
		}))
		firewallPipeline.Register(firewall.NewMultiTurnInspector(firewall.MultiTurnConfig{
			Enabled:            cfg.FirewallMTEnabled,
			WindowSize:         cfg.FirewallMTWindowSize,
			HeuristicThreshold: cfg.FirewallMTHeuristicThreshold,
		}))
		firewallPipeline.Register(firewall.NewSemanticInspector(firewall.SemanticConfig{
			Enabled:        cfg.FirewallSAEnabled,
			Threshold:      cfg.FirewallSAThreshold,
			BlockThreshold: cfg.FirewallSABlockThreshold,
		}))

		// PR-6: Semantic V2 (embedding-based). Регистрируется только если
		// ENABLED и все три компонента валидны: client, corpus, matching
		// provider/model/dim. Любая init-ошибка логируется, но не останавливает
		// сервер — V2 inspector просто не регистрируется, pipeline работает
		// без него.
		if cfg.FirewallSAV2Enabled {
			// In prod, any SA_v2 init failure is fatal: an enabled inspector that
			// silently falls back to fail-open gives false security confidence.
			// In dev, failures are logged and the inspector is skipped (allow rapid
			// iteration without a working embedding service).
			sv2InitFail := func(format string, args ...any) {
				if cfg.IsProduction() {
					log.Fatalf("semantic_v2: "+format+" (FATAL in prod: SA_v2 enabled but not running; disable FIREWALL_SA_V2_ENABLED or fix configuration)", args...)
				}
				log.Printf("semantic_v2: "+format+" (skipping inspector in dev)", args...)
			}
			embClient, err := embedding.NewClient(embedding.Config{
				Provider:  cfg.FirewallEmbeddingProvider,
				Endpoint:  cfg.FirewallEmbeddingEndpoint,
				Model:     cfg.FirewallEmbeddingModel,
				APIKey:    cfg.FirewallEmbeddingAPIKey,
				Dimension: cfg.FirewallEmbeddingDimension,
				Timeout:   cfg.FirewallEmbeddingTimeout,
			})
			if err != nil {
				sv2InitFail("embedding client init failed: %v", err)
			} else {
				corpus, err := embedding.LoadCorpus(cfg.FirewallSAV2CorpusPath)
				if err != nil {
					sv2InitFail("corpus load failed: %v", err)
				} else {
					sv2, err := firewall.NewSemanticV2Inspector(firewall.SemanticV2Config{
						Enabled:        true,
						Threshold:      cfg.FirewallSAV2Threshold,
						BlockThreshold: cfg.FirewallSAV2BlockThreshold,
						ShadowOnly:     cfg.FirewallSAV2ShadowOnly,
					}, embClient, corpus)
					if err != nil {
						sv2InitFail("inspector init failed: %v", err)
					} else {
						firewallPipeline.Register(sv2)
						log.Printf("semantic_v2: registered (provider=%s model=%s dim=%d corpus_items=%d shadow_only=%v)",
							embClient.Provider(), embClient.Model(), embClient.Dimension(), len(corpus.Items), cfg.FirewallSAV2ShadowOnly)
					}
				}
			}
		}

		log.Printf("firewall pipeline: enabled (judge=%v, mode_default=%s, mode_overrides=%d, semantic_v2=%v)",
			cfg.FirewallJudgeEnabled, inspectorModes.Default, len(inspectorModes.Overrides), cfg.FirewallSAV2Enabled)
	}

	// Provider Registry — skip providers without API keys
	registry := proxy.NewRegistry()
	if cfg.OpenAIAPIKey != "" {
		registry.Register(proxy.NewOpenAIProvider(cfg.OpenAIAPIKey))
	} else {
		log.Printf("provider openai: skipped (no API key)")
	}
	if cfg.AnthropicAPIKey != "" {
		registry.Register(proxy.NewAnthropicProvider(cfg.AnthropicAPIKey))
	} else {
		log.Printf("provider anthropic: skipped (no API key)")
	}
	if cfg.GeminiAPIKey != "" {
		registry.Register(proxy.NewGeminiProvider(cfg.GeminiAPIKey))
	} else {
		log.Printf("provider gemini: skipped (no API key)")
	}
	if cfg.MistralAPIKey != "" {
		registry.Register(proxy.NewMistralProvider(cfg.MistralAPIKey))
	} else {
		log.Printf("provider mistral: skipped (no API key)")
	}
	if cfg.GroqAPIKey != "" {
		registry.Register(proxy.NewGroqProvider(cfg.GroqAPIKey))
	} else {
		log.Printf("provider groq: skipped (no API key)")
	}
	if cfg.OpenRouterAPIKey != "" {
		registry.Register(proxy.NewOpenRouterProvider(cfg.OpenRouterAPIKey))
	} else {
		log.Printf("provider openrouter: skipped (no API key)")
	}
	// Ollama — always registered (no auth required)
	registry.Register(proxy.NewOllamaProvider(cfg.OllamaURL))

	// Intelligent Routing + Cache
	healthTracker := proxy.NewHealthTracker(redisClient)
	modelMapper := proxy.NewModelMapper(registry)
	strategy := proxy.RoutingStrategy(cfg.RoutingStrategy)

	var fallbackOrder []string
	if cfg.FallbackOrder != "" {
		fallbackOrder = strings.Split(cfg.FallbackOrder, ",")
	}

	router := proxy.NewRouter(registry, healthTracker, modelMapper, strategy, fallbackOrder)

	var cache *proxy.SemanticCache
	if cfg.CacheEnabled {
		ttl, err := time.ParseDuration(cfg.CacheTTL)
		if err != nil {
			ttl = time.Hour
		}
		cache = proxy.NewSemanticCache(redisClient, ttl)
	}

	// PR-A: audit privacy. Parse mode из env, fail-safe редакция в
	// redacted при invalid values. Делается ДО всех handlers, которым
	// mode нужен (audit + proxy).
	auditPayloadMode, modeErr := audit.ParsePayloadMode(cfg.AuditPayloadMode)
	if modeErr != nil {
		log.Printf("WARN: invalid AUDIT_PAYLOAD_MODE=%q (%v), fallback to redacted", cfg.AuditPayloadMode, modeErr)
		auditPayloadMode = audit.PayloadModeRedacted
	}
	if auditPayloadMode == audit.PayloadModeFull {
		log.Printf("WARN: AUDIT_PAYLOAD_MODE=full — request/response bodies stored verbatim; privacy implications")
	}
	if cfg.IsProduction() && cfg.AuditAllowNoRetentionInProd && cfg.AuditRetentionDays == 0 {
		log.Printf("WARN: prod started with AUDIT_RETENTION_DAYS=0 under explicit override; audit rows will not expire automatically")
	}

	// L-1: Enterprise bundle. Core-build — stub with nil services и
	// no-op callbacks; Enterprise-build (-tags enterprise) — полный
	// wiring в enterprise_wire.go.
	entBundle := buildEnterpriseBundle(enterpriseDeps{
		DB: db, Cfg: cfg, AuditRepo: auditRepo, BudgetRepo: budgetRepo, AuditSvc: auditSvc,
		AuthRepo: authRepo, AuthSvc: authSvc,
	})

	// Handlers. Все принимают enterprise-интерфейсы опционально (nil-
	// safe). В Core-билде entBundle.AdminAudit / Eraser / Governance
	// равны nil, и соответствующие code paths в каждом handler'е
	// деградируют корректно (recordAdmin* — no-op, EraseUser → 503).
	authHandler := auth.NewHandler(authSvc, entBundle.Eraser, entBundle.AdminAudit).
		WithDSARDPOSignals(cfg.DSARDPOSignalEnabled)
	// schedulerEnabled — для визуализации в /audit/status. Реальный
	// запуск scheduler'ов делает entBundle.StartSchedulers.
	auditSchedulerEnabled := cfg.AuditPurgeInterval > 0 && cfg.AuditRetentionDays > 0
	adminEventsSchedulerEnabled := cfg.AuditPurgeInterval > 0 && cfg.AdminAuditRetentionDays > 0
	auditHandler := audit.NewHandler(auditSvc, auditPayloadMode, cfg.AuditRetentionDays, auditSchedulerEnabled, entBundle.AdminAudit, cfg.AdminAuditRetentionDays, adminEventsSchedulerEnabled)
	policyHandler := policy.NewHandler(policySvc)
	budgetHandler := budget.NewHandler(budgetSvc).WithUserLookup(authRepo)
	dashHandler := dashboard.NewHandler(db, entBundle.AdminAudit)
	internalDBHandler := internaldb.NewHandler(internalDBManager, internalDBRepo, auditSvc, auditPayloadMode, dlpSvc, entBundle.AdminAudit)

	proxyHandler := proxy.NewHandler(registry, policySvc, auditSvc, budgetSvc, dlpSvc, cfg.AllowedProviderHosts, router, cache, healthTracker, cfg.MaxCompletionTokens, firewallPipeline, auditPayloadMode, entBundle.Governance, entBundle.AdminAudit)
	// PR-F7.1: transport-level streaming mode. Default "buffered"
	// сохраняет историческое поведение (full-buffer scan). "incremental"
	// включает F7.1 transport pass-through через streaming/* adapter
	// layer (response-side inspection придёт в F7.2 — в F7.1
	// incremental означает transport-only). Normalize защищает от
	// неизвестных значений (fallback buffered).
	proxyHandler.SetStreamingMode(config.NormalizeStreamingMode(cfg.StreamingMode))
	// PR-G4: wire org-level budget checker (enterprise-only; nil-safe in proxy).
	if entBundle.OrgBudget != nil {
		proxyHandler.SetOrgBudget(entBundle.OrgBudget)
	}

	connectivityCtx, connectivityCancel := context.WithCancel(context.Background())
	defer connectivityCancel()
	runConnectivityCheck := func() {
		summary := proxyHandler.RunScheduledConnectivityCheck(connectivityCtx)
		if summary.LastError != nil {
			log.Printf("provider connectivity scheduler error: %v", summary.LastError)
			return
		}
		if summary.Critical > 0 {
			log.Printf("provider connectivity scheduler alert: total=%d reachable=%d unreachable=%d egress_blocked=%d stale=%d", summary.Total, summary.Reachable, summary.Unreachable, summary.EgressBlocked, summary.Stale)
			return
		}
		log.Printf("provider connectivity scheduler: ok total=%d reachable=%d", summary.Total, summary.Reachable)
	}
	if cfg.ProviderConnectivityInterval > 0 {
		go func() {
			runConnectivityCheck()
			ticker := time.NewTicker(cfg.ProviderConnectivityInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					runConnectivityCheck()
				case <-connectivityCtx.Done():
					return
				}
			}
		}()
	}

	// PR-A / PR-D.1: retention/purge schedulers.
	// Полная реализация в enterprise_wire.go (-tags enterprise).
	// Core-build получает no-op функцию из enterprise_stubs.go.
	entBundle.StartSchedulers(connectivityCtx, cfg)

	// PR-W3: Merkle anchor scheduler для audit_logs (core table).
	// Enterprise tables (admin_event_logs, legal_hold_events, audit_purge_runs)
	// якорятся через enterprise_wire.go StartSchedulers.
	if cfg.AuditAnchorInterval > 0 {
		anchorRepo := chain.NewAnchorRepository(db)
		var anchorSink chain.AnchorSink = chain.NoOpSink{}
		switch cfg.AuditAnchorSink {
		case "file://":
			if cfg.AuditAnchorSinkPath != "" {
				anchorSink = chain.NewFileSink(cfg.AuditAnchorSinkPath)
			}
		case "immudb://":
			// PR-W4.2: wire real immudb client via HTTP REST API.
			// log.Fatalf if connection fails — do not silently fall back to NoOp.
			opts := chain.DefaultImmuDBOptions()
			if cfg.AuditImmuDBAPIPrefix != "" {
				opts.APIPrefix = cfg.AuditImmuDBAPIPrefix
			}
			if cfg.AuditImmuDBRestProfile != "" {
				parsedProfile, profileErr := chain.ParseImmuDBRESTProfile(cfg.AuditImmuDBRestProfile)
				if profileErr != nil {
					log.Fatalf("anchor scheduler: AUDIT_IMMUDB_REST_PROFILE: %v", profileErr)
				}
				opts.Profile = parsedProfile
			}
			immuClient, err := chain.DialImmuDBWithOptions(
				context.Background(),
				cfg.AuditImmuDBAddr,
				cfg.AuditImmuDBUsername,
				cfg.AuditImmuDBPassword,
				cfg.AuditImmuDBDatabase,
				opts,
			)
			if err != nil {
				log.Fatalf("anchor scheduler: immudb:// connect failed (addr=%s db=%s): %v",
					cfg.AuditImmuDBAddr, cfg.AuditImmuDBDatabase, err)
			}
			anchorSink = chain.NewImmuDBSink(immuClient, cfg.AuditImmuDBDatabase)
			log.Printf("anchor scheduler: immudb:// sink connected (addr=%s db=%s)",
				cfg.AuditImmuDBAddr, cfg.AuditImmuDBDatabase)
		}
		anchorSched := chain.NewAnchorScheduler(anchorRepo, anchorSink, cfg.AuditAnchorInterval,
			append([]string{"audit_logs", "audit_purge_runs"}, entBundle.AnchorExtraTables...))
		// PR-W4.1: optional Ed25519 signing.
		if cfg.AuditAnchorSigningKey != "" && cfg.AuditAnchorPubKeyID != "" {
			privKey, err := chain.ParsePrivateKey(cfg.AuditAnchorSigningKey)
			if err != nil {
				log.Fatalf("anchor signing key: %v", err)
			}
			// PR-W4.1 fix: parse AUDIT_ANCHOR_PUBKEY and use it for self-verification,
			// so a wrong pubkey value is caught at write time (not only in audit-verify).
			// Startup config validation (ValidateStartupConfig) also checks key pair match.
			var selfVerifyKey ed25519.PublicKey
			if cfg.AuditAnchorPubKey != "" {
				pk, err := chain.ParsePublicKey(cfg.AuditAnchorPubKey)
				if err != nil {
					log.Fatalf("AUDIT_ANCHOR_PUBKEY: %v", err)
				}
				selfVerifyKey = pk
			}
			anchorSched = anchorSched.WithSigning(privKey, cfg.AuditAnchorPubKeyID, selfVerifyKey)
		}
		// W8: wire additional independent witness sinks.
		if cfg.AuditAnchorAdditionalSinks != "" {
			additional := buildAdditionalAnchorSinks(connectivityCtx, cfg)
			if len(additional) > 0 {
				anchorSched = anchorSched.WithAdditionalSinks(additional...)
				log.Printf("anchor scheduler: %d additional sink(s) configured: %s",
					len(additional), cfg.AuditAnchorAdditionalSinks)
			}
		}
		go anchorSched.Run(connectivityCtx)
	}

	r := mux.NewRouter()

	// Public routes
	publicAuth := r.PathPrefix("/api/auth").Subrouter()
	publicAuth.HandleFunc("/login", authHandler.Login).Methods("POST")
	publicAuth.HandleFunc("/register", authHandler.Register).Methods("POST")
	// PR-E1: OIDC routes (enterprise build only; no-op in core).
	entBundle.RegisterPublicRoutes(publicAuth)
	publicAuth.Use(mw.RateLimitPublic(redisClient, 20, time.Minute))

	// PR-O1: Kubernetes liveness + readiness probes.
	// Liveness  → always 200 (process is alive).
	// Readiness → 200 if DB+Redis reachable, 503 otherwise.
	readinessChecker := &health.ReadinessChecker{DB: db, Redis: redisClient}
	r.HandleFunc("/api/health", health.LivenessHandler).Methods("GET")
	r.HandleFunc("/api/ready", readinessChecker.Ready).Methods("GET")

	// Prometheus /metrics endpoint. Без auth middleware (Prometheus scrapers
	// не авторизуются JWT). Ограничивать на уровне infra (ingress/firewall).
	// См. README секцию "Observability (Prometheus)".
	metrics.RegisterRoute(r)

	// Protected API routes
	api := r.PathPrefix("/api").Subrouter()
	api.Use(authSvc.AuthMiddleware)

	// Users (admin only)
	admin := api.PathPrefix("").Subrouter()
	admin.Use(auth.RequireRole(auth.RoleAdmin))
	admin.HandleFunc("/users", authHandler.ListUsers).Methods("GET")
	admin.HandleFunc("/users/{id}", authHandler.GetUser).Methods("GET")
	admin.HandleFunc("/users/{id}", authHandler.UpdateUser).Methods("PUT")

	// Audit logs
	admin.HandleFunc("/audit/logs", auditHandler.List).Methods("GET")
	admin.HandleFunc("/audit/status", auditHandler.Status).Methods("GET")

	// Policies (admin)
	admin.HandleFunc("/policies", policyHandler.List).Methods("GET")
	admin.HandleFunc("/policies", policyHandler.Create).Methods("POST")
	admin.HandleFunc("/policies/{id}", policyHandler.Update).Methods("PUT")
	admin.HandleFunc("/policies/{id}", policyHandler.Delete).Methods("DELETE")

	// L-1: enterprise-only admin routes (empty-set в Core-билде):
	//   POST /users/{id}/erase        — DSAR
	//   GET  /admin-events             — admin access audit
	//   GET  /governance/policy        — Provider/Model Governance
	//   PUT  /governance/policy
	entBundle.RegisterRoutes(admin, authHandler)

	// Budgets
	budgets := api.PathPrefix("/budgets").Subrouter()
	budgets.Use(auth.RequireAdminOrSelf("user_id"))
	budgets.HandleFunc("/{user_id}", budgetHandler.Get).Methods("GET")
	admin.HandleFunc("/budgets/{user_id}", budgetHandler.Update).Methods("PUT")

	// Dashboard
	admin.HandleFunc("/dashboard/stats", dashHandler.GetStats).Methods("GET")
	admin.HandleFunc("/dashboard/usage", dashHandler.GetUsage).Methods("GET")
	admin.HandleFunc("/dashboard/top-users", dashHandler.GetTopUsers).Methods("GET")
	internalDBList := auth.RequireRole(auth.RoleAdmin, auth.RoleAnalyst, auth.RoleAuditor)
	api.Handle("/internal-dbs", internalDBList(http.HandlerFunc(internalDBHandler.ListSources))).Methods("GET")
	api.Handle("/internal-dbs/", internalDBList(http.HandlerFunc(internalDBHandler.ListSources))).Methods("GET")

	internalDBQuery := auth.RequireRole(auth.RoleAdmin, auth.RoleAnalyst)
	api.Handle("/internal-dbs/query", internalDBQuery(http.HandlerFunc(internalDBHandler.Query))).Methods("POST")
	api.Handle("/internal-dbs/query/", internalDBQuery(http.HandlerFunc(internalDBHandler.Query))).Methods("POST")

	internalDBAdmin := api.PathPrefix("/internal-dbs/sources").Subrouter()
	internalDBAdmin.Use(auth.RequireRole(auth.RoleAdmin))
	internalDBAdmin.HandleFunc("", internalDBHandler.ListManagedSources).Methods("GET")
	internalDBAdmin.HandleFunc("/", internalDBHandler.ListManagedSources).Methods("GET")
	internalDBAdmin.HandleFunc("", internalDBHandler.CreateSource).Methods("POST")
	internalDBAdmin.HandleFunc("/", internalDBHandler.CreateSource).Methods("POST")
	internalDBAdmin.HandleFunc("/refresh", internalDBHandler.RefreshSources).Methods("POST")
	internalDBAdmin.HandleFunc("/{id}/test", internalDBHandler.TestSource).Methods("POST")
	internalDBAdmin.HandleFunc("/{id}", internalDBHandler.GetSource).Methods("GET")
	internalDBAdmin.HandleFunc("/{id}", internalDBHandler.UpdateSource).Methods("PUT")
	internalDBAdmin.HandleFunc("/{id}", internalDBHandler.DeleteSource).Methods("DELETE")
	api.HandleFunc("/auth/revoke", authHandler.RevokeTokens).Methods("POST")
	api.HandleFunc("/auth/rotate-api-key", authHandler.RotateAPIKey).Methods("POST")
	// PR-E1.1: MFA management (authenticated, admin-only).
	entBundle.RegisterMFARoutes(api)

	// PR-E2: SCIM 2.0 provisioning (separate bearer token, not admin JWT).
	entBundle.RegisterSCIMRoutes(r)

	// Proxy routes (authenticated + rate limited) — wildcard for all providers
	proxyRouter := r.PathPrefix("/proxy").Subrouter()
	proxyRouter.Use(authSvc.AuthMiddleware)
	proxyRouter.Use(mw.RateLimit(redisClient, 60, time.Minute))
	proxyRouter.HandleFunc("/providers", proxyHandler.ListProviders).Methods("GET")
	proxyRouter.Handle("/providers/connectivity", auth.RequireRole(auth.RoleAdmin)(http.HandlerFunc(proxyHandler.ProviderConnectivity))).Methods("GET")
	proxyRouter.Handle("/providers/connectivity/alerts", auth.RequireRole(auth.RoleAdmin)(http.HandlerFunc(proxyHandler.ProviderConnectivityAlerts))).Methods("GET")
	proxyRouter.Handle("/providers/test", auth.RequireRole(auth.RoleAdmin)(http.HandlerFunc(proxyHandler.TestAllProviders))).Methods("POST")
	proxyRouter.Handle("/providers/{provider}/test", auth.RequireRole(auth.RoleAdmin)(http.HandlerFunc(proxyHandler.TestProvider))).Methods("POST")
	proxyRouter.Handle("/firewall/status", auth.RequireRole(auth.RoleAdmin)(http.HandlerFunc(proxyHandler.FirewallStatus))).Methods("GET")
	proxyRouter.HandleFunc("/chat", proxyHandler.UnifiedChat).Methods("POST")
	proxyRouter.PathPrefix("/{provider}/").HandlerFunc(proxyHandler.ProxyChat).Methods("POST")

	// Apply global middleware
	handler := mw.CORS(cfg.CORSAllowedHosts)(r)
	handler = mw.SecurityHeaders(handler)
	handler = mw.PrometheusMetrics(handler) // PR-O1: HTTP request metrics
	handler = mw.Logging(handler)
	handler = mw.Recovery(handler)

	log.Printf("ShadowAI starting on :%s", cfg.ServerPort)
	srv := &http.Server{
		Addr:              ":" + cfg.ServerPort,
		Handler:           handler,
		ReadTimeout:       cfg.ServerReadTimeout,
		WriteTimeout:      cfg.ServerWriteTimeout,
		IdleTimeout:       cfg.ServerIdleTimeout,
		ReadHeaderTimeout: cfg.ServerReadHeaderTimeout,
		MaxHeaderBytes:    cfg.ServerMaxHeaderBytes,
	}

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdownCh
		log.Printf("shutdown signal received")
		connectivityCancel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Сначала останавливаем HTTP-приём, потом flush'им audit-очередь
		// чтобы не потерять security-события на shutdown.
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}

	// Flush audit queue перед exit — не теряем security-события.
	auditSvc.Close()
	depth, dropped, inserted, failed := auditSvc.Stats()
	log.Printf("audit shutdown: inserted=%d failed=%d dropped=%d queue_depth_remaining=%d",
		inserted, failed, dropped, depth)
}

// buildAdditionalAnchorSinks — W8: instantiates additional AnchorSink implementations
// from AUDIT_ANCHOR_ADDITIONAL_SINKS config. Called only when the field is non-empty.
// Logs each configured sink; fatalf on connection errors (fail-fast in prod).
func buildAdditionalAnchorSinks(ctx context.Context, cfg *config.Config) []chain.AnchorSink {
	var sinks []chain.AnchorSink
	for _, raw := range strings.Split(cfg.AuditAnchorAdditionalSinks, ",") {
		scheme := strings.TrimSpace(raw)
		switch scheme {
		case "file://":
			if cfg.AuditAnchorAdditionalFilePath == "" {
				log.Printf("anchor: additional file:// sink skipped (AUDIT_ANCHOR_ADDITIONAL_SINK_FILE_PATH not set)")
				continue
			}
			sinks = append(sinks, chain.NewFileSink(cfg.AuditAnchorAdditionalFilePath))
			log.Printf("anchor: additional file:// sink at %s", cfg.AuditAnchorAdditionalFilePath)

		case "immudb://":
			opts := chain.DefaultImmuDBOptions()
			if cfg.AuditImmuDBAPIPrefix != "" {
				opts.APIPrefix = cfg.AuditImmuDBAPIPrefix
			}
			if cfg.AuditImmuDBRestProfile != "" {
				parsedProfile, profileErr := chain.ParseImmuDBRESTProfile(cfg.AuditImmuDBRestProfile)
				if profileErr != nil {
					log.Fatalf("anchor: additional immudb:// AUDIT_IMMUDB_REST_PROFILE: %v", profileErr)
				}
				opts.Profile = parsedProfile
			}
			immuClient, err := chain.DialImmuDBWithOptions(
				ctx,
				cfg.AuditImmuDBAddr,
				cfg.AuditImmuDBUsername,
				cfg.AuditImmuDBPassword,
				cfg.AuditImmuDBDatabase,
				opts,
			)
			if err != nil {
				log.Fatalf("anchor: additional immudb:// connect failed (addr=%s db=%s): %v",
					cfg.AuditImmuDBAddr, cfg.AuditImmuDBDatabase, err)
			}
			sinks = append(sinks, chain.NewImmuDBSink(immuClient, cfg.AuditImmuDBDatabase))
			log.Printf("anchor: additional immudb:// sink connected (addr=%s db=%s)",
				cfg.AuditImmuDBAddr, cfg.AuditImmuDBDatabase)

		case "":
			// empty after trim — skip

		default:
			// Unsupported scheme. ValidateStartupConfig would have caught this in prod,
			// but log and skip gracefully for non-fatal misconfiguration in dev.
			log.Printf("anchor: unsupported additional sink scheme %q — skipped (supported: file://, immudb://)", scheme)
		}
	}
	return sinks
}
