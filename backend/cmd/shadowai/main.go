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

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/config"
	"github.com/shadowai/backend/internal/dashboard"
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/embedding"
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/governance"
	"github.com/shadowai/backend/internal/internaldb"
	"github.com/shadowai/backend/internal/metrics"
	mw "github.com/shadowai/backend/internal/middleware"
	"github.com/shadowai/backend/internal/platform/postgres"
	rdb "github.com/shadowai/backend/internal/platform/redis"
	"github.com/shadowai/backend/internal/policy"
	"github.com/shadowai/backend/internal/proxy"
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
	auditRepo := audit.NewRepository(db)
	policyRepo := policy.NewRepository(db)
	budgetRepo := budget.NewRepository(db)
	internalDBRepo := internaldb.NewRepository(db)

	// Services
	authSvc := auth.NewService(authRepo, cfg.JWTSecret)
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
			embClient, err := embedding.NewClient(embedding.Config{
				Provider:  cfg.FirewallEmbeddingProvider,
				Endpoint:  cfg.FirewallEmbeddingEndpoint,
				Model:     cfg.FirewallEmbeddingModel,
				APIKey:    cfg.FirewallEmbeddingAPIKey,
				Dimension: cfg.FirewallEmbeddingDimension,
				Timeout:   cfg.FirewallEmbeddingTimeout,
			})
			if err != nil {
				log.Printf("semantic_v2: embedding client init failed (skipping inspector): %v", err)
			} else {
				corpus, err := embedding.LoadCorpus(cfg.FirewallSAV2CorpusPath)
				if err != nil {
					log.Printf("semantic_v2: corpus load failed (skipping inspector): %v", err)
				} else {
					sv2, err := firewall.NewSemanticV2Inspector(firewall.SemanticV2Config{
						Enabled:        true,
						Threshold:      cfg.FirewallSAV2Threshold,
						BlockThreshold: cfg.FirewallSAV2BlockThreshold,
					}, embClient, corpus)
					if err != nil {
						log.Printf("semantic_v2: init failed (skipping inspector): %v", err)
					} else {
						firewallPipeline.Register(sv2)
						log.Printf("semantic_v2: registered (provider=%s model=%s dim=%d corpus_items=%d)",
							embClient.Provider(), embClient.Model(), embClient.Dimension(), len(corpus.Items))
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

	// Handlers
	// PR-D: admin access audit (отдельная таблица admin_event_logs).
	// Создаётся до handler'ов, потому что они принимают adminAuditSvc в DI.
	adminAuditRepo := adminaudit.NewRepository(db)
	adminAuditSvc := adminaudit.NewService(adminAuditRepo)
	adminAuditHandler := adminaudit.NewHandler(adminAuditRepo)

	// PR-B: DSAR/erasure wiring. auditRepo + budgetRepo используются
	// как AuditScrubber + BudgetDeleter через interface intersection.
	erasureSvc := auth.NewErasureService(db, auditRepo, budgetRepo)
	authHandler := auth.NewHandler(authSvc, erasureSvc, adminAuditSvc)
	// schedulerEnabled ровно повторяет условие запуска goroutine ниже
	// (cfg.AuditPurgeInterval > 0 && cfg.AuditRetentionDays > 0). Без
	// этой согласованности /audit/status врал бы оператору.
	auditSchedulerEnabled := cfg.AuditPurgeInterval > 0 && cfg.AuditRetentionDays > 0
	adminEventsSchedulerEnabled := cfg.AuditPurgeInterval > 0 && cfg.AdminAuditRetentionDays > 0
	auditHandler := audit.NewHandler(auditSvc, auditPayloadMode, cfg.AuditRetentionDays, auditSchedulerEnabled, adminAuditSvc, cfg.AdminAuditRetentionDays, adminEventsSchedulerEnabled)
	policyHandler := policy.NewHandler(policySvc)
	budgetHandler := budget.NewHandler(budgetSvc)
	dashHandler := dashboard.NewHandler(db, adminAuditSvc)
	internalDBHandler := internaldb.NewHandler(internalDBManager, internalDBRepo, auditSvc, auditPayloadMode, dlpSvc, adminAuditSvc)

	// PR-G1: Provider/Model Governance wiring.
	// Одно-таблица storage (migration 012_create_provider_governance_policies.sql)
	// с singleton-строкой. nil-safe: при отсутствии таблицы GetActive
	// вернёт (nil, nil) → governance_disabled.
	governanceRepo := governance.NewPGRepository(db)
	governanceSvc := governance.NewService(governanceRepo)
	governanceHandler := governance.NewHandler(governanceSvc, adminAuditSvc)

	proxyHandler := proxy.NewHandler(registry, policySvc, auditSvc, budgetSvc, dlpSvc, cfg.AllowedProviderHosts, router, cache, healthTracker, cfg.MaxCompletionTokens, firewallPipeline, auditPayloadMode, governanceSvc, adminAuditSvc)

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

	// PR-A: audit-purge scheduler. Запускается, если явно задан
	// AUDIT_PURGE_INTERVAL (>0) И AUDIT_RETENTION_DAYS (>0). Без обоих
	// значений — scheduler не стартует (CLI остаётся основным путём).
	if cfg.AuditPurgeInterval > 0 && cfg.AuditRetentionDays > 0 {
		go func() {
			log.Printf("audit-purge scheduler: interval=%s retention=%d days chunk=%d",
				cfg.AuditPurgeInterval, cfg.AuditRetentionDays, cfg.AuditPurgeChunkSize)
			ticker := time.NewTicker(cfg.AuditPurgeInterval)
			defer ticker.Stop()
			repo := auditSvc.GetRepo()
			purge := func() {
				cutoff := time.Now().UTC().Add(-time.Duration(cfg.AuditRetentionDays) * 24 * time.Hour)
				ctx, cancel := context.WithTimeout(connectivityCtx, 30*time.Minute)
				defer cancel()
				deleted, err := repo.PurgeOlderThan(ctx, cutoff, cfg.AuditPurgeChunkSize)
				if err != nil {
					log.Printf("audit-purge scheduler: err: %v", err)
					// PR-D: фиксируем failed purge в admin-event-logs.
					adminAuditSvc.Record(ctx, adminaudit.Event{
						ActorUserID: nil, Action: "purge", Resource: "audit_logs",
						Path: "scheduler", Method: "INTERNAL", Success: false,
						Metadata: map[string]any{
							"mode": "scheduler", "cutoff": cutoff.Format(time.RFC3339),
							"error": err.Error(),
						},
					})
					return
				}
				if err := repo.RecordPurgeRun(ctx, cutoff, deleted, audit.PurgeTargetAuditLogs); err != nil {
					log.Printf("audit-purge scheduler: record run failed: %v", err)
				}
				log.Printf("audit-purge scheduler: deleted %d rows (cutoff=%s)", deleted, cutoff.Format(time.RFC3339))
				adminAuditSvc.Record(ctx, adminaudit.Event{
					ActorUserID: nil, Action: "purge", Resource: "audit_logs",
					Path: "scheduler", Method: "INTERNAL", Success: true,
					Metadata: map[string]any{
						"mode": "scheduler", "cutoff": cutoff.Format(time.RFC3339),
						"rows_deleted": deleted,
					},
				})
			}
			for {
				select {
				case <-ticker.C:
					purge()
				case <-connectivityCtx.Done():
					return
				}
			}
		}()
	}

	// PR-D.1: scheduler для admin_event_logs. Отдельная retention
	// (compliance-aware: admin events обычно хранятся дольше).
	if cfg.AuditPurgeInterval > 0 && cfg.AdminAuditRetentionDays > 0 {
		go func() {
			log.Printf("admin-events purge scheduler: interval=%s retention=%d days chunk=%d",
				cfg.AuditPurgeInterval, cfg.AdminAuditRetentionDays, cfg.AuditPurgeChunkSize)
			ticker := time.NewTicker(cfg.AuditPurgeInterval)
			defer ticker.Stop()
			auditRepoHandle := auditSvc.GetRepo()
			purgeAdmin := func() {
				cutoff := time.Now().UTC().Add(-time.Duration(cfg.AdminAuditRetentionDays) * 24 * time.Hour)
				ctx, cancel := context.WithTimeout(connectivityCtx, 30*time.Minute)
				defer cancel()
				deleted, err := adminAuditRepo.PurgeOlderThan(ctx, cutoff, cfg.AuditPurgeChunkSize)
				if err != nil {
					log.Printf("admin-events purge scheduler: err: %v", err)
					adminAuditSvc.Record(ctx, adminaudit.Event{
						ActorUserID: nil, Action: "purge", Resource: adminaudit.PurgeTarget,
						Path: "scheduler", Method: "INTERNAL", Success: false,
						Metadata: map[string]any{
							"mode": "scheduler", "target": adminaudit.PurgeTarget,
							"cutoff": cutoff.Format(time.RFC3339), "error": err.Error(),
						},
					})
					return
				}
				if err := auditRepoHandle.RecordPurgeRun(ctx, cutoff, deleted, adminaudit.PurgeTarget); err != nil {
					log.Printf("admin-events purge scheduler: record run failed: %v", err)
				}
				log.Printf("admin-events purge scheduler: deleted %d rows (cutoff=%s)", deleted, cutoff.Format(time.RFC3339))
				adminAuditSvc.Record(ctx, adminaudit.Event{
					ActorUserID: nil, Action: "purge", Resource: adminaudit.PurgeTarget,
					Path: "scheduler", Method: "INTERNAL", Success: true,
					Metadata: map[string]any{
						"mode": "scheduler", "target": adminaudit.PurgeTarget,
						"cutoff": cutoff.Format(time.RFC3339), "rows_deleted": deleted,
					},
				})
			}
			for {
				select {
				case <-ticker.C:
					purgeAdmin()
				case <-connectivityCtx.Done():
					return
				}
			}
		}()
	}

	r := mux.NewRouter()

	// Public routes
	publicAuth := r.PathPrefix("/api/auth").Subrouter()
	publicAuth.HandleFunc("/login", authHandler.Login).Methods("POST")
	publicAuth.HandleFunc("/register", authHandler.Register).Methods("POST")
	publicAuth.Use(mw.RateLimitPublic(redisClient, 20, time.Minute))

	// Health check
	r.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}).Methods("GET")

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
	// PR-B: DSAR erasure. Admin-only, идемпотентный (повторный вызов
	// возвращает status=already_erased).
	admin.HandleFunc("/users/{id}/erase", authHandler.EraseUser).Methods("POST")

	// Audit logs
	admin.HandleFunc("/audit/logs", auditHandler.List).Methods("GET")
	admin.HandleFunc("/audit/status", auditHandler.Status).Methods("GET")
	// PR-D: admin access audit.
	admin.HandleFunc("/admin-events", adminAuditHandler.List).Methods("GET")

	// Policies (admin)
	admin.HandleFunc("/policies", policyHandler.List).Methods("GET")
	admin.HandleFunc("/policies", policyHandler.Create).Methods("POST")
	admin.HandleFunc("/policies/{id}", policyHandler.Update).Methods("PUT")
	admin.HandleFunc("/policies/{id}", policyHandler.Delete).Methods("DELETE")

	// PR-G1: Provider/Model Governance (admin-only).
	admin.HandleFunc("/governance/policy", governanceHandler.GetPolicy).Methods("GET")
	admin.HandleFunc("/governance/policy", governanceHandler.UpdatePolicy).Methods("PUT")

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
