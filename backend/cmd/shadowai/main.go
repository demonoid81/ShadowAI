package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/budget"
	"github.com/shadowai/backend/internal/config"
	"github.com/shadowai/backend/internal/dashboard"
	mw "github.com/shadowai/backend/internal/middleware"
	"github.com/shadowai/backend/internal/platform/postgres"
	rdb "github.com/shadowai/backend/internal/platform/redis"
	"github.com/shadowai/backend/internal/policy"
	"github.com/shadowai/backend/internal/proxy"
)

func main() {
	cfg := config.Load()

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

	// Services
	authSvc := auth.NewService(authRepo, cfg.JWTSecret)
	auditSvc := audit.NewService(auditRepo)
	policySvc := policy.NewService(policyRepo)
	budgetSvc := budget.NewService(budgetRepo, redisClient)

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

	// Handlers
	authHandler := auth.NewHandler(authSvc)
	auditHandler := audit.NewHandler(auditSvc)
	policyHandler := policy.NewHandler(policySvc)
	budgetHandler := budget.NewHandler(budgetSvc)
	dashHandler := dashboard.NewHandler(db)
	proxyHandler := proxy.NewHandler(registry, policySvc, auditSvc, budgetSvc, router, cache, healthTracker)

	r := mux.NewRouter()

	// Public routes
	r.HandleFunc("/api/auth/login", authHandler.Login).Methods("POST")
	r.HandleFunc("/api/auth/register", authHandler.Register).Methods("POST")

	// Health check
	r.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}).Methods("GET")

	// Protected API routes
	api := r.PathPrefix("/api").Subrouter()
	api.Use(authSvc.AuthMiddleware)

	// Users (admin only)
	admin := api.PathPrefix("").Subrouter()
	admin.Use(auth.RequireRole("admin"))
	admin.HandleFunc("/users", authHandler.ListUsers).Methods("GET")
	admin.HandleFunc("/users/{id}", authHandler.GetUser).Methods("GET")
	admin.HandleFunc("/users/{id}", authHandler.UpdateUser).Methods("PUT")

	// Audit logs
	api.HandleFunc("/audit/logs", auditHandler.List).Methods("GET")

	// Policies (admin)
	admin.HandleFunc("/policies", policyHandler.List).Methods("GET")
	admin.HandleFunc("/policies", policyHandler.Create).Methods("POST")
	admin.HandleFunc("/policies/{id}", policyHandler.Update).Methods("PUT")
	admin.HandleFunc("/policies/{id}", policyHandler.Delete).Methods("DELETE")

	// Budgets
	api.HandleFunc("/budgets/{user_id}", budgetHandler.Get).Methods("GET")
	admin.HandleFunc("/budgets/{user_id}", budgetHandler.Update).Methods("PUT")

	// Dashboard
	api.HandleFunc("/dashboard/stats", dashHandler.GetStats).Methods("GET")
	api.HandleFunc("/dashboard/usage", dashHandler.GetUsage).Methods("GET")
	api.HandleFunc("/dashboard/top-users", dashHandler.GetTopUsers).Methods("GET")

	// Proxy routes (authenticated + rate limited) — wildcard for all providers
	proxyRouter := r.PathPrefix("/proxy").Subrouter()
	proxyRouter.Use(authSvc.AuthMiddleware)
	proxyRouter.Use(mw.RateLimit(redisClient, 60, time.Minute))
	proxyRouter.HandleFunc("/providers", proxyHandler.ListProviders).Methods("GET")
	proxyRouter.HandleFunc("/chat", proxyHandler.UnifiedChat).Methods("POST")
	proxyRouter.PathPrefix("/{provider}/").HandlerFunc(proxyHandler.ProxyChat).Methods("POST")

	// Apply global middleware
	handler := mw.CORS()(r)
	handler = mw.Logging(handler)
	handler = mw.Recovery(handler)

	log.Printf("ShadowAI starting on :%s", cfg.ServerPort)
	if err := http.ListenAndServe(":"+cfg.ServerPort, handler); err != nil {
		log.Fatalf("server: %v", err)
	}
}
