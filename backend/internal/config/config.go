package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL             string
	RedisURL                string
	JWTSecret               string
	DLPMode                 string
	OpenAIAPIKey            string
	AnthropicAPIKey         string
	GeminiAPIKey            string
	MistralAPIKey           string
	GroqAPIKey              string
	OpenRouterAPIKey        string
	OllamaURL               string
	InternalDBSources       string
	InternalDBRefreshInterval time.Duration
	InternalDBQueryTimeout   time.Duration
	AllowedProviderHosts    string
	ServerPort              string
	RoutingStrategy         string
	FallbackOrder           string
	CacheEnabled            bool
	CacheTTL                string
	ProviderConnectivityInterval time.Duration
	MaxCompletionTokens     int
	CORSAllowedHosts        string
	TrustedProxyCIDRs       string
	ServerReadTimeout       time.Duration
	ServerWriteTimeout      time.Duration
	ServerIdleTimeout       time.Duration
	ServerReadHeaderTimeout time.Duration
	ServerMaxHeaderBytes    int

	// Firewall
	FirewallEnabled              bool
	FirewallPIEnabled            bool
	FirewallPIHeuristicThreshold float64
	FirewallPIJudgeThreshold     float64
	FirewallJBEnabled            bool
	FirewallJBHeuristicThreshold float64
	FirewallJBJudgeThreshold     float64
	FirewallJudgeEnabled         bool
	FirewallJudgeProvider        string
	FirewallJudgeModel           string
	FirewallJudgeEndpoint        string
	FirewallJudgeAPIKey          string
	FirewallJudgeTimeout         time.Duration
	FirewallCMEnabled            bool
	FirewallCMHeuristicThreshold float64
	FirewallCMJudgeThreshold     float64
	FirewallOVEnabled            bool
	FirewallOVHeuristicThreshold float64
	FirewallRLEnabled            bool
	FirewallRLMaxCharsPerMinute  int
	FirewallRLMaxFlagsPerMinute  int
	FirewallMTEnabled            bool
	FirewallMTWindowSize         int
	FirewallMTHeuristicThreshold float64
	FirewallSAEnabled            bool
	FirewallSAThreshold          float64
	FirewallSABlockThreshold     float64
	// Semantic V2 (embedding-based) — PR-6.
	FirewallSAV2Enabled          bool
	FirewallSAV2Threshold        float64
	FirewallSAV2BlockThreshold   float64
	FirewallSAV2CorpusPath       string
	FirewallEmbeddingProvider    string
	FirewallEmbeddingEndpoint    string
	FirewallEmbeddingModel       string
	FirewallEmbeddingAPIKey      string
	FirewallEmbeddingDimension   int
	FirewallEmbeddingTimeout     time.Duration
}

func Load() *Config {
	defaultReadTimeout, _ := time.ParseDuration("15s")
	defaultWriteTimeout, _ := time.ParseDuration("120s")
	defaultIdleTimeout, _ := time.ParseDuration("120s")
	defaultReadHeaderTimeout, _ := time.ParseDuration("5s")
	readTimeout := getDuration("SERVER_READ_TIMEOUT", defaultReadTimeout)
	writeTimeout := getDuration("SERVER_WRITE_TIMEOUT", defaultWriteTimeout)
	idleTimeout := getDuration("SERVER_IDLE_TIMEOUT", defaultIdleTimeout)
	readHeaderTimeout := getDuration("SERVER_READ_HEADER_TIMEOUT", defaultReadHeaderTimeout)

	return &Config{
		DatabaseURL:             getEnv("DATABASE_URL", "postgres://shadowai:shadowai_secret@localhost:5432/shadowai?sslmode=disable"),
		RedisURL:                getEnv("REDIS_URL", "redis://localhost:6379/0"),
		JWTSecret:               getEnv("JWT_SECRET", "change-me-in-production-32chars!!"),
		DLPMode:                 getEnv("DLP_MODE", "enforce"),
		OpenAIAPIKey:            getEnv("OPENAI_API_KEY", ""),
		AnthropicAPIKey:         getEnv("ANTHROPIC_API_KEY", ""),
		GeminiAPIKey:            getEnv("GEMINI_API_KEY", ""),
		MistralAPIKey:           getEnv("MISTRAL_API_KEY", ""),
		GroqAPIKey:              getEnv("GROQ_API_KEY", ""),
		OpenRouterAPIKey:        getEnv("OPENROUTER_API_KEY", ""),
		InternalDBSources:       getEnv("INTERNAL_DB_SOURCES", ""),
		InternalDBRefreshInterval: getDuration("INTERNAL_DB_REFRESH_INTERVAL", 30*time.Second),
		InternalDBQueryTimeout:  getDuration("INTERNAL_DB_QUERY_TIMEOUT", 8*time.Second),
		OllamaURL:               getEnv("OLLAMA_URL", "http://localhost:11434"),
		AllowedProviderHosts:    getEnv("ALLOWED_PROVIDER_HOSTS", "api.openai.com,api.anthropic.com,generativelanguage.googleapis.com,api.mistral.ai,api.groq.com,openrouter.ai,localhost"),
		ServerPort:              getEnv("SERVER_PORT", "8080"),
		RoutingStrategy:         getEnv("ROUTING_STRATEGY", "cheapest"),
		FallbackOrder:           getEnv("FALLBACK_ORDER", ""),
		CacheEnabled:            getEnv("CACHE_ENABLED", "true") == "true",
		CacheTTL:                getEnv("CACHE_TTL", "1h"),
		ProviderConnectivityInterval: getDuration("PROVIDER_CONNECTIVITY_INTERVAL", 5*time.Minute),
		MaxCompletionTokens:     getEnvInt("MAX_COMPLETION_TOKENS", 0),
		CORSAllowedHosts:        getEnv("CORS_ALLOWED_HOSTS", "http://localhost:3000,http://localhost:5173"),
		TrustedProxyCIDRs:       getEnv("TRUSTED_PROXY_CIDRS", ""),
		ServerReadTimeout:       readTimeout,
		ServerWriteTimeout:      writeTimeout,
		ServerIdleTimeout:       idleTimeout,
		ServerReadHeaderTimeout: readHeaderTimeout,
		ServerMaxHeaderBytes:    getEnvInt("SERVER_MAX_HEADER_BYTES", 1<<20),

		// Firewall
		FirewallEnabled:              getEnv("FIREWALL_ENABLED", "true") == "true",
		FirewallPIEnabled:            getEnv("FIREWALL_PI_ENABLED", "true") == "true",
		FirewallPIHeuristicThreshold: getEnvFloat("FIREWALL_PI_HEURISTIC_THRESHOLD", 0.8),
		FirewallPIJudgeThreshold:     getEnvFloat("FIREWALL_PI_JUDGE_THRESHOLD", 0.4),
		FirewallJBEnabled:            getEnv("FIREWALL_JB_ENABLED", "true") == "true",
		FirewallJBHeuristicThreshold: getEnvFloat("FIREWALL_JB_HEURISTIC_THRESHOLD", 0.8),
		FirewallJBJudgeThreshold:     getEnvFloat("FIREWALL_JB_JUDGE_THRESHOLD", 0.4),
		FirewallJudgeEnabled:         getEnv("FIREWALL_JUDGE_ENABLED", "false") == "true",
		FirewallJudgeProvider:        getEnv("FIREWALL_JUDGE_PROVIDER", "ollama"),
		FirewallJudgeModel:           getEnv("FIREWALL_JUDGE_MODEL", "llama3.2"),
		FirewallJudgeEndpoint:        getEnv("FIREWALL_JUDGE_ENDPOINT", "http://localhost:11434"),
		FirewallJudgeAPIKey:          getEnv("FIREWALL_JUDGE_API_KEY", ""),
		FirewallJudgeTimeout:         getDuration("FIREWALL_JUDGE_TIMEOUT", 5*time.Second),
		FirewallCMEnabled:            getEnv("FIREWALL_CM_ENABLED", "true") == "true",
		FirewallCMHeuristicThreshold: getEnvFloat("FIREWALL_CM_HEURISTIC_THRESHOLD", 0.7),
		FirewallCMJudgeThreshold:     getEnvFloat("FIREWALL_CM_JUDGE_THRESHOLD", 0.3),
		FirewallOVEnabled:            getEnv("FIREWALL_OV_ENABLED", "true") == "true",
		FirewallOVHeuristicThreshold: getEnvFloat("FIREWALL_OV_HEURISTIC_THRESHOLD", 0.7),
		FirewallRLEnabled:            getEnv("FIREWALL_RL_ENABLED", "false") == "true",
		FirewallRLMaxCharsPerMinute:  getEnvInt("FIREWALL_RL_MAX_CHARS_PER_MINUTE", 50000),
		FirewallRLMaxFlagsPerMinute:  getEnvInt("FIREWALL_RL_MAX_FLAGS_PER_MINUTE", 5),
		FirewallMTEnabled:            getEnv("FIREWALL_MT_ENABLED", "true") == "true",
		FirewallMTWindowSize:         getEnvInt("FIREWALL_MT_WINDOW_SIZE", 10),
		FirewallMTHeuristicThreshold: getEnvFloat("FIREWALL_MT_HEURISTIC_THRESHOLD", 0.6),
		FirewallSAEnabled:            getEnv("FIREWALL_SA_ENABLED", "true") == "true",
		FirewallSAThreshold:          getEnvFloat("FIREWALL_SA_THRESHOLD", 0.5),
		FirewallSABlockThreshold:     getEnvFloat("FIREWALL_SA_BLOCK_THRESHOLD", 0.75),
		// PR-6: Semantic V2 (embedding-based). По-умолчанию отключен,
		// потому что требует: (1) external embedding provider; (2) corpus
		// manifest; (3) provider/model/dimension match с corpus.
		FirewallSAV2Enabled:          getEnv("FIREWALL_SA_V2_ENABLED", "false") == "true",
		FirewallSAV2Threshold:        getEnvFloat("FIREWALL_SA_V2_THRESHOLD", 0.75),
		FirewallSAV2BlockThreshold:   getEnvFloat("FIREWALL_SA_V2_BLOCK_THRESHOLD", 0.88),
		FirewallSAV2CorpusPath:       getEnv("FIREWALL_SA_V2_CORPUS_PATH", "firewall_corpus/semantic_v2.json"),
		FirewallEmbeddingProvider:    getEnv("FIREWALL_EMBEDDING_PROVIDER", "ollama"),
		FirewallEmbeddingEndpoint:    getEnv("FIREWALL_EMBEDDING_ENDPOINT", "http://localhost:11434"),
		FirewallEmbeddingModel:       getEnv("FIREWALL_EMBEDDING_MODEL", "nomic-embed-text"),
		FirewallEmbeddingAPIKey:      getEnv("FIREWALL_EMBEDDING_API_KEY", ""),
		FirewallEmbeddingDimension:   getEnvInt("FIREWALL_EMBEDDING_DIMENSION", 768),
		FirewallEmbeddingTimeout:     getDuration("FIREWALL_EMBEDDING_TIMEOUT", 10*time.Second),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvFloat(key string, fallback float64) float64 {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func getEnvInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	custom, err := strconv.Atoi(value)
	if err != nil || custom <= 0 {
		return fallback
	}
	return custom
}
