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
