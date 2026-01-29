package config

import "os"

type Config struct {
	DatabaseURL string
	RedisURL    string
	JWTSecret   string
	OpenAIAPIKey string
	ServerPort  string
}

func Load() *Config {
	return &Config{
		DatabaseURL:  getEnv("DATABASE_URL", "postgres://shadowai:shadowai_secret@localhost:5432/shadowai?sslmode=disable"),
		RedisURL:     getEnv("REDIS_URL", "redis://localhost:6379/0"),
		JWTSecret:    getEnv("JWT_SECRET", "change-me-in-production-32chars!!"),
		OpenAIAPIKey: getEnv("OPENAI_API_KEY", ""),
		ServerPort:   getEnv("SERVER_PORT", "8080"),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
