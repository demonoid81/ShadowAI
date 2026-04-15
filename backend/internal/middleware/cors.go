package middleware

import (
	"net/http"
	"strings"

	"github.com/rs/cors"
)

func CORS(allowedHosts string) func(http.Handler) http.Handler {
	origins := []string{"http://localhost:3000", "http://localhost:5173"}
	if strings.TrimSpace(allowedHosts) != "" {
		origins = splitCSV(allowedHosts)
	}

	c := cors.New(cors.Options{
		AllowedOrigins:     origins,
		AllowedMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:     []string{"Authorization", "Content-Type", "X-API-Key", "X-No-Cache", "Origin"},
		ExposedHeaders:     []string{"X-Rate-Limit-Remaining", "X-Cache", "X-Provider"},
		OptionsPassthrough: true,
		AllowCredentials: true,
		MaxAge:            3600,
		Debug:             false,
	})
	return c.Handler
}

func splitCSV(values string) []string {
	parts := strings.Split(values, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		result = append(result, v)
	}
	return result
}
