package main

import (
	"os"
	"strings"
	"testing"
)

// TestMainRegistersMetricsRoute — static-check, что main.go действительно
// вызывает metrics.RegisterRoute. Без этого теста сценарий "route удалили
// из main.go и одновременно убрали import" остался бы невидимым для
// unit-тестов в internal/metrics (они вызывают helper напрямую и ничего
// не знают про main.go).
//
// Grep-based, а не AST-based, сознательно: regression-guard должен быть
// максимально простым и падать только при реальном удалении вызова.
func TestMainRegistersMetricsRoute(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "metrics.RegisterRoute") {
		t.Error("main.go не вызывает metrics.RegisterRoute — /metrics endpoint не будет зарегистрирован в prod. " +
			"Если вы намеренно удалили scrape, обновите README/alerting/prometheus.yml.")
	}

	// Дополнительный guard: import пакета metrics должен присутствовать.
	if !strings.Contains(src, `"github.com/shadowai/backend/internal/metrics"`) {
		t.Error("main.go не импортирует internal/metrics — metrics.RegisterRoute не может быть вызван.")
	}

	if !strings.Contains(src, "cfg.ValidateStartupConfig()") {
		t.Error("main.go не валидирует startup config — небезопасные prod defaults смогут стартовать.")
	}
}
