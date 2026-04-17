package firewallbench

import (
	"context"

	"github.com/shadowai/backend/internal/firewall"
)

// NewFirewallDetector оборачивает firewall.Inspector как DetectFunc.
// "Threat detected" = Decision.Action != ActionAllow.
//
// Ошибки InspectRequest и nil-decision трактуются как "не детектил",
// что отражается в FN (positive dataset) или TN (negative). Это
// консервативное решение: мы не хотим падать бенчмарк из-за единичного
// сбоя инспектора, но хотим чтобы сбой отразился в метриках recall.
//
// Важно: передаётся pure text через Payload.Text. Multi-turn и session-
// scoped инспекторы (MultiTurn, ContentRateLimiter) не покрыты — это
// отдельный layer бенчмарка.
func NewFirewallDetector(ins firewall.Inspector) DetectFunc {
	return func(ctx context.Context, text string) bool {
		d, err := ins.InspectRequest(ctx, &firewall.Payload{
			Text:  text,
			Phase: firewall.PhaseRequest,
		})
		if err != nil || d == nil {
			return false
		}
		return d.Action != firewall.ActionAllow
	}
}

// InspectorFactory создаёт инспектор с default enabled-конфигурацией
// и judge=nil (offline/детерминированный бенчмарк). Добавляется сюда,
// когда бенчмарк расширяется на новый инспектор.
type InspectorFactory struct {
	Name string
	Make func() firewall.Inspector
}

// Registry возвращает список доступных инспекторов для CLI. Порядок
// важен: он определяет порядок вывода в отчёте (и, следовательно,
// стабильность diff'ов между запусками).
func Registry() []InspectorFactory {
	return []InspectorFactory{
		{
			Name: "prompt_injection",
			Make: func() firewall.Inspector {
				return firewall.NewPromptInjectionInspector(
					firewall.PromptInjectionConfig{Enabled: true},
					nil, // judge=nil — offline, детерминированный
				)
			},
		},
		{
			Name: "jailbreak",
			Make: func() firewall.Inspector {
				return firewall.NewJailbreakInspector(
					firewall.JailbreakConfig{Enabled: true},
					nil,
				)
			},
		},
	}
}
