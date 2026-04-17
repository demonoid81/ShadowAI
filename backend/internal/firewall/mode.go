package firewall

import (
	"fmt"
	"os"
	"strings"
)

// InspectorMode управляет тем, как pipeline исполняет инспектор.
//
//   - ModeEnforce   — текущее поведение: Block/Sanitize/Flag применяются.
//   - ModeShadow    — инспектор запускается, но pipeline не применяет его
//     решение. Decision попадает в Decision.ShadowDecisions для audit;
//     метрика инкрементится с label mode=shadow. payload.Meta["flagged"]
//     не мутируется, recordFlag() не вызывается.
//   - ModeDisabled  — инспектор не запускается вообще. Ни audit, ни метрик.
//
// Значения выбраны так, чтобы их можно было безопасно сериализовать в
// env, config, API и audit columns (lower-case ASCII, без пробелов).
type InspectorMode string

const (
	ModeEnforce  InspectorMode = "enforce"
	ModeShadow   InspectorMode = "shadow"
	ModeDisabled InspectorMode = "disabled"
)

// ParseInspectorMode распознаёт строку (case-insensitive, с trim пробелов).
// Любое иное значение — ошибка: misconfig должен быть видимым, а не
// молча превращаться в enforce или disabled.
func ParseInspectorMode(s string) (InspectorMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModeEnforce):
		return ModeEnforce, nil
	case string(ModeShadow):
		return ModeShadow, nil
	case string(ModeDisabled):
		return ModeDisabled, nil
	default:
		return "", fmt.Errorf("unknown inspector mode %q (want enforce|shadow|disabled)", s)
	}
}

// InspectorModes — runtime-представление конфигурации режимов.
//
// Resolution shape спроектирован под будущий tenant-override layer:
// сейчас For(name) возвращает Override[name] ?? Default. В v2 здесь
// появится поверх Default уровень tenant-overrides: For(tenantID, name).
type InspectorModes struct {
	Default   InspectorMode
	Overrides map[string]InspectorMode
}

// NewInspectorModes создаёт пустую конфигурацию с заданным дефолтом.
func NewInspectorModes(def InspectorMode) *InspectorModes {
	return &InspectorModes{
		Default:   def,
		Overrides: make(map[string]InspectorMode),
	}
}

// For возвращает режим для инспектора с именем name.
// Порядок: Overrides[name] → Default → ModeEnforce (fail-safe).
// Nil-receiver безопасен: возвращает ModeEnforce.
func (m *InspectorModes) For(name string) InspectorMode {
	if m == nil {
		return ModeEnforce
	}
	if override, ok := m.Overrides[name]; ok {
		return override
	}
	if m.Default == "" {
		return ModeEnforce
	}
	return m.Default
}

// LoadInspectorModesFromEnv читает конфигурацию из process environment.
//
// Формат:
//   FIREWALL_MODE_DEFAULT=enforce|shadow|disabled        (default: enforce)
//   FIREWALL_MODE_<INSPECTOR>=enforce|shadow|disabled    (override)
//
// Имя инспектора в env — UPPER_SNAKE_CASE (напр. FIREWALL_MODE_PROMPT_INJECTION).
// Ключ в Overrides — lower_snake_case, чтобы совпадать с Inspector.Name().
//
// Невалидные значения логируются только через возврат fallback'ом в
// enforce (без логгера тут, чтобы пакет не зависел от logger'а приложения).
// Оператор обнаружит misconfig через status.Mode или метрики firewall.
func LoadInspectorModesFromEnv() *InspectorModes {
	modes := NewInspectorModes(ModeEnforce)

	if v := os.Getenv("FIREWALL_MODE_DEFAULT"); v != "" {
		if parsed, err := ParseInspectorMode(v); err == nil {
			modes.Default = parsed
		}
	}

	const prefix = "FIREWALL_MODE_"
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, prefix) {
			continue
		}
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}

		suffix := strings.TrimPrefix(key, prefix)
		if suffix == "" || suffix == "DEFAULT" {
			continue
		}

		parsed, err := ParseInspectorMode(val)
		if err != nil {
			continue
		}
		modes.Overrides[strings.ToLower(suffix)] = parsed
	}

	return modes
}
