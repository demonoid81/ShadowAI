package firewall

import (
	"testing"
)

// TestParseInspectorMode_Valid — все три валидных значения распознаются
// case-insensitive и с обрезкой пробелов. CLI/YAML часто передают
// значения с пробелами или смешанным регистром.
func TestParseInspectorMode_Valid(t *testing.T) {
	cases := []struct {
		in   string
		want InspectorMode
	}{
		{"enforce", ModeEnforce},
		{"shadow", ModeShadow},
		{"disabled", ModeDisabled},
		{"ENFORCE", ModeEnforce},
		{"  Shadow  ", ModeShadow},
		{"Disabled", ModeDisabled},
	}
	for _, tc := range cases {
		got, err := ParseInspectorMode(tc.in)
		if err != nil {
			t.Errorf("ParseInspectorMode(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseInspectorMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestParseInspectorMode_Invalid — любое другое значение → ошибка.
// Это критично для config loading: "silent accept" привёл бы к
// неочевидной деградации security (тихое падение в enforce не считается).
func TestParseInspectorMode_Invalid(t *testing.T) {
	bad := []string{"", "warn", "block", "allow", "log", "off", "on", "true"}
	for _, b := range bad {
		_, err := ParseInspectorMode(b)
		if err == nil {
			t.Errorf("ParseInspectorMode(%q) expected error, got nil", b)
		}
	}
}

// TestInspectorModes_For_Default — без overrides возвращает Default.
func TestInspectorModes_For_Default(t *testing.T) {
	m := NewInspectorModes(ModeShadow)
	if got := m.For("prompt_injection"); got != ModeShadow {
		t.Errorf("For(unknown) = %q, want Default=%q", got, ModeShadow)
	}
}

// TestInspectorModes_For_Override — override для конкретного инспектора
// имеет приоритет над Default.
func TestInspectorModes_For_Override(t *testing.T) {
	m := NewInspectorModes(ModeEnforce)
	m.Overrides["pii"] = ModeShadow
	m.Overrides["jailbreak"] = ModeDisabled

	if got := m.For("pii"); got != ModeShadow {
		t.Errorf("For(pii) = %q, want shadow", got)
	}
	if got := m.For("jailbreak"); got != ModeDisabled {
		t.Errorf("For(jailbreak) = %q, want disabled", got)
	}
	if got := m.For("prompt_injection"); got != ModeEnforce {
		t.Errorf("For(prompt_injection) = %q, want enforce (default)", got)
	}
}

// TestInspectorModes_For_NilSafe — на nil-указатель For возвращает ModeEnforce.
// Это защищает от NPE в коде, где modes может быть не инициализирован
// (legacy NewPipeline() без аргумента).
func TestInspectorModes_For_NilSafe(t *testing.T) {
	var m *InspectorModes
	if got := m.For("pii"); got != ModeEnforce {
		t.Errorf("nil.For(pii) = %q, want enforce (safe default)", got)
	}
}

// TestInspectorModes_For_EmptyDefault — пустой Default интерпретируется
// как ModeEnforce (fail-safe: "config не задан" != "отключите всё").
func TestInspectorModes_For_EmptyDefault(t *testing.T) {
	m := &InspectorModes{Default: "", Overrides: map[string]InspectorMode{}}
	if got := m.For("pii"); got != ModeEnforce {
		t.Errorf("empty Default.For(pii) = %q, want enforce", got)
	}
}

// TestLoadInspectorModesFromEnv_Default — FIREWALL_MODE_DEFAULT меняет
// default. Без override конкретные инспекторы наследуют его.
func TestLoadInspectorModesFromEnv_Default(t *testing.T) {
	t.Setenv("FIREWALL_MODE_DEFAULT", "shadow")
	m := LoadInspectorModesFromEnv()
	if m.Default != ModeShadow {
		t.Errorf("Default = %q, want shadow", m.Default)
	}
	if got := m.For("anything"); got != ModeShadow {
		t.Errorf("For(anything) = %q, want shadow (inherit default)", got)
	}
}

// TestLoadInspectorModesFromEnv_PerInspector — FIREWALL_MODE_<NAME>
// создаёт override для конкретного инспектора. Суффикс lower-casing'ется
// для согласованности с Inspector.Name().
func TestLoadInspectorModesFromEnv_PerInspector(t *testing.T) {
	t.Setenv("FIREWALL_MODE_DEFAULT", "enforce")
	t.Setenv("FIREWALL_MODE_PII", "shadow")
	t.Setenv("FIREWALL_MODE_PROMPT_INJECTION", "disabled")

	m := LoadInspectorModesFromEnv()

	if m.Default != ModeEnforce {
		t.Errorf("Default = %q, want enforce", m.Default)
	}
	if got := m.For("pii"); got != ModeShadow {
		t.Errorf("For(pii) = %q, want shadow", got)
	}
	if got := m.For("prompt_injection"); got != ModeDisabled {
		t.Errorf("For(prompt_injection) = %q, want disabled", got)
	}
	if got := m.For("jailbreak"); got != ModeEnforce {
		t.Errorf("For(jailbreak) = %q, want enforce (no override)", got)
	}
}

// TestLoadInspectorModesFromEnv_InvalidIgnored — невалидные значения в
// env не ломают загрузку: Default остаётся enforce, override игнорируется.
// Причина: операционная: misconfig env-var не должен положить приложение,
// только логгировать и откатиться на безопасный default.
func TestLoadInspectorModesFromEnv_InvalidIgnored(t *testing.T) {
	t.Setenv("FIREWALL_MODE_DEFAULT", "garbage")
	t.Setenv("FIREWALL_MODE_PII", "also-bad")

	m := LoadInspectorModesFromEnv()

	if m.Default != ModeEnforce {
		t.Errorf("invalid Default should fall back to enforce, got %q", m.Default)
	}
	if _, ok := m.Overrides["pii"]; ok {
		t.Error("invalid PII override должен быть пропущен, но остался в Overrides")
	}
	if got := m.For("pii"); got != ModeEnforce {
		t.Errorf("For(pii) after invalid override = %q, want enforce", got)
	}
}

// TestLoadInspectorModesFromEnv_Empty — без единой env-переменной:
// Default=enforce, Overrides пустой. Гарантирует, что "чистая" установка
// (backward compat) ведёт себя как до PR-4.
func TestLoadInspectorModesFromEnv_Empty(t *testing.T) {
	// Важно: НЕ вызываем Setenv — хотим реальную незаданность.
	// Для надёжности снимаем все FIREWALL_MODE_*, что могли протечь
	// из окружения test-runner'а.
	t.Setenv("FIREWALL_MODE_DEFAULT", "")
	t.Setenv("FIREWALL_MODE_PII", "")

	m := LoadInspectorModesFromEnv()
	if m.Default != ModeEnforce {
		t.Errorf("Default = %q, want enforce", m.Default)
	}
	if len(m.Overrides) != 0 {
		t.Errorf("Overrides должен быть пуст, got %+v", m.Overrides)
	}
}
