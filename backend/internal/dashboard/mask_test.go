package dashboard

import "testing"

// TestMaskEmail — PR-D.1 privacy: проверяем, что маска сохраняет
// domain (для recognition) и прячет local part. Никакой строки
// результата не должно полностью совпасть с оригиналом, если email
// валиден и длиннее 2 символов до @.
func TestMaskEmail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"john.doe@example.com", "jo***@example.com"},
		{"a@example.com", "*@example.com"},
		{"ab@example.com", "*@example.com"},
		{"abc@example.com", "ab***@example.com"},
		{"verylongname@sub.domain.example.com", "ve***@sub.domain.example.com"},
		{"noatsign", "***"},
		{"@missinglocal.com", "***"},
	}
	for _, tc := range cases {
		got := maskEmail(tc.in)
		if got != tc.want {
			t.Errorf("maskEmail(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMaskEmail_NeverReturnsRaw — property-style guard: для любого
// валидного email с local-part длиной >= 1 результат маски не должен
// содержать full local part (защита от drift в логике маскинга).
func TestMaskEmail_NeverReturnsRaw(t *testing.T) {
	inputs := []string{
		"sensitive@example.com",
		"ceo@competitor.com",
		"test.user+tag@example.co.uk",
	}
	for _, in := range inputs {
		masked := maskEmail(in)
		// Local part (до @) не должен появиться в masked как есть.
		at := -1
		for i, c := range in {
			if c == '@' {
				at = i
				break
			}
		}
		if at <= 0 {
			continue
		}
		local := in[:at]
		if len(local) > 2 && contains(masked, local) {
			t.Errorf("maskEmail(%q)=%q — полный local part %q просочился", in, masked, local)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
