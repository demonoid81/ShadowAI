package audit

import "testing"

// TestUUIDArrayLiteral — PR-L2 helper. Конвертация slice string →
// Postgres text[] literal `{...}`. Используется в
// PurgeOlderThanExcept для передачи exceptUserIDs в ANY().
func TestUUIDArrayLiteral(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"empty", nil, "{}"},
		{"empty slice", []string{}, "{}"},
		{"single UUID", []string{"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
			`{"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}`},
		{"two UUIDs",
			[]string{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"},
			`{"11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"}`},
		{"escapes double-quote",
			[]string{`a"b`},
			`{"a\"b"}`},
		{"escapes backslash",
			[]string{`a\b`},
			`{"a\\b"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := uuidArrayLiteral(c.in)
			if got != c.want {
				t.Errorf("uuidArrayLiteral(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
