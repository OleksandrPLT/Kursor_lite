package auth

import "testing"

// These cases mirror what was verified against web/static/js/accounts.js
// directly (via node) — the two implementations must agree, since one
// suggests a username live in the browser and the other generates one
// server-side from a ticket's "Create Account" button.
func TestSuggestUsername(t *testing.T) {
	cases := []struct{ first, last, want string }{
		{"Тарас", "Шевченко", "t.shevchenko"},
		{"Олена", "Іваненко", "o.ivanenko"},
		{"Юрій", "Гончарук", "i.honcharuk"},
		{"В'ячеслав", "Щербак", "v.shcherbak"},
		{"", "Шевченко", ""},
		{"Тарас", "", ""},
	}
	for _, c := range cases {
		got := SuggestUsername(c.first, c.last)
		if got != c.want {
			t.Errorf("SuggestUsername(%q, %q) = %q, want %q", c.first, c.last, got, c.want)
		}
	}
}
