package dbmanager

import "testing"

func TestValidIdentifier_Accepts(t *testing.T) {
	maxLength := "a" + stringOfLength(63) // exactly 64 chars, the limit
	valid := []string{
		"shop_prod",
		"a",
		"User123",
		"db_2026",
		maxLength,
	}
	for _, id := range valid {
		if err := ValidIdentifier(id); err != nil {
			t.Errorf("ValidIdentifier(%q): expected valid, got error: %v", id, err)
		}
	}
}

func TestValidIdentifier_RejectsInjectionAttempts(t *testing.T) {
	cases := []string{
		"",
		"1starts_with_digit",
		"has space",
		"has-hyphen",
		"has.dot",
		"has;semicolon",
		"`backtick`",
		`"doublequote"`,
		"'singlequote'",
		"db`; DROP TABLE users;--",
		"db\"; DROP TABLE users;--",
		"db\x00null",
		"назва", // non-ASCII
		"a" + stringOfLength(64), // 65 chars, over the limit
	}
	for _, id := range cases {
		if err := ValidIdentifier(id); err == nil {
			t.Errorf("ValidIdentifier(%q): expected error, got none", id)
		}
	}
}

func TestQuoteMySQL_DoublesEmbeddedBackticks(t *testing.T) {
	// Defense in depth only — this input would already be rejected by
	// ValidIdentifier, but the quoting function itself must still be
	// correct in isolation.
	got := QuoteMySQL("a`b")
	want := "`a``b`"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestQuotePostgres_DoublesEmbeddedQuotes(t *testing.T) {
	got := QuotePostgres(`a"b`)
	want := `"a""b"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func stringOfLength(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}
