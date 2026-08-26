package sysusers

import "testing"

func TestValidUsername(t *testing.T) {
	cases := []struct {
		u    string
		want bool
	}{
		{"taras", true},
		{"t.shevchenko", false}, // dots aren't in useradd's default charset
		{"_service", true},
		{"root", true},
		{"1invalid", false}, // must start with a letter or underscore
		{"UPPERCASE", false},
		{"", false},
		{"a; rm -rf /", false},
		{"has space", false},
	}
	for _, c := range cases {
		if got := ValidUsername(c.u); got != c.want {
			t.Errorf("ValidUsername(%q) = %v, want %v", c.u, got, c.want)
		}
	}
}

func TestGuardRootRefusesRoot(t *testing.T) {
	if err := guardRoot("root"); err == nil {
		t.Error("expected guardRoot(\"root\") to return an error")
	}
	if err := guardRoot("taras"); err != nil {
		t.Errorf("guardRoot(\"taras\") = %v, want nil", err)
	}
}
