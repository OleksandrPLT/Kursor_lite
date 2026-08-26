package version

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUpdateAvailable(t *testing.T) {
	old := GitCommit
	defer func() { GitCommit = old }()

	cases := []struct {
		running string
		latest  string
		want    bool
	}{
		{"dev", "abcdef1", false},     // a dev build never claims to be outdated
		{"", "abcdef1", false},        // empty is treated the same as "dev"
		{"abcdef1", "abcdef1", false}, // exact match — up to date
		{"abcdef1", "1234567", true},  // genuinely different commits
	}
	for _, c := range cases {
		GitCommit = c.running
		if got := UpdateAvailable(LatestInfo{ShortSHA: c.latest}); got != c.want {
			t.Errorf("running=%q latest=%q: UpdateAvailable() = %v, want %v", c.running, c.latest, got, c.want)
		}
	}
}

func TestCheckLatestParsesGitHubResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha":      "1234567890abcdef1234567890abcdef12345678",
			"html_url": "https://github.com/OleksandrPLT/Kursor_lite/commit/1234567",
			"commit": map[string]any{
				"message": "Fix the thing\n\nLonger body text here.",
				"author": map[string]any{
					"date": time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339),
				},
			},
		})
	}))
	defer server.Close()

	old := repoAPI
	repoAPI = server.URL
	defer func() { repoAPI = old }()

	got, err := CheckLatest()
	if err != nil {
		t.Fatalf("CheckLatest() error = %v", err)
	}
	if got.ShortSHA != "1234567" {
		t.Errorf("ShortSHA = %q, want %q", got.ShortSHA, "1234567")
	}
	if got.Message != "Fix the thing" {
		t.Errorf("Message = %q, want first line only", got.Message)
	}
	if got.Date.Year() != 2026 {
		t.Errorf("Date = %v, want year 2026", got.Date)
	}
}

func TestCheckLatestSurfacesNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // e.g. rate-limited
	}))
	defer server.Close()

	old := repoAPI
	repoAPI = server.URL
	defer func() { repoAPI = old }()

	if _, err := CheckLatest(); err == nil {
		t.Error("expected an error for a non-200 response, got nil")
	}
}
