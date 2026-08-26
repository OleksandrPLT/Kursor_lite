// Package version tracks which build of Kursor is actually running and
// checks GitHub for whether a newer one is available. It deliberately
// does NOT perform the update itself — replacing kursord's own running
// binary and restarting the very process serving this HTTP request is
// exactly the kind of self-surgery that's easy to get subtly wrong
// (the response may never flush back to the browser, a half-written
// binary is worse than an old one). The real update mechanism stays
// scripts/update.sh (or deploy.sh from another machine) — see the
// "System Updates" page, which shows what to run rather than trying to
// run it from inside itself.
package version

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GitCommit is set at build time via -ldflags
// "-X kursor/internal/version.GitCommit=<short hash>" — see
// scripts/install.sh / deploy.sh / update.sh, all three inject it the
// same way. Left as "dev" for anyone building directly with `go build`
// or `go run` outside those scripts (e.g. this project's own local
// dev loop), which is a legitimate, expected case, not an error.
var GitCommit = "dev"

// repoAPI is a var (not a const) so tests can point it at an
// httptest.Server instead of the real GitHub API.
var repoAPI = "https://api.github.com/repos/OleksandrPLT/Kursor_lite/commits/main"

var httpClient = &http.Client{Timeout: 6 * time.Second}

// LatestInfo is what GitHub's API returns about the newest commit on
// main, trimmed to what the page actually shows.
type LatestInfo struct {
	ShortSHA string
	Message  string
	Date     time.Time
	URL      string
}

// CheckLatest makes a real (unauthenticated) call to the GitHub API —
// fine for a manual "check now" click; GitHub's unauthenticated rate
// limit (60/hr per IP) is not something this page could plausibly hit
// through normal use.
func CheckLatest() (LatestInfo, error) {
	req, err := http.NewRequest("GET", repoAPI, nil)
	if err != nil {
		return LatestInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return LatestInfo{}, fmt.Errorf("couldn't reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return LatestInfo{}, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var parsed struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message string `json:"message"`
			Author  struct {
				Date time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return LatestInfo{}, err
	}

	short := parsed.SHA
	if len(short) > 7 {
		short = short[:7]
	}
	message := parsed.Commit.Message
	if i := strings.IndexByte(message, '\n'); i >= 0 {
		message = message[:i] // first line only — commit bodies can be long
	}

	return LatestInfo{ShortSHA: short, Message: message, Date: parsed.Commit.Author.Date, URL: parsed.HTMLURL}, nil
}

// UpdateAvailable compares the running build's commit against the
// latest one — a "dev" build (see GitCommit above) never claims to be
// out of date, since it's not tracking any real commit to compare.
func UpdateAvailable(latest LatestInfo) bool {
	return GitCommit != "dev" && GitCommit != "" && !strings.HasPrefix(latest.ShortSHA, GitCommit) && !strings.HasPrefix(GitCommit, latest.ShortSHA)
}
