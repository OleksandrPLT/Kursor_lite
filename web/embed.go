// Package web embeds Kursor's HTML templates and static assets
// (CSS/JS) into the compiled binary so `go build` produces one
// self-contained executable, per the project plan.
package web

import "embed"

//go:embed templates static
var FS embed.FS
