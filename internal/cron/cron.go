// Package cron manages real, OS-level scheduled tasks by generating a
// marked block inside the current user's crontab (via the standard
// `crontab` command — present on both Linux and macOS, so this works
// unmodified on the target Mac Pro deployment too, unlike systemd
// timers or launchd calendar jobs would).
//
// Everything outside the markers is left byte-for-byte untouched: if the
// operator already has cron entries of their own, Kursor never touches
// them. Kursor's own jobs live in the database (see store.CronJob) and
// this package only ever *regenerates* its own block from that data —
// the crontab is a view, never hand-edited.
package cron

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"kursor/internal/store"
)

const (
	beginMarker = "# >>> kursor managed jobs — do not edit below by hand >>>"
	endMarker   = "# <<< kursor managed jobs <<<"
)

// scheduleFieldRe is a deliberately permissive per-field cron syntax
// check (digits, *, */N, ranges, lists) — enough to catch obvious typos
// without reimplementing a full cron parser.
var scheduleFieldRe = regexp.MustCompile(`^(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?(,(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?)*$`)

// ValidateSchedule checks that expr looks like a standard 5-field cron
// expression (minute hour day-of-month month day-of-week).
func ValidateSchedule(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("expected 5 fields (minute hour day month weekday), got %d", len(fields))
	}
	for _, f := range fields {
		if !scheduleFieldRe.MatchString(f) {
			return fmt.Errorf("invalid field %q", f)
		}
	}
	return nil
}

// jobLine renders one job as a crontab line. A disabled job is written
// commented-out (prefixed with "#") so it's still visible/editable state
// but never runs — re-enabling just removes the leading "#".
func jobLine(j store.CronJob) string {
	label := j.Label
	if label == "" {
		label = fmt.Sprintf("job-%d", j.ID)
	}
	line := fmt.Sprintf("%s %s # kursor:%d %s", j.Schedule, j.Command, j.ID, label)
	if !j.Enabled {
		return "#" + line
	}
	return line
}

func buildBlock(jobs []store.CronJob) string {
	if len(jobs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(beginMarker + "\n")
	for _, j := range jobs {
		b.WriteString(jobLine(j) + "\n")
	}
	b.WriteString(endMarker + "\n")
	return b.String()
}

// splice replaces any existing marker block in existing with newBlock
// (appending it if none was found yet — or removing it entirely, if
// newBlock is ""), leaving everything else byte-for-byte as-is.
func splice(existing, newBlock string) string {
	begin := strings.Index(existing, beginMarker)
	end := strings.Index(existing, endMarker)

	var before, after string
	if begin >= 0 && end >= 0 && end > begin {
		before = strings.TrimRight(existing[:begin], "\n")
		after = strings.TrimLeft(existing[end+len(endMarker):], "\n")
	} else {
		before = strings.TrimRight(existing, "\n")
	}

	parts := make([]string, 0, 3)
	if before != "" {
		parts = append(parts, before)
	}
	if newBlock != "" {
		parts = append(parts, strings.TrimRight(newBlock, "\n"))
	}
	if after != "" {
		parts = append(parts, after)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n\n") + "\n"
}

// readCrontab returns the current crontab content, or "" if the user has
// none yet (crontab -l exits 1 with "no crontab for X" in that case —
// that's normal, not an error).
func readCrontab() (string, error) {
	cmd := exec.Command("crontab", "-l")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if strings.Contains(stderr.String(), "no crontab") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %v: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

func writeCrontab(content string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab -: %v: %s", err, stderr.String())
	}
	return nil
}

// Sync regenerates Kursor's managed block from jobs and writes it into
// the current user's crontab, preserving anything else already there.
// A no-op (never calls `crontab -`) when there's nothing to add and no
// prior Kursor block to remove — an operator with no jobs and no
// pre-existing crontab keeps having no crontab at all.
func Sync(jobs []store.CronJob) error {
	existing, err := readCrontab()
	if err != nil {
		return err
	}
	if len(jobs) == 0 && !strings.Contains(existing, beginMarker) {
		return nil
	}
	updated := splice(existing, buildBlock(jobs))
	if updated == existing {
		return nil
	}
	return writeCrontab(updated)
}
