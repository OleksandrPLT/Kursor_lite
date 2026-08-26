package store

import (
	"database/sql"
	"time"
)

// CronJob is a scheduled task Kursor manages. The OS crontab is a
// generated view of these rows — see internal/cron.Sync.
type CronJob struct {
	ID        int64
	Schedule  string // 5-field cron expression, e.g. "0 3 * * *"
	Command   string
	Label     string
	Enabled   bool
	CreatedBy int64
	CreatedAt time.Time
}

// ListCronJobs returns every job, oldest first.
func (s *Store) ListCronJobs() ([]CronJob, error) {
	rows, err := s.db.Query(`SELECT id, schedule, command, label, enabled, created_by, created_at
		FROM cron_jobs ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CronJob
	for rows.Next() {
		var j CronJob
		var enabled int
		var createdAt string
		if err := rows.Scan(&j.ID, &j.Schedule, &j.Command, &j.Label, &enabled, &j.CreatedBy, &createdAt); err != nil {
			return nil, err
		}
		j.Enabled = enabled != 0
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			j.CreatedAt = t
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// GetCronJob returns nil, nil if no such job exists.
func (s *Store) GetCronJob(id int64) (*CronJob, error) {
	var j CronJob
	var enabled int
	var createdAt string
	err := s.db.QueryRow(`SELECT id, schedule, command, label, enabled, created_by, created_at
		FROM cron_jobs WHERE id = ?`, id).
		Scan(&j.ID, &j.Schedule, &j.Command, &j.Label, &enabled, &j.CreatedBy, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	j.Enabled = enabled != 0
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		j.CreatedAt = t
	}
	return &j, nil
}

// CreateCronJob inserts a new job (enabled by default).
func (s *Store) CreateCronJob(schedule, command, label string, createdBy int64) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO cron_jobs (schedule, command, label, enabled, created_by, created_at, updated_at)
		VALUES (?, ?, ?, 1, ?, ?, ?)`,
		schedule, command, label, createdBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetCronJobEnabled flips a job's enabled flag.
func (s *Store) SetCronJobEnabled(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE cron_jobs SET enabled = ?, updated_at = ? WHERE id = ?`,
		v, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// DeleteCronJob removes a job.
func (s *Store) DeleteCronJob(id int64) error {
	_, err := s.db.Exec(`DELETE FROM cron_jobs WHERE id = ?`, id)
	return err
}
