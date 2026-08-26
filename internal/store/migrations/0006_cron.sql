-- Real cron job definitions, synced into the OS crontab by
-- internal/cron (see that package for the sync mechanics). This table
-- is the source of truth; the system crontab is a generated view of it.

CREATE TABLE IF NOT EXISTS cron_jobs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule   TEXT NOT NULL,
    command    TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
