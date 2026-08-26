-- Departments (with a parent/sub-department hierarchy, e.g. IT -> Admin)
-- and positions (job titles), both managed lists rather than free text,
-- per the user's request. No FK constraints declared (SQLite ALTER TABLE
-- + FK interplay is finicky) — referential integrity for department_id/
-- position_id is enforced in application code instead (see internal/store/org.go).

CREATE TABLE IF NOT EXISTS departments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    parent_id  INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS positions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

ALTER TABLE users ADD COLUMN department_id INTEGER;
ALTER TABLE users ADD COLUMN position_id INTEGER;
