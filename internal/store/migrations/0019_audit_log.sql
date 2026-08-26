-- Audit log: one row per state-changing request a logged-in user made
-- (see internal/server middleware.go's auditLog wrapper). GETs aren't
-- logged — too much noise for too little signal — only POST/PUT/
-- PATCH/DELETE, which is where every real action in this panel happens.

CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    username   TEXT NOT NULL,
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,
    status     INTEGER NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at DESC);
