-- In-panel notification center. link is a relative path the bell
-- dropdown/page navigates to when clicked (e.g. "/company/servicedesk/42").

CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL, -- "ticket_comment" | "ticket_status" | "ticket_assigned" | "approval_needed"
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    link       TEXT NOT NULL DEFAULT '',
    read_at    TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_notifications_user ON notifications (user_id, created_at DESC);
