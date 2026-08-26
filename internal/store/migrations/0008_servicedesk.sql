-- Service Desk phase 1 (see the project memory note on scope — this is
-- deliberately just ticket/incident tracking with a lightweight SLA,
-- not the full ITIL platform requested: CMDB, knowledge base, portal,
-- omnichannel, AI routing and analytics dashboards are later phases).

CREATE TABLE IF NOT EXISTS tickets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    type         TEXT NOT NULL DEFAULT 'incident',  -- 'incident' | 'request' | 'problem'
    status       TEXT NOT NULL DEFAULT 'new',       -- 'new' | 'in_progress' | 'resolved' | 'closed'
    priority     TEXT NOT NULL DEFAULT 'medium',    -- 'low' | 'medium' | 'high' | 'critical'
    requester_id INTEGER NOT NULL,
    assignee_id  INTEGER,
    due_at       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    resolved_at  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ticket_comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id  INTEGER NOT NULL,
    author_id  INTEGER NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
