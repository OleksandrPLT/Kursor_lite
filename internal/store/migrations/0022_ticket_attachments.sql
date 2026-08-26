-- Ticket attachments — a file can belong to the ticket itself (attached
-- at creation) or to one specific comment (attached when replying).
-- stored_name is the on-disk name (random, collision-proof); original_name
-- is what the uploader called it, shown/used as the download filename.

CREATE TABLE ticket_attachments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id     INTEGER NOT NULL,
    comment_id    INTEGER, -- NULL if attached directly to the ticket, not a specific comment
    original_name TEXT NOT NULL,
    stored_name   TEXT NOT NULL,
    size          INTEGER NOT NULL,
    uploaded_by   INTEGER NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_ticket_attachments_ticket ON ticket_attachments (ticket_id);
