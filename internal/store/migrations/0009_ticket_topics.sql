-- Ticket "topic" — which part of the system a ticket is about, using
-- the same taxonomy as the sidebar menu (sites, files, databases, vpn,
-- accounts, ...) so triage can filter/route by area without a separate
-- category-management screen.

ALTER TABLE tickets ADD COLUMN topic TEXT NOT NULL DEFAULT 'other';

-- Free-text "reason" chosen from a topic-specific quick-pick list on the
-- client (see web/static/js/servicedesk.js) — kept as plain text rather
-- than its own lookup table since it's descriptive metadata, not
-- something else references by ID.
ALTER TABLE tickets ADD COLUMN reason TEXT NOT NULL DEFAULT '';
