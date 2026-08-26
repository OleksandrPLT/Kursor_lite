-- Support groups: the "Модератор / Керівник / Підтримка 1-2-3 лінія"
-- access tiers — an assignable classifier on users (which group they
-- belong to) and on tickets (which group currently owns it), with
-- "rank" giving escalation a well-defined "next" group to move to.

CREATE TABLE support_groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    rank       INTEGER NOT NULL, -- lower = first line; escalation moves to the next-higher rank
    created_at TEXT NOT NULL
);

INSERT INTO support_groups (name, rank, created_at) VALUES
    ('Підтримка 1 лінія', 10, datetime('now')),
    ('Підтримка 2 лінія', 20, datetime('now')),
    ('Підтримка 3 лінія', 30, datetime('now')),
    ('Модератор', 40, datetime('now')),
    ('Керівник', 50, datetime('now'));

-- No FK constraint (see departments/positions migration 0005 for why —
-- SQLite ALTER TABLE + FK interplay is finicky); enforced in application
-- code (internal/store/supportgroups.go) instead.
ALTER TABLE users ADD COLUMN support_group_id INTEGER;
ALTER TABLE tickets ADD COLUMN support_group_id INTEGER;

-- Profile fields requested alongside support groups: internal phone
-- extension and contract number.
ALTER TABLE users ADD COLUMN extension TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN contract_number TEXT NOT NULL DEFAULT '';
