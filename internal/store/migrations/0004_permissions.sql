-- Per-module access levels for non-admin ("member") accounts. Admins
-- always have full access regardless of this field — it only narrows
-- what a member can reach (Sites / Files / Databases for now; Accounts
-- management stays admin-only, not grantable here).
-- Stored as a comma-separated list of module keys, e.g. "sites,files".

ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT '';
