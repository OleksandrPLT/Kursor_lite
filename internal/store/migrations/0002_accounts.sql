-- Extends the single bootstrap admin into proper multi-user accounts
-- (the "account manager" module — see the project plan's phase-2 SSO
-- note). Existing rows get role='admin', status='active' via DEFAULT,
-- so the bootstrap admin created before this migration keeps working.

ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
