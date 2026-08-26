-- Expands accounts into full employee profiles per the user's request:
-- structured full name (Ukrainian ПІБ convention — last/first/patronymic),
-- job title, phone, hire/termination dates, and a profile photo.
-- full_name from 0002 is left in place unused; Go now composes the
-- display name from the structured fields.

ALTER TABLE users ADD COLUMN last_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN first_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN patronymic TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN job_title TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN hired_at TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN terminated_at TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN avatar BLOB;
ALTER TABLE users ADD COLUMN avatar_mime TEXT NOT NULL DEFAULT '';
