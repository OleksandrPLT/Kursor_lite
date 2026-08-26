-- Request Fulfillment workflow (ITIL "service request" process, phase
-- 1.5): a ticket can concern an existing user (target_user_id — e.g.
-- "grant VPN access to X") or carry a full new-employee questionnaire
-- (request_kind = 'new_account'), go through an approval step, and —
-- once approved — create the real account with one click from the
-- ticket itself (created_account_id records that it did).

ALTER TABLE tickets ADD COLUMN target_user_id INTEGER;
ALTER TABLE tickets ADD COLUMN request_kind TEXT NOT NULL DEFAULT '';  -- '' | 'new_account' | 'grant_access'

ALTER TABLE tickets ADD COLUMN new_last_name     TEXT NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN new_first_name    TEXT NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN new_patronymic    TEXT NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN new_email         TEXT NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN new_phone         TEXT NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN new_department_id INTEGER;
ALTER TABLE tickets ADD COLUMN new_position_id   INTEGER;

ALTER TABLE tickets ADD COLUMN requires_approval  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tickets ADD COLUMN approval_status    TEXT NOT NULL DEFAULT 'none'; -- none|pending|approved|rejected
ALTER TABLE tickets ADD COLUMN approved_by        INTEGER;
ALTER TABLE tickets ADD COLUMN approved_at        TEXT NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN created_account_id INTEGER;
