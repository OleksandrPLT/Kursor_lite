-- Rounds out the request-fulfillment workflow:
--  - new_hired_at: hire date collected on the new-employee questionnaire
--    (fed into CreateUser's HiredAt when the account is created).
--  - requested_permissions: comma-separated module keys checked on a
--    "grant_access" request (same taxonomy as users.permissions).
--  - action_applied_at: generic one-shot guard for whichever one-click
--    action a ticket's request_kind triggers (create account / grant
--    access / terminate) — set once, checked before the button's
--    handler does anything, so re-clicking (or a slow double-submit)
--    can never double-apply it.
-- request_kind gains a third value here: 'terminate' — an employee
-- offboarding request that, once approved and actioned, disables the
-- target account via the same Store.Terminate used by the Accounts
-- page's "Звільнити" button (revokes every module permission at once,
-- since a disabled account fails GetSession on its very next request).

ALTER TABLE tickets ADD COLUMN new_hired_at TEXT NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN requested_permissions TEXT NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN action_applied_at TEXT NOT NULL DEFAULT '';
