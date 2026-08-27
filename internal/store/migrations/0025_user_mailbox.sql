-- Ties a Kursor account to a real mailbox on the WildDuck mail server
-- (internal/wildduck) — set when an admin opts to auto-provision one at
-- account-creation time. mailbox_id is WildDuck's own Mongo ObjectID
-- string, used for later actions (reset password, disable, delete);
-- mailbox_address is shown on the profile page and is just the email
-- address itself, kept alongside the id so the profile never needs a
-- live WildDuck call just to display it.
ALTER TABLE users ADD COLUMN mailbox_address TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN mailbox_id TEXT NOT NULL DEFAULT '';
