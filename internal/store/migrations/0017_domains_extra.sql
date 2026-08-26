-- Rounds out the Domains page into "maximal settings" territory:
-- everything here past the original registrar/expiry/auto-renew is
-- informational tracking (Kursor has no registrar API to actually flip
-- WHOIS privacy or DNSSEC — see internal/mail's registrar fields for
-- the same honesty line drawn earlier), tracked here so it's visible
-- next to the domain instead of scattered in someone's notes.

ALTER TABLE domains ADD COLUMN whois_privacy INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN dnssec INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN contact_email TEXT NOT NULL DEFAULT '';
ALTER TABLE domains ADD COLUMN tags TEXT NOT NULL DEFAULT '';
