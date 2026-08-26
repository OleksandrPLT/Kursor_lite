-- Real virtual-mail domains/mailboxes (internal/mail: Postfix + Dovecot).
-- password_hash is whatever `doveadm pw` returned — a Dovecot-format
-- crypt string, stored verbatim (never the plaintext).

CREATE TABLE mail_domains (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE mail_mailboxes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    address       TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
