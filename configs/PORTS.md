# Ports & configs Kursor by Intech touches

Every port below is only actually listening once you turn the
corresponding module on from the panel UI — nothing here opens itself
just because the code exists. `scripts/install.sh` opens the panel's own
port automatically (ufw/firewalld, whichever is present); every other
row is a "open this when you enable that module" note, printed again at
the end of install.sh for convenience.

| Port | Proto | Service | Managed by | Config file | Notes |
|---|---|---|---|---|---|
| 8888 | tcp | Kursor panel itself | `kursord` | `KURSOR_ADDR` env var | Change via `KURSOR_PORT` before running install.sh, or edit the systemd unit's `Environment=KURSOR_ADDR=` line afterward. |
| 80 | tcp | HTTP (managed sites) | Nginx | `/etc/nginx/sites-available/<domain>.conf` | Opened per-site by the Site Manager; also where Let's Encrypt's HTTP-01 challenge answers. |
| 443 | tcp | HTTPS (managed sites) | Nginx | same, plus the SSL vhost variant | Only present once a certificate is issued for that site. |
| 22 | tcp | SSH | the OS, not Kursor | `/etc/ssh/sshd_config` | Not managed by Kursor at all — listed here only because it's the other way onto this box besides Kursor's own web terminal. |
| 51820 | udp | WireGuard VPN | `internal/vpn` | `/etc/wireguard/wg0.conf` | Port is configurable per-host in Network → VPN → Server settings; 51820 is WireGuard's own convention, not a Kursor default baked into code. |
| 53 | tcp+udp | DNS | `internal/dns` (dnsmasq) | `/etc/dnsmasq.d/kursor.conf` | Only needed open on your LAN/VPN interface if this box is meant to actually resolve for other machines — never expose 53 to the public internet unless you mean to run an open resolver. |
| 3306 | tcp | MySQL/MariaDB | `internal/dbmanager` | engine's own `my.cnf` | Kursor connects over the local unix socket for admin actions; 3306 only matters if something outside this box needs to reach the database directly. |
| 5432 | tcp | PostgreSQL | `internal/dbmanager` | engine's own `postgresql.conf` | Same note as MySQL above — local socket for Kursor itself, 5432 only for external access. |
| 25 | tcp | SMTP (mail delivery between servers) | `internal/mail` (Postfix) | `/etc/postfix/main.cf` | Needed open for other mail servers to deliver mail to your domains. |
| 587 | tcp | SMTP submission (your users sending mail) | `internal/mail` (Postfix) | same | What mail clients actually connect to for sending. |
| 143 / 993 | tcp | IMAP / IMAPS | `internal/mail` (Dovecot) | Dovecot's own config + `/etc/dovecot/conf.d/90-kursor-auth.conf` | 993 (TLS) is what a real deployment should expose; plain 143 only on trusted networks. |

## Config files, all in one place

| What | Path | Owner |
|---|---|---|
| Kursor's own data (sqlite db, OIDC signing key, WireGuard server key) | `$KURSOR_DATA_DIR` (default `/var/lib/kursor`) | `internal/store`, `internal/oidc`, `internal/vpn` |
| Managed site docroots | `$KURSOR_WWW_ROOT` (default `/var/www/kursor`) | `internal/sites` |
| Nginx vhosts | `/etc/nginx/sites-available/`, `sites-enabled/` | `internal/sites` |
| WireGuard | `/etc/wireguard/wg0.conf` | `internal/vpn` |
| DNS | `/etc/dnsmasq.d/kursor.conf` | `internal/dns` |
| Mail (MTA side) | `/etc/postfix/vmailbox`, `main.cf` (`virtual_mailbox_*`) | `internal/mail` |
| Mail (IMAP/auth side) | `/etc/dovecot/conf.d/90-kursor-auth.conf`, `/etc/dovecot/kursor-users` | `internal/mail` |
| Kursor's own cron jobs | current user's real crontab (a marked block inside it) | `internal/cron` |
| systemd unit | `/etc/systemd/system/kursor.service` | `scripts/install.sh` |
| Login/MOTD banner | `/etc/update-motd.d/50-kursor` or a marked block in `/etc/motd` | `scripts/install.sh` |

Nothing here needs hand-editing in normal use — every file in this list
is written and kept in sync by Kursor's own render→validate→reload code
paths (see each package's doc comment), the same way the panel itself
never expects you to hand-edit its sqlite database.
