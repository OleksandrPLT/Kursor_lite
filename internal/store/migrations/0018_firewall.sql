-- Port descriptions and port forwarding rules. Kursor-side only:
-- ufw/firewalld/iptables remain the actual source of truth for which
-- ports are open (see internal/firewall) — this table just layers a
-- human-readable label on top of a (port, proto) pair, since a
-- description isn't something all three backends support uniformly.

CREATE TABLE port_labels (
    port        INTEGER NOT NULL,
    proto       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (port, proto)
);

-- Port forwarding (DNAT): external_port on this host forwards to
-- internal_ip:internal_port — e.g. exposing a Docker container or an
-- internal VM's service through this box's own public IP.
CREATE TABLE port_forwards (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    external_port  INTEGER NOT NULL,
    external_proto TEXT NOT NULL,
    internal_ip    TEXT NOT NULL,
    internal_port  INTEGER NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);
