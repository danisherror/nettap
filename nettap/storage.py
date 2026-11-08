"""SQLite-backed store for enriched flow records, container metadata, and the
shared "desired state" / "live sessions" tables that let multiple `nettap`
CLI invocations coordinate with one running `nettap watch` daemon.

SQLite is deliberately the default: this is a single-host tool and SQLite
means zero extra services to run. Swapping in ClickHouse/Postgres for
multi-host or high-volume setups is on the roadmap (see TODO.md) - the
`insert_flows`/`query` boundary is kept narrow on purpose to make that swap
localized to this file.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS containers (
    container_id    TEXT PRIMARY KEY,
    name            TEXT,
    image           TEXT,
    veth            TEXT,
    networks        TEXT,   -- JSON list
    ip_addresses    TEXT,   -- JSON: {network: ip}
    labels          TEXT,   -- JSON
    first_seen      REAL,
    published_ports TEXT,   -- JSON: discovery.ContainerNetInfo.published_ports
    started_at      REAL,   -- when the container last started (Docker API); NULL if unknown
    capture_scope   TEXT    -- "ports" for sidecar --attribute-by-port (hostports.py), else NULL
);

-- when a --attribute-by-port target held each TCP/UDP port (hostports.py)
CREATE TABLE IF NOT EXISTS owned_ports (
    container_name  TEXT,
    transport       TEXT,
    port            INTEGER,
    first_seen      REAL,
    last_seen       REAL
);
CREATE INDEX IF NOT EXISTS idx_owned_ports ON owned_ports(container_name, transport, port);

CREATE TABLE IF NOT EXISTS flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL,
    container_id    TEXT,
    container_name  TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    length          INTEGER,
    dns_query       TEXT,
    tls_sni         TEXT,
    pcap_file       TEXT,
    dns_answers     TEXT,   -- JSON list of A/AAAA addresses in a DNS response
    http_host       TEXT,   -- Host header of a plaintext HTTP request
    transport       TEXT    -- tcp/udp/sctp/icmp/icmpv6 (enrich.transport_of), NULL if none
);

CREATE INDEX IF NOT EXISTS idx_flows_container ON flows(container_id);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_pcap ON flows(pcap_file);

-- "desired state": what nettap attach/detach requests, honored by the poller
-- in controller.py within one poll cycle of a running `nettap watch`.
CREATE TABLE IF NOT EXISTS desired_refs (
    ref             TEXT PRIMARY KEY,
    requested_at    REAL
);

CREATE TABLE IF NOT EXISTS desired_labels (
    label_key       TEXT,
    label_value     TEXT,
    requested_at    REAL,
    PRIMARY KEY (label_key, label_value)
);

-- what a running daemon actually has attached right now, so `nettap status`
-- from another invocation can report something meaningful.
CREATE TABLE IF NOT EXISTS live_sessions (
    container_id    TEXT PRIMARY KEY,
    container_name  TEXT,
    veth            TEXT,
    pcap_pattern    TEXT,
    pid             INTEGER,
    started_at      REAL,
    updated_at      REAL,
    dns_pcap_pattern TEXT,   -- the container's lo capture (capture.EMBEDDED_DNS)
    dns_pid         INTEGER,
    heartbeat_interval REAL, -- seconds between updated_at refreshes by the daemon
    rotate_seconds  REAL     -- tcpdump -G interval, so `enrich` knows when a pcap is done
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    _add_missing_columns(conn)
    return conn


# Columns added after a table's first release. CREATE TABLE IF NOT EXISTS
# leaves an older table alone, so add them to existing databases here.
_ADDED_COLUMNS = {
    "containers": {"published_ports": "TEXT", "started_at": "REAL", "capture_scope": "TEXT"},
    "flows": {"dns_answers": "TEXT", "http_host": "TEXT", "transport": "TEXT"},
    "live_sessions": {"dns_pcap_pattern": "TEXT", "dns_pid": "INTEGER",
                      "heartbeat_interval": "REAL", "rotate_seconds": "REAL"},
}


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    for table, columns in _ADDED_COLUMNS.items():
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, sql_type in columns.items():
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
    conn.commit()


@contextmanager
def cursor(conn: sqlite3.Connection):
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    finally:
        cur.close()


def upsert_container(conn: sqlite3.Connection, info) -> None:
    with cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO containers (container_id, name, image, veth, networks, ip_addresses, labels,
                                    first_seen, published_ports, started_at, capture_scope)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(container_id) DO UPDATE SET
                name=excluded.name, image=excluded.image, veth=excluded.veth,
                networks=excluded.networks, ip_addresses=excluded.ip_addresses, labels=excluded.labels,
                published_ports=excluded.published_ports, started_at=excluded.started_at,
                capture_scope=excluded.capture_scope
            """,
            (
                info.container_id, info.name, info.image, info.veth,
                json.dumps(info.networks), json.dumps(info.ip_addresses),
                json.dumps(info.labels), time.time(),
                json.dumps(getattr(info, "published_ports", None) or []),
                getattr(info, "started_at", None),
                getattr(info, "capture_scope", None),
            ),
        )


def port_scoped(conn: sqlite3.Connection, container_name: str) -> bool:
    """Whether `container_name`'s capture is kept to its own ports
    (sidecar --attribute-by-port, see hostports.py)."""
    return conn.execute("SELECT 1 FROM containers WHERE name = ? AND capture_scope = 'ports'",
                        (container_name,)).fetchone() is not None


def pcap_enriched(conn: sqlite3.Connection, path: str) -> bool:
    """Whether flows from this pcap are already stored - the enrich loop's
    in-memory list starts empty after a restart, and parsing a file twice
    doubles its traffic in every report (seen live 2026-11-08)."""
    return conn.execute("SELECT 1 FROM flows WHERE pcap_file = ? LIMIT 1", (path,)).fetchone() is not None


def insert_flows(conn: sqlite3.Connection, rows: list[dict]) -> int:
    if not rows:
        return 0
    with cursor(conn) as cur:
        cur.executemany(
            """
            INSERT INTO flows (ts, container_id, container_name, src_ip, dst_ip,
                                src_port, dst_port, protocol, length, dns_query, tls_sni,
                                pcap_file, dns_answers, http_host, transport)
            VALUES (:ts, :container_id, :container_name, :src_ip, :dst_ip,
                    :src_port, :dst_port, :protocol, :length, :dns_query, :tls_sni,
                    :pcap_file, :dns_answers, :http_host, :transport)
            """,
            [{"dns_answers": None, "http_host": None, "transport": None, **r} for r in rows],
        )
    return len(rows)


# ---- desired state (what `attach`/`detach` mutate) -------------------------

def add_desired_ref(conn: sqlite3.Connection, ref: str) -> None:
    with cursor(conn) as cur:
        cur.execute(
            "INSERT OR IGNORE INTO desired_refs (ref, requested_at) VALUES (?, ?)",
            (ref, time.time()),
        )


def remove_desired_ref(conn: sqlite3.Connection, ref: str) -> None:
    with cursor(conn) as cur:
        cur.execute("DELETE FROM desired_refs WHERE ref = ?", (ref,))


def list_desired_refs(conn: sqlite3.Connection) -> list[str]:
    return [r["ref"] for r in conn.execute("SELECT ref FROM desired_refs")]


def add_desired_label(conn: sqlite3.Connection, key: str, value: str) -> None:
    with cursor(conn) as cur:
        cur.execute(
            "INSERT OR IGNORE INTO desired_labels (label_key, label_value, requested_at) VALUES (?, ?, ?)",
            (key, value, time.time()),
        )


def remove_desired_label(conn: sqlite3.Connection, key: str, value: str) -> None:
    with cursor(conn) as cur:
        cur.execute(
            "DELETE FROM desired_labels WHERE label_key = ? AND label_value = ?", (key, value)
        )


def list_desired_labels(conn: sqlite3.Connection) -> dict[str, str]:
    return {
        r["label_key"]: r["label_value"]
        for r in conn.execute("SELECT label_key, label_value FROM desired_labels")
    }


def clear_desired_state(conn: sqlite3.Connection) -> None:
    with cursor(conn) as cur:
        cur.execute("DELETE FROM desired_refs")
        cur.execute("DELETE FROM desired_labels")


# ---- live sessions (what the running daemon reports) -----------------------

def set_live_session(conn: sqlite3.Connection, info, pcap_pattern: str, pid: int,
                     dns_pcap_pattern: str | None = None, dns_pid: int | None = None,
                     rotate_seconds: float | None = None) -> None:
    with cursor(conn) as cur:
        now = time.time()
        cur.execute(
            """
            INSERT INTO live_sessions (container_id, container_name, veth, pcap_pattern, pid,
                                       started_at, updated_at, dns_pcap_pattern, dns_pid,
                                       rotate_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(container_id) DO UPDATE SET
                container_name=excluded.container_name, veth=excluded.veth,
                pcap_pattern=excluded.pcap_pattern, pid=excluded.pid, updated_at=excluded.updated_at,
                dns_pcap_pattern=excluded.dns_pcap_pattern, dns_pid=excluded.dns_pid,
                rotate_seconds=excluded.rotate_seconds
            """,
            (info.container_id, info.name, info.veth, pcap_pattern, pid, now, now,
             dns_pcap_pattern, dns_pid, rotate_seconds),
        )


def save_capture_session(conn: sqlite3.Connection, session) -> None:
    """set_live_session() for a capture.CaptureSession: both of its tcpdumps."""
    dns = session.dns_process
    set_live_session(conn, session.info, session.pcap_pattern, session.process.pid,
                     session.dns_pcap_pattern if dns else None, dns.pid if dns else None,
                     session.rotate_seconds)


def heartbeat_live_sessions(conn: sqlite3.Connection, container_ids, interval: float) -> None:
    """Mark these rows as still owned by a running daemon, which promises to
    do this again within `interval` seconds."""
    ids = list(container_ids)
    if not ids:
        return
    with cursor(conn) as cur:
        cur.execute(
            f"UPDATE live_sessions SET updated_at = ?, heartbeat_interval = ? "
            f"WHERE container_id IN ({','.join('?' * len(ids))})",
            (time.time(), interval, *ids),
        )


def is_stale(row: dict, now: float | None = None) -> bool:
    """True if the daemon that owns this live_sessions row has missed several
    heartbeats - it most likely died without cleaning up. The slack covers a
    slow loop iteration. Rows without a heartbeat yet aren't judged."""
    interval = row.get("heartbeat_interval")
    if not interval or not row.get("updated_at"):
        return False
    return (now or time.time()) - row["updated_at"] > 3 * interval + 10


def clear_live_session(conn: sqlite3.Connection, container_id: str) -> None:
    with cursor(conn) as cur:
        cur.execute("DELETE FROM live_sessions WHERE container_id = ?", (container_id,))


def known_container_names(conn: sqlite3.Connection) -> list[str]:
    """Every container name that has EITHER captured flow rows OR was ever
    inspected/attached - used to give a "did you mean...?" hint when a
    `--container` value doesn't match anything, instead of silently
    reporting zero traffic for a plain typo or the wrong container name."""
    rows = conn.execute(
        "SELECT DISTINCT container_name AS name FROM flows WHERE container_name IS NOT NULL "
        "UNION SELECT DISTINCT name FROM containers WHERE name IS NOT NULL"
    ).fetchall()
    return sorted({r["name"] for r in rows if r["name"]})


def list_live_sessions(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM live_sessions ORDER BY started_at")]
