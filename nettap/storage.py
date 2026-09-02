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
    first_seen      REAL
);

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
    pcap_file       TEXT
);

CREATE INDEX IF NOT EXISTS idx_flows_container ON flows(container_id);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip);

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
    updated_at      REAL
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


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
            INSERT INTO containers (container_id, name, image, veth, networks, ip_addresses, labels, first_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(container_id) DO UPDATE SET
                name=excluded.name, image=excluded.image, veth=excluded.veth,
                networks=excluded.networks, ip_addresses=excluded.ip_addresses, labels=excluded.labels
            """,
            (
                info.container_id, info.name, info.image, info.veth,
                json.dumps(info.networks), json.dumps(info.ip_addresses),
                json.dumps(info.labels), time.time(),
            ),
        )


def insert_flows(conn: sqlite3.Connection, rows: list[dict]) -> int:
    if not rows:
        return 0
    with cursor(conn) as cur:
        cur.executemany(
            """
            INSERT INTO flows (ts, container_id, container_name, src_ip, dst_ip,
                                src_port, dst_port, protocol, length, dns_query, tls_sni, pcap_file)
            VALUES (:ts, :container_id, :container_name, :src_ip, :dst_ip,
                    :src_port, :dst_port, :protocol, :length, :dns_query, :tls_sni, :pcap_file)
            """,
            rows,
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

def set_live_session(conn: sqlite3.Connection, info, pcap_pattern: str, pid: int) -> None:
    with cursor(conn) as cur:
        now = time.time()
        cur.execute(
            """
            INSERT INTO live_sessions (container_id, container_name, veth, pcap_pattern, pid, started_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(container_id) DO UPDATE SET
                container_name=excluded.container_name, veth=excluded.veth,
                pcap_pattern=excluded.pcap_pattern, pid=excluded.pid, updated_at=excluded.updated_at
            """,
            (info.container_id, info.name, info.veth, pcap_pattern, pid, now, now),
        )


def clear_live_session(conn: sqlite3.Connection, container_id: str) -> None:
    with cursor(conn) as cur:
        cur.execute("DELETE FROM live_sessions WHERE container_id = ?", (container_id,))


def list_live_sessions(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM live_sessions ORDER BY started_at")]
