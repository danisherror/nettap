"""Read-side queries over the flow store: top talkers, container-to-container
matrix, DNS lookups, protocol mix, and "traffic that left the Docker network
entirely" (i.e. docker-internet)."""
from __future__ import annotations

import sqlite3


def top_talkers(conn: sqlite3.Connection, container: str | None = None, limit: int = 10) -> list[dict]:
    where = "WHERE container_name = ?" if container else ""
    params = (container,) if container else ()
    cur = conn.execute(
        f"""
        SELECT src_ip, dst_ip, SUM(length) AS bytes, COUNT(*) AS packets
        FROM flows
        {where}
        GROUP BY src_ip, dst_ip
        ORDER BY bytes DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    return [dict(r) for r in cur.fetchall()]


def container_matrix(conn: sqlite3.Connection) -> list[dict]:
    """Traffic between containers, resolved by matching dst_ip against known
    container IPs. See TODO.md: this misses NATed/published-port traffic
    where the observed dst_ip isn't the peer container's own address."""
    cur = conn.execute(
        """
        SELECT f.container_name AS src_container,
               c.name AS dst_container,
               SUM(f.length) AS bytes,
               COUNT(*) AS packets
        FROM flows f
        JOIN containers c ON EXISTS (
            SELECT 1 FROM json_each(c.ip_addresses) je WHERE je.value = f.dst_ip
        )
        WHERE f.container_name != c.name
        GROUP BY src_container, dst_container
        ORDER BY bytes DESC
        """
    )
    return [dict(r) for r in cur.fetchall()]


def external_destinations(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    """dst_ips that don't belong to any known container - i.e. docker-internet traffic."""
    cur = conn.execute(
        """
        SELECT f.dst_ip, SUM(f.length) AS bytes, COUNT(*) AS packets,
               GROUP_CONCAT(DISTINCT f.container_name) AS containers
        FROM flows f
        WHERE f.dst_ip IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM containers c, json_each(c.ip_addresses) je WHERE je.value = f.dst_ip
          )
        GROUP BY f.dst_ip
        ORDER BY bytes DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [dict(r) for r in cur.fetchall()]


def dns_queries(conn: sqlite3.Connection, container: str | None = None, limit: int = 50) -> list[dict]:
    where = "WHERE dns_query IS NOT NULL"
    params: tuple = ()
    if container:
        where += " AND container_name = ?"
        params = (container,)
    cur = conn.execute(
        f"""
        SELECT container_name, dns_query, COUNT(*) AS lookups
        FROM flows
        {where}
        GROUP BY container_name, dns_query
        ORDER BY lookups DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    return [dict(r) for r in cur.fetchall()]


def protocol_breakdown(conn: sqlite3.Connection, container: str | None = None) -> list[dict]:
    where = "WHERE container_name = ?" if container else ""
    params = (container,) if container else ()
    cur = conn.execute(
        f"""
        SELECT protocol, SUM(length) AS bytes, COUNT(*) AS packets
        FROM flows
        {where}
        GROUP BY protocol
        ORDER BY bytes DESC
        """,
        params,
    )
    return [dict(r) for r in cur.fetchall()]
