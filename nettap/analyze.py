"""Read-side queries over the flow store: top talkers, container-to-container
matrix, DNS lookups, protocol mix, and "traffic that left the Docker network
entirely" (i.e. docker-internet)."""
from __future__ import annotations

import ipaddress
import sqlite3

# Docker Desktop's default internal subnet, where it runs its own DNS server
# and HTTP proxy. Users can change it, so this is only a hint.
# Source: https://docs.docker.com/desktop/settings-and-maintenance/settings/
DOCKER_DESKTOP_SUBNET = ipaddress.ip_network("192.168.65.0/24")


def ip_scope(ip: str | None) -> str:
    """'internet' for publicly routable unicast addresses, else 'local'
    (private/RFC1918, link-local, CGNAT, loopback, multicast, broadcast, or
    anything that doesn't parse as an IP). Multicast is checked separately
    because Python counts e.g. ff02::1 as is_global."""
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return "local"
    return "internet" if addr.is_global and not addr.is_multicast else "local"


def local_hint(ip: str | None) -> str | None:
    """Short plain-language guess at what a local address is, or None."""
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    if addr.version == 4 and addr in DOCKER_DESKTOP_SUBNET:
        return "likely Docker Desktop's internal DNS server or proxy"
    if addr.is_multicast:
        return "multicast, used for local discovery such as mDNS or IPv6 neighbour discovery"
    if addr.is_link_local:
        return "link-local, only valid on this network segment"
    return None


NON_IP_NOTE = "non-IP frames (e.g. ARP), which have no IP addresses"


def top_talkers(conn: sqlite3.Connection, container: str | None = None, limit: int = 10) -> list[dict]:
    """Biggest src/dst pairs by bytes. Each row lists the `protocols` seen.
    Frames with no IP layer (ARP etc.) group into one row with null IPs and
    a `note` saying so."""
    where = "WHERE container_name = ?" if container else ""
    params = (container,) if container else ()
    cur = conn.execute(
        f"""
        SELECT src_ip, dst_ip, SUM(length) AS bytes, COUNT(*) AS packets,
               GROUP_CONCAT(DISTINCT protocol) AS protocols
        FROM flows
        {where}
        GROUP BY src_ip, dst_ip
        ORDER BY bytes DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    rows = [dict(r) for r in cur.fetchall()]
    for row in rows:
        if row["src_ip"] is None and row["dst_ip"] is None:
            row["note"] = NON_IP_NOTE
    return rows


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


def external_destinations(conn: sqlite3.Connection, limit: int = 20,
                          scope: str | None = None) -> list[dict]:
    """dst_ips that don't belong to any known container. Each row gets a
    `scope`: 'internet' (docker-internet traffic) or 'local' (private,
    link-local, multicast etc. - e.g. Docker Desktop's DNS resolver; see
    ip_scope). Local rows also get a `hint` (may be None). Pass
    scope='internet' or 'local' to keep only one kind; `limit` applies
    before that filter."""
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
    rows = []
    for r in cur.fetchall():
        row = dict(r)
        row["scope"] = ip_scope(row["dst_ip"])
        if row["scope"] == "local":
            row["hint"] = local_hint(row["dst_ip"])
        if scope is None or row["scope"] == scope:
            rows.append(row)
    return rows


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
