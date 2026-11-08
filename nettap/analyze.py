"""Read-side queries over the flow store: top talkers, container-to-container
matrix, DNS lookups, protocol mix, and "traffic that left the Docker network
entirely" (i.e. docker-internet)."""
from __future__ import annotations

import ipaddress
import sqlite3

from .capture import EMBEDDED_DNS

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
    if str(addr) == EMBEDDED_DNS:
        return "Docker's embedded DNS server, used on user-defined networks"
    if addr.is_loopback:
        return "loopback - the container itself (e.g. its side of a lookup to 127.0.0.11)"
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


# One row per (container name, address), with `since` - when that name got
# the address (the container's start time from the Docker API, else when
# nettap first recorded it) - and whether the name has a capture of its own.
# `containers` can hold several rows for one container - a sidecar stores its
# target under the target's name and `--docker-api` stores the same container
# under its real ID - and joining on those rows directly counted each flow
# once per row (seen live 2026-11-08: two sidecars with --docker-api doubled
# every peer's bytes).
_CONTAINER_IPS = """
    container_ips AS (
        SELECT c.name, je.value AS ip,
               MIN(COALESCE(c.started_at, c.first_seen)) AS since,
               c.name IN (SELECT container_name FROM flows) AS captured
        FROM containers c, json_each(c.ip_addresses) je
        WHERE c.name IS NOT NULL AND je.value != ''
        GROUP BY c.name, je.value
    )"""

def _holders(cte: str, ip_col: str, where: str = "1") -> str:
    """A CTE `cte` of (flow id, name): for each flow matching `where`, the one
    container name that held address f.<ip_col> at the flow's time - the
    latest `since` at or before then. Docker doesn't give one address to two
    running containers, so a container recreated under another name at an
    old address takes it over from that moment (seen live 2026-11-08: both
    names got all of the address's traffic). Two names of one container
    (sidecar label + real name, same start time) go to the one with its own
    capture. A flow older than every claim goes to the earliest one.
    A join + ROW_NUMBER, not a correlated subquery: SQLite 3.46 (the Docker
    image) can't use an outer column in a subquery's ORDER BY."""
    return f"""
    {cte} AS (
        SELECT id, name FROM (
            SELECT f.id, h.name, ROW_NUMBER() OVER (
                PARTITION BY f.id
                ORDER BY h.since <= f.ts DESC,
                         CASE WHEN h.since <= f.ts THEN h.since END DESC,
                         h.captured DESC, h.since, h.name) AS rn
            FROM flows f JOIN container_ips h ON h.ip = f.{ip_col}
            WHERE {where}
        ) WHERE rn = 1
    )"""


# True when {ip} is also an address of the flow's own container. One container
# can have two names (a sidecar's --target label and the real name another
# sidecar's --docker-api records), and the other name isn't a peer.
_OWN_IP = """EXISTS (SELECT 1 FROM container_ips own
                    WHERE own.name = f.container_name AND own.ip = {ip})"""


def _published_port_owners(conn: sqlite3.Connection) -> dict[tuple, str]:
    """{(host port, protocol): container name} for ports published by one
    container, protocol as Docker names it (tcp/udp/sctp). Each port is also
    listed as (port, None) when every protocol on it has the same owner -
    used for flows stored before flows.transport existed.

    One container can be stored under two names that share an address - a
    sidecar's --target label, and its real name from another sidecar's
    --docker-api - and both rows then list its ports. Those count as one
    owner, named by the name its own capture uses (flows.container_name) if
    any. A port claimed by names with no address in common is ambiguous and
    left out."""
    claims: dict[tuple, set] = {}
    for r in conn.execute(
            "SELECT DISTINCT c.name, json_extract(je.value, '$.host_port') AS port, "
            "       COALESCE(json_extract(je.value, '$.protocol'), 'tcp') AS proto "
            "FROM containers c, json_each(c.published_ports) je "
            "WHERE c.name IS NOT NULL AND c.published_ports IS NOT NULL"):
        claims.setdefault((r["port"], r["proto"]), set()).add(r["name"])
    ips: dict[str, set] = {}
    for r in conn.execute(f"WITH {_CONTAINER_IPS} SELECT name, ip FROM container_ips"):
        ips.setdefault(r["name"], set()).add(r["ip"])
    captured = None
    owners: dict[tuple, str] = {}
    for key, names in claims.items():
        if len(names) > 1:
            if not set.intersection(*(ips.get(n, set()) for n in names)):
                continue
            if captured is None:
                captured = {r[0] for r in conn.execute(
                    "SELECT DISTINCT container_name FROM flows")}
            names = {n for n in names if n in captured} or names
        owners[key] = min(names)
    by_port: dict[int, set] = {}
    for (port, _), name in owners.items():
        by_port.setdefault(port, set()).add(name)
    ambiguous = {port for port, _ in claims.keys() - owners.keys()}
    for port, names in by_port.items():
        if len(names) == 1 and port not in ambiguous:
            owners[(port, None)] = names.pop()
    return owners


def _published_port_flows(conn: sqlite3.Connection, container: str | None = None):
    """Flows that reached another container through a port it publishes on
    the host, as (flow container, peer, length, sent, flow) - sent is False
    for the replies, flow is the flows row. Seen on the wire, such a request
    goes to the host (e.g. host.docker.internal, 192.168.65.254 on Docker
    Desktop) on the host port, not to the peer's own address, and the peer's
    capture sees a proxy address on a random port (live test, Docker Desktop
    for Mac, 2026-11-08), so only the client's side can be matched - by a
    local, non-container address plus a published host port and transport
    (a flow with no transport recorded, from before that column, matches on
    the port alone)."""
    owners = _published_port_owners(conn)
    if not owners:
        return
    ports = sorted({port for port, _ in owners})
    where, params = "", ()
    if container:
        where, params = " AND f.container_name = ?", (container,)
    marks = ",".join("?" * len(ports))
    cur = conn.execute(
        f"""
        WITH {_CONTAINER_IPS}
        SELECT f.id, f.container_name, f.src_ip, f.dst_ip, f.src_port, f.dst_port,
               f.length, f.transport
        FROM flows f
        WHERE (f.dst_port IN ({marks}) OR f.src_port IN ({marks})){where}
          AND NOT EXISTS (SELECT 1 FROM container_ips ci WHERE ci.ip IN (f.src_ip, f.dst_ip)
                                                          AND ci.name != f.container_name)
        """,
        (*ports, *ports, *params),
    )
    for f in cur:
        for addr, port, sent in ((f["dst_ip"], f["dst_port"], True),
                                 (f["src_ip"], f["src_port"], False)):
            peer = owners.get((port, f["transport"]))
            if peer and peer != f["container_name"] and addr and ip_scope(addr) == "local":
                yield f["container_name"], peer, f["length"], sent, f
                break


def container_matrix(conn: sqlite3.Connection) -> list[dict]:
    """Traffic between containers, one row per (source capture, destination
    container, via), biggest first. `via` is "direct" when dst_ip is the
    destination container's own address, or "published port" when the
    flow went to the host on a port that container publishes (see
    _published_port_flows). Traffic through a published port is only
    counted from the client's capture; in the server's it shows up as a
    local destination."""
    cur = conn.execute(
        f"""
        WITH {_CONTAINER_IPS},
        -- skip the capture's own address under another name (see _OWN_IP)
        {_holders("dst_holder", "dst_ip", "NOT " + _OWN_IP.format(ip="f.dst_ip"))}
        SELECT f.container_name AS src_container, d.name AS dst_container,
               SUM(f.length) AS bytes, COUNT(*) AS packets
        FROM flows f JOIN dst_holder d ON d.id = f.id
        WHERE f.container_name != d.name
        GROUP BY src_container, dst_container
        """
    )
    rows = [{**dict(r), "via": "direct"} for r in cur.fetchall()]
    published: dict[tuple, dict] = {}
    for src, peer, length, sent, _ in _published_port_flows(conn):
        if sent:
            row = published.setdefault((src, peer), {
                "src_container": src, "dst_container": peer, "bytes": 0, "packets": 0,
                "via": "published port"})
            row["bytes"] += length or 0
            row["packets"] += 1
    rows += published.values()
    return sorted(rows, key=lambda r: -r["bytes"])


def container_peers(conn: sqlite3.Connection, container: str) -> list[dict]:
    """Other containers `container` exchanged traffic with, one row per peer,
    biggest first: {"container", "bytes", "packets", "sent_bytes",
    "received_bytes"}. Counted from `container`'s own capture only, so it
    doesn't depend on the peer being captured too; container_matrix()
    instead gives one row per capture and direction. Includes traffic
    through a port the peer publishes on the host."""
    cur = conn.execute(
        f"""
        WITH {_CONTAINER_IPS},
        {_holders("src_holder", "src_ip",
                  "f.container_name = ? AND NOT " + _OWN_IP.format(ip="f.src_ip"))},
        {_holders("dst_holder", "dst_ip",
                  "f.container_name = ? AND NOT " + _OWN_IP.format(ip="f.dst_ip"))},
        peer_flows AS (
            -- one row per flow and peer, even if both ends are that peer's
            SELECT id, MAX(length) AS length, name, MAX(sent) AS sent
            FROM (SELECT f.id, f.length, d.name, 1 AS sent
                  FROM flows f JOIN dst_holder d ON d.id = f.id
                  UNION ALL
                  SELECT f.id, f.length, s.name, 0
                  FROM flows f JOIN src_holder s ON s.id = f.id)
            WHERE name != ?
            GROUP BY id, name
        )
        SELECT name AS container,
               SUM(length) AS bytes, COUNT(*) AS packets,
               SUM(CASE WHEN sent THEN length ELSE 0 END) AS sent_bytes,
               SUM(CASE WHEN sent THEN 0 ELSE length END) AS received_bytes
        FROM peer_flows
        GROUP BY name
        """,
        (container, container, container),
    )
    peers = {r["container"]: dict(r) for r in cur.fetchall()}
    for _, peer, length, sent, _ in _published_port_flows(conn, container):
        row = peers.setdefault(peer, {"container": peer, "bytes": 0, "packets": 0,
                                      "sent_bytes": 0, "received_bytes": 0})
        length = length or 0
        row["bytes"] += length
        row["packets"] += 1
        row["sent_bytes" if sent else "received_bytes"] += length
    return sorted(peers.values(), key=lambda r: -r["bytes"])


def _strip_port(host: str) -> str:
    """'example.com:8080' -> 'example.com', '[::1]:80' -> '::1'."""
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def hostnames(conn: sqlite3.Connection, container: str | None = None) -> dict[str, dict]:
    """Best hostname seen in the capture for each destination IP, as
    {ip: {"hostname": ..., "source": "tls-sni" | "http-host" | "dns"}}.

    Sources, most trusted first: the TLS SNI and the HTTP Host header sent on
    a connection to that IP (the client named the server it wanted), then
    DNS answers listing that IP (the name the client looked up; a shared CDN
    address can be the answer for several names). Within a source the most
    frequently seen name wins. `container` limits this to one container's
    traffic."""
    where, params = "", ()
    if container:
        where, params = " AND container_name = ?", (container,)
    by_source = {
        "tls-sni": conn.execute(
            "SELECT dst_ip AS ip, tls_sni AS name, COUNT(*) AS n FROM flows "
            f"WHERE tls_sni IS NOT NULL AND dst_ip IS NOT NULL{where} "
            "GROUP BY ip, name", params),
        "http-host": conn.execute(
            "SELECT dst_ip AS ip, http_host AS name, COUNT(*) AS n FROM flows "
            f"WHERE http_host IS NOT NULL AND dst_ip IS NOT NULL{where} "
            "GROUP BY ip, name", params),
        "dns": conn.execute(
            "SELECT je.value AS ip, dns_query AS name, COUNT(*) AS n "
            "FROM flows, json_each(flows.dns_answers) je "
            f"WHERE dns_answers IS NOT NULL AND dns_query IS NOT NULL{where} "
            "GROUP BY ip, name", params),
    }
    out: dict[str, dict] = {}
    for source, cur in by_source.items():  # dicts keep insertion order: priority
        best: dict[str, tuple[int, str]] = {}
        for r in cur:
            name = r["name"].strip().rstrip(".")
            if source == "http-host":
                name = _strip_port(name)
            if not name or _is_ip(name):
                continue
            if (r["n"], name) > best.get(r["ip"], (0, "")):
                best[r["ip"]] = (r["n"], name)
        for ip, (_, name) in best.items():
            out.setdefault(ip, {"hostname": name, "source": source})
    return out


def external_destinations(conn: sqlite3.Connection, limit: int = 20,
                          scope: str | None = None,
                          container: str | None = None) -> list[dict]:
    """dst_ips that don't belong to any known container. Each row gets a
    `scope`: 'internet' (docker-internet traffic) or 'local' (private,
    link-local, multicast etc. - e.g. Docker Desktop's DNS resolver; see
    ip_scope), and a `hostname` / `hostname_source` from hostnames() (None
    if no name was seen). Local rows also get a `hint` (may be None). Pass
    scope='internet' or 'local' to keep only one kind; `limit` applies
    before that filter. `container` counts only that container's capture
    (bytes, packets and hostnames).

    Flows that went to the host on a port another container publishes are
    left out: container_matrix() and container_peers() already count them
    as traffic to that container (see _published_port_flows)."""
    where, params = "", ()
    if container:
        where, params = " AND f.container_name = ?", (container,)
    cur = conn.execute(
        f"""
        SELECT f.dst_ip, f.container_name, SUM(f.length) AS bytes, COUNT(*) AS packets
        FROM flows f
        WHERE f.dst_ip IS NOT NULL{where}
          AND NOT EXISTS (
              SELECT 1 FROM containers c, json_each(c.ip_addresses) je WHERE je.value = f.dst_ip
          )
        GROUP BY f.dst_ip, f.container_name
        """,
        params,
    )
    groups = {(r["dst_ip"], r["container_name"]): dict(r) for r in cur.fetchall()}
    for owner, _, length, _, f in _published_port_flows(conn, container):
        g = groups.get((f["dst_ip"], owner))
        if g:  # only the request direction is here; replies go to owner's own IP
            g["bytes"] = (g["bytes"] or 0) - (length or 0)
            g["packets"] -= 1

    by_ip: dict[str, dict] = {}
    for (ip, name), g in groups.items():
        if g["packets"] <= 0:
            continue
        row = by_ip.setdefault(ip, {"dst_ip": ip, "bytes": 0, "packets": 0, "containers": []})
        row["bytes"] += g["bytes"] or 0
        row["packets"] += g["packets"]
        if name:
            row["containers"].append(name)
    ranked = sorted(by_ip.values(), key=lambda r: (-r["bytes"], r["dst_ip"]))[:limit]

    names = hostnames(conn, container)
    rows = []
    for row in ranked:
        row["containers"] = ",".join(sorted(row["containers"])) or None
        name = names.get(row["dst_ip"], {})
        row["hostname"] = name.get("hostname")
        row["hostname_source"] = name.get("source")
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
