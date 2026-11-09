"""`nettap check`: did a container only contact what it's allowed to?

An allowlist is a text file with one entry per line (`#` starts a comment):

    db                  # a container name (as nettap knows it)
    api.stripe.com      # a hostname
    *.amazonaws.com     # any subdomain (not amazonaws.com itself)
    10.0.0.0/8          # an address or CIDR range

A destination is allowed when its address is in an allowed range, or any
name seen for it matches an entry: the container holding the address, or a
hostname from the capture - the TLS SNI or HTTP Host the container sent to
it, or a DNS answer it got listing it. Those names come from the
container's own traffic, so a hostile program can claim any of them (e.g. a
made-up SNI): this catches unplanned dependencies, it isn't a security
boundary.

Destinations are the far ends of the container's connections that it
opened itself. Without TCP flags in the flow store, "opened itself" is
judged by ports: a connection from a port in Linux's ephemeral range
(32768-60999, `net.ipv4.ip_local_port_range`,
https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html) to a
port below it was opened by this side, the reverse was opened by the
peer. Anything else (both or neither ephemeral, ICMP) counts as opened by
the container, so an unclear case is checked rather than skipped.
`direction="all"` also checks peers that connected to the container.

Always allowed: the container's own addresses, loopback (including
Docker's embedded DNS at 127.0.0.11), and addresses that aren't a single
host (multicast, broadcast, link-local, unspecified) - IPv6 neighbour
discovery and mDNS put those in almost every capture.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import sqlite3
from dataclasses import dataclass, field

from . import analyze

EPHEMERAL_LOW = 32768


@dataclass
class Allowlist:
    networks: list = field(default_factory=list)   # ip_network objects
    names: set = field(default_factory=set)        # exact names, lower case
    patterns: list = field(default_factory=list)   # "*.example.com", lower case

    def __len__(self) -> int:
        return len(self.networks) + len(self.names) + len(self.patterns)

    def add(self, entry: str, where: str = "") -> None:
        entry = entry.strip()
        if not entry:
            return
        try:
            self.networks.append(ipaddress.ip_network(entry, strict=False))
            return
        except ValueError:
            pass
        name = entry.lower().rstrip(".")
        if name.startswith("*."):
            rest = name[2:]
            if not rest or "*" in rest:
                raise ValueError(f"{where}bad wildcard {entry!r} (use e.g. *.example.com)")
            self.patterns.append(name)
        elif "*" in name or "/" in name or " " in name:
            raise ValueError(f"{where}not a hostname, container name, address or CIDR: {entry!r}")
        else:
            self.names.add(name)

    def match_ip(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net in self.networks:
            if addr.version == net.version and addr in net:
                return str(net)
        return None

    def match_name(self, name: str) -> str | None:
        name = name.lower().rstrip(".")
        if name in self.names:
            return name
        for pattern in self.patterns:
            # "*.example.com": at least one more label in front
            if name.endswith(pattern[1:]) and fnmatch.fnmatchcase(name, pattern):
                return pattern
        return None


def parse_allowlist(text: str, source: str = "allowlist") -> Allowlist:
    allow = Allowlist()
    for n, line in enumerate(text.splitlines(), 1):
        allow.add(line.split("#", 1)[0], where=f"{source} line {n}: ")
    return allow


def always_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 4 and addr == ipaddress.ip_address("255.255.255.255"):
        return True
    return addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_unspecified


def _opened_by(local_port, remote_port) -> str:
    """'us', 'them' or 'unclear' (treated as 'us' by the caller)."""
    if local_port is None or remote_port is None:
        return "unclear"
    local_eph, remote_eph = local_port >= EPHEMERAL_LOW, remote_port >= EPHEMERAL_LOW
    if local_eph and not remote_eph:
        return "us"
    if remote_eph and not local_eph:
        return "them"
    return "unclear"


def _names_by_ip(conn: sqlite3.Connection, container: str) -> dict[str, set]:
    """Every hostname seen for each address in the container's traffic:
    SNI, HTTP Host (port stripped), DNS answers."""
    out: dict[str, set] = {}
    queries = (
        "SELECT dst_ip AS ip, tls_sni AS name FROM flows "
        "WHERE container_name = ? AND tls_sni IS NOT NULL AND dst_ip IS NOT NULL",
        "SELECT dst_ip AS ip, http_host AS name FROM flows "
        "WHERE container_name = ? AND http_host IS NOT NULL AND dst_ip IS NOT NULL",
        "SELECT je.value AS ip, dns_query AS name FROM flows, json_each(flows.dns_answers) je "
        "WHERE container_name = ? AND dns_answers IS NOT NULL AND dns_query IS NOT NULL",
    )
    for sql in queries:
        for r in conn.execute(sql, (container,)):
            name = analyze._strip_port(r["name"].strip()).rstrip(".")
            if name and not analyze._is_ip(name):
                out.setdefault(r["ip"], set()).add(name)
    return out


def _containers_by_ip(conn: sqlite3.Connection) -> dict[str, set]:
    out: dict[str, set] = {}
    for r in conn.execute("SELECT name, ip_addresses FROM containers WHERE name IS NOT NULL"):
        for ip in json.loads(r["ip_addresses"] or "{}").values():
            if ip:
                out.setdefault(ip, set()).add(r["name"])
    return out


def destinations(conn: sqlite3.Connection, container: str, direction: str = "out") -> list[dict]:
    """The far ends of `container`'s traffic, one row per address (or per
    peer container, for traffic through a port it publishes on the host):
    {"ip", "containers", "hostnames", "ports", "bytes", "packets"}, leaving
    out always-allowed addresses and, with direction="out", peers that only
    connected to the container."""
    from .report import _self_ips

    self_ips = set(_self_ips(conn, container))
    via_port = {f["id"]: peer for _, peer, _, sent, f in analyze._published_port_flows(conn, container)}
    rows: dict[str, dict] = {}
    opened: dict[str, bool] = {}
    for f in conn.execute(
            "SELECT id, src_ip, dst_ip, src_port, dst_port, transport, length FROM flows "
            "WHERE container_name = ? AND (src_ip IS NOT NULL OR dst_ip IS NOT NULL)",
            (container,)):
        if f["src_ip"] in self_ips:
            remote, lport, rport = f["dst_ip"], f["src_port"], f["dst_port"]
        elif f["dst_ip"] in self_ips:
            remote, lport, rport = f["src_ip"], f["dst_port"], f["src_port"]
        else:  # e.g. the lo capture (127.0.0.1 <-> 127.0.0.11)
            remote, lport, rport = f["dst_ip"], f["src_port"], f["dst_port"]
        if not remote or remote in self_ips or always_allowed(remote):
            continue
        key = f"container:{via_port[f['id']]}" if f["id"] in via_port else remote
        row = rows.setdefault(key, {"ip": remote, "containers": set(), "hostnames": set(),
                                    "ports": set(), "bytes": 0, "packets": 0})
        if f["id"] in via_port:
            row["containers"].add(via_port[f["id"]])
        row["bytes"] += f["length"] or 0
        row["packets"] += 1
        if _opened_by(lport, rport) != "them":
            opened[key] = True
            if rport is not None:
                row["ports"].add(f"{f['transport'] or '?'}/{rport}")
        elif lport is not None:  # only listed with direction="all"
            row["ports"].add(f"{f['transport'] or '?'}/{lport} (inbound)")

    names = _names_by_ip(conn, container)
    holders = _containers_by_ip(conn)
    out = []
    for key, row in rows.items():
        if direction == "out" and not opened.get(key):
            continue
        if not row["containers"]:
            row["containers"] = holders.get(row["ip"], set()) - {container}
            row["hostnames"] = names.get(row["ip"], set())
        out.append(row)
    return sorted(out, key=lambda r: (-r["bytes"], r["ip"]))


def check(conn: sqlite3.Connection, container: str, allow: Allowlist,
          direction: str = "out") -> list[dict]:
    """destinations() with "destination" (best name), "allowed" and
    "matched" (the entry that allowed it) added; lists turned into sorted
    lists. Disallowed first, then biggest first."""
    results = []
    for row in destinations(conn, container, direction):
        matched = allow.match_ip(row["ip"])
        for name in sorted(row["containers"]) + sorted(row["hostnames"]):
            matched = matched or allow.match_name(name)
        containers, hostnames = sorted(row["containers"]), sorted(row["hostnames"])
        results.append({
            "destination": (containers or hostnames or [row["ip"]])[0],
            "ip": row["ip"],
            "allowed": matched is not None,
            "matched": matched,
            "containers": containers,
            "hostnames": hostnames,
            "ports": sorted(row["ports"]),
            "bytes": row["bytes"],
            "packets": row["packets"],
        })
    return sorted(results, key=lambda r: (r["allowed"], -r["bytes"], r["ip"]))
