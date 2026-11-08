"""Port-based attribution for a `--network host` target (sidecar
--attribute-by-port, and `watch`).

Such a container has no network namespace of its own, so a capture in it
sees the whole Docker host. Instead the sidecar also joins the target's PID
namespace (`--pid container:<target>`), samples which TCP/UDP ports the
target's processes have sockets on, and records when each was in use
(`owned_ports` table). Enrichment then keeps only packets whose host-side
address and port belonged to the target at that moment.

Reading another process's /proc/<pid>/fd needs a ptrace access check
(https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html), so processes
running as another user need `--cap-add SYS_PTRACE` - seen live 2026-11-08:
without it nginx's worker processes (user nginx) gave EACCES.

`watch` does the same for every `--network host` container it captures,
but without seeing their processes (it doesn't run with --pid=host): it
asks the kernel which cgroup created each socket (`ss --cgroup`,
https://manpages.debian.org/testing/iproute2/ss.8.en.html - a cgroup v2
path such as /docker/<id> or /system.slice/docker-<id>.scope) and matches
the container ID. ss can only turn the kernel's cgroup ID into a path when
nettap runs in the host's cgroup namespace (compose `cgroup: host`,
https://docs.docker.com/reference/compose-file/services/#cgroup); otherwise
it prints `cgroup:unreachable:1` and "Failed to open cgroup2 by ID" (seen
live 2026-11-08 on Docker Desktop for Mac).

Limit: a connection opened and closed between two samples is missed, so
listening ports are reliable but short outgoing requests may not be.
TIME-WAIT sockets carry no cgroup, so they don't help `watch` either.
"""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess

SAMPLE_SECONDS = 0.25
# Sightings of a port closer together than this extend one interval; also
# the slack when matching a packet's time against an interval.
GAP_SECONDS = 2.0

_SOCKET = re.compile(r"socket:\[(\d+)\]")


def _pids(proc: str) -> list[int]:
    return [int(p) for p in os.listdir(proc) if p.isdigit()]


def _own_tree(proc: str, me: int) -> set[int]:
    """`me` and every process descended from it (tcpdump, tshark)."""
    children: dict[int, list[int]] = {}
    for pid in _pids(proc):
        try:
            with open(f"{proc}/{pid}/stat") as f:
                # "pid (comm) state ppid ..." - comm may contain spaces/parens
                ppid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(pid)
    tree, todo = set(), [me]
    while todo:
        pid = todo.pop()
        if pid not in tree:
            tree.add(pid)
            todo += children.get(pid, [])
    return tree


def target_processes(proc: str = "/proc", me: int | None = None) -> tuple[list[int], list[int]]:
    """(pids of the target's processes, those of them whose sockets can't be
    read). Every process visible here that isn't this sidecar or one of its
    children is the target's - assuming `--pid container:<target>`; without
    it the list is empty."""
    me = os.getpid() if me is None else me
    own = _own_tree(proc, me)
    pids, denied = [], []
    for pid in _pids(proc):
        if pid in own:
            continue
        pids.append(pid)
        try:
            os.listdir(f"{proc}/{pid}/fd")
        except PermissionError:
            denied.append(pid)
        except OSError:
            pass  # exited meanwhile
    return pids, denied


def owned_ports(proc: str = "/proc", me: int | None = None) -> set[tuple[str, int]]:
    """{(transport, local port)} of every TCP/UDP socket, IPv4 or IPv6,
    listening or connected, held by the target's processes right now."""
    inodes = set()
    for pid in target_processes(proc, me)[0]:
        try:
            fds = os.listdir(f"{proc}/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                m = _SOCKET.fullmatch(os.readlink(f"{proc}/{pid}/fd/{fd}"))
            except OSError:
                continue
            if m:
                inodes.add(m[1])
    ports = set()
    for table, transport in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            with open(f"{proc}/net/{table}") as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            # sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
            fields = line.split()
            if len(fields) > 9 and fields[9] in inodes:
                port = int(fields[1].rsplit(":", 1)[1], 16)
                if port:
                    ports.add((transport, port))
    return ports


SS_CMD = ["ss", "-H", "-t", "-u", "-a", "-n", "--cgroup"]
_CGROUP = re.compile(r"cgroup:(\S+)")


def _ss() -> tuple[str, str]:
    """(stdout, stderr) of SS_CMD; empty if ss is missing or fails."""
    try:
        proc = subprocess.run(SS_CMD, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "", ""
    return proc.stdout, proc.stderr


def parse_ss(text: str) -> list[tuple[str, int, str]]:
    """[(transport, local port, cgroup path)] from `ss -H -tuan --cgroup`
    lines like 'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* cgroup:/docker/<id>'.
    Sockets without a usable cgroup (TIME-WAIT, unreachable) are left out."""
    out = []
    for line in text.splitlines():
        fields = line.split()
        m = _CGROUP.search(line)
        if len(fields) < 6 or fields[0] not in ("tcp", "udp") or not m:
            continue
        if not m[1].startswith("/"):  # "unreachable:1": ss couldn't resolve the ID
            continue
        try:
            port = int(fields[4].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if port:
            out.append((fields[0], port, m[1]))
    return out


def cgroup_attribution_works(ss=None) -> bool:
    """Whether ss can name the cgroup of this host's sockets, i.e. nettap
    runs in the host's cgroup namespace (see module docstring)."""
    stdout, stderr = (ss or _ss)()
    if "Failed to open cgroup2" in stderr or "cgroup:unreachable" in stdout:
        return False
    return "cgroup:/" in stdout


def ports_by_container(container_ids, ss=None) -> dict[str, set[tuple[str, int]]]:
    """{container ID: {(transport, local port)}} of the sockets each
    container's processes created, from one ss call. A container's cgroup
    path holds its full ID with both the cgroupfs and systemd drivers."""
    out: dict[str, set[tuple[str, int]]] = {c: set() for c in container_ids if c}
    if not out:
        return out
    for transport, port, path in parse_ss((ss or _ss)()[0]):
        for cid in out:
            if cid in path:
                out[cid].add((transport, port))
    return out


def record(conn: sqlite3.Connection, container: str, ports, now: float) -> None:
    """Note that `container` held these ports at `now`, extending an interval
    seen within GAP_SECONDS or starting a new one."""
    with conn:
        for transport, port in ports:
            cur = conn.execute(
                "UPDATE owned_ports SET last_seen = ? WHERE container_name = ? AND transport = ? "
                "AND port = ? AND last_seen >= ?",
                (now, container, transport, port, now - GAP_SECONDS))
            if cur.rowcount == 0:
                conn.execute(
                    "INSERT INTO owned_ports (container_name, transport, port, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?)", (container, transport, port, now, now))


def keep_owned(conn: sqlite3.Connection, container: str, rows: list[dict]) -> list[dict]:
    """The flow rows whose host-side end - an address of `container`'s row
    (the host's interface addresses) plus a port - belonged to `container`
    at the packet's time. Everything else on the host (other containers'
    NATed traffic, the host's own) is dropped, as are packets without a
    TCP/UDP port (ARP, ICMP)."""
    import json

    local = set()
    for r in conn.execute("SELECT ip_addresses FROM containers WHERE name = ?", (container,)):
        local |= {ip for ip in json.loads(r["ip_addresses"] or "{}").values() if ip}
    spans: dict[tuple, list[tuple[float, float]]] = {}
    for r in conn.execute("SELECT transport, port, first_seen, last_seen FROM owned_ports "
                          "WHERE container_name = ?", (container,)):
        spans.setdefault((r["transport"], r["port"]), []).append((r["first_seen"], r["last_seen"]))

    def owned(transport, port, ts):
        return ts is not None and any(a - GAP_SECONDS <= ts <= b + GAP_SECONDS
                                      for a, b in spans.get((transport, port), ()))

    return [r for r in rows
            if r.get("transport") in ("tcp", "udp") and (
                (r["src_ip"] in local and owned(r["transport"], r["src_port"], r["ts"]))
                or (r["dst_ip"] in local and owned(r["transport"], r["dst_port"], r["ts"])))]
