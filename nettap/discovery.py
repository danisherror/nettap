"""Resolve which host-side veth interface carries a given container's traffic.

Docker gives every container its own network namespace, wired to the host via
a veth pair: one end becomes `eth0` inside the container, the other end sits
on the host attached to a bridge (docker0 or a user-defined bridge). Capturing
on that host-side veth sees *everything* the container sends or receives -
host traffic, other-container traffic (via the bridge), and internet traffic
(after NAT) - because it's the only door in or out.

The trick to find that host-side interface without needing anything installed
inside the container image itself:

  1. Enter the container's network namespace (via its Docker "SandboxKey",
     the netns file dockerd already bind-mounts under /var/run/docker/netns)
     using the *host's* `nsenter` + `cat`, and read
     /sys/class/net/eth0/iflink. That file holds the ifindex of eth0's veth
     peer, i.e. the ifindex of the host-side end - the kernel exposes this
     regardless of what's installed in the container image.
  2. Back in the host's own namespace, scan /sys/class/net/*/ifindex for the
     interface whose ifindex matches. That name (e.g. "veth3a1f9c2") is what
     you hand to tcpdump.

This intentionally avoids requiring --privileged + --pid=host; it only needs
CAP_SYS_ADMIN (to enter another netns) and read access to
/var/run/docker/netns. See TODO.md for the known gaps (host networking,
macvlan, overlay networks) where this trick doesn't apply.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .utils import run

NET_CLASS_DIR = "/sys/class/net"


@dataclass
class ContainerNetInfo:
    container_id: str
    name: str
    image: str
    veth: str | None              # host-side interface name, or None if not resolvable
    ip_addresses: dict[str, str]  # network_name -> ip
    networks: list[str]
    labels: dict[str, str]
    sandbox_key: str | None
    uses_host_network: bool
    # ports published on the host: [{"host_port", "container_port", "protocol"}]
    published_ports: list[dict] = field(default_factory=list)
    # when the container last started (State.StartedAt), epoch seconds
    started_at: float | None = None
    # "ports": a --network host target captured on the host, kept to its own
    # ports at enrichment (hostports.py); None: a capture of its own netns
    capture_scope: str | None = None


def bridge_interfaces(sys_net: str = "/sys/class/net") -> list[str]:
    """Linux bridges in this process's network namespace (docker0, br-...).
    Docker creates them in the host's namespace - docker0 for the default
    bridge network, br-<id> per user-defined one
    (https://docs.docker.com/engine/network/drivers/bridge/) - and a normal
    container's namespace has none. So if a sidecar sees any, its target
    runs with --network host and shares the host's namespace
    (https://docs.docker.com/engine/network/drivers/host/). Exception: a
    container running its own Docker daemon (Docker-in-Docker). Seen live
    2026-11-08 on Docker Desktop for Mac: docker0 and two br-* in the host
    namespace, none in a bridge-network container's."""
    import os

    try:
        names = os.listdir(sys_net)
    except OSError:
        return []
    return sorted(n for n in names if os.path.isdir(os.path.join(sys_net, n, "bridge")))


def interface_exists(iface: str, sys_net: str = "/sys/class/net") -> bool:
    """Whether `iface` exists in this process's network namespace. Assumes
    it does where /sys/class/net isn't available (not Linux)."""
    import os

    if not os.path.isdir(sys_net):
        return True
    return os.path.exists(os.path.join(sys_net, iface))


def interface_ips(iface: str = "eth0") -> dict[str, str]:
    """Addresses assigned to `iface` in *this* process's network namespace,
    shaped like ContainerNetInfo.ip_addresses. Used by `sidecar`, which shares
    the target container's netns, so these are the target's own addresses -
    no docker.sock needed. The first IPv4 address is keyed by the bare
    interface name; any others get "<iface>/<family>#<n>" keys. Returns {} if
    `ip` fails (e.g. no such interface)."""
    import json
    import logging

    try:
        data = json.loads(run(["ip", "-j", "addr", "show", "dev", iface]) or "[]")
    except Exception as exc:  # noqa: BLE001 - best effort; report falls back to heuristics
        logging.getLogger(__name__).warning("could not read addresses of %s: %s", iface, exc)
        return {}
    out: dict[str, str] = {}
    counts: dict[str, int] = {}
    for link in data:
        for addr in link.get("addr_info", []):
            ip, family = addr.get("local"), addr.get("family", "")
            if not ip:
                continue
            if family == "inet" and iface not in out:
                out[iface] = ip
            else:
                counts[family] = counts.get(family, 0) + 1
                out[f"{iface}/{family}#{counts[family]}"] = ip
    return out


def _peer_ifindex(sandbox_key: str, iface: str = "eth0") -> int | None:
    try:
        out = run(["nsenter", f"--net={sandbox_key}", "cat", f"/sys/class/net/{iface}/iflink"])
    except (RuntimeError, OSError):
        return None
    out = out.strip()
    if not out.isdigit():
        return None
    return int(out)


def _ifindex_to_name(ifindex: int) -> str | None:
    try:
        entries = os.listdir(NET_CLASS_DIR)
    except FileNotFoundError:
        return None
    for name in entries:
        try:
            with open(f"{NET_CLASS_DIR}/{name}/ifindex") as f:
                if int(f.read().strip()) == ifindex:
                    return name
        except (FileNotFoundError, ValueError, OSError):
            continue
    return None


def resolve_veth(sandbox_key: str) -> str | None:
    """Return the host-side veth interface name for a container's netns, or None."""
    peer = _peer_ifindex(sandbox_key)
    if peer is None:
        return None
    return _ifindex_to_name(peer)


def published_ports(ports: dict | None) -> list[dict]:
    """NetworkSettings.Ports from `docker inspect` ({"80/tcp": [{"HostIp":
    "0.0.0.0", "HostPort": "18080"}, ...], "443/tcp": null}) as one entry per
    distinct host port; unpublished ports (null) are left out.
    https://docs.docker.com/reference/api/engine/version/v1.47/#tag/Container/operation/ContainerInspect"""
    found = {}
    for spec, bindings in (ports or {}).items():
        port, _, proto = spec.partition("/")
        for b in bindings or []:
            try:
                host_port, container_port = int(b.get("HostPort") or ""), int(port)
            except ValueError:
                continue
            proto = proto or "tcp"
            found[(host_port, proto)] = {"host_port": host_port,
                                         "container_port": container_port, "protocol": proto}
    return sorted(found.values(), key=lambda p: (p["host_port"], p["protocol"]))


def network_ips(networks: dict) -> dict[str, str]:
    """NetworkSettings.Networks from `docker inspect` as ContainerNetInfo.
    ip_addresses: the IPv4 address keyed by network name (empty string if
    none), plus the IPv6 one, if any, under "<network>/inet6" - like
    interface_ips(), so a peer reached over IPv6 is still recognised.
    Link-local IPv6 addresses aren't listed by the API.
    https://docs.docker.com/reference/api/engine/version/v1.47/#tag/Container/operation/ContainerInspect"""
    out = {}
    for net, info in networks.items():
        info = info or {}
        out[net] = info.get("IPAddress") or ""
        if info.get("GlobalIPv6Address"):
            out[f"{net}/inet6"] = info["GlobalIPv6Address"]
    return out


def docker_time(text: str | None) -> float | None:
    """A Docker API timestamp ("2026-11-08T07:40:32.123456789Z", RFC 3339
    with up to nanoseconds) as epoch seconds; None for a missing, unparsable
    or zero time ("0001-01-01T00:00:00Z", a container that never started)."""
    import re
    from datetime import datetime

    m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)",
                     text or "")
    if not m or m[1].startswith("0001-"):
        return None
    tz = "+00:00" if m[3] == "Z" else m[3]
    return datetime.fromisoformat(m[1] + tz).timestamp() + float(m[2] or 0)


def inspect_container(docker_client, container_id: str, resolve: bool = True) -> ContainerNetInfo:
    """Build a ContainerNetInfo from the Docker API, resolving the veth as a
    side effect unless resolve=False (it needs the host's netns, which a
    sidecar doesn't have)."""
    c = docker_client.containers.get(container_id)
    attrs = c.attrs
    net_settings = attrs.get("NetworkSettings", {}) or {}
    networks = net_settings.get("Networks", {}) or {}
    sandbox_key = net_settings.get("SandboxKey") or None
    host_mode = (attrs.get("HostConfig", {}) or {}).get("NetworkMode") == "host"

    ip_addresses = network_ips(networks)

    veth = None
    if resolve and sandbox_key and not host_mode:
        veth = resolve_veth(sandbox_key)

    return ContainerNetInfo(
        container_id=c.id,
        name=c.name,
        image=(attrs.get("Config", {}) or {}).get("Image", ""),
        veth=veth,
        ip_addresses=ip_addresses,
        networks=list(networks.keys()),
        labels=(attrs.get("Config", {}) or {}).get("Labels") or {},
        sandbox_key=sandbox_key,
        uses_host_network=host_mode,
        published_ports=published_ports(net_settings.get("Ports")),
        started_at=docker_time((attrs.get("State", {}) or {}).get("StartedAt")),
    )


def split_by_netns(docker_client, own_ips) -> tuple[ContainerNetInfo | None, list[ContainerNetInfo]]:
    """Running containers as (the one whose network namespace we share, the
    others). For a sidecar: the first is its target, found by any IP in
    `own_ips` (the shared interface's addresses), the second its possible
    peers. Containers without an IP (e.g. other sidecars, which use the
    netns of their target) are left out of both."""
    own = set(own_ips)
    target, others = None, []
    for c in docker_client.containers.list():
        info = inspect_container(docker_client, c.id, resolve=False)
        ips = {ip for ip in info.ip_addresses.values() if ip}
        if not ips:
            continue
        if ips & own:
            target = target or info
        else:
            others.append(info)
    return target, others


def other_containers(docker_client, own_ips) -> list[ContainerNetInfo]:
    """Every running container with an IP of its own, except the one whose
    network namespace we share - for a sidecar, which already records its
    target under the --target name and would otherwise see the target as its
    own peer. See split_by_netns."""
    return split_by_netns(docker_client, own_ips)[1]
