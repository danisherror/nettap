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
     with the *host's* `nsenter` and ask netlink about eth0:
     `ip -j -d link show dev eth0`. That gives eth0's own ifindex, its link
     kind ("veth", "macvlan", ...) and, for a veth, the ifindex of its peer -
     the host-side end.
     Not /sys/class/net/eth0/iflink: sysfs shows the namespace of whoever
     mounted it, so under `nsenter --net` it's still the host's eth0 (seen
     live 2026-11-08 - every container resolved to the host's eth0; `ip
     netns exec` remounts /sys for this reason, see netns_switch() in
     https://github.com/iproute2/iproute2/blob/main/lib/namespace.c).
  2. Back in the host's own namespace, scan /sys/class/net/*/ifindex for the
     interface whose ifindex matches, and check that its iflink points back
     at the container's eth0. That name (e.g. "veth3a1f9c2") is what you
     hand to tcpdump.

macvlan and ipvlan containers have no veth: eth0's link is the parent
interface (e.g. the host's eth0), which carries the whole host's traffic.
Those are captured on their own eth0 from inside their namespace instead
(nsenter + tcpdump), like the `lo` DNS capture.

This intentionally avoids requiring --privileged + --pid=host; it only needs
CAP_SYS_ADMIN (to enter another netns) and read access to
/var/run/docker/netns. See TODO.md for the known gaps (host networking,
overlay networks) where this trick doesn't apply.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

from .utils import run

logger = logging.getLogger(__name__)

NET_CLASS_DIR = "/sys/class/net"
# link kinds whose parent is a shared host interface: captured inside the
# container's netns (https://docs.docker.com/engine/network/drivers/macvlan/,
# https://docs.docker.com/engine/network/drivers/ipvlan/)
NETNS_CAPTURE_KINDS = ("macvlan", "ipvlan")


@dataclass
class ContainerNetInfo:
    container_id: str
    name: str
    image: str
    veth: str | None              # interface to capture on, or None if not resolvable:
                                  # host-side veth, or one inside the netns (below)
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
    # veth names an interface inside the container's netns (macvlan/ipvlan),
    # captured by entering the namespace through sandbox_key
    capture_in_netns: bool = False
    # eth0's link kind from netlink ("veth", "macvlan", ...), for messages
    link_kind: str | None = None


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


def _link_info(sandbox_key: str, iface: str = "eth0") -> dict | None:
    """eth0's ifindex, link kind and link_index (a veth's peer, or a
    macvlan/ipvlan's parent), read over netlink inside the container's
    netns. Needs iproute2 with JSON output (-j, iproute2 4.13+)."""
    try:
        out = run(["nsenter", f"--net={sandbox_key}", "ip", "-j", "-d", "link", "show", "dev", iface])
        links = json.loads(out)
    except RuntimeError as exc:
        if "Invalid argument" in str(exc):
            _warn_stale_netns(sandbox_key)
        return None
    except (OSError, ValueError):
        return None
    if not isinstance(links, list) or not links or not isinstance(links[0], dict):
        return None
    link = links[0]
    return {
        "ifindex": link.get("ifindex"),
        "link_index": link.get("link_index"),
        "kind": (link.get("linkinfo") or {}).get("info_kind"),
    }


_stale_warned: set[str] = set()


def _warn_stale_netns(sandbox_key: str) -> None:
    """nsenter gets EINVAL when the netns file is a plain empty file, not a
    namespace: what nettap's container sees for containers started after it
    when /var/run/docker/netns is bind-mounted without propagation (Docker's
    default is rprivate). Seen live 2026-11-08. Needs ':rslave' on that mount,
    which Docker Desktop doesn't support
    (https://docs.docker.com/engine/storage/bind-mounts/#configure-bind-propagation)."""
    if sandbox_key in _stale_warned:
        return
    _stale_warned.add(sandbox_key)
    logger.warning(
        "cannot enter netns %s (nsenter: Invalid argument): the container probably "
        "started after nettap and /var/run/docker/netns is mounted without "
        "propagation - mount it with ':ro,rslave' (see docker-compose.yml)", sandbox_key)


def _read_int(path: str) -> int | None:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _ifindex_to_name(ifindex: int) -> str | None:
    try:
        entries = os.listdir(NET_CLASS_DIR)
    except FileNotFoundError:
        return None
    for name in entries:
        if _read_int(f"{NET_CLASS_DIR}/{name}/ifindex") == ifindex:
            return name
    return None


def resolve_capture(sandbox_key: str, iface: str = "eth0") -> tuple[str | None, bool, str | None]:
    """Where to capture a container's traffic: (interface, in_netns, kind).

    For a veth: the host-side peer, provided its iflink points back at the
    container's interface. A peer in another namespace (a Swarm overlay
    network's) would otherwise match an unrelated host interface that
    happens to share its ifindex.
    For macvlan/ipvlan: the container's own interface, in_netns=True.
    Otherwise (None, False, kind)."""
    link = _link_info(sandbox_key, iface)
    if link is None:
        return None, False, None
    kind = link["kind"]
    if kind in NETNS_CAPTURE_KINDS:
        return iface, True, kind
    if kind == "veth" and isinstance(link["link_index"], int):
        name = _ifindex_to_name(link["link_index"])
        if name and _read_int(f"{NET_CLASS_DIR}/{name}/iflink") == link["ifindex"]:
            return name, False, kind
    return None, False, kind


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

    veth, in_netns, kind = None, False, None
    if resolve and sandbox_key and not host_mode:
        veth, in_netns, kind = resolve_capture(sandbox_key)

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
        capture_in_netns=in_netns,
        link_kind=kind,
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
