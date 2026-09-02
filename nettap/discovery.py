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
from dataclasses import dataclass

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


def inspect_container(docker_client, container_id: str) -> ContainerNetInfo:
    """Build a ContainerNetInfo from the Docker API, resolving the veth as a side effect."""
    c = docker_client.containers.get(container_id)
    attrs = c.attrs
    net_settings = attrs.get("NetworkSettings", {}) or {}
    networks = net_settings.get("Networks", {}) or {}
    sandbox_key = net_settings.get("SandboxKey") or None
    host_mode = (attrs.get("HostConfig", {}) or {}).get("NetworkMode") == "host"

    ip_addresses = {net: (info.get("IPAddress") or "") for net, info in networks.items()}

    veth = None
    if sandbox_key and not host_mode:
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
    )
