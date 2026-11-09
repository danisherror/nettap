"""discovery.resolve_capture() against real containers and a real kernel.

The unit tests mock `ip`/nsenter/sysfs, so they agree with whatever we
assume - the old `nsenter --net cat /sys/class/net/eth0/iflink` approach
passed all of them while resolving every container to the host's eth0.
These tests check the answer against ground truth read from inside each
container instead: `docker exec` sees the container's own sysfs, so its
eth0 iflink is the ifindex of the host-side veth peer.

Run with `sudo python -m pytest -m live tests/live` on a Linux Docker host
(nsenter needs root, and the tests run in the host's network namespace).
Skipped anywhere else. Everything created is named nettap-live-<random>
and removed afterwards.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid

import pytest

from nettap import discovery

pytestmark = pytest.mark.live

IMAGE = "alpine:3.20"
PREFIX = f"nettap-live-{uuid.uuid4().hex[:6]}"


def _skip_reason() -> str | None:
    if not sys.platform.startswith("linux"):
        return "needs a Linux Docker host"
    if os.geteuid() != 0:
        return "needs root (nsenter into container namespaces)"
    for tool in ("docker", "nsenter", "ip"):
        if not shutil.which(tool):
            return f"{tool} not found"
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        return "no Docker daemon"
    return None


_reason = _skip_reason()
if _reason:
    pytest.skip(_reason, allow_module_level=True)


def sh(*cmd: str) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def host_links() -> dict[int, dict]:
    """The host namespace's links by ifindex, straight from netlink."""
    return {l["ifindex"]: l for l in json.loads(sh("ip", "-j", "link", "show"))}


def sandbox_key(name: str) -> str:
    return sh("docker", "inspect", "-f", "{{.NetworkSettings.SandboxKey}}", name)


def peer_veth(name: str, iface: str = "eth0") -> dict:
    """The host-side veth of the container's `iface`, found from inside the
    container (its own sysfs) and then on the host by ifindex."""
    peer_index = int(sh("docker", "exec", name, "cat", f"/sys/class/net/{iface}/iflink"))
    link = host_links().get(peer_index)
    assert link is not None, f"no host interface with ifindex {peer_index}"
    return link


def bridge_name(network: str) -> str:
    """The Linux bridge behind a Docker bridge network: docker0 for the
    default one, br-<first 12 chars of the network ID> otherwise
    (https://docs.docker.com/engine/network/drivers/bridge/#options)."""
    if network == "bridge":
        return "docker0"
    return "br-" + sh("docker", "network", "inspect", "-f", "{{.Id}}", network)[:12]


@pytest.fixture(scope="module")
def docker_objects():
    """Create networks/containers/dummy links through the returned helpers;
    all of them are removed when the module's tests are done."""
    containers, networks, links = [], [], []
    sh("docker", "pull", "-q", IMAGE)

    def network(suffix: str, *args: str) -> str:
        name = f"{PREFIX}-{suffix}"
        sh("docker", "network", "create", *args, name)
        networks.append(name)
        return name

    def container(suffix: str, *networks_: str) -> str:
        name = f"{PREFIX}-{suffix}"
        first, rest = networks_[0], networks_[1:]
        sh("docker", "run", "-d", "--name", name, "--network", first, IMAGE, "sleep", "600")
        containers.append(name)
        for net in rest:
            sh("docker", "network", "connect", net, name)
        return name

    def dummy(suffix: str) -> str:
        # a parent for macvlan/ipvlan that isn't the host's real uplink
        name = f"ntl{suffix}{PREFIX[-4:]}"[:15]
        sh("ip", "link", "add", name, "type", "dummy")
        links.append(name)
        sh("ip", "link", "set", name, "up")
        return name

    yield network, container, dummy

    for name in containers:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    for name in networks:
        subprocess.run(["docker", "network", "rm", name], capture_output=True)
    for name in links:
        subprocess.run(["ip", "link", "del", name], capture_output=True)


def test_user_defined_bridge_resolves_to_its_own_veth(docker_objects):
    network, container, _ = docker_objects
    net = network("br")
    name = container("br", net)

    iface, in_netns, kind = discovery.resolve_capture(sandbox_key(name))

    veth = peer_veth(name)
    assert (iface, in_netns, kind) == (veth["ifname"], False, "veth")
    assert veth.get("master") == bridge_name(net)


def test_default_bridge_resolves_to_its_own_veth(docker_objects):
    _, container, _ = docker_objects
    name = container("default", "bridge")

    iface, in_netns, kind = discovery.resolve_capture(sandbox_key(name))

    veth = peer_veth(name)
    assert (iface, in_netns, kind) == (veth["ifname"], False, "veth")
    assert veth.get("master") == "docker0"


def test_two_containers_on_one_bridge_get_different_veths(docker_objects):
    network, container, _ = docker_objects
    net = network("pair")
    a, b = container("pair-a", net), container("pair-b", net)

    iface_a = discovery.resolve_capture(sandbox_key(a))[0]
    iface_b = discovery.resolve_capture(sandbox_key(b))[0]

    assert iface_a == peer_veth(a)["ifname"]
    assert iface_b == peer_veth(b)["ifname"]
    assert iface_a != iface_b


def test_resolved_interface_is_not_the_hosts_uplink(docker_objects):
    """The old sysfs bug in one line: every container resolved to the
    interface carrying the host's own internet traffic."""
    network, container, _ = docker_objects
    name = container("uplink", network("uplink"))

    iface = discovery.resolve_capture(sandbox_key(name))[0]

    assert iface != discovery.default_route_interface()
    [link] = json.loads(sh("ip", "-j", "-d", "link", "show", "dev", iface))
    assert link["linkinfo"]["info_kind"] == "veth"


@pytest.mark.parametrize("driver", ["macvlan", "ipvlan"])
def test_macvlan_and_ipvlan_are_captured_inside_their_netns(docker_objects, driver):
    network, container, dummy = docker_objects
    parent = dummy(driver[:3])
    subnet = {"macvlan": "10.231.1.0/24", "ipvlan": "10.231.2.0/24"}[driver]
    net = network(driver, "-d", driver, "--subnet", subnet, "-o", f"parent={parent}")
    name = container(driver, net)

    iface, in_netns, kind = discovery.resolve_capture(sandbox_key(name))

    assert (iface, in_netns, kind) == ("eth0", True, driver)
    # ground truth: inside the container, eth0's link is the dummy parent
    parent_index = int(sh("docker", "exec", name, "cat", "/sys/class/net/eth0/iflink"))
    assert host_links()[parent_index]["ifname"] == parent


def test_container_on_two_networks_is_captured_on_every_interface(docker_objects):
    network, container, _ = docker_objects
    first, second = network("multi-a"), network("multi-b")
    name = container("multi", first, second)

    iface, in_netns, kind = discovery.resolve_capture(sandbox_key(name))

    assert (iface, in_netns, kind) == (discovery.ANY_IFACE, True, "veth")
    # ground truth: two veths, one on each network's bridge
    masters = {peer_veth(name, i).get("master") for i in ("eth0", "eth1")}
    assert masters == {bridge_name(first), bridge_name(second)}
