import json
from unittest.mock import MagicMock, patch
import pytest

from nettap import discovery


def test_ifindex_to_name(tmp_path, monkeypatch):
    net_dir = tmp_path / "net"
    (net_dir / "eth0").mkdir(parents=True)
    (net_dir / "eth0" / "ifindex").write_text("7\n")
    (net_dir / "veth123").mkdir(parents=True)
    (net_dir / "veth123" / "ifindex").write_text("42\n")

    monkeypatch.setattr(discovery, "NET_CLASS_DIR", str(net_dir))
    assert discovery._ifindex_to_name(42) == "veth123"
    assert discovery._ifindex_to_name(999) is None


def _ip_link_json(kind, ifindex=11, link_index=247):
    """`ip -j -d link show dev eth0` output (trimmed), as seen live 2026-11-08."""
    return json.dumps([{"ifindex": ifindex, "ifname": "eth0", "link_index": link_index,
                        "link_netnsid": 0, "linkinfo": {"info_kind": kind}}])


def _host_net(tmp_path, monkeypatch, ifaces):
    net_dir = tmp_path / "net"
    for name, (ifindex, iflink) in ifaces.items():
        (net_dir / name).mkdir(parents=True)
        (net_dir / name / "ifindex").write_text(f"{ifindex}\n")
        (net_dir / name / "iflink").write_text(f"{iflink}\n")
    monkeypatch.setattr(discovery, "NET_CLASS_DIR", str(net_dir))


HOST = {"eth0": (4, 4), "vethb56415c": (247, 11), "eth0.98": (248, 4)}


@patch("nettap.discovery.run")
def test_link_info_asks_netlink_inside_the_netns(mock_run):
    mock_run.return_value = _ip_link_json("veth")
    assert discovery._link_info("/var/run/docker/netns/abc") == {
        "ifindex": 11, "link_index": 247, "kind": "veth"}
    args = mock_run.call_args[0][0]
    assert args[:2] == ["nsenter", "--net=/var/run/docker/netns/abc"]
    # not sysfs: under nsenter --net, /sys/class/net still shows the host's
    # interfaces (seen live 2026-11-08)
    assert args[2:] == ["ip", "-j", "-d", "link", "show", "dev", "eth0"]


@pytest.mark.parametrize("effect", [RuntimeError("boom"), OSError("no ip"), "not json", "[]"])
def test_link_info_failure_returns_none(effect):
    kw = {"side_effect": effect} if isinstance(effect, Exception) else {"return_value": effect}
    with patch("nettap.discovery.run", **kw):
        assert discovery._link_info("/does/not/exist") is None


def test_resolve_capture_veth_maps_peer_to_host_interface(tmp_path, monkeypatch):
    _host_net(tmp_path, monkeypatch, HOST)
    with patch("nettap.discovery.run", return_value=_ip_link_json("veth")):
        assert discovery.resolve_capture("sb") == ("vethb56415c", False, "veth")


def test_resolve_capture_rejects_peer_that_does_not_point_back(tmp_path, monkeypatch):
    # a veth whose peer lives in another netns (a Swarm overlay network's):
    # the host interface with that ifindex is unrelated - capture inside the
    # netns on every interface instead
    _host_net(tmp_path, monkeypatch, {"vethother": (247, 99)})
    with patch("nettap.discovery.run", return_value=_ip_link_json("veth")):
        assert discovery.resolve_capture("sb") == ("any", True, "veth")


def test_resolve_capture_overlay_peer_missing_from_host(tmp_path, monkeypatch):
    # seen live 2026-11-08: an overlay container's eth0 peers with ifindex
    # 286 in the overlay's namespace; the host has no such interface
    _host_net(tmp_path, monkeypatch, HOST)
    with patch("nettap.discovery.run", return_value=_ip_link_json("veth", 285, 286)):
        assert discovery.resolve_capture("sb") == ("any", True, "veth")


@pytest.mark.parametrize("kind,link_index", [("macvlan", 4), ("ipvlan", 248)])
def test_resolve_capture_macvlan_ipvlan_capture_inside_netns(tmp_path, monkeypatch, kind, link_index):
    # their link is the parent (the host's eth0 / eth0.98) - capturing there
    # would record the whole host's traffic as this container's
    _host_net(tmp_path, monkeypatch, HOST)
    with patch("nettap.discovery.run", return_value=_ip_link_json(kind, 246, link_index)):
        assert discovery.resolve_capture("sb") == ("eth0", True, kind)


def test_resolve_capture_unknown_kind(tmp_path, monkeypatch):
    _host_net(tmp_path, monkeypatch, HOST)
    with patch("nettap.discovery.run", return_value=_ip_link_json("vxlan", 11, 4)):
        assert discovery.resolve_capture("sb") == (None, False, "vxlan")


def _fake_container(id_="abc123", name="web", image="nginx:latest",
                     sandbox_key="/var/run/docker/netns/abc123",
                     networks=None, labels=None, host_mode=False):
    attrs = {
        "NetworkSettings": {
            "SandboxKey": sandbox_key,
            "Networks": networks or {"bridge": {"IPAddress": "172.17.0.2"}},
            "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
        },
        "Config": {"Image": image, "Labels": labels or {}},
        "HostConfig": {"NetworkMode": "host" if host_mode else "bridge"},
    }
    c = MagicMock()
    c.id = id_
    c.name = name
    c.attrs = attrs
    return c


def test_inspect_container_resolves_veth(monkeypatch):
    client = MagicMock()
    client.containers.get.return_value = _fake_container()
    monkeypatch.setattr(discovery, "resolve_capture", lambda sandbox_key: ("veth999", False, "veth"))

    info = discovery.inspect_container(client, "abc123")
    assert info.name == "web"
    assert info.veth == "veth999"
    assert not info.capture_in_netns
    assert info.ip_addresses == {"bridge": "172.17.0.2"}
    assert info.published_ports == [{"host_port": 8080, "container_port": 80, "protocol": "tcp"}]
    assert not info.uses_host_network


def test_inspect_container_host_network_skips_veth(monkeypatch):
    client = MagicMock()
    client.containers.get.return_value = _fake_container(host_mode=True)
    called = []
    monkeypatch.setattr(discovery, "resolve_capture", lambda sandbox_key: called.append(1) or ("shouldnt-happen", False, "veth"))

    info = discovery.inspect_container(client, "abc123")
    assert info.veth is None
    assert info.uses_host_network
    assert called == []


def test_inspect_container_macvlan_captures_inside_netns(monkeypatch):
    client = MagicMock()
    client.containers.get.return_value = _fake_container()
    monkeypatch.setattr(discovery, "resolve_capture", lambda sandbox_key: ("eth0", True, "macvlan"))
    monkeypatch.setattr(discovery, "interface_ips", lambda *a, **kw: {"eth0": "172.17.0.2"})
    info = discovery.inspect_container(client, "abc123")
    assert (info.veth, info.capture_in_netns, info.link_kind) == ("eth0", True, "macvlan")
    assert info.ip_addresses == {"bridge": "172.17.0.2"}  # already known, not repeated


# `nsenter ... ip -j addr show` in a Swarm overlay container (trimmed, seen
# live 2026-11-08): eth0 on the overlay, eth1 on docker_gwbridge
OVERLAY_ADDRS = json.dumps([
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"}]},
    {"ifname": "eth0", "addr_info": [
        {"family": "inet", "local": "10.0.1.7", "scope": "global"},
        {"family": "inet6", "local": "fe80::1", "scope": "link"}]},
    {"ifname": "eth1", "addr_info": [{"family": "inet", "local": "172.20.0.4", "scope": "global"}]},
])


def test_interface_ips_all_interfaces_in_another_netns():
    with patch("nettap.discovery.run", return_value=OVERLAY_ADDRS) as mock_run:
        assert discovery.interface_ips(None, "/var/run/docker/netns/ov", skip_link_local=True) == {
            "eth0": "10.0.1.7", "eth1": "172.20.0.4"}
    assert mock_run.call_args[0][0] == [
        "nsenter", "--net=/var/run/docker/netns/ov", "ip", "-j", "addr", "show"]


def test_inspect_container_overlay_records_gwbridge_address(monkeypatch):
    client = MagicMock()
    client.containers.get.return_value = _fake_container(
        networks={"ov-net": {"IPAddress": "10.0.1.7"}})
    monkeypatch.setattr(discovery, "resolve_capture", lambda sandbox_key: ("any", True, "veth"))
    with patch("nettap.discovery.run", return_value=OVERLAY_ADDRS):
        info = discovery.inspect_container(client, "abc123")
    assert info.ip_addresses == {"ov-net": "10.0.1.7", "eth1": "172.20.0.4"}


def test_inspect_container_host_veth_does_not_read_netns_addresses(monkeypatch):
    client = MagicMock()
    client.containers.get.return_value = _fake_container()
    monkeypatch.setattr(discovery, "resolve_capture", lambda sandbox_key: ("veth1", False, "veth"))
    monkeypatch.setattr(discovery, "interface_ips", lambda *a, **kw: 1 / 0)  # must not be called
    assert discovery.inspect_container(client, "abc123").ip_addresses == {"bridge": "172.17.0.2"}


def test_published_ports_reads_docker_inspect_bindings():
    from nettap.discovery import published_ports
    ports = {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"},
                        {"HostIp": "::", "HostPort": "18080"}],
             "443/tcp": None, "53/udp": [{"HostIp": "", "HostPort": "5353"}]}
    assert published_ports(ports) == [
        {"host_port": 5353, "container_port": 53, "protocol": "udp"},
        {"host_port": 18080, "container_port": 80, "protocol": "tcp"}]
    assert published_ports(None) == []


def test_inspect_container_reads_ipv6_addresses(monkeypatch):
    c = _fake_container(networks={
        "app": {"IPAddress": "172.20.0.3", "GlobalIPv6Address": "fd00:20::3"},
        "v6only": {"IPAddress": "", "GlobalIPv6Address": "fd00:30::3"},
        "plain": {"IPAddress": "172.21.0.3", "GlobalIPv6Address": ""},
    })
    client = MagicMock()
    client.containers.get.return_value = c
    info = discovery.inspect_container(client, c.id, resolve=False)
    assert info.ip_addresses == {"app": "172.20.0.3", "app/inet6": "fd00:20::3",
                                 "v6only": "", "v6only/inet6": "fd00:30::3",
                                 "plain": "172.21.0.3"}
    assert info.networks == ["app", "v6only", "plain"]


def test_docker_time():
    assert discovery.docker_time("2026-11-08T07:40:32.5Z") == 1794123632.5
    assert discovery.docker_time("2026-11-08T07:40:32.123456789Z") == \
        pytest.approx(1794123632.123456789)
    assert discovery.docker_time("2026-11-08T08:40:32+01:00") == 1794123632.0
    assert discovery.docker_time("0001-01-01T00:00:00Z") is None  # never started
    assert discovery.docker_time(None) is None
    assert discovery.docker_time("garbage") is None


def test_inspect_container_reads_start_time():
    c = _fake_container()
    c.attrs["State"] = {"StartedAt": "2026-11-08T07:40:32.5Z"}
    client = MagicMock()
    client.containers.get.return_value = c
    assert discovery.inspect_container(client, c.id, resolve=False).started_at == 1794123632.5


def test_link_info_warns_once_about_unpropagated_netns_mount(caplog):
    discovery._stale_warned.clear()
    err = RuntimeError("command failed (1): nsenter ...\nstderr: nsenter: reassociate "
                       "to namespace 'ns/net' failed: Invalid argument")
    with patch("nettap.discovery.run", side_effect=err):
        assert discovery._link_info("/var/run/docker/netns/late") is None
        assert discovery._link_info("/var/run/docker/netns/late") is None
    hints = [r for r in caplog.records if "rslave" in r.getMessage()]
    assert len(hints) == 1
