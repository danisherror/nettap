"""watch: --network host containers captured on the host's interface and
kept to the ports `ss --cgroup` says their cgroup holds (TODO.md P1)."""
from unittest.mock import MagicMock, patch

from nettap import cli, discovery, hostports, storage
from nettap.capture import CaptureManager
from nettap.discovery import ContainerNetInfo
from tests.test_capture import _FakeProc
from tests.test_discovery import _fake_container

NGINX = "1baf7ac4fc1243ef823881e752eb78e56b954080bc587e8f4d511a9eb975fa9c"
CLIENT = "5faca94ebdaefdf371dd4ccbf40788356952d78558c0b12d1dfa1dd1b526f3ac"

# real output from Docker Desktop for Mac (2026-11-08), plus a systemd-driver
# path and an IPv6/UDP socket
SS_OK = f"""\
tcp LISTEN 0      511      0.0.0.0:80    0.0.0.0:* cgroup:/docker/{NGINX}
tcp LISTEN 0      511         [::]:80       [::]:* cgroup:/docker/{NGINX} v6only:1
tcp LISTEN 0      4096     0.0.0.0:111   0.0.0.0:* cgroup:/
tcp SYN-SENT  0      1      192.168.65.3:62598 172.66.147.243:80 cgroup:/docker/{CLIENT}
tcp TIME-WAIT 0      0      192.168.65.3:62550 172.66.147.243:80
udp UNCONN 0      0     [fe80::1%eth0]:5353   [::]:* cgroup:/system.slice/docker-{CLIENT}.scope
"""
SS_PRIVATE_CGROUPNS = "udp UNCONN 0 0 0.0.0.0:111 0.0.0.0:*  cgroup:unreachable:1\n"


def test_parse_ss_keeps_sockets_with_a_cgroup_path():
    assert hostports.parse_ss(SS_OK + SS_PRIVATE_CGROUPNS) == [
        ("tcp", 80, f"/docker/{NGINX}"),
        ("tcp", 80, f"/docker/{NGINX}"),
        ("tcp", 111, "/"),
        ("tcp", 62598, f"/docker/{CLIENT}"),
        ("udp", 5353, f"/system.slice/docker-{CLIENT}.scope"),
    ]


def test_cgroup_attribution_needs_the_host_cgroup_namespace():
    assert hostports.cgroup_attribution_works(lambda: (SS_OK, ""))
    assert not hostports.cgroup_attribution_works(
        lambda: (SS_PRIVATE_CGROUPNS, "Failed to open cgroup2 by ID\n"))
    assert not hostports.cgroup_attribution_works(lambda: ("", ""))  # no ss


def test_ports_by_container_matches_the_id_in_either_cgroup_driver():
    ports = hostports.ports_by_container([NGINX, CLIENT, "other"], lambda: (SS_OK, ""))
    assert ports == {NGINX: {("tcp", 80)},
                     CLIENT: {("tcp", 62598), ("udp", 5353)},
                     "other": set()}


def _host_container():
    client = MagicMock()
    client.containers.get.return_value = _fake_container(host_mode=True)
    return client


def test_inspect_host_network_container_captures_the_default_route_interface(monkeypatch):
    monkeypatch.setattr(discovery, "default_route_interface", lambda: "eth0")
    monkeypatch.setattr(discovery, "interface_ips", lambda iface, **kw: {iface: "192.168.65.3"})
    monkeypatch.setattr(hostports, "cgroup_attribution_works", lambda: True)
    monkeypatch.setattr(discovery, "resolve_capture", lambda *a: 1 / 0)

    info = discovery.inspect_container(_host_container(), "abc123")
    assert info.uses_host_network
    assert (info.veth, info.capture_scope) == ("eth0", "ports")
    assert info.ip_addresses == {"eth0": "192.168.65.3"}


def test_inspect_host_network_container_without_cgroup_attribution(monkeypatch):
    monkeypatch.setattr(discovery, "default_route_interface", lambda: "eth0")
    monkeypatch.setattr(hostports, "cgroup_attribution_works", lambda: False)

    info = discovery.inspect_container(_host_container(), "abc123")
    assert info.capture_scope is None


def _host_info(scope="ports"):
    return ContainerNetInfo(
        container_id=NGINX, name="hn", image="nginx", veth="eth0",
        ip_addresses={"eth0": "192.168.65.3"}, networks=["host"], labels={},
        sandbox_key="/var/run/docker/netns/default", uses_host_network=True,
        capture_scope=scope)


@patch("nettap.capture.subprocess.Popen")
def test_attach_host_network_container_captures_host_interface_without_dns(
        mock_popen, tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tcpdump")
    mock_popen.return_value = _FakeProc()
    mgr = CaptureManager(str(tmp_path))

    session = mgr.attach(_host_info())
    assert session is not None and session.dns_process is None
    (cmd,), _ = mock_popen.call_args
    assert cmd[:3] == ["tcpdump", "-i", "eth0"]  # no nsenter
    assert mock_popen.call_count == 1
    assert mgr.status()[0]["capture_scope"] == "ports"


@patch("nettap.capture.subprocess.Popen")
def test_attach_skips_host_network_container_without_port_attribution(
        mock_popen, tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tcpdump")
    assert CaptureManager(str(tmp_path)).attach(_host_info(scope=None)) is None
    mock_popen.assert_not_called()


def test_sampler_records_ports_of_host_network_captures_only(tmp_path, monkeypatch):
    db = str(tmp_path / "n.db")
    stop = {"flag": False}

    class Mgr:
        def status(self):
            return [{"container_id": NGINX, "container": "hn", "capture_scope": "ports"},
                    {"container_id": CLIENT, "container": "bridged", "capture_scope": None}]

    def fake_ss():
        stop["flag"] = True  # one iteration
        return SS_OK, ""

    monkeypatch.setattr(hostports, "_ss", fake_ss)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    cli._sample_host_network_ports(Mgr(), db, stop)

    rows = storage.connect(db).execute(
        "SELECT container_name, transport, port FROM owned_ports").fetchall()
    assert [tuple(r) for r in rows] == [("hn", "tcp", 80)]


def test_default_route_interface_follows_policy_routing(monkeypatch):
    # Docker Desktop's VM: no default route in the main table, `ip route get`
    # finds eth0 through table 2
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return ('[{"dst":"1.1.1.1","gateway":"192.168.65.1","dev":"eth0","table":"2"}]'
                if cmd[-1] == "1.1.1.1" else "[]")

    monkeypatch.setattr(discovery, "run", fake_run)
    assert discovery.default_route_interface() == "eth0"
    assert calls == [["ip", "-j", "route", "get", "1.1.1.1"]]


def test_default_route_interface_falls_back_to_ipv6_then_none(monkeypatch):
    def v6_only(cmd, **kw):
        if cmd[-1] == "1.1.1.1":
            raise RuntimeError("RTNETLINK answers: Network is unreachable")
        return '[{"dst":"2606:4700:4700::1111","dev":"ens3"}]'

    monkeypatch.setattr(discovery, "run", v6_only)
    assert discovery.default_route_interface() == "ens3"
    monkeypatch.setattr(discovery, "run", lambda cmd, **kw: (_ for _ in ()).throw(RuntimeError()))
    assert discovery.default_route_interface() is None
