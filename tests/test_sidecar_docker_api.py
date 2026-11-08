"""`nettap sidecar --docker-api`: record the other containers from the Docker
API so a sidecar's report can name peers without a sidecar of their own
(TODO.md, report.py known gaps)."""
from unittest.mock import MagicMock

from click.testing import CliRunner

from nettap import analyze, cli, discovery, storage
from tests.test_discovery import _fake_container
from tests.test_sidecar_iface_gone import FakeMgr

TARGET_IP = "172.18.0.2"


def _client(*containers):
    client = MagicMock()
    client.containers.list.return_value = list(containers)
    client.containers.get.side_effect = {c.id: c for c in containers}.get
    return client


def _net(ip):
    return {"app": {"IPAddress": ip}}


CONTAINERS = (
    _fake_container("t1", "real-target-name", networks=_net(TARGET_IP)),  # the netns we share
    _fake_container("d1", "db", networks=_net("172.18.0.3")),
    _fake_container("s1", "web-sidecar", networks=_net("")),             # --network container:
)


def test_other_containers_skips_target_and_ipless(monkeypatch):
    monkeypatch.setattr(discovery, "resolve_capture", lambda key: 1 / 0)  # must not be called
    found = discovery.other_containers(_client(*CONTAINERS), [TARGET_IP, "fd00::2"])
    assert [(c.name, c.ip_addresses, c.veth) for c in found] == [("db", {"app": "172.18.0.3"}, None)]


def _sidecar(tmp_path, monkeypatch, client, passes=2):
    checks = iter([True] * passes + [False])
    monkeypatch.setattr(discovery, "interface_exists", lambda iface: next(checks))
    monkeypatch.setattr(discovery, "interface_ips", lambda iface: {"eth0": TARGET_IP})
    monkeypatch.setattr(cli, "CaptureManager", FakeMgr)
    monkeypatch.setattr(cli, "_docker_client", lambda: client)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    return CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "sidecar", "--target", "web",
                                        "--no-auto-enrich", "--docker-api"])


def test_sidecar_records_peers_so_the_report_can_name_them(tmp_path, monkeypatch):
    result = _sidecar(tmp_path, monkeypatch, _client(*CONTAINERS))
    assert result.exit_code == 3  # the fake interface "disappeared" to end the loop
    conn = storage.connect(str(tmp_path / "nettap.db"))
    assert storage.known_container_names(conn) == ["db", "web"]
    storage.insert_flows(conn, [
        {"ts": 1, "container_id": "web", "container_name": "web", "src_ip": TARGET_IP,
         "dst_ip": "172.18.0.3", "src_port": 4000, "dst_port": 5432, "protocol": "TCP",
         "length": 100, "dns_query": None, "tls_sni": None, "pcap_file": "a.pcap"},
    ])
    assert [p["container"] for p in analyze.container_peers(conn, "web")] == ["db"]


def test_sidecar_keeps_capturing_when_the_docker_api_fails_later(tmp_path, monkeypatch):
    client = _client(*CONTAINERS)
    client.containers.list.side_effect = RuntimeError("socket closed")
    result = _sidecar(tmp_path, monkeypatch, client)
    assert result.exit_code == 3 and FakeMgr.last.detached  # ran its loop to the end


def test_sidecar_refuses_to_start_without_the_docker_api(tmp_path, monkeypatch):
    client = MagicMock()
    client.ping.side_effect = ConnectionError("no such file")
    FakeMgr.last = None
    result = _sidecar(tmp_path, monkeypatch, client)
    assert result.exit_code == 1 and "/var/run/docker.sock" in result.output
    assert FakeMgr.last is None


def test_sidecar_records_its_targets_published_ports(tmp_path, monkeypatch):
    result = _sidecar(tmp_path, monkeypatch, _client(*CONTAINERS))
    assert result.exit_code == 3
    conn = storage.connect(str(tmp_path / "nettap.db"))
    row = conn.execute("SELECT name, ip_addresses, published_ports FROM containers "
                       "WHERE container_id = 'web'").fetchone()
    assert row["name"] == "web"  # still the --target label, not the API's name
    assert row["ip_addresses"] == '{"eth0": "172.18.0.2"}'
    assert row["published_ports"] == \
        '[{"host_port": 8080, "container_port": 80, "protocol": "tcp"}]'


def test_sidecar_records_its_targets_start_time(tmp_path, monkeypatch):
    target = _fake_container("t1", "real-target-name", networks=_net(TARGET_IP))
    target.attrs["State"] = {"StartedAt": "2026-11-08T07:40:32.5Z"}
    result = _sidecar(tmp_path, monkeypatch, _client(target, *CONTAINERS[1:]))
    assert result.exit_code == 3
    conn = storage.connect(str(tmp_path / "nettap.db"))
    row = conn.execute("SELECT started_at FROM containers WHERE container_id = 'web'").fetchone()
    assert row["started_at"] == 1794123632.5


def test_split_by_netns_returns_the_target(monkeypatch):
    target, others = discovery.split_by_netns(_client(*CONTAINERS), [TARGET_IP])
    assert target.name == "real-target-name"
    assert [c.name for c in others] == ["db"]
