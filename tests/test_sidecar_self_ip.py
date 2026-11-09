"""Regression tests for the sidecar-mode bug where a container listed its own
IP as an "internet destination" (TODO.md, live test 2026-11-08): sidecar
saved the container with ip_addresses={}, so every reply packet into the
container counted as external traffic."""
import json

from click.testing import CliRunner

from nettap import analyze, cli, discovery, report, storage
from nettap.discovery import ContainerNetInfo

SELF = "172.17.0.2"


def _sidecar_seed(conn, ip_addresses):
    info = ContainerNetInfo("web", "web", "", "eth0", ip_addresses, [], {}, None, False)
    storage.upsert_container(conn, info)
    storage.insert_flows(conn, [
        {"ts": 0, "container_id": "web", "container_name": "web", "src_ip": SELF,
         "dst_ip": "8.8.8.8", "src_port": 4000, "dst_port": 53, "protocol": "DNS",
         "length": 80, "dns_query": "example.com", "tls_sni": None, "pcap_file": "a.pcap"},
        {"ts": 1,"container_id": "web", "container_name": "web", "src_ip": SELF,
         "dst_ip": "93.184.216.34", "src_port": 4001, "dst_port": 443, "protocol": "TLS",
         "length": 500, "dns_query": None, "tls_sni": "example.com", "pcap_file": "a.pcap"},
        # the reply - dst is the container itself, and bigger than the request
        {"ts": 2, "container_id": "web", "container_name": "web", "src_ip": "93.184.216.34",
         "dst_ip": SELF, "src_port": 443, "dst_port": 4001, "protocol": "TLS",
         "length": 9000, "dns_query": None, "tls_sni": None, "pcap_file": "a.pcap"},
    ])


def test_report_excludes_self_ip_even_without_known_ips(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _sidecar_seed(conn, {})
    data = report.build_report(conn, "web")
    assert [r["dst_ip"] for r in data["external_destinations"]] == ["93.184.216.34", "8.8.8.8"]


def test_external_excludes_registered_sidecar_ip(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _sidecar_seed(conn, {"eth0": SELF})
    assert [r["dst_ip"] for r in analyze.external_destinations(conn)] == ["93.184.216.34", "8.8.8.8"]


IP_JSON = json.dumps([{
    "ifname": "eth0",
    "addr_info": [
        {"family": "inet", "local": "172.17.0.2", "prefixlen": 16},
        {"family": "inet6", "local": "fd00::2", "prefixlen": 64},
        {"family": "inet6", "local": "fe80::42:acff:fe11:2", "prefixlen": 64},
    ],
}])


def test_interface_ips_parses_ip_json(monkeypatch):
    monkeypatch.setattr(discovery, "run", lambda cmd, **kw: IP_JSON)
    assert discovery.interface_ips("eth0") == {
        "eth0": "172.17.0.2",
        "eth0/inet6#1": "fd00::2",
        "eth0/inet6#2": "fe80::42:acff:fe11:2",
    }


def test_interface_ips_failure_returns_empty(monkeypatch):
    def boom(cmd, **kw):
        raise RuntimeError("no such device")
    monkeypatch.setattr(discovery, "run", boom)
    assert discovery.interface_ips("eth9") == {}


def test_sidecar_records_own_ips(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "run", lambda cmd, **kw: IP_JSON)
    monkeypatch.setattr(discovery, "interface_exists", lambda iface: True)
    saved = {}

    class FakeMgr:
        def __init__(self, *a, **kw): pass
        def attach(self, info):
            saved["info"] = info
            return None
        def restart_dead(self): return []
        def enforce_retention(self, **_kw): return []
        def detach_all(self): pass

    monkeypatch.setattr(cli, "CaptureManager", FakeMgr)
    # stop the loop straight away
    monkeypatch.setattr(cli.time, "sleep", lambda s: (_ for _ in ()).throw(KeyboardInterrupt))
    CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "sidecar", "--target", "web",
                                 "--no-auto-enrich"])
    assert saved["info"].ip_addresses["eth0"] == "172.17.0.2"
    conn = storage.connect(str(tmp_path / "nettap.db"))
    row = conn.execute("SELECT ip_addresses FROM containers WHERE name='web'").fetchone()
    assert json.loads(row["ip_addresses"])["eth0"] == "172.17.0.2"
