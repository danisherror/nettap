"""Destinations that aren't another container are split into "internet" and
"local" (private/RFC1918, link-local, multicast, broadcast) - Docker
Desktop's internal DNS resolver (192.168.65.7) used to be reported as an
internet destination (TODO.md, live test 2026-11-08)."""
import pytest

from nettap import analyze, report, storage
from nettap.discovery import ContainerNetInfo

SELF = "172.17.0.2"


@pytest.mark.parametrize("ip,scope", [
    ("8.8.8.8", "internet"),
    ("2606:4700::1", "internet"),
    ("192.168.65.7", "local"),
    ("10.0.0.5", "local"),
    ("fe80::1", "local"),
    ("fd00::2", "local"),
    ("ff02::1", "local"),        # multicast: is_global is True in Python, still not internet
    ("224.0.0.251", "local"),
    ("255.255.255.255", "local"),
    ("100.64.1.1", "local"),     # carrier-grade NAT
    ("not-an-ip", "local"),
])
def test_ip_scope(ip, scope):
    assert analyze.ip_scope(ip) == scope


def test_docker_desktop_hint():
    assert "Docker Desktop" in analyze.local_hint("192.168.65.7")
    assert analyze.local_hint("10.0.0.5") is None


def _seed(conn):
    storage.upsert_container(conn, ContainerNetInfo(
        "web", "web", "", "eth0", {"eth0": SELF}, [], {}, None, False))
    row = dict(container_id="web", container_name="web", src_ip=SELF, src_port=4000,
               protocol="DNS", dns_query=None, tls_sni=None, pcap_file="a.pcap")
    storage.insert_flows(conn, [
        {**row, "ts": 1, "dst_ip": "192.168.65.7", "dst_port": 53, "length": 80},
        {**row, "ts": 2, "dst_ip": "93.184.216.34", "dst_port": 443, "length": 900,
         "protocol": "TLS"},
    ])


def test_external_destinations_labels_scope(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    scopes = {r["dst_ip"]: r["scope"] for r in analyze.external_destinations(conn)}
    assert scopes == {"93.184.216.34": "internet", "192.168.65.7": "local"}


def test_report_separates_local_from_internet(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    data = report.build_report(conn, "web")
    assert [r["dst_ip"] for r in data["external_destinations"]] == ["93.184.216.34"]
    assert [r["dst_ip"] for r in data["local_destinations"]] == ["192.168.65.7"]

    text = report.render_text(data)
    internet_part, local_part = text.split("Local / private network addresses")
    assert "192.168.65.7" not in internet_part
    assert "192.168.65.7" in local_part and "Docker Desktop" in local_part

    html = report.render_html(data)
    assert "Local / private network addresses" in html and "Docker Desktop" in html


def test_cli_external_scope_filter(tmp_path):
    import json
    from click.testing import CliRunner
    from nettap import cli

    _seed(storage.connect(str(tmp_path / "nettap.db")))
    run = lambda *a: json.loads(CliRunner().invoke(
        cli.cli, ["--data-dir", str(tmp_path), "analyze", "external", *a]).output)
    assert [r["dst_ip"] for r in run("--scope", "internet")] == ["93.184.216.34"]
    assert [r["dst_ip"] for r in run("--scope", "local")] == ["192.168.65.7"]
    assert len(run()) == 2
