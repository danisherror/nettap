"""analyze.hostnames(): naming destination IPs from TLS SNI, HTTP Host and
DNS answers, and the flows-table upgrade that adds the columns it needs."""
import json
import sqlite3

from nettap import analyze, report, storage
from nettap.discovery import ContainerNetInfo

SELF = "172.17.0.2"


def _flow(dst, container="web", **kw):
    row = {"ts": 0, "container_id": container, "container_name": container,
           "src_ip": SELF, "dst_ip": dst, "src_port": 40000, "dst_port": 443,
           "protocol": "TCP", "length": 100, "dns_query": None, "tls_sni": None,
           "pcap_file": "a.pcap"}
    row.update(kw)
    return row


def _dns(name, answers, container="web"):
    return _flow(SELF, container, src_ip="192.168.65.7", protocol="DNS",
                 dns_query=name, dns_answers=json.dumps(answers))


def _conn(tmp_path, rows):
    conn = storage.connect(str(tmp_path / "n.db"))
    storage.insert_flows(conn, rows)
    return conn


def test_each_source_names_an_ip(tmp_path):
    conn = _conn(tmp_path, [
        _flow("1.1.1.1", tls_sni="one.example"),
        _flow("2.2.2.2", protocol="HTTP", http_host="two.example:8080"),
        _dns("three.example.", ["3.3.3.3", "2606:4700::3"]),
    ])
    assert analyze.hostnames(conn) == {
        "1.1.1.1": {"hostname": "one.example", "source": "tls-sni"},
        "2.2.2.2": {"hostname": "two.example", "source": "http-host"},
        "3.3.3.3": {"hostname": "three.example", "source": "dns"},
        "2606:4700::3": {"hostname": "three.example", "source": "dns"},
    }


def test_sni_beats_http_beats_dns(tmp_path):
    conn = _conn(tmp_path, [
        _dns("cdn-alias.example", ["1.1.1.1", "2.2.2.2"]),
        _flow("1.1.1.1", tls_sni="real.example"),
        _flow("1.1.1.1", http_host="http.example"),
        _flow("2.2.2.2", http_host="http.example"),
    ])
    names = analyze.hostnames(conn)
    assert names["1.1.1.1"]["hostname"] == "real.example"
    assert names["2.2.2.2"]["hostname"] == "http.example"


def test_most_frequent_name_wins_within_a_source(tmp_path):
    conn = _conn(tmp_path, [_dns("rare.example", ["1.1.1.1"])]
                 + [_dns("common.example", ["1.1.1.1"])] * 3)
    assert analyze.hostnames(conn)["1.1.1.1"]["hostname"] == "common.example"


def test_ip_literal_host_headers_are_ignored(tmp_path):
    conn = _conn(tmp_path, [
        _flow("1.1.1.1", http_host="1.1.1.1:80"),
        _flow("2.2.2.2", http_host="[2606:4700::1]:80"),
    ])
    assert analyze.hostnames(conn) == {}


def test_scoped_to_one_container(tmp_path):
    conn = _conn(tmp_path, [_dns("other.example", ["1.1.1.1"], container="db")])
    assert analyze.hostnames(conn, "web") == {}
    assert analyze.hostnames(conn, "db")["1.1.1.1"]["hostname"] == "other.example"


def test_external_and_report_use_dns_names(tmp_path):
    conn = _conn(tmp_path, [_dns("example.com", ["93.184.216.34"]),
                            _flow("93.184.216.34", protocol="HTTP", dst_port=80)])
    storage.upsert_container(conn, ContainerNetInfo(
        "web", "web", "", "eth0", {"eth0": SELF}, [], {}, None, False))
    ext = {r["dst_ip"]: r for r in analyze.external_destinations(conn)}
    assert ext["93.184.216.34"]["hostname"] == "example.com"
    assert ext["93.184.216.34"]["hostname_source"] == "dns"
    data = report.build_report(conn, "web")
    assert data["external_destinations"][0]["hostname"] == "example.com"
    assert "example.com (93.184.216.34)" in report.render_text(data)


def test_old_database_gets_new_columns(tmp_path):
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.execute("""CREATE TABLE flows (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL,
        container_id TEXT, container_name TEXT, src_ip TEXT, dst_ip TEXT,
        src_port INTEGER, dst_port INTEGER, protocol TEXT, length INTEGER,
        dns_query TEXT, tls_sni TEXT, pcap_file TEXT)""")
    old.execute("INSERT INTO flows (dst_ip, tls_sni) VALUES ('1.1.1.1', 'old.example')")
    old.commit()
    old.close()

    conn = storage.connect(path)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(flows)")}
    assert {"dns_answers", "http_host"} <= cols
    storage.insert_flows(conn, [_dns("new.example", ["2.2.2.2"])])
    assert set(analyze.hostnames(conn)) == {"1.1.1.1", "2.2.2.2"}
    storage.connect(path)  # second upgrade pass is a no-op
