from nettap import report, storage
from nettap.discovery import ContainerNetInfo


def _seed(conn):
    web = ContainerNetInfo("c1", "web", "nginx", "veth1", {"bridge": "172.18.0.2"}, ["bridge"], {}, "sb1", False)
    db = ContainerNetInfo("c2", "db", "postgres", "veth2", {"bridge": "172.18.0.3"}, ["bridge"], {}, "sb2", False)
    storage.upsert_container(conn, web)
    storage.upsert_container(conn, db)
    storage.insert_flows(conn, [
        # web -> db (container-to-container)
        {"ts": 1000, "container_id": "c1", "container_name": "web", "src_ip": "172.18.0.2",
         "dst_ip": "172.18.0.3", "src_port": 4000, "dst_port": 5432, "protocol": "TCP",
         "length": 500, "dns_query": None, "tls_sni": None, "pcap_file": "a.pcap"},
        # db -> web (reverse direction, same pair)
        {"ts": 1001, "container_id": "c1", "container_name": "web", "src_ip": "172.18.0.3",
         "dst_ip": "172.18.0.2", "src_port": 5432, "dst_port": 4000, "protocol": "TCP",
         "length": 300, "dns_query": None, "tls_sni": None, "pcap_file": "a.pcap"},
        # web -> internet (TLS, with SNI)
        {"ts": 1002, "container_id": "c1", "container_name": "web", "src_ip": "172.18.0.2",
         "dst_ip": "93.184.216.34", "src_port": 4001, "dst_port": 443, "protocol": "TLS",
         "length": 12000, "dns_query": None, "tls_sni": "example.com", "pcap_file": "a.pcap"},
        # web -> internet DNS lookup
        {"ts": 1003, "container_id": "c1", "container_name": "web", "src_ip": "172.18.0.2",
         "dst_ip": "8.8.8.8", "src_port": 4002, "dst_port": 53, "protocol": "DNS",
         "length": 80, "dns_query": "example.com", "tls_sni": None, "pcap_file": "a.pcap"},
    ])


def test_self_ip_heuristic(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    assert report._self_ip(conn, "web") == "172.18.0.2"


def test_build_report_shape(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    data = report.build_report(conn, "web")
    assert data["packet_count"] == 4
    assert data["self_ip"] == "172.18.0.2"
    assert data["sent_bytes"] == 500 + 12000 + 80   # rows where src_ip == self
    assert data["received_bytes"] == 300             # rows where dst_ip == self
    assert data["container_peers"] == [{"container": "db", "bytes": 800, "packets": 2,
                                        "sent_bytes": 500, "received_bytes": 300}]
    assert len(data["external_destinations"]) == 2
    hostnames = {r["dst_ip"]: r.get("hostname") for r in data["external_destinations"]}
    assert hostnames["93.184.216.34"] == "example.com"
    assert hostnames["8.8.8.8"] is None
    assert data["dns_queries"][0]["dns_query"] == "example.com"


def test_render_text_contains_key_facts(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    text = report.render_text(report.build_report(conn, "web"))
    assert "web" in text
    assert "example.com" in text
    assert "db" in text
    assert "DNS" not in text or "Domain names" in text  # section header present if DNS rows exist


def test_render_text_empty_report():
    empty = {
        "container": "ghost", "self_ip": None, "packet_count": 0, "total_bytes": 0,
        "start": None, "end": None, "sent_bytes": 0, "sent_packets": 0,
        "received_bytes": 0, "received_packets": 0, "container_peers": [],
        "external_destinations": [], "dns_queries": [], "protocols": [],
    }
    text = report.render_text(empty)
    assert "No traffic has been analyzed" in text


def test_render_html_is_well_formed(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    out = report.render_html(report.build_report(conn, "web"))
    assert out.startswith("<!doctype html>")
    assert "example.com" in out
    assert "<script" not in out  # stays static, no JS needed
    assert out.count("<html>") == 1 and "</html>" in out


def test_format_bytes():
    assert report.format_bytes(0) == "0 B"
    assert report.format_bytes(500) == "500 B"
    assert report.format_bytes(2048) == "2.0 KB"
    assert report.format_bytes(5 * 1024 * 1024) == "5.0 MB"


def _flow(src, dst, proto="ICMPv6", length=100):
    return {"ts": 1, "container_id": "c1", "container_name": "v6", "src_ip": src,
            "dst_ip": dst, "src_port": None, "dst_port": None, "protocol": proto,
            "length": length, "dns_query": None, "tls_sni": None, "pcap_file": "a.pcap"}


# IPv6 neighbour-discovery chatter to multicast outnumbers the container's
# own traffic (seen live 2026-11-08: the report named ff02::16 as the container)
V6_FLOWS = [_flow("::", "ff02::16")] * 5 + [_flow("fe80::1", "ff02::2")] * 4 + [
    _flow("172.20.0.3", "172.20.0.2", "ICMP", 98),
    _flow("172.20.0.2", "172.20.0.3", "ICMP", 98),
    _flow("fd00::3", "fd00::2", "ICMPv6", 118),
    _flow("fd00::2", "fd00::3", "ICMPv6", 118),
]


def test_report_uses_recorded_ips_across_ipv4_and_ipv6(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    info = ContainerNetInfo("c1", "v6", "alpine", None,
                            {"eth0": "172.20.0.3", "eth0/inet6#1": "fd00::3"}, [], {}, None, False)
    storage.upsert_container(conn, info)
    storage.insert_flows(conn, V6_FLOWS)
    data = report.build_report(conn, "v6")

    assert set(data["self_ips"]) == {"172.20.0.3", "fd00::3"}
    assert data["sent_bytes"] == 98 + 118
    assert data["received_bytes"] == 98 + 118
    assert "172.20.0.3" in report.render_text(data) and "fd00::3" in report.render_text(data)


def test_self_ip_guess_skips_multicast_and_unspecified(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    storage.insert_flows(conn, V6_FLOWS)   # no containers row: falls back to the guess
    assert report._self_ip(conn, "v6") == "fe80::1"


def test_peer_captured_too_is_listed_once(tmp_path):
    # db's own capture (db -> web) must not add a second row to web's report
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    storage.insert_flows(conn, [
        {"ts": 1001, "container_id": "c2", "container_name": "db", "src_ip": "172.18.0.3",
         "dst_ip": "172.18.0.2", "src_port": 5432, "dst_port": 4000, "protocol": "TCP",
         "length": 300, "dns_query": None, "tls_sni": None, "pcap_file": "b.pcap"},
    ])
    data = report.build_report(conn, "web")
    assert [(r["container"], r["bytes"]) for r in data["container_peers"]] == [("db", 800)]
    text = report.render_text(data)
    assert text.count("  - db:") == 1 and "sent 500 B, received 300 B" in text
    assert report.build_report(conn, "db")["container_peers"][0]["container"] == "web"
