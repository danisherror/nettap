from nettap import analyze, storage
from nettap.discovery import ContainerNetInfo


def _seed(conn):
    web = ContainerNetInfo("c1", "web", "nginx", "veth1", {"bridge": "172.17.0.2"}, ["bridge"], {}, "sb1", False)
    db = ContainerNetInfo("c2", "db", "postgres", "veth2", {"bridge": "172.17.0.3"}, ["bridge"], {}, "sb2", False)
    storage.upsert_container(conn, web)
    storage.upsert_container(conn, db)
    storage.insert_flows(conn, [
        {"ts": 1, "container_id": "c1", "container_name": "web", "src_ip": "172.17.0.2",
         "dst_ip": "172.17.0.3", "src_port": 4000, "dst_port": 5432, "protocol": "TCP",
         "length": 500, "dns_query": None, "tls_sni": None, "pcap_file": "a.pcap"},
        {"ts": 2, "container_id": "c1", "container_name": "web", "src_ip": "172.17.0.2",
         "dst_ip": "93.184.216.34", "src_port": 4001, "dst_port": 443, "protocol": "TLS",
         "length": 1200, "dns_query": None, "tls_sni": "example.com", "pcap_file": "a.pcap"},
        {"ts": 3, "container_id": "c1", "container_name": "web", "src_ip": "172.17.0.2",
         "dst_ip": "8.8.8.8", "src_port": 4002, "dst_port": 53, "protocol": "DNS",
         "length": 80, "dns_query": "example.com", "tls_sni": None, "pcap_file": "a.pcap"},
    ])


def test_top_talkers(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    talkers = analyze.top_talkers(conn, limit=5)
    assert talkers[0]["bytes"] == 1200  # the example.com flow is the biggest


def test_container_matrix(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    matrix = analyze.container_matrix(conn)
    assert matrix == [{"src_container": "web", "dst_container": "db", "bytes": 500, "packets": 1}]


def test_external_destinations(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    ext = analyze.external_destinations(conn)
    dsts = {row["dst_ip"] for row in ext}
    assert dsts == {"93.184.216.34", "8.8.8.8"}


def test_dns_queries(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    dns = analyze.dns_queries(conn)
    assert dns[0]["dns_query"] == "example.com"


def test_protocol_breakdown(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    protos = {row["protocol"] for row in analyze.protocol_breakdown(conn)}
    assert protos == {"TCP", "TLS", "DNS"}
