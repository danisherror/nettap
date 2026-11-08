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
    assert matrix == [{"src_container": "web", "dst_container": "db", "bytes": 500, "packets": 1,
         "via": "direct"}]


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


def test_top_talkers_labels_non_ip_rows(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    storage.insert_flows(conn, [
        {"ts": 4, "container_id": "c1", "container_name": "web", "src_ip": None,
         "dst_ip": None, "src_port": None, "dst_port": None, "protocol": "ARP",
         "length": 42, "dns_query": None, "tls_sni": None, "pcap_file": "a.pcap"},
    ])
    rows = {(r["src_ip"], r["dst_ip"]): r for r in analyze.top_talkers(conn)}

    assert rows[(None, None)]["note"] == analyze.NON_IP_NOTE
    assert rows[(None, None)]["protocols"] == "ARP"
    assert "note" not in rows[("172.17.0.2", "93.184.216.34")]
    assert rows[("172.17.0.2", "93.184.216.34")]["protocols"] == "TLS"


def test_container_queries_count_a_container_with_two_rows_once(tmp_path):
    # live test 2026-11-08: a sidecar stores its target under the target's
    # name, and another sidecar's --docker-api stores it under its real ID
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    storage.upsert_container(conn, ContainerNetInfo(
        "db", "db", "", "eth0", {"eth0": "172.17.0.3"}, [], {}, None, False))
    assert analyze.container_matrix(conn) == [
        {"src_container": "web", "dst_container": "db", "bytes": 500, "packets": 1,
         "via": "direct"}]
    assert analyze.container_peers(conn, "web") == [
        {"container": "db", "bytes": 500, "packets": 1, "sent_bytes": 500, "received_bytes": 0}]


def _flow(container, src, sport, dst, dport, length):
    return {"ts": 1, "container_id": container, "container_name": container, "src_ip": src,
            "dst_ip": dst, "src_port": sport, "dst_port": dport, "protocol": "TCP",
            "length": length, "dns_query": None, "tls_sni": None, "pcap_file": "p.pcap"}


def _seed_published(conn):
    # shapes from a live test on Docker Desktop for Mac (2026-11-08): cli asks
    # host.docker.internal:18080, srv sees the request come from a proxy
    pub = [{"host_port": 18080, "container_port": 80, "protocol": "tcp"}]
    storage.upsert_container(conn, ContainerNetInfo(
        "s1", "srv", "", None, {"a": "172.20.0.2"}, [], {}, None, False, pub))
    storage.upsert_container(conn, ContainerNetInfo(
        "c1", "cli", "", None, {"b": "172.21.0.2"}, [], {}, None, False))
    storage.insert_flows(conn, [
        _flow("cli", "172.21.0.2", 36762, "192.168.65.254", 18080, 300),
        _flow("cli", "192.168.65.254", 18080, "172.21.0.2", 36762, 900),
        _flow("srv", "192.168.65.1", 53143, "172.20.0.2", 80, 300),
        _flow("srv", "172.20.0.2", 80, "192.168.65.1", 53143, 900),
        # not the published port, or not a local address: not srv's
        _flow("cli", "172.21.0.2", 36763, "192.168.65.254", 18081, 50),
        _flow("cli", "172.21.0.2", 36764, "93.184.216.34", 18080, 70),
    ])


def test_container_matrix_counts_traffic_through_a_published_port(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed_published(conn)
    assert analyze.container_matrix(conn) == [
        {"src_container": "cli", "dst_container": "srv", "bytes": 300, "packets": 1,
         "via": "published port"}]
    assert analyze.container_peers(conn, "cli") == [
        {"container": "srv", "bytes": 1200, "packets": 2, "sent_bytes": 300, "received_bytes": 900}]
    assert analyze.container_peers(conn, "srv") == []  # the proxy hides the client


def test_a_port_published_by_two_containers_is_not_attributed(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed_published(conn)
    storage.upsert_container(conn, ContainerNetInfo(
        "s2", "srv2", "", None, {"a": "172.20.0.3"}, [], {}, None, False,
        [{"host_port": 18080, "container_port": 80, "protocol": "tcp"}]))
    assert analyze.container_matrix(conn) == []


def test_published_port_traffic_is_not_also_a_local_destination(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed_published(conn)
    ext = {r["dst_ip"]: r for r in analyze.external_destinations(conn, container="cli")}
    # only the 50 B to a port nobody publishes is left on the host address
    assert ext["192.168.65.254"]["bytes"] == 50
    assert ext["192.168.65.254"]["packets"] == 1
    assert ext["93.184.216.34"]["bytes"] == 70
    # srv's side can't be matched, so the proxy stays a local destination
    assert analyze.external_destinations(conn, container="srv")[0]["dst_ip"] == "192.168.65.1"


def test_external_destinations_drops_a_host_address_used_only_for_published_ports(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    pub = [{"host_port": 18080, "container_port": 80, "protocol": "tcp"}]
    storage.upsert_container(conn, ContainerNetInfo(
        "s1", "srv", "", None, {"a": "172.20.0.2"}, [], {}, None, False, pub))
    storage.insert_flows(conn, [_flow("cli", "172.21.0.2", 36762, "192.168.65.254", 18080, 300)])
    assert analyze.external_destinations(conn) == []


def test_external_destinations_counts_one_containers_bytes(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    storage.insert_flows(conn, [
        _flow("a", "172.17.0.2", 4000, "93.184.216.34", 443, 100),
        _flow("b", "172.17.0.3", 4000, "93.184.216.34", 443, 900),
    ])
    (both,) = analyze.external_destinations(conn)
    assert (both["bytes"], both["packets"], both["containers"]) == (1000, 2, "a,b")
    (only_a,) = analyze.external_destinations(conn, container="a")
    assert (only_a["bytes"], only_a["packets"], only_a["containers"]) == (100, 1, "a")


def test_a_port_two_names_of_one_container_claim_is_attributed(tmp_path):
    # srv's own sidecar labels it "srv"; cli's --docker-api stores the real name
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed_published(conn)
    storage.upsert_container(conn, ContainerNetInfo(
        "s1-real", "proj-srv-1", "", None, {"a": "172.20.0.2"}, [], {}, None, False,
        [{"host_port": 18080, "container_port": 80, "protocol": "tcp"}]))
    assert analyze.container_matrix(conn) == [
        {"src_container": "cli", "dst_container": "srv", "bytes": 300, "packets": 1,
         "via": "published port"}]
    # srv's replies to itself aren't traffic to "proj-srv-1"
    assert analyze.container_peers(conn, "srv") == []


def _proto_flow(transport, dport, length):
    return {**_flow("cli", "172.21.0.2", 40000, "192.168.65.254", dport, length),
            "transport": transport}


def test_published_port_match_checks_the_transport(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    storage.upsert_container(conn, ContainerNetInfo(
        "s1", "srv", "", None, {"a": "172.20.0.2"}, [], {}, None, False,
        [{"host_port": 5353, "container_port": 53, "protocol": "udp"}]))
    storage.upsert_container(conn, ContainerNetInfo(
        "c1", "cli", "", None, {"b": "172.21.0.2"}, [], {}, None, False))
    storage.insert_flows(conn, [
        _proto_flow("udp", 5353, 100),   # srv's
        _proto_flow("tcp", 5353, 200),   # nothing publishes 5353/tcp
        _proto_flow("icmp", 5353, 300),  # ICMP error quoting a header - not srv's
        _proto_flow(None, 5353, 400),    # stored before flows.transport: port only
    ])
    assert analyze.container_matrix(conn) == [
        {"src_container": "cli", "dst_container": "srv", "bytes": 500, "packets": 2,
         "via": "published port"}]


def test_one_port_two_protocols_two_owners(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    for cid, name, ip, proto in (("s1", "dns", "172.20.0.2", "udp"),
                                 ("s2", "web", "172.20.0.3", "tcp")):
        storage.upsert_container(conn, ContainerNetInfo(
            cid, name, "", None, {"a": ip}, [], {}, None, False,
            [{"host_port": 8053, "container_port": 53, "protocol": proto}]))
    storage.insert_flows(conn, [_proto_flow("udp", 8053, 100), _proto_flow("tcp", 8053, 200),
                                _proto_flow(None, 8053, 400)])  # can't tell: left out
    assert sorted((r["dst_container"], r["bytes"]) for r in analyze.container_matrix(conn)) == [
        ("dns", 100), ("web", 200)]
