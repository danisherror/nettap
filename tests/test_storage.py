from nettap import storage
from nettap.discovery import ContainerNetInfo


def _info(container_id="c1", name="web", veth="veth1"):
    return ContainerNetInfo(
        container_id=container_id, name=name, image="nginx", veth=veth,
        ip_addresses={"bridge": "172.17.0.2"}, networks=["bridge"],
        labels={"monitor": "true"}, sandbox_key="/var/run/docker/netns/c1",
        uses_host_network=False,
    )


def test_upsert_and_query_container(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    storage.upsert_container(conn, _info())
    row = conn.execute("SELECT * FROM containers WHERE container_id='c1'").fetchone()
    assert row["name"] == "web"
    assert row["veth"] == "veth1"


def test_desired_state_roundtrip(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    storage.add_desired_ref(conn, "web")
    storage.add_desired_label(conn, "monitor", "true")
    assert storage.list_desired_refs(conn) == ["web"]
    assert storage.list_desired_labels(conn) == {"monitor": "true"}

    storage.remove_desired_ref(conn, "web")
    assert storage.list_desired_refs(conn) == []

    storage.clear_desired_state(conn)
    assert storage.list_desired_labels(conn) == {}


def test_insert_and_list_flows(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    storage.upsert_container(conn, _info())
    rows = [{
        "ts": 1.0, "container_id": "c1", "container_name": "web",
        "src_ip": "172.17.0.2", "dst_ip": "1.1.1.1", "src_port": 5555,
        "dst_port": 443, "protocol": "TLS", "length": 100,
        "dns_query": None, "tls_sni": "example.com", "pcap_file": "x.pcap",
    }]
    n = storage.insert_flows(conn, rows)
    assert n == 1
    count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    assert count == 1


def test_known_container_names(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    assert storage.known_container_names(conn) == []

    storage.upsert_container(conn, _info(container_id="c1", name="web"))
    assert storage.known_container_names(conn) == ["web"]

    # a name that only ever showed up in flows (e.g. from the batch 'enrich'
    # command, which doesn't know the real container_id) should count too
    storage.insert_flows(conn, [{
        "ts": 1.0, "container_id": "", "container_name": "orphaned",
        "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "src_port": 1, "dst_port": 2,
        "protocol": "TCP", "length": 10, "dns_query": None, "tls_sni": None,
        "pcap_file": "x.pcap",
    }])
    assert storage.known_container_names(conn) == ["orphaned", "web"]


def test_live_sessions_roundtrip(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    info = _info()
    storage.set_live_session(conn, info, "web_%Y%m%d%H%M%S.pcap", 1234)
    sessions = storage.list_live_sessions(conn)
    assert len(sessions) == 1
    assert sessions[0]["container_name"] == "web"

    storage.clear_live_session(conn, "c1")
    assert storage.list_live_sessions(conn) == []
