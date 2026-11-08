"""sidecar --attribute-by-port: sample a --network host target's sockets and
keep only its own traffic from a capture of the whole host (TODO.md P1)."""
import os

from click.testing import CliRunner

from nettap import cli, discovery, hostports, storage
from nettap.discovery import ContainerNetInfo
from tests.test_sidecar_iface_gone import FakeMgr

ME = 50  # the sidecar's own pid in the fake /proc

# /proc/net/tcp format; inode is the 10th field
TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1
   1: 0300A8C0:A1B2 22B8D85D:01BB 01 00000000:00000000 00:00000000 00000000   101        0 1002 1
   2: 0300A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1
"""
UDP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1003 2
"""


def _proc(tmp_path):
    """Target processes 1 (nginx master) and 7 (worker); the sidecar (50)
    and its tcpdump child (51), whose socket (inode 2001, port 8080) must not
    count as the target's."""
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    (proc / "net" / "tcp").write_text(TCP)
    (proc / "net" / "udp6").write_text(UDP6)
    for pid, ppid, inodes in ((1, 0, ["1001", "1003"]), (7, 1, ["1002"]),
                              (ME, 0, []), (51, ME, ["2001"])):
        (proc / str(pid) / "fd").mkdir(parents=True)
        (proc / str(pid) / "stat").write_text(f"{pid} (some (odd) name) S {ppid} 1 1 0\n")
        os.symlink("/dev/null", proc / str(pid) / "fd" / "0")
        for n, inode in enumerate(inodes, start=3):
            os.symlink(f"socket:[{inode}]", proc / str(pid) / "fd" / str(n))
    return str(proc)


def test_owned_ports_reads_the_targets_sockets_only(tmp_path):
    proc = _proc(tmp_path)
    pids, denied = hostports.target_processes(proc, me=ME)
    assert (sorted(pids), denied) == ([1, 7], [])
    assert hostports.owned_ports(proc, me=ME) == {("tcp", 80), ("tcp", 0xA1B2), ("udp", 5353)}


def test_target_processes_reports_unreadable_ones(tmp_path):
    proc = _proc(tmp_path)
    os.chmod(f"{proc}/7/fd", 0)
    try:
        if os.geteuid() == 0:
            return  # root reads it anyway
        pids, denied = hostports.target_processes(proc, me=ME)
        assert sorted(pids) == [1, 7] and denied == [7]
    finally:
        os.chmod(f"{proc}/7/fd", 0o755)


def _db(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    storage.upsert_container(conn, ContainerNetInfo(
        "web", "web", "", "eth0", {"eth0": "192.168.65.3"}, [], {}, None, False,
        capture_scope="ports"))
    return conn


def test_record_extends_or_starts_intervals(tmp_path):
    conn = _db(tmp_path)
    for now in (100.0, 100.25, 101.0):
        hostports.record(conn, "web", {("tcp", 80)}, now)
    hostports.record(conn, "web", {("tcp", 80)}, 110.0)  # gap > GAP_SECONDS
    assert [tuple(r) for r in conn.execute(
        "SELECT first_seen, last_seen FROM owned_ports ORDER BY first_seen")] == \
        [(100.0, 101.0), (110.0, 110.0)]


def _row(src, sport, dst, dport, ts, transport="tcp"):
    return {"ts": ts, "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
            "transport": transport}


def test_keep_owned_keeps_only_the_targets_host_side_ports(tmp_path):
    conn = _db(tmp_path)
    hostports.record(conn, "web", {("tcp", 80)}, 100.0)
    hostports.record(conn, "web", {("tcp", 80)}, 101.0)
    host, peer = "192.168.65.3", "10.0.0.9"
    keep = [_row(peer, 5000, host, 80, 100.5),           # request to the target
            _row(host, 80, peer, 5000, 102.5)]           # reply, within the slack
    drop = [_row(host, 40000, "93.184.216.34", 80, 100.5),  # another container's NAT: remote :80
            _row(peer, 5000, host, 80, 150.0),           # port 80 not the target's by then
            _row(peer, 5000, host, 80, 100.5, "udp"),    # wrong transport
            _row(peer, 5000, "10.0.0.8", 80, 100.5),     # not a host address
            {**_row(None, None, None, None, 100.5), "transport": None}]  # ARP
    assert hostports.keep_owned(conn, "web", keep + drop) == keep


def _sidecar(tmp_path, monkeypatch, pids, denied, *extra):
    monkeypatch.setattr(discovery, "bridge_interfaces", lambda sys_net=None: ["docker0"])
    monkeypatch.setattr(hostports, "target_processes", lambda *a, **kw: (pids, denied))
    monkeypatch.setattr(hostports, "owned_ports", lambda *a, **kw: {("tcp", 80)})
    checks = iter([True, True, False])
    monkeypatch.setattr(discovery, "interface_exists", lambda iface: next(checks))
    monkeypatch.setattr(discovery, "run", lambda cmd, **kw: "[]")
    monkeypatch.setattr(cli, "CaptureManager", FakeMgr)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    FakeMgr.last = None
    return CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "sidecar", "--target",
                                        "web", "--no-auto-enrich", "--attribute-by-port", *extra])


def test_sidecar_attribute_by_port_needs_the_targets_pid_namespace(tmp_path, monkeypatch):
    result = _sidecar(tmp_path, monkeypatch, [], [])
    assert result.exit_code == 1 and "--pid container:<target>" in result.output
    assert FakeMgr.last is None


def test_sidecar_attribute_by_port_needs_sys_ptrace_for_other_users(tmp_path, monkeypatch):
    result = _sidecar(tmp_path, monkeypatch, [1, 7], [7])
    assert result.exit_code == 1 and "SYS_PTRACE" in result.output


def test_sidecar_attribute_by_port_marks_the_capture(tmp_path, monkeypatch):
    # time.sleep is stubbed out, so the real sampler would spin and hold the DB
    sampled = []
    monkeypatch.setattr(cli, "_sample_ports", lambda db, name, stop: sampled.append(name))
    result = _sidecar(tmp_path, monkeypatch, [1, 7], [])
    assert result.exit_code == 3, result.output  # ran its loop despite the bridges
    conn = storage.connect(str(tmp_path / "nettap.db"))
    assert storage.port_scoped(conn, "web")
    assert sampled == ["web"]


def test_sample_ports_records_until_stopped(tmp_path, monkeypatch):
    db = str(tmp_path / "n.db")
    stop = {"flag": False}
    calls = iter([{("tcp", 80)}, {("tcp", 80), ("udp", 53)}])

    def owned(*a, **kw):
        ports = next(calls, None)
        if ports is None:
            stop["flag"] = True
            return set()
        return ports
    monkeypatch.setattr(hostports, "owned_ports", owned)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    cli._sample_ports(db, "web", stop)
    conn = storage.connect(db)
    assert sorted(tuple(r) for r in conn.execute(
        "SELECT transport, port FROM owned_ports")) == [("tcp", 80), ("udp", 53)]


def test_report_explains_a_port_scoped_capture(tmp_path):
    from nettap import report
    conn = _db(tmp_path)
    flow = {"ts": 1, "container_id": "", "src_ip": "192.168.65.3", "dst_ip": "93.184.216.34",
            "src_port": 40000, "dst_port": 80, "protocol": "TCP", "length": 60,
            "dns_query": None, "tls_sni": None, "pcap_file": "p.pcap", "transport": "tcp"}
    storage.insert_flows(conn, [{**flow, "container_name": "web"},
                                {**flow, "container_name": "db", "src_ip": "172.17.0.3"}])
    data = report.build_report(conn, "web")
    assert data["port_scoped"]
    assert "--network host" in report.render_text(data)
    assert "--network host" in report.render_html(data)
    storage.upsert_container(conn, ContainerNetInfo(
        "db", "db", "", "eth0", {"eth0": "172.17.0.3"}, [], {}, None, False))
    assert "--network host" not in report.render_text(report.build_report(conn, "db"))
