"""Regression test for a real bug: _enrich_loop's background thread used to
share the *same* sqlite3.Connection object the main thread created. sqlite3
connections are only usable from the thread that created them by default
(check_same_thread=True), so that thread died on its first real insert with
a silent sqlite3.ProgrammingError - nothing in the app noticed, it just
stopped enriching forever, and only a manually-run `nettap enrich` (its own
fresh process/connection) ever actually worked. Fixed by having the loop
open its own connection from a db_path. This test drives the real threaded
loop end-to-end against a temp DB file to prove that works."""
from __future__ import annotations

import threading
import time
from unittest.mock import patch

from nettap import storage
from nettap.cli import _enrich_loop


# a file tcpdump opened just now is still being written
NOW = time.strftime("%Y%m%d%H%M%S")


class _FakeMgr:
    """Duck-types CaptureManager.status() enough for _enrich_loop's needs."""

    def __init__(self, pattern):
        self._pattern = pattern

    def status(self):
        return [{
            "container": "web", "container_id": "c1",
            "veth": "veth1", "pcap_pattern": self._pattern,
            "alive": True, "started_at": time.time(), "rotate_seconds": 60,
        }]


@patch("nettap.cli.parse_pcap")
def test_enrich_loop_uses_its_own_connection(mock_parse_pcap, tmp_path):
    mock_parse_pcap.return_value = [{
        "ts": 1.0, "container_id": "c1", "container_name": "web",
        "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "src_port": 1, "dst_port": 2,
        "protocol": "TCP", "length": 10, "dns_query": None, "tls_sni": None,
        "pcap_file": "web_1.pcap",
    }]

    db_path = str(tmp_path / "nettap.db")
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    # two files present so finished[:-1] leaves exactly one "already rotated
    # past" file for the loop to enrich
    (pcap_dir / "web_20261108000001.pcap").write_bytes(b"\x00")
    (pcap_dir / f"web_{NOW}.pcap").write_bytes(b"\x00")
    pattern = str(pcap_dir / "web_%Y%m%d%H%M%S.pcap")

    stop = {"flag": False}
    t = threading.Thread(
        target=_enrich_loop, args=(_FakeMgr(pattern), db_path, 0.05, stop), daemon=True
    )
    t.start()
    try:
        deadline = time.time() + 2
        rows = []
        while time.time() < deadline:
            conn = storage.connect(db_path)
            rows = conn.execute("SELECT * FROM flows").fetchall()
            conn.close()
            if rows:
                break
            time.sleep(0.05)
        assert len(rows) == 1, "enrich thread never wrote a row - the cross-thread sqlite3 bug is back"
        assert rows[0]["dst_ip"] == "5.6.7.8"
        assert t.is_alive(), "enrich thread died instead of looping - check for an uncaught exception"
    finally:
        stop["flag"] = True
        t.join(timeout=2)


@patch("nettap.cli.parse_pcap", return_value=[])
def test_enrich_loop_also_reads_the_dns_capture(mock_parse_pcap, tmp_path):
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    for name in ["web_20261108000001.pcap", f"web_{NOW}.pcap",
                 "web_20261108000001.dns.pcap", f"web_{NOW}.dns.pcap"]:
        (pcap_dir / name).write_bytes(b"\x00")

    class Mgr(_FakeMgr):
        def status(self):
            rows = super().status()
            rows[0]["dns_pcap_pattern"] = str(pcap_dir / "web_%Y%m%d%H%M%S.dns.pcap")
            return rows

    stop = {"flag": False}
    t = threading.Thread(target=_enrich_loop, daemon=True, args=(
        Mgr(str(pcap_dir / "web_%Y%m%d%H%M%S.pcap")), str(tmp_path / "n.db"), 0.05, stop))
    t.start()
    try:
        deadline = time.time() + 2
        while mock_parse_pcap.call_count < 2 and time.time() < deadline:
            time.sleep(0.05)
    finally:
        stop["flag"] = True
        t.join(timeout=2)
    # each capture's newest file is still being written, so it's skipped
    assert sorted(c.args[0].rsplit("/", 1)[1] for c in mock_parse_pcap.call_args_list) == [
        "web_20261108000001.dns.pcap", "web_20261108000001.pcap"]


def test_enrich_command_names_dns_pcaps_after_their_container(tmp_path):
    from click.testing import CliRunner
    from nettap import cli

    (tmp_path / "pcap").mkdir()
    for name in ["my_app_20261108000001.pcap", "my_app_20261108000001.dns.pcap"]:
        (tmp_path / "pcap" / name).write_bytes(b"\x00")
    with patch("nettap.cli.parse_pcap", return_value=[]) as parse:
        result = CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "enrich"])
    assert result.exit_code == 0, result.output
    assert [c.kwargs["container_name"] for c in parse.call_args_list] == ["my_app", "my_app"]


def _run_loop(mgr, db_path, until, timeout=2):
    stop = {"flag": False}
    t = threading.Thread(target=_enrich_loop, args=(mgr, db_path, 0.05, stop), daemon=True)
    t.start()
    try:
        deadline = time.time() + timeout
        while not until() and time.time() < deadline:
            time.sleep(0.05)
    finally:
        stop["flag"] = True
        t.join(timeout=2)


@patch("nettap.cli.parse_pcap", return_value=[])
def test_enrich_loop_skips_files_stored_before_a_restart(mock_parse_pcap, tmp_path):
    # live test 2026-11-08: a restarted sidecar parsed every old pcap again
    # and doubled their traffic in the report
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    done, new = pcap_dir / "web_20261108000001.pcap", pcap_dir / "web_20261108000002.pcap"
    for f in (done, new):
        f.write_bytes(b"\x00")
    db_path = str(tmp_path / "n.db")
    conn = storage.connect(db_path)
    storage.insert_flows(conn, [{
        "ts": 1.0, "container_id": "c1", "container_name": "web", "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8", "src_port": 1, "dst_port": 2, "protocol": "TCP", "length": 10,
        "dns_query": None, "tls_sni": None, "pcap_file": str(done)}])
    conn.close()
    _run_loop(_FakeMgr(str(pcap_dir / "web_%Y%m%d%H%M%S.pcap")), db_path,
              until=lambda: mock_parse_pcap.call_count >= 1)
    time.sleep(0.2)  # a few more passes, to catch a repeat parse
    assert [c.args[0] for c in mock_parse_pcap.call_args_list] == [str(new)]


def test_enrich_command_leaves_files_a_live_daemon_is_writing(tmp_path):
    from click.testing import CliRunner
    from nettap import cli
    from nettap.discovery import ContainerNetInfo

    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    for name in ["web_20261108000001.pcap", f"web_{NOW}.pcap"]:
        (pcap_dir / name).write_bytes(b"\x00")
    conn = storage.connect(str(tmp_path / "nettap.db"))
    info = ContainerNetInfo("c1", "web", "", "eth0", {}, [], {}, None, False)
    storage.set_live_session(conn, info, str(pcap_dir / "web_%Y%m%d%H%M%S.pcap"), 1,
                             rotate_seconds=60)
    storage.heartbeat_live_sessions(conn, ["c1"], 5)

    def parsed():
        with patch("nettap.cli.parse_pcap", return_value=[]) as parse:
            CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "enrich"])
        return [c.args[0].rsplit("/", 1)[1] for c in parse.call_args_list]

    assert parsed() == ["web_20261108000001.pcap"]
    # once the daemon is gone (stale row), nothing is still being written
    conn.execute("UPDATE live_sessions SET updated_at = ?", (time.time() - 600,))
    conn.commit()
    assert parsed() == ["web_20261108000001.pcap", f"web_{NOW}.pcap"]
