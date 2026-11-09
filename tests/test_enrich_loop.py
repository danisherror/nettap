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

import struct
import threading
import time
from unittest.mock import patch

from nettap import storage
from nettap.cli import _enrich_loop


# a file tcpdump opened just now is still being written
NOW = time.strftime("%Y%m%d%H%M%S")
# a pcap header plus one packet record, timestamped long ago
PCAP = (struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1000, 0, 4, 4) + b"abcd")


def _row(path):
    return {"ts": 1.0, "container_id": "c1", "container_name": "web",
            "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "src_port": 1, "dst_port": 2,
            "protocol": "TCP", "length": 10, "dns_query": None, "tls_sni": None,
            "pcap_file": path}


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


def _run_loop(mgr, db_path, until, timeout=2):
    stop = {"flag": False}
    t = threading.Thread(target=_enrich_loop, args=(mgr, db_path, stop, 0.05), daemon=True)
    t.start()
    try:
        deadline = time.time() + timeout
        while not until() and time.time() < deadline:
            time.sleep(0.05)
        assert t.is_alive(), "enrich thread died instead of looping - check for an uncaught exception"
    finally:
        stop["flag"] = True
        t.join(timeout=2)


def _parsed(calls):
    return sorted(c.args[0].rsplit("/", 1)[1] for c in calls)


@patch("nettap.ingest._parse_chunk", side_effect=lambda path, *a: [_row(path)])
def test_enrich_loop_uses_its_own_connection(_parse, tmp_path):
    db_path = str(tmp_path / "nettap.db")
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    (pcap_dir / "web_20261108000001.pcap").write_bytes(PCAP)
    pattern = str(pcap_dir / "web_%Y%m%d%H%M%S.pcap")

    def stored():
        conn = storage.connect(db_path)
        try:
            return conn.execute("SELECT * FROM flows").fetchall()
        finally:
            conn.close()

    _run_loop(_FakeMgr(pattern), db_path, until=lambda: stored())
    rows = stored()
    assert len(rows) == 1, "enrich thread never wrote a row - the cross-thread sqlite3 bug is back"
    assert rows[0]["dst_ip"] == "5.6.7.8"


@patch("nettap.ingest._parse_chunk", return_value=[])
def test_enrich_loop_reads_the_file_tcpdump_is_still_writing(parse, tmp_path):
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    (pcap_dir / f"web_{NOW}.pcap").write_bytes(PCAP)

    _run_loop(_FakeMgr(str(pcap_dir / "web_%Y%m%d%H%M%S.pcap")), str(tmp_path / "n.db"),
              until=lambda: parse.call_count >= 1)

    assert _parsed(parse.call_args_list) == [f"web_{NOW}.pcap"]


@patch("nettap.ingest._parse_chunk", return_value=[])
def test_enrich_loop_also_reads_the_dns_capture(parse, tmp_path):
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    for name in ["web_20261108000001.pcap", "web_20261108000001.dns.pcap"]:
        (pcap_dir / name).write_bytes(PCAP)

    class Mgr(_FakeMgr):
        def status(self):
            rows = super().status()
            rows[0]["dns_pcap_pattern"] = str(pcap_dir / "web_%Y%m%d%H%M%S.dns.pcap")
            return rows

    _run_loop(Mgr(str(pcap_dir / "web_%Y%m%d%H%M%S.pcap")), str(tmp_path / "n.db"),
              until=lambda: parse.call_count >= 2)
    time.sleep(0.2)  # a few more passes, to catch a repeat parse
    assert _parsed(parse.call_args_list) == ["web_20261108000001.dns.pcap",
                                             "web_20261108000001.pcap"]


def test_enrich_command_names_dns_pcaps_after_their_container(tmp_path):
    from click.testing import CliRunner
    from nettap import cli

    (tmp_path / "pcap").mkdir()
    for name in ["my_app_20261108000001.pcap", "my_app_20261108000001.dns.pcap"]:
        (tmp_path / "pcap" / name).write_bytes(PCAP)
    with patch("nettap.ingest._parse_chunk", return_value=[]) as parse:
        result = CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "enrich"])
    assert result.exit_code == 0, result.output
    assert [c.args[5] for c in parse.call_args_list] == ["my_app", "my_app"]


@patch("nettap.ingest._parse_chunk", return_value=[])
def test_enrich_loop_skips_files_stored_before_a_restart(parse, tmp_path):
    # live test 2026-11-08: a restarted sidecar parsed every old pcap again
    # and doubled their traffic in the report
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    done, new = pcap_dir / "web_20261108000001.pcap", pcap_dir / "web_20261108000002.pcap"
    for f in (done, new):
        f.write_bytes(PCAP)
    db_path = str(tmp_path / "n.db")
    conn = storage.connect(db_path)
    storage.insert_flows(conn, [_row(str(done))])
    conn.close()
    _run_loop(_FakeMgr(str(pcap_dir / "web_%Y%m%d%H%M%S.pcap")), db_path,
              until=lambda: parse.call_count >= 1)
    time.sleep(0.2)
    assert [c.args[0] for c in parse.call_args_list] == [str(new)]


def test_enrich_command_leaves_files_a_live_daemon_is_writing(tmp_path):
    from click.testing import CliRunner
    from nettap import cli
    from nettap.discovery import ContainerNetInfo

    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    for name in ["web_20261108000001.pcap", f"web_{NOW}.pcap"]:
        (pcap_dir / name).write_bytes(PCAP)
    conn = storage.connect(str(tmp_path / "nettap.db"))
    info = ContainerNetInfo("c1", "web", "", "eth0", {}, [], {}, None, False)
    storage.set_live_session(conn, info, str(pcap_dir / "web_%Y%m%d%H%M%S.pcap"), 1,
                             rotate_seconds=60)
    storage.heartbeat_live_sessions(conn, ["c1"], 5)

    def parsed():
        with patch("nettap.ingest._parse_chunk", return_value=[]) as parse:
            CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "enrich"])
        return _parsed(parse.call_args_list)

    assert parsed() == ["web_20261108000001.pcap"]
    # once the daemon is gone (stale row), nothing is still being written;
    # the file parsed on the first run isn't parsed again
    conn.execute("UPDATE live_sessions SET updated_at = ?", (time.time() - 600,))
    conn.commit()
    assert parsed() == [f"web_{NOW}.pcap"]
