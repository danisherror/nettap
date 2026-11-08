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


class _FakeMgr:
    """Duck-types CaptureManager.status() enough for _enrich_loop's needs."""

    def __init__(self, pattern):
        self._pattern = pattern

    def status(self):
        return [{
            "container": "web", "container_id": "c1",
            "veth": "veth1", "pcap_pattern": self._pattern,
            "alive": True, "started_at": time.time(),
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
    (pcap_dir / "web_20261108000002.pcap").write_bytes(b"\x00")
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
    for name in ["web_20261108000001.pcap", "web_20261108000002.pcap",
                 "web_20261108000001.dns.pcap", "web_20261108000002.dns.pcap"]:
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
