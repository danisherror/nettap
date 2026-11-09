"""Tests for pcap retention (purge_pcaps / CaptureManager.enforce_retention)."""
from __future__ import annotations

import os
from unittest.mock import patch

from nettap.capture import CaptureManager, purge_pcaps

NOW = 1_000_000.0


def _pcap(d, name, size=100, age=0.0):
    p = d / name
    p.write_bytes(b"x" * size)
    os.utime(p, (NOW - age, NOW - age))
    return p


def test_no_limits_deletes_nothing(tmp_path):
    _pcap(tmp_path, "web_20261101000000.pcap", age=10**6)
    _pcap(tmp_path, "web_20261108000000.pcap")
    assert purge_pcaps(tmp_path, now=NOW) == []


def test_max_age_deletes_only_old_files(tmp_path):
    old = _pcap(tmp_path, "web_20261101000000.pcap", age=7200)
    mid = _pcap(tmp_path, "web_20261108000000.pcap", age=60)
    new = _pcap(tmp_path, "web_20261108000100.pcap", age=0)
    assert purge_pcaps(tmp_path, max_age_seconds=3600, now=NOW) == [old]
    assert mid.exists() and new.exists()


def test_max_bytes_deletes_oldest_first_until_under_cap(tmp_path):
    a = _pcap(tmp_path, "web_20261108000000.pcap", age=300)
    b = _pcap(tmp_path, "web_20261108000100.pcap", age=200)
    c = _pcap(tmp_path, "web_20261108000200.pcap", age=100)
    d = _pcap(tmp_path, "web_20261108000300.pcap", age=0)
    assert purge_pcaps(tmp_path, max_bytes=250, now=NOW) == [a, b]
    assert c.exists() and d.exists()


def test_newest_file_of_each_capture_is_kept(tmp_path):
    # still being written by tcpdump, even if it's old by mtime (idle capture)
    # or the cap can't be met without it
    web = _pcap(tmp_path, "web_20261101000000.pcap", age=10**6)
    db_old = _pcap(tmp_path, "db_20261101000000.pcap", age=10**6)
    db_new = _pcap(tmp_path, "db_20261102000000.pcap", age=10**6)
    assert purge_pcaps(tmp_path, max_age_seconds=60, max_bytes=0, now=NOW) == [db_old]
    assert web.exists() and db_new.exists()


def test_kept_files_still_count_toward_cap(tmp_path):
    big_current = _pcap(tmp_path, "web_20261108000100.pcap", size=1000, age=500)
    other_old = _pcap(tmp_path, "db_20261108000000.pcap", size=10, age=100)
    other_new = _pcap(tmp_path, "db_20261108000200.pcap", size=10, age=0)
    assert purge_pcaps(tmp_path, max_bytes=1015, now=NOW) == [other_old]
    assert big_current.exists() and other_new.exists()


def test_non_pcap_files_are_ignored(tmp_path):
    other = tmp_path / "notes.txt"
    other.write_bytes(b"x" * 1000)
    _pcap(tmp_path, "web_20261108000000.pcap")
    assert purge_pcaps(tmp_path, max_bytes=1, now=NOW) == []
    assert other.exists()


def test_enforce_retention_is_throttled(tmp_path):
    with patch("nettap.capture.shutil.which", return_value="/usr/bin/tcpdump"):
        mgr = CaptureManager(str(tmp_path), max_bytes=1)
    with patch("nettap.capture.purge_pcaps", return_value=[]) as purge:
        mgr.enforce_retention(min_interval=30)
        mgr.enforce_retention(min_interval=30)
    assert purge.call_count == 1
    assert purge.call_args.args[0] == tmp_path / "pcap"


def test_enforce_retention_off_by_default(tmp_path):
    with patch("nettap.capture.shutil.which", return_value="/usr/bin/tcpdump"):
        mgr = CaptureManager(str(tmp_path))
    with patch("nettap.capture.purge_pcaps") as purge:
        mgr.enforce_retention()
    purge.assert_not_called()


def test_newest_dns_capture_file_is_kept_separately(tmp_path):
    # web's DNS capture is a capture of its own: its newest file may still be
    # open in tcpdump even though web's main capture has newer files
    dns_old = _pcap(tmp_path, "web_20261108000000.dns.pcap", age=400)
    dns_new = _pcap(tmp_path, "web_20261108000100.dns.pcap", age=300)
    old = _pcap(tmp_path, "web_20261108000200.pcap", age=200)
    new = _pcap(tmp_path, "web_20261108000300.pcap", age=0)
    assert purge_pcaps(tmp_path, max_age_seconds=100, now=NOW) == [dns_old, old]
    assert dns_new.exists() and new.exists()


# --- defaults, logging and the unread warning ---------------------------------

import logging

from click.testing import CliRunner

from nettap import cli, discovery, storage
from nettap.capture import DEFAULT_MAX_AGE_HOURS, DEFAULT_MAX_SIZE_MB


def test_deletion_is_logged_with_reason(tmp_path, caplog):
    _pcap(tmp_path, "web_20261101000000.pcap", size=2048, age=7200)
    _pcap(tmp_path, "web_20261108000000.pcap", age=0)
    with caplog.at_level(logging.INFO, logger="nettap.capture"):
        purge_pcaps(tmp_path, max_age_seconds=3600, now=NOW)
    assert "deleted 1 pcap(s) (2.0 KB, older than 1h)" in caplog.text


def test_deleting_an_unparsed_file_warns(tmp_path, caplog):
    unread = _pcap(tmp_path, "web_20261101000000.pcap", age=7200)
    read = _pcap(tmp_path, "web_20261101000100.pcap", age=7100)
    _pcap(tmp_path, "web_20261108000000.pcap", age=0)
    with caplog.at_level(logging.INFO, logger="nettap.capture"):
        deleted = purge_pcaps(tmp_path, max_age_seconds=3600, now=NOW,
                              unread=lambda p: p == unread)
    assert deleted == [unread, read]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert unread.name in warnings[0].getMessage()
    assert read.name not in warnings[0].getMessage()


def test_a_failing_unread_check_doesnt_stop_deletion(tmp_path):
    old = _pcap(tmp_path, "web_20261101000000.pcap", age=7200)
    _pcap(tmp_path, "web_20261108000000.pcap", age=0)

    def boom(_p):
        raise RuntimeError("db locked")
    assert purge_pcaps(tmp_path, max_age_seconds=3600, now=NOW, unread=boom) == [old]


def test_pcap_unread(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    path = tmp_path / "web_20261101000000.pcap"
    assert storage.pcap_unread(conn, path)  # never seen
    storage.store_pcap_chunk(conn, str(path), 0, 100, False, [])
    assert storage.pcap_unread(conn, path)  # partly read
    storage.store_pcap_chunk(conn, str(path), 100, 200, True, [])
    assert not storage.pcap_unread(conn, path)  # done


def _run_sidecar(tmp_path, monkeypatch, *extra):
    monkeypatch.setattr(discovery, "interface_exists", lambda iface: True)
    monkeypatch.setattr(discovery, "interface_ips", lambda iface: {})
    monkeypatch.setattr(discovery, "bridge_interfaces", lambda: [])
    seen = {}

    class FakeMgr:
        def __init__(self, *a, **kw): seen.update(kw)
        def attach(self, info): return None
        def restart_dead(self): return []
        def enforce_retention(self, **kw): seen["unread"] = kw.get("unread"); return []
        def detach_all(self): pass

    monkeypatch.setattr(cli, "CaptureManager", FakeMgr)
    monkeypatch.setattr(cli.time, "sleep", lambda s: (_ for _ in ()).throw(KeyboardInterrupt))
    CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "sidecar", "--target", "web",
                                 "--no-auto-enrich", *extra])
    return seen


def test_sidecar_has_retention_on_by_default(tmp_path, monkeypatch):
    seen = _run_sidecar(tmp_path, monkeypatch)
    assert seen["max_age_seconds"] == DEFAULT_MAX_AGE_HOURS * 3600
    assert seen["max_bytes"] == int(DEFAULT_MAX_SIZE_MB * 1024 * 1024)
    assert callable(seen["unread"])  # deletions of unparsed files get a warning


def test_zero_turns_a_limit_off(tmp_path, monkeypatch):
    seen = _run_sidecar(tmp_path, monkeypatch, "--pcap-max-age-hours", "0",
                        "--pcap-max-size-mb", "0")
    assert seen["max_age_seconds"] is None and seen["max_bytes"] is None
