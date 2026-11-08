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
