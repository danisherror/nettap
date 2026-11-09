"""ingest.py: parsing a pcap in pieces while tcpdump is still writing it."""
from __future__ import annotations

import shutil
import struct
from unittest.mock import patch

import pytest

from nettap import ingest, storage

HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def record(ts: int, payload: bytes = b"x" * 20) -> bytes:
    return struct.pack("<IIII", ts, 0, len(payload), len(payload)) + payload


def row(path, n=0):
    return {"ts": float(n), "container_id": "c1", "container_name": "web", "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2", "src_port": n, "dst_port": 2, "protocol": "UDP", "length": 1,
            "dns_query": None, "tls_sni": None, "pcap_file": path}


@pytest.fixture
def conn(tmp_path):
    return storage.connect(str(tmp_path / "n.db"))


# ---- complete_records -------------------------------------------------------

def test_complete_records_stops_before_a_partly_written_record(tmp_path):
    p = tmp_path / "a.pcap"
    full = record(100) + record(101)
    p.write_bytes(HEADER + full + record(102)[:10])

    header, end, size = ingest.complete_records(str(p), 0)

    assert header == HEADER
    assert end == len(HEADER) + len(full)
    assert size == end + 10


def test_complete_records_continues_from_an_offset(tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(HEADER + record(100) + record(101))
    first = len(HEADER) + len(record(100))

    assert ingest.complete_records(str(p), first)[1] == p.stat().st_size


def test_complete_records_leaves_packets_newer_than_until(tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(HEADER + record(100) + record(200))

    assert ingest.complete_records(str(p), 0, until_ts=150)[1] == len(HEADER) + len(record(100))


def test_complete_records_of_a_file_without_a_full_header(tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(HEADER[:10])

    assert ingest.complete_records(str(p), 0)[1] == 0


@pytest.mark.parametrize("magic", [0xA1B2C3D4, 0xA1B23C4D])
def test_complete_records_reads_big_endian_files(tmp_path, magic):
    p = tmp_path / "a.pcap"
    payload = b"y" * 7
    p.write_bytes(struct.pack(">IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
                  + struct.pack(">IIII", 1, 0, 7, 7) + payload)

    assert ingest.complete_records(str(p), 0)[1] == p.stat().st_size


def test_complete_records_rejects_other_files(tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)  # pcapng

    with pytest.raises(ValueError):
        ingest.complete_records(str(p), 0)


# ---- enrich_pcap --------------------------------------------------------------

def _chunks(calls):
    return [(c.args[2], c.args[3]) for c in calls]


def test_enrich_pcap_stores_a_growing_file_piece_by_piece(tmp_path, conn):
    p = tmp_path / "web_20261109000000.pcap"
    p.write_bytes(HEADER + record(100))
    end1 = p.stat().st_size

    with patch("nettap.ingest._parse_chunk", side_effect=lambda path, *a: [row(path)]) as parse:
        assert ingest.enrich_pcap(conn, str(p), "c1", "web", final=False, now=1000) == 1
        assert ingest.enrich_pcap(conn, str(p), "c1", "web", final=False, now=1000) == 0
        with open(p, "ab") as f:
            f.write(record(101))
        assert ingest.enrich_pcap(conn, str(p), "c1", "web", final=False, now=1000) == 1
        assert ingest.enrich_pcap(conn, str(p), "c1", "web", final=True) == 0

    assert _chunks(parse.call_args_list) == [(len(HEADER), end1), (end1, p.stat().st_size)]
    assert storage.pcap_progress(conn, str(p)) == (p.stat().st_size, True)
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 2


def test_enrich_pcap_holds_back_the_newest_packets_of_an_open_file(tmp_path, conn):
    p = tmp_path / "web_20261109000000.pcap"
    p.write_bytes(HEADER + record(100) + record(999))

    with patch("nettap.ingest._parse_chunk", return_value=[]) as parse:
        ingest.enrich_pcap(conn, str(p), "c1", "web", final=False, now=1000)
        ingest.enrich_pcap(conn, str(p), "c1", "web", final=True)

    first = len(HEADER) + len(record(100))
    assert _chunks(parse.call_args_list) == [(len(HEADER), first), (first, p.stat().st_size)]


def test_enrich_pcap_never_stores_a_part_twice(tmp_path, conn):
    """A second process (e.g. `nettap enrich` beside a daemon) that read the
    same offset loses the race and stores nothing."""
    p = tmp_path / "web_20261109000000.pcap"
    p.write_bytes(HEADER + record(100))
    other = storage.connect(str(tmp_path / "n.db"))

    def store_first_elsewhere(path, header, start, end, *a):
        storage.store_pcap_chunk(other, path, 0, end, False, [row(path, 1)])
        return [row(path, 2)]

    with patch("nettap.ingest._parse_chunk", side_effect=store_first_elsewhere):
        assert ingest.enrich_pcap(conn, str(p), "c1", "web", final=False, now=1000) == 0

    assert [r[0] for r in conn.execute("SELECT src_port FROM flows")] == [1]


def test_enrich_pcap_treats_files_parsed_before_progress_existed_as_done(tmp_path, conn):
    p = tmp_path / "web_20261109000000.pcap"
    p.write_bytes(HEADER + record(100))
    storage.insert_flows(conn, [row(str(p))])

    with patch("nettap.ingest._parse_chunk") as parse:
        assert ingest.enrich_pcap(conn, str(p), "c1", "web", final=True) == 0

    parse.assert_not_called()
    assert storage.pcap_progress(conn, str(p)) == (p.stat().st_size, True)


def test_enrich_pcap_skips_a_file_that_is_not_a_pcap(tmp_path, conn):
    p = tmp_path / "web_20261109000000.pcap"
    p.write_bytes(b"not a pcap at all, sorry")

    assert ingest.enrich_pcap(conn, str(p), "c1", "web", final=False) == 0
    assert storage.pcap_progress(conn, str(p))[1] is True


def test_enrich_pcap_keeps_only_owned_ports_for_a_port_scoped_capture(tmp_path, conn):
    p = tmp_path / "web_20261109000000.pcap"
    p.write_bytes(HEADER + record(100))
    with patch("nettap.ingest._parse_chunk", return_value=[row(str(p), 1), row(str(p), 2)]), \
            patch("nettap.ingest.storage.port_scoped", return_value=True), \
            patch("nettap.ingest.hostports.keep_owned", side_effect=lambda c, n, rows: rows[:1]):
        assert ingest.enrich_pcap(conn, str(p), "c1", "web", final=True) == 1


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_chunks_parsed_by_real_tshark_add_up_to_the_whole_file(tmp_path, conn):
    from tests.test_enrich import _write_pcap

    whole = tmp_path / "whole.pcap"
    _write_pcap(whole)
    data = whole.read_bytes()
    growing = tmp_path / "web_20261109000000.pcap"
    # tcpdump has written the header, two packets and part of the third
    _, cut, _ = ingest.complete_records(str(whole), 0, until_ts=1001)
    growing.write_bytes(data[:cut + 5])

    first = ingest.enrich_pcap(conn, str(growing), "c1", "web", final=False, now=10**9)
    growing.write_bytes(data)
    rest = ingest.enrich_pcap(conn, str(growing), "c1", "web", final=True)

    assert (first, rest) == (2, 3)
    stored = [r["src_ip"] for r in conn.execute("SELECT src_ip FROM flows ORDER BY ts")]
    assert stored == [None, "2001:db8::2", "10.0.0.1", "192.168.65.7", "172.17.0.2"]
    assert {r[0] for r in conn.execute("SELECT DISTINCT pcap_file FROM flows")} == {str(growing)}
