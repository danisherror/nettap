"""nettap export: json/csv flow rows and merged pcaps."""
import csv
import io
import json
import shutil
import struct
import subprocess

import pytest
from click.testing import CliRunner

from nettap import export, storage
from nettap.cli import cli
from nettap.discovery import ContainerNetInfo


def _pcap(path, packets, link_type=1, nano=False, endian="<"):
    """packets: [(ts_float, payload)]"""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, link_type))
        for ts, data in packets:
            sec = int(ts)
            frac = round((ts - sec) * (1e9 if nano else 1e6))
            f.write(struct.pack(endian + "IIII", sec, frac, len(data), len(data)) + data)


def _read_pcap(data: bytes):
    magic, = struct.unpack("<I", data[:4])
    assert magic == 0xA1B2C3D4
    link_type, = struct.unpack("<I", data[20:24])
    pos, out = 24, []
    while pos < len(data):
        sec, usec, incl, _ = struct.unpack("<IIII", data[pos:pos + 16])
        out.append((sec + usec / 1e6, data[pos + 16:pos + 16 + incl]))
        pos += 16 + incl
    return link_type, out


def test_merge_in_time_order_and_filter(tmp_path):
    a, b = tmp_path / "web_20261109120000.pcap", tmp_path / "web_20261109120000.dns.pcap"
    _pcap(a, [(100.0, b"a1"), (102.0, b"a2"), (104.0, b"a3")])
    _pcap(b, [(101.5, b"b1"), (103.0, b"b2")], nano=True, endian=">")
    out = io.BytesIO()
    n, kind = export.write_pcap([a, b], out, since=101, until=104)
    assert (n, kind) == (3, "pcap")
    link_type, packets = _read_pcap(out.getvalue())
    assert link_type == 1
    assert [(round(t, 3), d) for t, d in packets] == [(101.5, b"b1"), (102.0, b"a2"), (103.0, b"b2")]


def test_incomplete_last_record_is_skipped(tmp_path):
    p = tmp_path / "web_20261109120000.pcap"
    _pcap(p, [(100.0, b"full")])
    with open(p, "ab") as f:
        f.write(struct.pack("<IIII", 101, 0, 50, 50) + b"short")
    out = io.BytesIO()
    assert export.write_pcap([p], out)[0] == 1


def test_mixed_link_types_give_pcapng(tmp_path):
    a, b = tmp_path / "x_20261109120000.pcap", tmp_path / "x_20261109120001.pcap"
    _pcap(a, [(100.0, b"eth")], link_type=1)
    _pcap(b, [(101.0, b"sll")], link_type=113)
    assert export.output_kind([a, b]) == "pcapng"
    out = io.BytesIO()
    n, kind = export.write_pcap([a, b], out)
    assert (n, kind) == (2, "pcapng")
    data = out.getvalue()
    assert struct.unpack("<I", data[:4])[0] == 0x0A0D0D0A
    # every block's two length fields agree and blocks tile the file
    pos, types = 0, []
    while pos < len(data):
        btype, length = struct.unpack("<II", data[pos:pos + 8])
        assert struct.unpack("<I", data[pos + length - 4:pos + length])[0] == length
        types.append(btype)
        pos += length
    assert pos == len(data)
    assert types == [0x0A0D0D0A, 1, 1, 6, 6]


@pytest.mark.skipif(not shutil.which("tshark"), reason="needs tshark")
def test_tshark_reads_pcapng(tmp_path):
    a, b = tmp_path / "x_20261109120000.pcap", tmp_path / "x_20261109120001.pcap"
    _pcap(a, [(100.0, b"\0" * 60)], link_type=1)
    _pcap(b, [(101.0, b"\0" * 60)], link_type=113)
    out = tmp_path / "out.pcapng"
    with open(out, "wb") as f:
        export.write_pcap([a, b], f)
    res = subprocess.run(["tshark", "-r", str(out)], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert len(res.stdout.strip().splitlines()) == 2


def test_container_pcaps_only_that_container(tmp_path):
    for name in ("web_20261109120000.pcap", "web_20261109120000.dns.pcap",
                 "web_2_20261109120000.pcap", "db_20261109120000.pcap", "notes.txt"):
        (tmp_path / name).write_bytes(b"")
    assert [p.name for p in export.container_pcaps(tmp_path, "web")] == [
        "web_20261109120000.dns.pcap", "web_20261109120000.pcap"]


def _seed(conn):
    storage.upsert_container(conn, ContainerNetInfo("c1", "web", "img", "eth0", {"n": "172.18.0.2"},
                                                    ["n"], {}, None, False))
    rows = []
    for i, ts in enumerate((100.0, 200.0, 300.0)):
        rows.append({"ts": ts, "container_id": "c1", "container_name": "web", "src_ip": "172.18.0.2",
                     "dst_ip": "8.8.8.8", "src_port": 40000 + i, "dst_port": 53, "protocol": "DNS",
                     "length": 80, "dns_query": "example.com", "tls_sni": None,
                     "pcap_file": f"/data/pcap/web_2026110912000{i}.pcap", "transport": "udp",
                     "dns_answers": json.dumps(["93.184.216.34"])})
    storage.insert_flows(conn, rows)


def _invoke(*args):
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def test_cli_json_and_csv(tmp_path):
    _seed(storage.connect(str(tmp_path / "nettap.db")))
    out = tmp_path / "o.json"
    r = _invoke("--data-dir", str(tmp_path), "export", "--container", "web", "--since", "150",
                "--out", str(out))
    assert r.exit_code == 0, r.output
    rows = json.loads(out.read_text())
    assert [row["ts"] for row in rows] == [200.0, 300.0]
    assert rows[0]["dns_answers"] == ["93.184.216.34"]
    assert rows[0]["time"].startswith("1970-01-01T00:03:20")

    out = tmp_path / "o.csv"
    r = _invoke("--data-dir", str(tmp_path), "export", "--container", "web", "--format", "csv",
                "--until", "200", "--out", str(out))
    rows = list(csv.DictReader(out.open()))
    assert len(rows) == 1 and rows[0]["dns_answers"] == "93.184.216.34"
    assert list(rows[0]) == export.FLOW_COLUMNS


def test_cli_json_empty_is_valid(tmp_path):
    _seed(storage.connect(str(tmp_path / "nettap.db")))
    r = _invoke("--data-dir", str(tmp_path), "export", "--container", "web", "--since", "1000")
    # click < 8.2 mixes stderr (the "exported ..." line, written last) into stdout
    assert json.loads(r.stdout.split("exported")[0]) == []


def test_cli_pcap_notes_deleted_pcaps(tmp_path):
    _seed(storage.connect(str(tmp_path / "nettap.db")))
    (tmp_path / "pcap").mkdir()
    # only the last of the three source pcaps is still there
    _pcap(tmp_path / "pcap" / "web_20261109120002.pcap", [(300.0, b"x" * 60)])
    r = _invoke("--data-dir", str(tmp_path), "export", "--container", "web", "--format", "pcap")
    assert r.exit_code == 0, r.output
    assert "wrote 1 packets" in r.output
    assert "2 flow rows in this range came from pcaps that no longer exist" in r.output
    assert (tmp_path / "web_export.pcap").exists()


def test_cli_pcap_none_left(tmp_path):
    _seed(storage.connect(str(tmp_path / "nettap.db")))
    r = _invoke("--data-dir", str(tmp_path), "export", "--container", "web", "--format", "pcap")
    assert r.exit_code == 1
    assert "no pcaps for 'web'" in r.output
