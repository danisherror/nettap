"""`nettap export`: one container's traffic for a time range, as a file to
share - the flow rows as JSON or CSV, or the raw packets as one pcap.

The pcap is built from the container's capture files in the pcap
directory (its interface capture and its DNS capture on lo), keeping the
packets in the time range and merging them in time order. Packets whose
pcaps retention already deleted are gone; the flow rows of those packets
are still in the store, so JSON/CSV can cover more than a pcap export.

When all source files have the same link type (the usual case: Ethernet
for both eth0 and lo), the output is a classic pcap; otherwise it's
pcapng, the only one of the two formats that can hold several link types
(https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html).
"""
from __future__ import annotations

import csv
import heapq
import json
import logging
import sqlite3
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Iterator

from .capture import capture_name
from .ingest import _MAGIC, _MAX_RECORD, GLOBAL_HEADER, RECORD_HEADER

logger = logging.getLogger(__name__)

FLOW_COLUMNS = ["ts", "time", "container_name", "src_ip", "src_port", "dst_ip", "dst_port",
                "transport", "protocol", "length", "dns_query", "dns_answers", "tls_sni",
                "http_host", "pcap_file"]

_NANO_MAGIC = {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}


def _where(container: str, since: float | None, until: float | None) -> tuple[str, list]:
    where, params = ["container_name = ?"], [container]
    if since is not None:
        where.append("ts >= ?")
        params.append(since)
    if until is not None:
        where.append("ts < ?")
        params.append(until)
    return " AND ".join(where), params


def flow_rows(conn: sqlite3.Connection, container: str, since: float | None = None,
              until: float | None = None) -> Iterator[dict]:
    """The container's flow rows in the range, oldest first, with an ISO
    `time` (UTC) and `dns_answers` as a list."""
    where, params = _where(container, since, until)
    cur = conn.execute(
        f"SELECT ts, container_name, src_ip, src_port, dst_ip, dst_port, transport, protocol, "
        f"length, dns_query, dns_answers, tls_sni, http_host, pcap_file FROM flows "
        f"WHERE {where} ORDER BY ts, id", params)
    for r in cur:
        row = dict(r)
        row["time"] = (datetime.fromtimestamp(row["ts"], tz=timezone.utc)
                       .isoformat(timespec="microseconds") if row["ts"] is not None else None)
        row["dns_answers"] = json.loads(row["dns_answers"]) if row["dns_answers"] else None
        yield {k: row[k] for k in FLOW_COLUMNS}


def write_json(rows, out: IO[str]) -> int:
    """A JSON array, one row per line, written as it goes."""
    n = 0
    out.write("[")
    for row in rows:
        out.write(("," if n else "") + "\n  " + json.dumps(row))
        n += 1
    out.write("\n]\n" if n else "]\n")
    return n


def write_csv(rows, out: IO[str]) -> int:
    writer = csv.DictWriter(out, fieldnames=FLOW_COLUMNS)
    writer.writeheader()
    n = 0
    for row in rows:
        if row["dns_answers"] is not None:
            row = {**row, "dns_answers": " ".join(row["dns_answers"])}
        writer.writerow(row)
        n += 1
    return n


# ---- pcap ------------------------------------------------------------------

def container_pcaps(pcap_dir, container: str) -> list[Path]:
    """The pcaps nettap wrote for this container (interface and DNS), by name."""
    return sorted(p for p in Path(pcap_dir).glob("*.pcap") if capture_name(p) == container)


def _packets(path: Path, since: float | None, until: float | None):
    """(ts, sec, usec, orig_len, data, link_type, snaplen) for each complete
    record in [since, until). Skips a file that isn't a pcap."""
    with open(path, "rb") as f:
        header = f.read(GLOBAL_HEADER)
        endian = _MAGIC.get(header[:4]) if len(header) == GLOBAL_HEADER else None
        if endian is None:
            logger.warning("%s is not a pcap file - skipping it", path)
            return
        nano = header[:4] in _NANO_MAGIC
        snaplen, link_type = struct.unpack(endian + "II", header[16:24])
        while True:
            rec = f.read(RECORD_HEADER)
            if len(rec) < RECORD_HEADER:
                return
            sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
            if incl > _MAX_RECORD:
                logger.warning("%s: corrupt packet record, ignoring the rest", path)
                return
            data = f.read(incl)
            if len(data) < incl:  # still being written
                return
            usec = frac // 1000 if nano else frac
            ts = sec + usec / 1e6
            if (since is not None and ts < since) or (until is not None and ts >= until):
                continue
            yield ts, sec, usec, orig, data, link_type, snaplen


def _write_pcap(out: IO[bytes], packets, link_type: int, snaplen: int) -> int:
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, link_type))
    n = 0
    for _ts, sec, usec, orig, data, _lt, _sl in packets:
        out.write(struct.pack("<IIII", sec, usec, len(data), orig))
        out.write(data)
        n += 1
    return n


def _block(block_type: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def _write_pcapng(out: IO[bytes], packets, interfaces: list[tuple[int, int]]) -> int:
    """interfaces: [(link_type, snaplen)], in interface ID order. Timestamps
    are in microseconds, pcapng's default resolution."""
    out.write(_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    for link_type, snaplen in interfaces:
        out.write(_block(1, struct.pack("<HHI", link_type, 0, snaplen)))
    ids = {iface: i for i, iface in enumerate(interfaces)}
    n = 0
    for _ts, sec, usec, orig, data, link_type, snaplen in packets:
        t = sec * 1_000_000 + usec
        out.write(_block(6, struct.pack("<IIIII", ids[(link_type, snaplen)], t >> 32,
                                        t & 0xFFFFFFFF, len(data), orig) + data))
        n += 1
    return n


def _header(path: Path) -> tuple[int, int] | None:
    """(link_type, snaplen) of a pcap, or None if it isn't one."""
    with open(path, "rb") as f:
        header = f.read(GLOBAL_HEADER)
    endian = _MAGIC.get(header[:4]) if len(header) == GLOBAL_HEADER else None
    if endian is None:
        return None
    snaplen, link_type = struct.unpack(endian + "II", header[16:24])
    return link_type, snaplen


def output_kind(paths: list[Path]) -> str:
    """"pcap" when the files share one link type, else "pcapng"."""
    return "pcap" if len({h[0] for h in map(_header, paths) if h}) <= 1 else "pcapng"


def write_pcap(paths: list[Path], out: IO[bytes], since: float | None = None,
               until: float | None = None) -> tuple[int, str]:
    """Merge the packets of `paths` in [since, until) into `out`, oldest
    first. Returns (packets written, "pcap" or "pcapng")."""
    headers = {p: _header(p) for p in paths}
    paths = [p for p in paths if headers[p]]
    link_types = {headers[p][0] for p in paths}
    merged = heapq.merge(*(_packets(p, since, until) for p in paths), key=lambda pkt: pkt[0])
    if len(link_types) <= 1:
        link_type = link_types.pop() if link_types else 1  # 1 = Ethernet
        snaplen = max((headers[p][1] for p in paths), default=262144)
        # one snaplen for all: the largest, so no packet is longer than it
        return _write_pcap(out, merged, link_type, snaplen), "pcap"
    interfaces = sorted({headers[p] for p in paths})
    return _write_pcapng(out, merged, interfaces), "pcapng"
