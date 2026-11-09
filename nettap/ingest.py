"""Parse pcaps into the flow store while tcpdump is still writing them.

tcpdump runs with -U, so each packet is flushed to the file as soon as it's
captured. Instead of waiting for the file to rotate (up to rotate_seconds,
60 by default), each pass takes only the complete packet records added
since the last pass, copies them behind the file's own header into a small
temporary pcap, and runs tshark over that. How far each file has been read
(a byte offset) is stored in `pcap_progress`, in the same transaction as
the rows, so a file is never counted twice - after a restart, or when
`nettap enrich` and a running daemon look at the same file.

pcap file format (24-byte global header, then a 16-byte header before each
packet): https://www.tcpdump.org/manpages/pcap-savefile.5.html. tcpdump -w
writes this format, never pcapng.

A packet split from its TCP stream's earlier packets can lose the TLS SNI
or HTTP Host tshark would find by reassembling them; at 5s per chunk that
only affects a ClientHello or request spanning a chunk boundary.
"""
from __future__ import annotations

import logging
import os
import struct
import tempfile
import time

from . import hostports, storage
from .enrich import parse_pcap

logger = logging.getLogger(__name__)

GLOBAL_HEADER = 24
RECORD_HEADER = 16
# packets newer than this are left for the next pass while a file is still
# open: gives a port-scoped capture's socket sampling (hostports, every
# 0.25s) time to record the port a packet used
HOLDBACK_SECONDS = 2.0
# far above any snaplen tcpdump uses (262144); a bigger length means the
# file is corrupt from here on
_MAX_RECORD = 16 * 1024 * 1024

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",  # microsecond timestamps
    b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",  # nanosecond timestamps
}


def complete_records(path: str, offset: int, until_ts: float | None = None) -> tuple[bytes, int, int]:
    """(global header, end, size): `end` is the offset just past the last
    complete packet record at or after `offset` (at least the end of the
    global header) whose timestamp is at most `until_ts` (None: no limit).
    A record tcpdump is still writing, or a file shorter than its header,
    stops the scan there. Raises ValueError for a file that isn't a pcap."""
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        header = f.read(GLOBAL_HEADER)
        if len(header) < GLOBAL_HEADER:
            return header, 0, size
        endian = _MAGIC.get(header[:4])
        if endian is None:
            raise ValueError(f"{path} is not a pcap file")
        pos = max(offset, GLOBAL_HEADER)
        f.seek(pos)
        while True:
            rec = f.read(RECORD_HEADER)
            if len(rec) < RECORD_HEADER:
                break
            ts_sec, _frac, incl_len, _orig = struct.unpack(endian + "IIII", rec)
            if incl_len > _MAX_RECORD:
                logger.warning("%s: corrupt packet record at byte %d, ignoring the rest",
                               path, pos)
                return header, pos, pos
            if pos + RECORD_HEADER + incl_len > size:
                break
            if until_ts is not None and ts_sec > until_ts:
                break
            pos += RECORD_HEADER + incl_len
            f.seek(pos)
        return header, pos, size


def _parse_chunk(path: str, header: bytes, start: int, end: int,
                 container_id: str, container_name: str) -> list[dict]:
    """Flow rows for the records in path[start:end], tagged with `path`."""
    with open(path, "rb") as src, tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        src.seek(start)
        tmp.write(header)
        remaining = end - start
        while remaining:
            block = src.read(min(remaining, 1 << 20))
            if not block:
                break
            tmp.write(block)
            remaining -= len(block)
        tmp.flush()
        rows = parse_pcap(tmp.name, container_id=container_id, container_name=container_name)
    for r in rows:
        r["pcap_file"] = path
    return rows


def enrich_pcap(conn, path: str, container_id: str, container_name: str,
                final: bool, now: float | None = None) -> int:
    """Store the flows of whatever part of `path` hasn't been stored yet,
    and return how many rows were added. `final`: tcpdump won't write to it
    again, so take every complete record and mark the file done; otherwise
    leave the last HOLDBACK_SECONDS for the next pass."""
    progress = storage.pcap_progress(conn, path)
    if progress is None and storage.pcap_enriched(conn, path):
        # parsed whole before pcap_progress existed
        storage.store_pcap_chunk(conn, path, 0, os.path.getsize(path), True, [])
        return 0
    start, done = progress or (0, False)
    if done:
        return 0
    until = None if final else (now or time.time()) - HOLDBACK_SECONDS
    try:
        header, end, size = complete_records(path, start, until)
    except ValueError as e:
        logger.warning("%s - skipping it", e)
        storage.store_pcap_chunk(conn, path, start, start, True, [])
        return 0
    except FileNotFoundError:  # deleted by retention in the meantime
        return 0
    rows = []
    if end > max(start, GLOBAL_HEADER):
        rows = _parse_chunk(path, header, max(start, GLOBAL_HEADER), end,
                            container_id, container_name)
        if rows and storage.port_scoped(conn, container_name):
            rows = hostports.keep_owned(conn, container_name, rows)
    elif not final:
        return 0
    if final and end < size:
        logger.debug("%s: ignoring %d trailing bytes of an incomplete packet", path, size - end)
    if not storage.store_pcap_chunk(conn, path, start, end, final, rows):
        return 0  # someone else stored this part first
    return len(rows)
