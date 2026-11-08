"""Turns a raw pcap into structured flow rows via tshark, so the rest of the
tool can query bytes/protocols/DNS/TLS-SNI without re-parsing pcaps by hand.

tshark is used here (rather than a hand-rolled pcap parser) because its
protocol dissectors already get these fields right. This is intentionally a
thin layer: swapping it for Zeek or Suricata (much richer protocol logs -
full HTTP requests, JA3 fingerprints, extracted files) is a tracked follow-up
(see TODO.md) and would only touch this file plus the FIELDS list below.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import shutil
import subprocess

logger = logging.getLogger("nettap.enrich")

# ipv6.src/ipv6.dst are separate fields from ip.src/ip.dst in tshark; without
# them every IPv6 packet would be stored with null addresses.
FIELDS = [
    "frame.time_epoch",
    "ip.src", "ip.dst",
    "ipv6.src", "ipv6.dst",
    "tcp.srcport", "udp.srcport",
    "tcp.dstport", "udp.dstport",
    "_ws.col.Protocol",
    "frame.len",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "dns.a", "dns.aaaa",
    "http.host",
]

# tshark joins repeated values of a field with this. "|" can't appear in an
# IP address, port, protocol name or hostname.
_AGG = "|"


def require_tshark() -> None:
    if shutil.which("tshark") is None:
        raise RuntimeError("tshark not found on PATH - install it (the provided Dockerfile does)")


def parse_pcap(pcap_path: str, container_id: str, container_name: str) -> list[dict]:
    """Run tshark over a pcap and return flow-row dicts ready for storage.insert_flows."""
    require_tshark()
    # All occurrences of each field, joined by _AGG: a DNS response lists
    # several answer addresses. Every other field keeps only its first value -
    # ICMP error packets quote the original IP header, so ip.src comes back
    # as "outer|inner" and the inner one must not be stored.
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-E", "separator=,", "-E", "quote=d",
           "-E", "occurrence=a", "-E", f"aggregator={_AGG}"]
    for f in FIELDS:
        cmd += ["-e", f]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        logger.error("tshark timed out on %s", pcap_path)
        return []

    if proc.returncode != 0:
        logger.error("tshark failed on %s: %s", pcap_path, proc.stderr.strip())
        return []

    rows = []
    reader = csv.reader(io.StringIO(proc.stdout))
    for parts in reader:
        if len(parts) != len(FIELDS):
            continue
        *firsts, dns_a, dns_aaaa, http_host = parts
        (ts, src4, dst4, src6, dst6, tcp_sport, udp_sport, tcp_dport, udp_dport,
         proto, length, dns_qry, tls_sni) = (v.split(_AGG, 1)[0] for v in firsts)
        answers = list(dict.fromkeys(  # dedupe, keep order
            a for a in f"{dns_a}{_AGG}{dns_aaaa}".split(_AGG) if a))

        src = src4 or src6
        dst = dst4 or dst6
        sport = tcp_sport or udp_sport or None
        dport = tcp_dport or udp_dport or None
        rows.append({
            "ts": float(ts) if ts else None,
            "container_id": container_id,
            "container_name": container_name,
            "src_ip": src or None,
            "dst_ip": dst or None,
            "src_port": int(sport) if sport else None,
            "dst_port": int(dport) if dport else None,
            "protocol": proto or None,
            "length": int(length) if length else None,
            "dns_query": dns_qry or None,
            "tls_sni": tls_sni or None,
            "dns_answers": json.dumps(answers) if answers else None,
            "http_host": http_host.split(_AGG, 1)[0] or None,
            "pcap_file": pcap_path,
        })
    return rows
