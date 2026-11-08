"""Turns the flow-level data in analyze.py into a plain-language summary -
something readable by someone who has never opened Wireshark or heard of a
5-tuple, not a JSON dump of flow rows.

Two renderers are provided: `render_text` (for `docker exec ... nettap
report`, printed straight to the terminal) and `render_html` (a
self-contained, no-dependency HTML file meant to be opened by double-clicking
it in Finder/Explorer - no server, no internet connection needed, since
everything is inlined).
"""
from __future__ import annotations

import html as html_escape
import ipaddress
import json
import sqlite3
import unicodedata
from datetime import datetime, timezone

from . import analyze


def _printable(s: str) -> str:
    """Show control and format characters (category C*: ESC, newlines, bidi
    overrides, ...) as visible escapes. Hostnames come from captured traffic
    (TLS SNI, HTTP Host, DNS) and tshark passes e.g. a raw ESC from an HTTP
    Host header through, which printed as-is would drive the terminal."""
    return "".join(
        ch if not unicodedata.category(ch).startswith("C")
        else f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}"
        for ch in s
    )


def format_bytes(n: float | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _ip_counts(conn: sqlite3.Connection, container: str) -> list[tuple[str, int]]:
    """Every IP seen in this container's flows (as src or dst), most rows first."""
    rows = conn.execute(
        """
        SELECT ip, COUNT(*) AS n FROM (
            SELECT src_ip AS ip FROM flows WHERE container_name = ? AND src_ip IS NOT NULL
            UNION ALL
            SELECT dst_ip AS ip FROM flows WHERE container_name = ? AND dst_ip IS NOT NULL
        )
        GROUP BY ip ORDER BY n DESC
        """,
        (container, container),
    ).fetchall()
    return [(r["ip"], r["n"]) for r in rows]


def _can_be_host_address(ip: str) -> bool:
    """False for multicast and unspecified addresses (::, 0.0.0.0), which show
    up a lot in IPv6 neighbour discovery but never belong to the container."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified)


def _self_ips(conn: sqlite3.Connection, container: str) -> list[str]:
    """The container's own addresses, most-seen first.

    Uses the addresses recorded in `containers.ip_addresses` (both `watch`
    and `sidecar` store them). Only if none are recorded does it guess: the
    unicast IP seen in the most rows, since every packet on the container's
    interface has its own address on one side. That guess can misfire for a
    container that talks to one peer far more than anything else."""
    recorded: set[str] = set()
    for r in conn.execute("SELECT ip_addresses FROM containers WHERE name = ?", (container,)):
        recorded.update(v for v in json.loads(r["ip_addresses"] or "{}").values() if v)
    counts = _ip_counts(conn, container)
    if recorded:
        seen = [ip for ip, _ in counts if ip in recorded]
        return seen + sorted(recorded - set(seen))
    guess = next((ip for ip, _ in counts if _can_be_host_address(ip)), None)
    return [guess] if guess else []


def _self_ip(conn: sqlite3.Connection, container: str) -> str | None:
    """The container's main address (see _self_ips), or None."""
    ips = _self_ips(conn, container)
    return ips[0] if ips else None


def build_report(conn: sqlite3.Connection, container: str) -> dict:
    """Gather everything render_text/render_html need into one plain dict."""
    totals = conn.execute(
        "SELECT COUNT(*) AS n, SUM(length) AS bytes, MIN(ts) AS start, MAX(ts) AS end "
        "FROM flows WHERE container_name = ?",
        (container,),
    ).fetchone()

    self_ips = _self_ips(conn, container)
    self_ip = self_ips[0] if self_ips else None

    # count across all the container's addresses (e.g. its IPv4 and IPv6)
    marks = ",".join("?" * len(self_ips))
    sent = conn.execute(
        f"SELECT SUM(length) AS b, COUNT(*) AS n FROM flows "
        f"WHERE container_name = ? AND src_ip IN ({marks})",
        (container, *self_ips),
    ).fetchone()
    received = conn.execute(
        f"SELECT SUM(length) AS b, COUNT(*) AS n FROM flows "
        f"WHERE container_name = ? AND dst_ip IN ({marks})",
        (container, *self_ips),
    ).fetchone()

    peers = analyze.container_peers(conn, container)

    # Drop the container's own IP as a backstop: if its addresses were never
    # recorded (e.g. data from an older sidecar), replies into it would
    # otherwise show up as an "internet destination".
    non_container = [
        r for r in analyze.external_destinations(conn, limit=200)
        if container in (r["containers"] or "").split(",") and r["dst_ip"] not in self_ips
    ]
    # private/link-local/multicast addresses (e.g. Docker Desktop's DNS
    # resolver) aren't the internet - list them separately
    external = [r for r in non_container if r["scope"] == "internet"]
    local = [r for r in non_container if r["scope"] == "local"]
    # name each destination from this container's own traffic (TLS SNI, HTTP
    # Host, DNS answers), not names other containers happened to use
    names = analyze.hostnames(conn, container)
    for row in external:
        row["hostname"] = names.get(row["dst_ip"], {}).get("hostname")

    return {
        "container": container,
        "self_ip": self_ip,
        "self_ips": self_ips,
        "packet_count": totals["n"] or 0,
        "total_bytes": totals["bytes"] or 0,
        "start": totals["start"],
        "end": totals["end"],
        "sent_bytes": sent["b"] or 0,
        "sent_packets": sent["n"] or 0,
        "received_bytes": received["b"] or 0,
        "received_packets": received["n"] or 0,
        "container_peers": peers,
        "external_destinations": sorted(external, key=lambda r: -(r["bytes"] or 0)),
        "local_destinations": sorted(local, key=lambda r: -(r["bytes"] or 0)),
        "dns_queries": analyze.dns_queries(conn, container, limit=50),
        "protocols": analyze.protocol_breakdown(conn, container),
    }


def _fmt_time(ts: float | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_text(report: dict) -> str:
    c = report["container"]
    lines = [f"Traffic report for container: {c}"]
    self_ips = report.get("self_ips") or ([report["self_ip"]] if report["self_ip"] else [])
    if self_ips:
        lines.append(f"(identified on the network as {', '.join(self_ips)})")
    lines.append("")

    if report["packet_count"] == 0:
        lines += [
            "No traffic has been analyzed yet for this container.",
            "If capture just started, wait for a pcap rotation (default 60s) and",
            "run 'nettap enrich' (or wait for auto-enrich), then generate this report again.",
        ]
        return "\n".join(_printable(line) for line in lines)

    start, end = _fmt_time(report["start"]), _fmt_time(report["end"])
    if start and end:
        lines.append(f"Time window covered: {start}  to  {end}")
    lines.append(
        f"Total traffic seen: {format_bytes(report['total_bytes'])} "
        f"across {report['packet_count']} packets"
    )
    lines.append(f"  - sent by this container:     {format_bytes(report['sent_bytes'])} "
                 f"({report['sent_packets']} packets)")
    lines.append(f"  - received by this container: {format_bytes(report['received_bytes'])} "
                 f"({report['received_packets']} packets)")
    lines.append("")

    lines.append("Other containers it talked to:")
    if report["container_peers"]:
        for r in report["container_peers"]:
            lines.append(f"  - {r['container']}: {format_bytes(r['bytes'])} across "
                         f"{r['packets']} packets (sent {format_bytes(r['sent_bytes'])}, "
                         f"received {format_bytes(r['received_bytes'])})")
    else:
        lines.append("  (none observed)")
    lines.append("")

    lines.append("Internet destinations it reached:")
    if report["external_destinations"]:
        for r in report["external_destinations"]:
            label = r.get("hostname") or r["dst_ip"]
            extra = f" ({r['dst_ip']})" if r.get("hostname") else ""
            lines.append(f"  - {label}{extra}: {format_bytes(r['bytes'])} across {r['packets']} packets")
    else:
        lines.append("  (none - no traffic left the Docker network)")
    lines.append("")

    local = report.get("local_destinations") or []
    if local:
        lines.append("Local / private network addresses it reached (not the internet):")
        for r in local:
            hint = f" - {r['hint']}" if r.get("hint") else ""
            lines.append(f"  - {r['dst_ip']}: {format_bytes(r['bytes'])} "
                         f"across {r['packets']} packets{hint}")
        lines.append("")

    if report["dns_queries"]:
        lines.append("Domain names it looked up (DNS):")
        for r in report["dns_queries"]:
            n = r["lookups"]
            lines.append(f"  - {r['dns_query']} ({n} lookup{'s' if n != 1 else ''})")
        lines.append("")

    if report["protocols"]:
        lines.append("Protocol mix:")
        for r in report["protocols"]:
            lines.append(f"  - {r['protocol'] or 'unknown'}: "
                         f"{format_bytes(r['bytes'])} across {r['packets']} packets")
        lines.append("")

    lines.append(
        "Note: this only covers what crossed this container's own network interface "
        "(plus its lookups to Docker's built-in DNS server), "
        "and only metadata (addresses, sizes, hostnames) - not the contents of encrypted "
        "(TLS/HTTPS) connections. nettap doesn't judge what's normal for your setup; review "
        "the destinations above yourself."
    )
    return "\n".join(_printable(line) for line in lines)


def _bar(bytes_: int, max_bytes: int) -> str:
    pct = 0 if not max_bytes else max(2, round(100 * (bytes_ or 0) / max_bytes))
    return f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>'


def render_html(report: dict) -> str:
    def esc(s: str) -> str:
        return html_escape.escape(_printable(s))

    c = esc(report["container"])

    if report["packet_count"] == 0:
        body = (
            "<p class='empty'>No traffic has been analyzed yet for this container. "
            "If capture just started, wait for a pcap rotation (default 60s), run "
            "<code>nettap enrich</code>, then regenerate this report.</p>"
        )
    else:
        start, end = _fmt_time(report["start"]), _fmt_time(report["end"])
        peer_max = max([r["bytes"] or 0 for r in report["container_peers"]], default=0)
        ext_max = max([r["bytes"] or 0 for r in report["external_destinations"]], default=0)

        peers_html = "".join(
            f"<div class='row'><div class='row-label'>{esc(r['container'])}</div>"
            f"{_bar(r['bytes'], peer_max)}"
            f"<div class='row-value'>{format_bytes(r['bytes'])}</div></div>"
            for r in report["container_peers"]
        ) or "<p class='empty'>No traffic to other containers on this host was observed.</p>"

        def _ext_row(r):
            label = esc(r.get("hostname") or r["dst_ip"])
            suffix = f" <span class='muted'>({esc(r['dst_ip'])})</span>" if r.get("hostname") else ""
            return (
                f"<div class='row'><div class='row-label'>{label}{suffix}</div>"
                f"{_bar(r['bytes'], ext_max)}"
                f"<div class='row-value'>{format_bytes(r['bytes'])}</div></div>"
            )

        ext_html = "".join(_ext_row(r) for r in report["external_destinations"]) or \
            "<p class='empty'>No traffic left the Docker network to the internet.</p>"

        local = report.get("local_destinations") or []
        local_max = max([r["bytes"] or 0 for r in local], default=0)
        local_html = "".join(
            f"<div class='row'><div class='row-label' title='{esc(r.get('hint') or '')}'>"
            f"{esc(r['dst_ip'])}"
            + (f" <span class='muted'>({esc(r['hint'])})</span>" if r.get("hint") else "")
            + f"</div>{_bar(r['bytes'], local_max)}"
            f"<div class='row-value'>{format_bytes(r['bytes'])}</div></div>"
            for r in local
        )
        local_section = (
            "<h2>Local / private network addresses it reached (not the internet)</h2>"
            f"<div class='rows'>{local_html}</div>"
        ) if local else ""

        dns_html = "".join(
            f"<li>{esc(r['dns_query'])} <span class='muted'>"
            f"({r['lookups']} lookup{'s' if r['lookups'] != 1 else ''})</span></li>"
            for r in report["dns_queries"]
        ) or "<li class='muted'>none observed</li>"

        proto_html = "".join(
            f"<tr><td>{esc(r['protocol'] or 'unknown')}</td>"
            f"<td>{format_bytes(r['bytes'])}</td><td>{r['packets']}</td></tr>"
            for r in report["protocols"]
        )

        body = f"""
        <div class="summary-grid">
          <div class="stat"><div class="stat-value">{format_bytes(report['total_bytes'])}</div><div class="stat-label">total traffic</div></div>
          <div class="stat"><div class="stat-value">{report['packet_count']}</div><div class="stat-label">packets</div></div>
          <div class="stat"><div class="stat-value">{format_bytes(report['sent_bytes'])}</div><div class="stat-label">sent</div></div>
          <div class="stat"><div class="stat-value">{format_bytes(report['received_bytes'])}</div><div class="stat-label">received</div></div>
        </div>
        {f"<p class='window'>Time window: {esc(start)} &nbsp;to&nbsp; {esc(end)}</p>" if start and end else ""}

        <h2>Other containers it talked to</h2>
        <div class="rows">{peers_html}</div>

        <h2>Internet destinations it reached</h2>
        <div class="rows">{ext_html}</div>

        {local_section}

        <h2>Domain names it looked up (DNS)</h2>
        <ul class="dns-list">{dns_html}</ul>

        <h2>Protocol mix</h2>
        <table>
          <thead><tr><th>Protocol</th><th>Bytes</th><th>Packets</th></tr></thead>
          <tbody>{proto_html}</tbody>
        </table>

        <p class="note">This only covers what crossed this container's own network interface
        (plus its lookups to Docker's built-in DNS server), and only metadata (addresses, sizes, hostnames) - not the contents of encrypted
        (TLS/HTTPS) connections. Nothing above has been judged "normal" or "suspicious" -
        review it yourself.</p>
        """

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Traffic report: {c}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
          max-width: 780px; margin: 40px auto; padding: 0 20px; line-height: 1.5;
          background: #fff; color: #1a1a1a; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #16171a; color: #e8e8ea; }}
    .stat, table, .row {{ background: #202226 !important; border-color: #333 !important; }}
    .bar-track {{ background: #333 !important; }}
    code {{ background: #2a2c30 !important; }}
  }}
  h1 {{ font-size: 1.5rem; margin-bottom: 4px; }}
  h2 {{ font-size: 1.05rem; margin-top: 32px; border-bottom: 1px solid #ddd; padding-bottom: 6px; }}
  .subtitle {{ color: #888; margin-top: 0; }}
  .window {{ color: #888; font-size: 0.9rem; }}
  .summary-grid {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 20px 0; }}
  .stat {{ flex: 1; min-width: 120px; background: #f6f6f7; border: 1px solid #eee;
           border-radius: 10px; padding: 14px 16px; text-align: center; }}
  .stat-value {{ font-size: 1.4rem; font-weight: 600; }}
  .stat-label {{ color: #888; font-size: 0.8rem; text-transform: uppercase; letter-spacing: .03em; }}
  .rows {{ display: flex; flex-direction: column; gap: 8px; }}
  .row {{ display: grid; grid-template-columns: 200px 1fr 90px; align-items: center; gap: 10px;
          background: #f9f9fa; border: 1px solid #eee; border-radius: 8px; padding: 8px 12px; }}
  .row-label {{ font-size: 0.9rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .row-value {{ text-align: right; font-variant-numeric: tabular-nums; font-size: 0.9rem; color: #555; }}
  .bar-track {{ background: #eaeaec; border-radius: 4px; height: 8px; overflow: hidden; }}
  .bar-fill {{ background: #6f8bff; height: 100%; }}
  .dns-list {{ columns: 2; }}
  .muted {{ color: #999; font-size: 0.85em; }}
  table {{ width: 100%; border-collapse: collapse; background: #f9f9fa; border: 1px solid #eee; border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 0.9rem; }}
  code {{ background: #f1f1f1; padding: 1px 5px; border-radius: 4px; }}
  .note {{ margin-top: 28px; color: #888; font-size: 0.85rem; }}
  .empty {{ color: #888; }}
</style></head>
<body>
  <h1>Traffic report: {c}</h1>
  <p class="subtitle">What this container sent and received, in plain language.</p>
  {body}
</body></html>"""
