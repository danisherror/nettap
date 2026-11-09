"""What changed between two captures: `nettap report --compare`.

Takes two report dicts from report.build_report() - a baseline and the
current one, e.g. two `nettap inspect` runs of different image versions, or
one container before and after an upgrade (a time window each, see
storage.window) - and lists, per kind of destination, what is new, what is
no longer contacted and what changed a lot in bytes.

Internet destinations are matched by hostname when one was seen (a CDN name
often resolves to different addresses from one run to the next), else by
address. Bytes aren't scaled by how long each capture ran, so the time
window of both is shown next to the changes.
"""
from __future__ import annotations

# A destination counts as "changed" when its bytes grew or shrank by at least
# this factor, and by at least MIN_CHANGE_BYTES - so a 100 B -> 300 B
# difference in a few packets doesn't show up as a change.
CHANGE_FACTOR = 2.0
MIN_CHANGE_BYTES = 10 * 1024


def _internet(report: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in report.get("external_destinations") or []:
        key = r.get("hostname") or r["dst_ip"]
        row = out.setdefault(key, {"name": key, "addresses": set(), "bytes": 0})
        row["addresses"].add(r["dst_ip"])
        row["bytes"] += r["bytes"] or 0
    for row in out.values():
        addrs = sorted(row.pop("addresses") - {row["name"]})
        row["detail"] = ", ".join(addrs) or None
    return out


def _local(report: dict) -> dict[str, dict]:
    # Multicast, link-local etc. aren't destinations, and some change every
    # run: IPv6 neighbour discovery uses a multicast group derived from the
    # container's own address (ff02::1:ffXX:XXXX, RFC 4291 section 2.7.1).
    from .check import always_allowed
    return {r["dst_ip"]: {"name": r["dst_ip"], "detail": r.get("hint"), "bytes": r["bytes"] or 0}
            for r in report.get("local_destinations") or [] if not always_allowed(r["dst_ip"])}


def _peers(report: dict) -> dict[str, dict]:
    return {r["container"]: {"name": r["container"], "detail": None, "bytes": r["bytes"] or 0}
            for r in report.get("container_peers") or []}


def _dns(report: dict) -> dict[str, dict]:
    return {r["dns_query"]: {"name": r["dns_query"], "detail": None, "lookups": r["lookups"]}
            for r in report.get("dns_queries") or []}


SECTIONS = (
    ("containers", "Other containers", _peers),
    ("internet", "Internet destinations", _internet),
    ("local", "Local / private network addresses", _local),
    ("dns", "Domain names looked up", _dns),
)


def _big_change(before: int, after: int) -> bool:
    lo, hi = sorted((before, after))
    return hi - lo >= MIN_CHANGE_BYTES and (lo == 0 or hi / lo >= CHANGE_FACTOR)


def compare(baseline: dict, current: dict, baseline_label: str, current_label: str) -> dict:
    """{"baseline": {...}, "current": {...}, "sections": [...], "changed": bool}.
    Each section: {"key", "title", "new", "gone", "changed"}; items in
    new/gone are {"name", "detail", "bytes"} (DNS: "lookups" instead of
    bytes), changed items {"name", "detail", "before_bytes", "after_bytes"}.
    Biggest first."""
    sections = []
    for key, title, pick in SECTIONS:
        a, b = pick(baseline), pick(current)
        size = (lambda r: r.get("lookups", 0)) if key == "dns" else (lambda r: r["bytes"])
        new = sorted((b[k] for k in b.keys() - a.keys()), key=lambda r: (-size(r), r["name"]))
        gone = sorted((a[k] for k in a.keys() - b.keys()), key=lambda r: (-size(r), r["name"]))
        changed = []
        if key != "dns":
            for k in a.keys() & b.keys():
                if _big_change(a[k]["bytes"], b[k]["bytes"]):
                    changed.append({"name": k, "detail": b[k]["detail"] or a[k]["detail"],
                                    "before_bytes": a[k]["bytes"], "after_bytes": b[k]["bytes"]})
            changed.sort(key=lambda r: (-abs(r["after_bytes"] - r["before_bytes"]), r["name"]))
        sections.append({"key": key, "title": title, "new": new, "gone": gone, "changed": changed})

    def side(report, label):
        return {"label": label, "container": report["container"], "start": report["start"],
                "end": report["end"], "total_bytes": report["total_bytes"],
                "packet_count": report["packet_count"]}

    return {
        "baseline": side(baseline, baseline_label),
        "current": side(current, current_label),
        "sections": sections,
        "changed": any(s["new"] or s["gone"] or s["changed"] for s in sections),
    }
