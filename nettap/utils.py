"""Small shared helpers: subprocess wrapper, logging setup, label parsing,
terminal-safe text and tables."""
from __future__ import annotations

import logging
import subprocess
import unicodedata
from typing import Sequence


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


def run(cmd: Sequence[str], timeout: float = 10.0, check: bool = True) -> str:
    """Run a command and return stdout as text. Raises on non-zero exit if check=True."""
    proc = subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stderr: {proc.stderr.strip()}"
        )
    return proc.stdout


def parse_label_selector(selector: str | None) -> dict[str, str]:
    """Parse 'a=b,c=d' into {'a': 'b', 'c': 'd'}. Empty/None -> {}."""
    if not selector:
        return {}
    out: dict[str, str] = {}
    for pair in selector.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError(f"invalid label selector segment: {pair!r} (expected key=value)")
        k, v = pair.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def printable(s: str) -> str:
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


def format_table(rows: list[dict], max_width: int = 60) -> str:
    """Rows of dicts as an aligned plain-text table for the terminal. Columns
    are every key seen, in first-seen order (rows may differ, e.g. only local
    destinations have a `hint`). Byte counts are shown human-readable, long
    cells are cut at `max_width` - the JSON output has the full values."""
    if not rows:
        return "(no rows)"
    columns: list[str] = []
    for row in rows:
        columns += [k for k in row if k not in columns]

    def cell(key, value):
        if value is None:
            return ""
        if key == "bytes" or key.endswith("_bytes"):
            return format_bytes(value)
        if isinstance(value, (list, tuple)):
            value = ", ".join(map(str, value))
        text = printable(str(value))
        return text if len(text) <= max_width else text[:max_width - 3] + "..."

    table = [[cell(k, row.get(k)) for k in columns] for row in rows]
    numeric = [all(isinstance(row.get(k), (int, float)) or row.get(k) is None for row in rows)
               for k in columns]
    widths = [max(len(k), *(len(r[i]) for r in table)) for i, k in enumerate(columns)]

    def line(cells):
        return "  ".join(c.rjust(w) if num else c.ljust(w)
                         for c, w, num in zip(cells, widths, numeric)).rstrip()

    return "\n".join([line(columns), line(["-" * w for w in widths]), *map(line, table)])


_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> float:
    """'90' or '90s' -> 90.0, '5m' -> 300.0, '2h', '1d'. Raises ValueError."""
    text = (text or "").strip().lower()
    unit = text[-1:] if text[-1:] in _DURATION_UNITS else "s"
    number = text[:-1] if text[-1:] in _DURATION_UNITS else text
    value = float(number)
    if value < 0:
        raise ValueError(f"negative duration: {text!r}")
    return value * _DURATION_UNITS[unit]


def parse_time(text: str, now: float | None = None) -> float:
    """A point in time as a Unix timestamp, from:
    - a duration meaning "that long ago": '15m', '2h', '1d';
    - Unix seconds: '1762700000';
    - an ISO 8601 date/time: '2026-11-09', '2026-11-09T12:30', '2026-11-09 12:30:00+00:00'
      (local time when no offset is given, like the timestamps tcpdump puts in pcap names).
    Raises ValueError."""
    import time as _time
    from datetime import datetime

    text = (text or "").strip()
    if text[-1:].lower() in _DURATION_UNITS:
        try:
            return (now if now is not None else _time.time()) - parse_duration(text)
        except ValueError:
            pass
    try:
        return float(text)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"not a time: {text!r} (use e.g. 15m, 2h, 2026-11-09T12:30 "
                         f"or Unix seconds)") from None
    return dt.timestamp()  # naive -> local time
