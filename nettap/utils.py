"""Small shared helpers: subprocess wrapper, logging setup, label parsing."""
from __future__ import annotations

import logging
import subprocess
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
