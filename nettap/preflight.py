"""Startup checks for common setup mistakes. Each failed check raises
SetupError with one line saying what's wrong and the exact fix, which the
CLI prints and exits non-zero on - instead of a traceback, or a tcpdump that
fails and gets restarted forever.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path
from shutil import which

import click

# bit numbers from <linux/capability.h>
CAP_BITS = {"NET_ADMIN": 12, "NET_RAW": 13, "SYS_PTRACE": 19, "SYS_ADMIN": 21}

DOCKER_SOCK = "/var/run/docker.sock"


class SetupError(click.ClickException):
    """A setup mistake the user can fix. Click prints "Error: <message>" and
    exits with status 1."""


def effective_caps(status_path: str = "/proc/self/status") -> int | None:
    """This process's effective capability set, or None if unknown."""
    try:
        with open(status_path) as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return None


def missing_caps(needed, status_path: str = "/proc/self/status",
                 euid: int | None = None, platform: str | None = None) -> list[str]:
    """The capabilities in `needed` this process lacks. Only checked for
    root on Linux (the Docker setup): a non-root user may instead run a
    tcpdump with file capabilities, which this can't see."""
    if not (platform or sys.platform).startswith("linux"):
        return []
    if (os.geteuid() if euid is None else euid) != 0:
        return []
    caps = effective_caps(status_path)
    if caps is None:
        return []
    return [name for name in needed if not caps >> CAP_BITS[name] & 1]


def require_caps(needed, **kw) -> None:
    """tcpdump needs NET_RAW (without it: "You don't have permission to
    perform this capture"); watch's nsenter needs SYS_ADMIN. Seen live
    2026-11-09 with `docker run --cap-drop NET_RAW`."""
    missing = missing_caps(needed, **kw)
    if missing:
        flags = " ".join(f"--cap-add {c}" for c in missing)
        raise SetupError(
            f"missing Linux capabilit{'y' if len(missing) == 1 else 'ies'} "
            f"{', '.join(missing)} - start the nettap container with {flags} "
            f"(or cap_add: [{', '.join(missing)}] in docker-compose.yml)")


def require_tools(*tools: str) -> None:
    missing = [t for t in tools if which(t) is None]
    if missing:
        raise SetupError(
            f"{' and '.join(missing)} not found on PATH - run nettap from its Docker "
            f"image (docker build -t nettap .), or install {' and '.join(missing)}")


def require_writable_dir(path, flag: str = "--data-dir") -> None:
    """Create `path` if needed and make sure files can be written in it."""
    p = Path(path)
    try:
        p.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=p, prefix=".nettap-write-test-"):
            pass
    except OSError as e:
        reason = e.strerror or str(e)
        raise SetupError(
            f"can't write to data directory '{p}' ({reason}) - pass {flag} with a "
            f"writable directory, or make the mounted one writable "
            f"(drop :ro from the mount, or chmod -R u+rwX ./data on the host)") from None


def docker_client(env=None, sock: str | None = None, need: str = ""):
    """docker.from_env(), pinged, or SetupError saying how to give access.
    `need` names the option that needs Docker (e.g. "--docker-api")."""
    import docker

    env = os.environ if env is None else env
    sock = sock or DOCKER_SOCK
    who = f"{need} needs" if need else "nettap needs"
    mount = f"-v {sock}:{sock}"
    if not env.get("DOCKER_HOST"):
        if not os.path.exists(sock):
            raise SetupError(f"{who} the Docker API, but there's no {sock} here - "
                             f"mount it with {mount}")
        if not os.access(sock, os.R_OK | os.W_OK):
            raise SetupError(f"{who} the Docker API, but {sock} isn't readable and "
                             f"writable by this user - run nettap as root, or add the "
                             f"user to the docker group")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        if env.get("DOCKER_HOST"):
            where, fix = env["DOCKER_HOST"], "check that Docker is running there, or unset DOCKER_HOST"
        else:
            where, fix = sock, f"check that Docker is running and {mount} is mounted"
        raise SetupError(f"{who} the Docker API, but {where} isn't answering "
                         f"({_short_reason(e)}) - {fix}") from None
    return client


def _short_reason(exc: Exception) -> str:
    """The OS-level cause buried in docker/requests' nested error text, e.g.
    "Connection refused" instead of three lines of urllib3 wrappers."""
    text = str(exc)
    m = re.search(r"\[Errno -?\d+\] ([^'\")\]]+)", text)
    if m:
        return m.group(1).strip()
    return text if len(text) <= 120 else text[:117] + "..."
