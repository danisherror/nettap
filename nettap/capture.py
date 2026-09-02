"""Starts/stops per-container tcpdump captures on the veth resolved by
discovery.py, rotating pcap files so a long-running capture doesn't grow
unbounded."""
from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .discovery import ContainerNetInfo

logger = logging.getLogger("nettap.capture")


def _pump_stderr(name: str, pipe) -> None:
    """Relay a tcpdump child's stderr into our own logging instead of letting
    it sit in an unread pipe - this is what makes 'docker logs <nettap
    container>' actually show tcpdump's own "listening on eth0..." line and,
    more importantly, any error it hits (bad interface, permission denied,
    etc). Runs on its own daemon thread for the life of the subprocess."""
    try:
        for line in iter(pipe.readline, ""):
            line = line.rstrip()
            if line:
                logger.info("tcpdump[%s]: %s", name, line)
    except (ValueError, OSError):
        pass  # pipe closed underneath us, e.g. during detach() - not an error
    finally:
        try:
            pipe.close()
        except OSError:
            pass


@dataclass
class CaptureSession:
    info: ContainerNetInfo
    process: subprocess.Popen
    pcap_pattern: str
    started_at: float = field(default_factory=time.time)


class CaptureManager:
    """Owns one tcpdump subprocess per attached container."""

    def __init__(self, data_dir: str, rotate_seconds: int = 60, snaplen: int = 0):
        self.data_dir = Path(data_dir)
        self.pcap_dir = self.data_dir / "pcap"
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.rotate_seconds = rotate_seconds
        self.snaplen = snaplen
        self._sessions: dict[str, CaptureSession] = {}
        self._require_tcpdump()

    @staticmethod
    def _require_tcpdump() -> None:
        if shutil.which("tcpdump") is None:
            raise RuntimeError(
                "tcpdump not found on PATH - install it (the provided Dockerfile does)"
            )

    def is_attached(self, container_id: str) -> bool:
        return container_id in self._sessions

    def attached_ids(self) -> set[str]:
        return set(self._sessions.keys())

    def attach(self, info: ContainerNetInfo) -> CaptureSession | None:
        if info.uses_host_network:
            logger.warning(
                "%s uses --network host: no dedicated veth exists, skipping "
                "(see TODO.md: host-network attribution needs the eBPF path)",
                info.name,
            )
            return None
        if not info.veth:
            logger.warning("could not resolve host veth for %s, skipping", info.name)
            return None
        if info.container_id in self._sessions:
            return self._sessions[info.container_id]

        safe_name = info.name.lstrip("/").replace("/", "_")
        pattern = str(self.pcap_dir / f"{safe_name}_%Y%m%d%H%M%S.pcap")

        cmd = [
            "tcpdump",
            "-i", info.veth,
            "-w", pattern,
            "-G", str(self.rotate_seconds),
            "-U",   # flush each packet so files are readable while capturing
            "-n",   # skip name resolution, keeps capture cheap
        ]
        if self.snaplen:
            cmd += ["-s", str(self.snaplen)]

        logger.info("attaching to %s on %s -> %s", info.name, info.veth, pattern)
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        if proc.stderr:
            threading.Thread(target=_pump_stderr, args=(info.name, proc.stderr), daemon=True).start()
        session = CaptureSession(info=info, process=proc, pcap_pattern=pattern)
        self._sessions[info.container_id] = session
        return session

    def detach(self, container_id: str) -> None:
        session = self._sessions.pop(container_id, None)
        if not session:
            return
        logger.info("detaching from %s", session.info.name)
        session.process.terminate()
        try:
            session.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            session.process.kill()

    def detach_all(self) -> None:
        for cid in list(self._sessions):
            self.detach(cid)

    def restart_dead(self) -> list[CaptureSession]:
        """Find capture sessions whose tcpdump process exited on its own
        (crash, killed interface, etc.) and restart them against the same
        target. Without this, a capture that dies quietly just stops
        producing new pcaps forever - the symptom being "the report stopped
        updating" with no visible error. Returns the newly (re)started
        sessions so the caller can refresh anything it's tracking (e.g. the
        live_sessions DB row's pid)."""
        restarted = []
        for cid, session in list(self._sessions.items()):
            returncode = session.process.poll()
            if returncode is not None:
                logger.warning(
                    "capture for %s (pid %s) exited unexpectedly (code %s) - restarting",
                    session.info.name, session.process.pid, returncode,
                )
                del self._sessions[cid]
                new_session = self.attach(session.info)
                if new_session:
                    restarted.append(new_session)
        return restarted

    def status(self) -> list[dict]:
        out = []
        for session in self._sessions.values():
            alive = session.process.poll() is None
            out.append(
                {
                    "container": session.info.name,
                    "container_id": session.info.container_id,
                    "veth": session.info.veth,
                    "pcap_pattern": session.pcap_pattern,
                    "alive": alive,
                    "started_at": session.started_at,
                }
            )
        return out
