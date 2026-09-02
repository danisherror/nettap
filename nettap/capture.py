"""Starts/stops per-container tcpdump captures on the veth resolved by
discovery.py, rotating pcap files so a long-running capture doesn't grow
unbounded."""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .discovery import ContainerNetInfo

logger = logging.getLogger("nettap.capture")


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
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
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
