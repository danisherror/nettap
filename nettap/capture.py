"""Starts/stops per-container tcpdump captures on the veth resolved by
discovery.py, rotating pcap files so a long-running capture doesn't grow
unbounded."""
from __future__ import annotations

import ctypes
import ctypes.util
import glob
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .discovery import ContainerNetInfo

logger = logging.getLogger("nettap.capture")

_PR_SET_PDEATHSIG = 1  # from <linux/prctl.h>


def _load_prctl():
    """libc's prctl, looked up once in the parent so the forked child only
    has to call it. None off Linux."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True).prctl
    except (OSError, AttributeError):
        return None


_prctl = _load_prctl()


def _die_with_parent(parent_pid: int):
    """preexec_fn for tcpdump: have the kernel send it SIGTERM when nettap
    dies, even by SIGKILL, so captures aren't left running as orphans.
    The signal fires when the *thread* that started the child exits, so
    attach() must be called from a long-lived thread (watch and sidecar
    both call it from the main thread). See prctl(2):
    https://man7.org/linux/man-pages/man2/prctl.2.html"""
    def fn():
        _prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
        if os.getppid() != parent_pid:  # parent already gone before prctl ran
            os._exit(1)
    return fn


def _cmdline(pid: int) -> str | None:
    """A process's command line, space-joined, or None if it isn't running
    (or we can't see it)."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw.replace(b"\0", b" ").decode(errors="replace").strip()
    except FileNotFoundError:
        if Path("/proc").is_dir():
            return None
    except OSError:
        return None
    try:  # no /proc (macOS)
        out = subprocess.run(["ps", "-p", str(pid), "-o", "args="],
                             capture_output=True, text=True, check=False)
    except OSError:
        return None
    return out.stdout.strip() or None


def reap_orphans(sessions: list[dict]) -> list[int]:
    """Kill tcpdumps left behind by an earlier nettap that died without
    cleaning up, using the rows it left in live_sessions. A pid is only
    killed if it is still tcpdump writing that row's pcap pattern, so a pid
    reused by something else is left alone. Returns the pids killed.

    On Linux the PDEATHSIG set in attach() normally stops orphans happening
    at all, and inside the nettap container the kernel kills every child
    when nettap (PID 1) exits; this is the backstop for everything else."""
    killed = []
    captures = [(row, row.get(pid_key), row.get(pattern_key))
                for row in sessions
                for pid_key, pattern_key in (("pid", "pcap_pattern"),
                                             ("dns_pid", "dns_pcap_pattern"))]
    for row, pid, pattern in captures:
        if not pid or not pattern or pid == os.getpid():
            continue
        cmd = _cmdline(pid)
        if not cmd or "tcpdump" not in cmd.split(" ", 1)[0] or pattern not in cmd:
            continue
        logger.warning("killing orphaned tcpdump for %s (pid %s) left by an earlier run",
                       row.get("container_name"), pid)
        try:
            os.kill(pid, signal.SIGTERM)
            killed.append(pid)
        except ProcessLookupError:
            pass
        except PermissionError:
            logger.warning("no permission to kill orphaned tcpdump pid %s", pid)
    return killed


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


_TS = "%Y%m%d%H%M%S"  # tcpdump -G fills this in when it rotates
_PCAP_NAME = re.compile(r"^(?P<name>.+)_(?P<ts>\d{14})(?P<kind>\.dns)?\.pcap$")

# Docker's embedded DNS server. Containers on user-defined networks (every
# Compose network included) resolve names through it, over their own `lo`,
# so those lookups never cross eth0 or the host-side veth.
# https://docs.docker.com/engine/network/#dns-services
EMBEDDED_DNS = "127.0.0.11"
DNS_SUFFIX = ".dns"  # web_<ts>.dns.pcap holds web's lookups to EMBEDDED_DNS


def capture_name(path) -> str | None:
    """The container name a pcap written by nettap belongs to
    ('web_20261108120000.pcap' or '...dns.pcap' -> 'web'), else None."""
    m = _PCAP_NAME.match(Path(path).name)
    return m["name"] if m else None


def pcap_files(pattern: str) -> list[str]:
    """The files tcpdump has written for one -w pattern, oldest first. A
    plain glob on the pattern would also match other captures' files, e.g.
    web_2_<ts>.pcap or web_<ts>.dns.pcap for the pattern web_<ts>.pcap."""
    exact = re.compile(re.escape(pattern).replace(re.escape(_TS), r"\d{14}") + "$")
    return sorted(p for p in glob.glob(pattern.replace(_TS, "*")) if exact.match(p))


def pcap_opened_at(path) -> float | None:
    """When tcpdump opened this file, from the timestamp in its name (which
    tcpdump formats in local time - nettap runs in the same environment)."""
    m = _PCAP_NAME.match(Path(path).name)
    return time.mktime(time.strptime(m["ts"], _TS)) if m else None


def finished_pcaps(pattern: str, rotate_seconds: float, now: float | None = None,
                   slack: float = 2.0) -> list[str]:
    """The files for one -w pattern that tcpdump won't write to again.

    That's every file but the newest, and the newest too once its rotation
    interval has passed: tcpdump's -G only rotates when a packet arrives,
    and writes that packet to the new file, so a container that went quiet
    leaves its last file open but complete (dump_packet_and_trunc() in
    https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.c).
    Waiting for the next packet instead used to hold back the last traffic
    of an idle container indefinitely (seen live 2026-11-08). Assumes no -C
    (size-based rotation), which would reuse the timestamp."""
    files = pcap_files(pattern)
    if files:
        opened = pcap_opened_at(files[-1])
        if opened is None or opened + rotate_seconds + slack > (now or time.time()):
            files = files[:-1]
    return files


def purge_pcaps(pcap_dir, max_age_seconds: float | None = None,
                max_bytes: int | None = None, now: float | None = None) -> list[Path]:
    """Delete pcaps oldest-first (by mtime) until none is older than
    max_age_seconds and the directory's pcaps total at most max_bytes.

    The newest file of each capture (`<name>_<timestamp>[.dns].pcap`) is never
    deleted, since tcpdump may still be writing it - possibly a capture run
    by another nettap sharing this directory, like several sidecars on one
    data volume. Those files still count toward max_bytes. Returns the
    deleted paths."""
    if max_age_seconds is None and max_bytes is None:
        return []
    now = time.time() if now is None else now
    files = []
    newest: dict[str, str] = {}
    for path in Path(pcap_dir).glob("*.pcap"):
        try:
            st = path.stat()
        except FileNotFoundError:
            continue
        files.append((st.st_mtime, st.st_size, path))
        m = _PCAP_NAME.match(path.name)
        if m:
            capture = m["name"] + (m["kind"] or "")
            if path.name > newest.get(capture, ""):
                newest[capture] = path.name  # timestamped names sort by time
    keep = set(newest.values())
    files.sort()
    total = sum(size for _, size, _ in files)
    deleted = []
    for mtime, size, path in files:
        too_old = max_age_seconds is not None and now - mtime > max_age_seconds
        too_big = max_bytes is not None and total > max_bytes
        if not (too_old or too_big):
            break  # sorted oldest-first, so every later file is within limits
        if path.name in keep:
            continue
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("could not delete old pcap %s: %s", path, exc)
            continue
        total -= size
        deleted.append(path)
    if deleted:
        logger.info("retention: deleted %d old pcap(s), %d bytes of pcaps left",
                    len(deleted), total)
    return deleted


@dataclass
class CaptureSession:
    info: ContainerNetInfo
    process: subprocess.Popen
    pcap_pattern: str
    rotate_seconds: int = 60
    started_at: float = field(default_factory=time.time)
    # second tcpdump on the container's lo, for lookups to EMBEDDED_DNS
    dns_process: subprocess.Popen | None = None
    dns_pcap_pattern: str | None = None


class CaptureManager:
    """Owns the tcpdump subprocesses for each attached container: one on its
    interface and one on its `lo` that only records lookups to Docker's
    embedded DNS server (see EMBEDDED_DNS).

    `own_netns` is for `sidecar`, which shares the target's network
    namespace: its `lo` is the target's. Otherwise (`watch`) the DNS capture
    enters the container's namespace through its SandboxKey with nsenter."""

    def __init__(self, data_dir: str, rotate_seconds: int = 60, snaplen: int = 0,
                 max_age_seconds: float | None = None, max_bytes: int | None = None,
                 own_netns: bool = False):
        self.data_dir = Path(data_dir)
        self.pcap_dir = self.data_dir / "pcap"
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.rotate_seconds = rotate_seconds
        self.snaplen = snaplen
        self.max_age_seconds = max_age_seconds
        self.max_bytes = max_bytes
        self.own_netns = own_netns
        self._last_purge = 0.0
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

        pattern = str(self.pcap_dir / f"{self._safe_name(info)}_{_TS}.pcap")
        logger.info("attaching to %s on %s -> %s", info.name, info.veth, pattern)
        proc = self._spawn(info.name, self._tcpdump_cmd(info.veth, pattern))
        session = CaptureSession(info=info, process=proc, pcap_pattern=pattern,
                                 rotate_seconds=self.rotate_seconds)
        self._start_dns(session)
        self._sessions[info.container_id] = session
        return session

    @staticmethod
    def _safe_name(info: ContainerNetInfo) -> str:
        return info.name.lstrip("/").replace("/", "_")

    def _tcpdump_cmd(self, iface: str, pattern: str) -> list[str]:
        cmd = [
            "tcpdump",
            "-i", iface,
            "-w", pattern,
            "-G", str(self.rotate_seconds),
            "-U",   # flush each packet so files are readable while capturing
            "-n",   # skip name resolution, keeps capture cheap
        ]
        if self.snaplen:
            cmd += ["-s", str(self.snaplen)]
        if _prctl:
            # Debian's tcpdump otherwise switches to a 'tcpdump' user, and a
            # user change clears the parent-death signal (prctl(2)) - seen in
            # a live test 2026-11-08. With -w it writes raw packets without
            # decoding them, so staying root adds little risk.
            cmd += ["-Z", "root"]
        return cmd

    def _spawn(self, label: str, cmd: list[str]) -> subprocess.Popen:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1,
            preexec_fn=_die_with_parent(os.getpid()) if _prctl else None,
        )
        if proc.stderr:
            threading.Thread(target=_pump_stderr, args=(label, proc.stderr), daemon=True).start()
        return proc

    def _start_dns(self, session: CaptureSession) -> None:
        """Start the embedded-DNS capture on the container's lo. Filtered by
        host, not port: Docker NATs port 53 on 127.0.0.11 to a random port
        (seen live 2026-11-08). Not -i any, which would also take in the
        app's own localhost traffic and see each loopback packet twice."""
        info = session.info
        if self.own_netns:
            prefix = []
        elif info.sandbox_key:
            # nsenter execs tcpdump in place (it only forks for --pid/--fork),
            # so the parent-death signal set before the exec still applies.
            # https://man7.org/linux/man-pages/man1/nsenter.1.html
            prefix = ["nsenter", f"--net={info.sandbox_key}"]
        else:
            return
        pattern = str(self.pcap_dir / f"{self._safe_name(info)}_{_TS}{DNS_SUFFIX}.pcap")
        logger.info("capturing %s's lookups to %s on its lo -> %s", info.name, EMBEDDED_DNS, pattern)
        session.dns_pcap_pattern = pattern
        session.dns_process = self._spawn(
            f"{info.name}/lo", prefix + self._tcpdump_cmd("lo", pattern) + ["host", EMBEDDED_DNS])

    @staticmethod
    def _stop(proc: subprocess.Popen | None) -> None:
        if proc is None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    def detach(self, container_id: str) -> None:
        session = self._sessions.pop(container_id, None)
        if not session:
            return
        logger.info("detaching from %s", session.info.name)
        self._stop(session.process)
        self._stop(session.dns_process)

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
        live_sessions DB row's pids). A dead DNS capture is restarted on its
        own, without touching the main one."""
        restarted = []
        for cid, session in list(self._sessions.items()):
            returncode = session.process.poll()
            if returncode is not None:
                logger.warning(
                    "capture for %s (pid %s) exited unexpectedly (code %s) - restarting",
                    session.info.name, session.process.pid, returncode,
                )
                del self._sessions[cid]
                self._stop(session.dns_process)
                new_session = self.attach(session.info)
                if new_session:
                    restarted.append(new_session)
            elif session.dns_process and session.dns_process.poll() is not None:
                logger.warning(
                    "DNS capture for %s (pid %s) exited unexpectedly (code %s) - restarting",
                    session.info.name, session.dns_process.pid, session.dns_process.poll(),
                )
                self._start_dns(session)
                restarted.append(session)
        return restarted

    def enforce_retention(self, min_interval: float = 30.0) -> list[Path]:
        """Apply the age/size limits to the whole pcap dir, at most once per
        min_interval seconds. Covers pcaps from earlier runs and other
        containers too, so the cap holds for the directory as a whole."""
        if self.max_age_seconds is None and self.max_bytes is None:
            return []
        now = time.time()
        if now - self._last_purge < min_interval:
            return []
        self._last_purge = now
        return purge_pcaps(self.pcap_dir, self.max_age_seconds, self.max_bytes, now=now)

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
                    "dns_pcap_pattern": session.dns_pcap_pattern,
                    "rotate_seconds": session.rotate_seconds,
                    "alive": alive,
                    "started_at": session.started_at,
                }
            )
        return out
