"""`nettap inspect <image>`: run an image for a while and report everything
it contacted - one command instead of starting a container, a sidecar,
waiting, enriching and writing the report by hand.

The capture has to be running before the image's first packet: many images
phone home, resolve names or pull config the moment they start, and a
sidecar started after the target would miss exactly that. So the sidecar
starts first, in a network namespace of its own, and once its tcpdump is
listening the image runs in that namespace (`--network container:<sidecar>`,
the way a Kubernetes pod's containers share the pause container's
network). The image sees a normal network: its own eth0 and IP, DNS, any
published ports (set on the sidecar, which owns the namespace).

Steps, all through the Docker API (needs docker.sock):
  1. pull the image if it isn't there;
  2. start the sidecar and wait for "listening on eth0";
  3. run the image in the sidecar's network for --duration, or until it exits;
  4. stop the image, then the sidecar (tcpdump flushes the last packets);
  5. `nettap enrich` and `nettap report` (text and HTML) in one-off
     containers of the nettap image, so the host needs no tshark;
  6. remove every container it created (unless --keep-containers).
"""
from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

LABEL = "nettap.inspect"      # on every container this creates: the run name
LISTEN_TIMEOUT = 30.0         # seconds to wait for the sidecar's tcpdump
STOP_TIMEOUT = 10             # docker stop grace period for the image
# after the image stops, before stopping the sidecar: the image's last
# packets (e.g. a FIN after SIGTERM) are still on their way to the pcap
SETTLE_SECONDS = 1.0


class InspectError(Exception):
    """A step failed in a way the user should hear about in one line."""


def run_name(image: str, now: float | None = None) -> str:
    """'nginx:alpine' -> 'nginx-alpine-20261109-153000': usable as a
    container name and a pcap file name, and unique per second."""
    base = re.sub(r"[^a-zA-Z0-9_.-]+", "-", image.split("@", 1)[0]).strip("-.") or "image"
    stamp = datetime.fromtimestamp(now if now is not None else time.time()).strftime("%Y%m%d-%H%M%S")
    return f"{base[:60]}-{stamp}"


@dataclass
class InspectSpec:
    image: str
    command: list[str] = field(default_factory=list)
    name: str = ""                  # run name: what flows are labelled with
    duration: float = 60.0
    nettap_image: str = "nettap"
    data_source: str = ""           # mounted at /data in the sidecar and helpers
    network: str | None = None      # None: Docker's default bridge
    env: list[str] = field(default_factory=list)
    publish: dict = field(default_factory=dict)   # docker-py `ports`
    entrypoint: str | None = None
    rotate_seconds: int = 60
    baseline: str | None = None     # report --compare this earlier run
    keep_containers: bool = False

    @property
    def sidecar_name(self) -> str:
        return f"nettap-inspect-{self.name}-capture"

    @property
    def target_name(self) -> str:
        return f"nettap-inspect-{self.name}"

    @property
    def volumes(self) -> dict:
        return {self.data_source: {"bind": "/data", "mode": "rw"}}


def parse_publish(values) -> dict:
    """docker-py `ports` from -p values: '8080:80' -> {'80/tcp': 8080},
    '127.0.0.1:8080:80/udp' -> {'80/udp': ('127.0.0.1', 8080)}, '80' ->
    {'80/tcp': None} (a random host port)."""
    ports: dict = {}
    for value in values or ():
        spec, _, proto = value.partition("/")
        parts = spec.split(":")
        try:
            if len(parts) == 1:
                container, host = int(parts[0]), None
            elif len(parts) == 2:
                container, host = int(parts[1]), int(parts[0])
            elif len(parts) == 3:
                container, host = int(parts[2]), (parts[0], int(parts[1]))
            else:
                raise ValueError
        except ValueError:
            raise ValueError(f"bad --publish {value!r} (use e.g. 8080:80, 80 or "
                             f"127.0.0.1:8080:80/udp)") from None
        ports[f"{container}/{proto or 'tcp'}"] = host
    return ports


def ensure_image(client, image: str, echo) -> None:
    """Pull image unless Docker already has it."""
    import docker
    from docker.utils import parse_repository_tag

    try:
        client.images.get(image)
        return
    except docker.errors.ImageNotFound:
        pass
    repo, tag = parse_repository_tag(image)
    echo(f"pulling {image}...")
    try:
        client.images.pull(repo, tag=tag or "latest")
    except docker.errors.APIError as e:
        raise InspectError(f"can't pull {image}: {e.explanation or e}") from None


def _tail(container, lines: int = 20) -> str:
    try:
        return container.logs(tail=lines).decode(errors="replace").rstrip()
    except Exception:  # noqa: BLE001 - only used to explain a failure
        return ""


def _wait_listening(sidecar, stop: threading.Event, timeout: float = LISTEN_TIMEOUT) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline and not stop.is_set():
        sidecar.reload()
        if sidecar.status not in ("created", "running"):
            raise InspectError(f"the capture sidecar exited before it started capturing:\n"
                               f"{_tail(sidecar)}")
        if b"listening on eth0" in sidecar.logs():
            return
        time.sleep(0.5)
    if not stop.is_set():
        raise InspectError(f"the capture sidecar didn't start capturing within {timeout:g}s:\n"
                           f"{_tail(sidecar)}")


def run_once(client, spec: InspectSpec, command: list[str]) -> tuple[int, str]:
    """Run `nettap <command>` in a one-off container of the nettap image
    with the data mounted; (exit code, output)."""
    c = client.containers.create(spec.nettap_image, command, volumes=spec.volumes,
                                 labels={LABEL: spec.name})
    try:
        c.start()
        code = c.wait().get("StatusCode", 1)
        return code, c.logs(stdout=True, stderr=True).decode(errors="replace")
    finally:
        try:
            c.remove(force=True)
        except Exception:  # noqa: BLE001
            logger.debug("removing helper container failed", exc_info=True)


def inspect(client, spec: InspectSpec, stop: threading.Event | None = None,
            echo=print) -> dict:
    """Run the steps in the module docstring. Returns {"name", "exit_code"
    (None if the image was still running when time was up), "ran_seconds",
    "report_text", "report_html" (path inside /data)}. Raises InspectError."""
    stop = stop or threading.Event()
    ensure_image(client, spec.image, echo)
    created = []
    try:
        echo(f"starting capture for run {spec.name}...")
        sidecar = client.containers.run(
            spec.nettap_image,
            ["sidecar", "--target", spec.name, "--rotate-seconds", str(spec.rotate_seconds)],
            name=spec.sidecar_name, detach=True, network=spec.network,
            ports=spec.publish or None, cap_add=["NET_ADMIN", "NET_RAW"],
            volumes=spec.volumes, labels={LABEL: spec.name})
        created.append(sidecar)
        _wait_listening(sidecar, stop)

        target = None
        started = time.time()
        if not stop.is_set():
            echo(f"running {spec.image} for up to {spec.duration:g}s (Ctrl+C to stop early)...")
            target = client.containers.run(
                spec.image, spec.command or None, name=spec.target_name, detach=True,
                network_mode=f"container:{sidecar.id}", environment=spec.env or None,
                entrypoint=spec.entrypoint, labels={LABEL: spec.name})
            created.append(target)
            started = time.time()
            while not stop.is_set() and time.time() - started < spec.duration:
                target.reload()
                if target.status not in ("created", "running"):
                    break
                stop.wait(1.0)

        exit_code = None
        ran = time.time() - started
        if target is not None:
            target.reload()
            if target.status in ("created", "running"):
                echo(f"stopping {spec.image} after {ran:.0f}s...")
                target.stop(timeout=STOP_TIMEOUT)
            else:
                exit_code = (target.attrs.get("State") or {}).get("ExitCode")
                echo(f"{spec.image} exited with code {exit_code} after {ran:.0f}s")
                if exit_code:
                    tail = _tail(target)
                    if tail:
                        echo("its last output:\n" + "\n".join("  " + l for l in tail.splitlines()))
        time.sleep(SETTLE_SECONDS)
        sidecar.stop(timeout=30)  # SIGTERM: tcpdump writes out what it has

        echo("parsing the capture...")
        code, out = run_once(client, spec, ["enrich"])
        if code:
            raise InspectError(f"nettap enrich failed (exit {code}):\n{out.rstrip()}")
        compare = ["--compare", spec.baseline] if spec.baseline else []
        html = f"/data/{spec.name}_report.html"
        code, text = run_once(client, spec, ["report", "--container", spec.name, *compare])
        if code:
            raise InspectError(f"nettap report failed (exit {code}):\n{text.rstrip()}")
        code, out = run_once(client, spec, ["report", "--container", spec.name, *compare,
                                            "--format", "html", "--out", html])
        if code:
            raise InspectError(f"nettap report --format html failed (exit {code}):\n{out.rstrip()}")
        return {"name": spec.name, "exit_code": exit_code, "ran_seconds": ran,
                "report_text": text, "report_html": html}
    finally:
        if not spec.keep_containers:
            for c in reversed(created):
                try:
                    c.remove(force=True)
                except Exception:  # noqa: BLE001 - best effort
                    logger.warning("couldn't remove container %s", getattr(c, "name", c))
