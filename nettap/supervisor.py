"""`nettap sidecars`: keep one sidecar container per labelled target.

A sidecar joins its target's network namespace once, when it starts
(`--network container:<target>`). When the target stops, Docker removes the
shared eth0 and the sidecar exits with code 3; a restarted target gets a new
namespace the old sidecar can't follow; a recreated target is a different
container altogether (seen live 2026-11-08, see TODO.md). Docker's restart
policies don't help: they retry while the target is still down and give up.

This loop does that bookkeeping through the Docker API (needs docker.sock).
Every poll it compares the running containers matching a label selector
with the sidecars it created (found by their labels) and:

  - creates a sidecar for a target that has none,
  - starts a sidecar that exited because its target stopped (code 3), or
    that stopped before its target last started,
  - restarts a running sidecar that started before its target did (a
    `docker restart` it hasn't noticed yet),
  - recreates a sidecar whose target was replaced by a new container under
    the same name,
  - removes a sidecar whose target is gone or no longer matches.

A sidecar that exited with another code (a crash, a config error, or a
plain `docker stop`) is left alone until its target restarts, so a broken
sidecar isn't restarted in a loop.
"""
from __future__ import annotations

import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .discovery import docker_time

logger = logging.getLogger(__name__)

# labels on the sidecars this creates: the target's name and container ID
TARGET_LABEL = "nettap.sidecar.target"
TARGET_ID_LABEL = "nettap.sidecar.target-id"
# the supervisor's label selector, so two supervisors with different
# selectors leave each other's sidecars alone
SELECTOR_LABEL = "nettap.sidecar.selector"
# a sidecar exits with this when its target stops (see cli.sidecar)
TARGET_GONE_EXIT = 3
DOCKER_SOCK = "/var/run/docker.sock"
DEFAULT_IMAGE = "nettap"


def sidecar_name(target: str) -> str:
    return f"nettap-sidecar-{target}"


def selector_text(labels: dict[str, str]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


@dataclass
class SidecarSpec:
    """How to run each sidecar: `image` (whose entrypoint is `nettap
    --data-dir /data`), `data_source` mounted at /data (a host path or a
    volume name, as for `docker run -v`), extra arguments for `nettap
    sidecar`, and whether to give it docker.sock and --docker-api."""
    image: str
    data_source: str
    sidecar_args: list[str] = field(default_factory=list)
    docker_api: bool = False

    def run_kwargs(self, target, selector: str) -> dict:
        volumes = {self.data_source: {"bind": "/data", "mode": "rw"}}
        command = ["sidecar", "--target", target.name, *self.sidecar_args]
        if self.docker_api:
            volumes[DOCKER_SOCK] = {"bind": DOCKER_SOCK, "mode": "rw"}
            command.append("--docker-api")
        return {
            "image": self.image,
            "command": command,
            "name": sidecar_name(target.name),
            "detach": True,
            "network_mode": f"container:{target.id}",
            "cap_add": ["NET_ADMIN", "NET_RAW"],
            "volumes": volumes,
            "labels": {TARGET_LABEL: target.name, TARGET_ID_LABEL: target.id,
                       SELECTOR_LABEL: selector},
        }


def own_container(client):
    """The container this process runs in, or None outside one. Docker sets
    a container's hostname to its short ID unless --hostname is given."""
    hostname = socket.gethostname()
    try:
        c = client.containers.get(hostname)
    except Exception:  # noqa: BLE001 - not found, or no permission: not in a container
        return None
    if (c.attrs.get("Config") or {}).get("Hostname") != hostname:
        return None
    return c


def default_spec(client, data_dir: str) -> tuple[str, str]:
    """(image, data source) for sidecars: when running in a container, its
    own image and whatever is mounted at data_dir, so sidecars write to the
    same place; otherwise the "nettap" image and data_dir's absolute path."""
    me = own_container(client)
    data_dir = os.path.abspath(data_dir)
    if me is None:
        return DEFAULT_IMAGE, data_dir
    image = (me.attrs.get("Config") or {}).get("Image") or DEFAULT_IMAGE
    for m in me.attrs.get("Mounts") or []:
        if m.get("Destination") == data_dir:
            return image, (m.get("Name") if m.get("Type") == "volume" else m.get("Source"))
    raise RuntimeError(
        f"nothing is mounted at {data_dir} in this container, so sidecars can't "
        f"share it - mount the data dir (e.g. -v \"$(pwd)/data:{data_dir}\") or "
        f"pass --data-volume")


def _started(c) -> float:
    return docker_time((c.attrs.get("State") or {}).get("StartedAt")) or 0.0


def _finished(c) -> float:
    return docker_time((c.attrs.get("State") or {}).get("FinishedAt")) or 0.0


def _matches(c, labels: dict[str, str]) -> bool:
    have = c.labels or {}
    return all(have.get(k) == v for k, v in labels.items())


class Supervisor:
    def __init__(self, client, labels: dict[str, str], spec: SidecarSpec,
                 exclude_ids: set[str] = frozenset()):
        if not labels:
            raise ValueError("a label selector is required")
        self.client = client
        self.labels = labels
        self.selector = selector_text(labels)
        self.spec = spec
        self.exclude_ids = set(exclude_ids)
        self._warned: set[tuple] = set()

    def _warn_once(self, key: tuple, msg: str, *args) -> None:
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(msg, *args)

    def _sidecars(self, containers) -> list:
        return [c for c in containers
                if TARGET_LABEL in (c.labels or {})
                and c.labels.get(SELECTOR_LABEL) == self.selector]

    def _targets(self, containers) -> dict[str, object]:
        out = {}
        for c in containers:
            if c.status != "running" or c.id in self.exclude_ids or TARGET_LABEL in (c.labels or {}):
                continue
            if not _matches(c, self.labels):
                continue
            mode = (c.attrs.get("HostConfig") or {}).get("NetworkMode") or ""
            if mode == "host" or mode.startswith("container:"):
                self._warn_once(("mode", c.id), "skipping %s: it uses --network %s, which "
                                "a sidecar can't capture on its own", c.name, mode)
                continue
            out[c.name] = c
        return out

    def reconcile(self) -> list[tuple[str, str]]:
        """One pass. Returns the actions taken as (action, target name)."""
        containers = self.client.containers.list(all=True)
        by_id = {c.id: c for c in containers}
        sidecars = {c.labels[TARGET_LABEL]: c for c in self._sidecars(containers)}
        targets = self._targets(containers)
        actions = []

        for name, target in targets.items():
            sc = sidecars.get(name)
            if sc is not None and sc.labels.get(TARGET_ID_LABEL) != target.id:
                logger.info("%s was recreated - replacing its sidecar", name)
                sc.remove(force=True)
                sc = None
                actions.append(("remove", name))
            if sc is None:
                logger.info("starting a sidecar for %s", name)
                self.client.containers.run(**self.spec.run_kwargs(target, self.selector))
                actions.append(("create", name))
            elif sc.status == "running":
                if _started(sc) < _started(target):
                    logger.info("%s restarted - restarting its sidecar", name)
                    sc.restart()
                    actions.append(("restart", name))
            elif self._should_start(sc, target):
                logger.info("%s is running again - starting its sidecar", name)
                sc.start()
                actions.append(("start", name))
            else:
                code = (sc.attrs.get("State") or {}).get("ExitCode")
                self._warn_once(("exited", sc.id, _finished(sc)),
                                "sidecar %s exited with code %s - not restarting it until %s "
                                "restarts (see `docker logs %s`)", sc.name, code, name, sc.name)

        for name, sc in sidecars.items():
            if name in targets:
                continue
            target = by_id.get(sc.labels.get(TARGET_ID_LABEL))
            if target is not None and target.status != "running" and _matches(target, self.labels):
                continue  # stopped for now: start the sidecar when it's back
            logger.info("%s is gone or no longer matches - removing its sidecar", name)
            sc.remove(force=True)
            actions.append(("remove", name))
        return actions

    @staticmethod
    def _should_start(sc, target) -> bool:
        state = sc.attrs.get("State") or {}
        if sc.status == "created":
            return True
        if state.get("ExitCode") == TARGET_GONE_EXIT:
            return True
        return _finished(sc) < _started(target)

    def remove_all(self) -> None:
        """Stop (so tcpdump flushes its pcaps) and remove every sidecar this
        manages, in parallel."""
        sidecars = self._sidecars(self.client.containers.list(all=True))

        def _remove(c):
            try:
                c.stop(timeout=10)
                c.remove(force=True)
            except Exception:  # noqa: BLE001 - best effort on shutdown
                logger.exception("removing sidecar %s failed", c.name)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_remove, sidecars))

