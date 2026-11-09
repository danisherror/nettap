"""The reconciliation loop that keeps running captures in sync with "desired
state": containers matching a label selector passed on the command line, plus
whatever's been requested at runtime via `nettap attach <ref>` / `nettap
detach <ref>` (which just write rows into the shared SQLite DB - see
storage.py). Every poll cycle it resolves desired state to a set of running
containers, diffs that against currently-attached sessions, and
attaches/detaches the difference. Runs until asked to stop.

This is a polling controller rather than a pure Docker-events subscriber, on
purpose: `nettap attach` run from a second terminal takes effect without any
extra plumbing (the daemon just picks it up next cycle), and a missed 'die'
event doesn't leave a zombie capture running forever. The tradeoff is attach
latency bounded by poll_interval (default 5s) - so `watch` also listens to
Docker's events stream (events.py) and runs a pass as soon as a container
starts or dies, keeping the poll as the safety net.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

from . import storage
from .capture import CaptureManager
from .discovery import inspect_container

logger = logging.getLogger("nettap.controller")


@dataclass
class Selector:
    match_all: bool = False
    base_labels: dict[str, str] = field(default_factory=dict)  # from CLI --label at startup

    def desired_containers(self, docker_client, conn) -> list:
        if self.match_all:
            return docker_client.containers.list()

        refs = set(storage.list_desired_refs(conn))
        labels = dict(self.base_labels)
        labels.update(storage.list_desired_labels(conn))

        matched: dict[str, object] = {}
        for c in docker_client.containers.list():
            if c.id in refs or c.name in refs or c.short_id in refs:
                matched[c.id] = c
                continue
            if labels:
                c_labels = c.labels or {}
                if all(c_labels.get(k) == v for k, v in labels.items()):
                    matched[c.id] = c
        return list(matched.values())


def run(docker_client, conn, mgr: CaptureManager, selector: Selector,
        poll_interval: float = 5.0, stop_flag=lambda: False,
        wake: threading.Event | None = None) -> None:
    """Reconcile every poll_interval seconds, or as soon as `wake` is set
    (by events.wake_on_events on a container start/die)."""
    wake = wake or threading.Event()
    while not stop_flag():
        # before the main try: a failing Docker API doesn't mean the
        # captures are gone, and `status` should keep showing them as live
        try:
            storage.heartbeat_live_sessions(conn, mgr.attached_ids(), poll_interval)
        except Exception:
            logger.exception("live_sessions heartbeat failed, continuing")
        try:
            for session in mgr.restart_dead():
                storage.save_capture_session(conn, session)

            desired = selector.desired_containers(docker_client, conn)
            desired_ids = {c.id for c in desired}

            for c in desired:
                if not mgr.is_attached(c.id):
                    info = inspect_container(docker_client, c.id)
                    storage.upsert_container(conn, info)
                    session = mgr.attach(info)
                    if session:
                        storage.save_capture_session(conn, session)

            for cid in mgr.attached_ids() - desired_ids:
                mgr.detach(cid)
                storage.clear_live_session(conn, cid)

            mgr.enforce_retention(unread=lambda path: storage.pcap_unread(conn, path))

        except Exception:
            logger.exception("controller loop iteration failed, continuing")

        wake.wait(poll_interval)
        wake.clear()
