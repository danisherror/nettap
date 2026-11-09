"""Wake a polling loop as soon as Docker starts or stops a container.

`watch` and `sidecars` reconcile on a timer (default 5s). Polling stays the
source of truth - a missed or dropped event only costs one poll interval -
but a container start or death now triggers a pass right away instead of
up to poll_interval later. Events API:
https://docs.docker.com/reference/api/engine/version/v1.47/#tag/System/operation/SystemEvents
"""
from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

CONTAINER_EVENTS = ["start", "die", "destroy"]
RETRY_SECONDS = 5.0


def wake_on_events(client, wake: threading.Event, stop: threading.Event) -> None:
    """Set `wake` for every container start/die/destroy event until `stop`
    is set. Reconnects after an error. Meant for a daemon thread: the
    events stream blocks until the next event arrives."""
    while not stop.is_set():
        try:
            stream = client.events(decode=True, filters={"type": "container",
                                                         "event": CONTAINER_EVENTS})
            for event in stream:
                if stop.is_set():
                    return
                logger.debug("docker event %s %s", event.get("Action") or event.get("status"),
                             (event.get("Actor") or {}).get("Attributes", {}).get("name"))
                wake.set()
        except Exception as e:  # noqa: BLE001 - daemon restarted, socket gone: polling covers it
            logger.debug("docker events stream ended (%s), reconnecting in %ss", e, RETRY_SECONDS)
        stop.wait(RETRY_SECONDS)


def start(client, stop: threading.Event) -> threading.Event:
    """Run wake_on_events on a daemon thread; returns the `wake` event."""
    wake = threading.Event()
    threading.Thread(target=wake_on_events, args=(client, wake, stop), daemon=True,
                     name="docker-events").start()
    return wake
