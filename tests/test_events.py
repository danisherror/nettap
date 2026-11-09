import threading

from nettap import events


class _Client:
    """events() yields one event, then the stream breaks; the second call
    blocks until the test is done."""

    def __init__(self, release):
        self.calls, self.filters, self.release = 0, [], release

    def events(self, decode, filters):
        self.calls += 1
        self.filters.append(filters)
        if self.calls == 1:
            def stream():
                yield {"Action": "start", "Actor": {"Attributes": {"name": "web"}}}
                raise ConnectionError("daemon went away")
            return stream()
        self.release.wait(5)
        return iter(())


def test_wakes_on_container_events_and_reconnects(monkeypatch):
    monkeypatch.setattr(events, "RETRY_SECONDS", 0.01)
    stop, release = threading.Event(), threading.Event()
    client = _Client(release)

    wake = events.start(client, stop)
    try:
        assert wake.wait(2), "no wake-up for a container start event"
        for _ in range(200):
            if client.calls >= 2:
                break
            threading.Event().wait(0.01)
        assert client.calls >= 2, "did not reconnect after the stream broke"
        assert client.filters[0] == {"type": "container", "event": ["start", "die", "destroy"]}
    finally:
        stop.set()
        release.set()
