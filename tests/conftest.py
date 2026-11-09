import pytest

from nettap import discovery

_real_bridge_interfaces = discovery.bridge_interfaces


@pytest.fixture(autouse=True)
def _no_host_bridges(monkeypatch):
    """The sidecar refuses to run where Docker's bridges are visible (the
    host's network namespace) - which is where tests run on a Linux Docker
    host. Report none unless a test passes its own directory."""
    monkeypatch.setattr(discovery, "bridge_interfaces",
                        lambda sys_net=None: [] if sys_net is None
                        else _real_bridge_interfaces(sys_net))


from nettap import preflight

_real_effective_caps = preflight.effective_caps


@pytest.fixture(autouse=True)
def _preflight_passes(monkeypatch):
    """Tests run without tcpdump/tshark/nsenter installed, and maybe as root
    without capabilities. Pretend both are fine; tests of the checks patch
    `preflight.which` themselves or pass their own status file."""
    monkeypatch.setattr(preflight, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(preflight, "effective_caps",
                        lambda status_path="/proc/self/status":
                        (1 << 64) - 1 if status_path == "/proc/self/status"
                        else _real_effective_caps(status_path))
