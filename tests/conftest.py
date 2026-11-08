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
