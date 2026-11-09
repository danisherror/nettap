"""The sidecar's shared interface disappears when its target container stops
or is removed (live test, TODO.md 2026-11-08). The sidecar used to restart
tcpdump every second forever; it should exit with an error instead."""
from click.testing import CliRunner

from nettap import cli, discovery


class FakeMgr:
    def __init__(self, *a, **kw):
        self.detached = False
        FakeMgr.last = self

    def attach(self, info):
        return None

    def restart_dead(self):
        return []

    def enforce_retention(self, **_kw):
        return []

    def detach_all(self):
        self.detached = True


def _run(tmp_path, monkeypatch, exists):
    monkeypatch.setattr(discovery, "run", lambda cmd, **kw: "[]")
    monkeypatch.setattr(discovery, "interface_exists", exists)
    monkeypatch.setattr(cli, "CaptureManager", FakeMgr)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    return CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "sidecar",
                                        "--target", "web", "--no-auto-enrich"])


def test_sidecar_exits_when_interface_disappears(tmp_path, monkeypatch):
    checks = iter([True, True, True, False])  # startup check, 2 loop passes, then gone
    result = _run(tmp_path, monkeypatch, lambda iface: next(checks))
    assert result.exit_code == 3
    assert FakeMgr.last.detached


def test_sidecar_refuses_to_start_without_interface(tmp_path, monkeypatch):
    FakeMgr.last = None
    result = _run(tmp_path, monkeypatch, lambda iface: False)
    assert result.exit_code == 1
    assert "no interface 'eth0'" in result.output
    assert FakeMgr.last is None  # never got as far as capturing


def test_interface_exists(tmp_path):
    (tmp_path / "eth0").mkdir()
    assert discovery.interface_exists("eth0", sys_net=str(tmp_path))
    assert not discovery.interface_exists("eth9", sys_net=str(tmp_path))
    assert discovery.interface_exists("eth9", sys_net=str(tmp_path / "missing"))


def test_bridge_interfaces(tmp_path):
    for name in ("eth0", "docker0", "br-81fb302e3906", "lo"):
        (tmp_path / name).mkdir()
    (tmp_path / "docker0" / "bridge").mkdir()
    (tmp_path / "br-81fb302e3906" / "bridge").mkdir()
    (tmp_path / "bonding_masters").write_text("")
    assert discovery.bridge_interfaces(str(tmp_path)) == ["br-81fb302e3906", "docker0"]
    assert discovery.bridge_interfaces(str(tmp_path / "missing")) == []


def _run_with_bridges(tmp_path, monkeypatch, bridges, *extra):
    monkeypatch.setattr(discovery, "bridge_interfaces", lambda: bridges)
    checks = iter([True, True, False])
    monkeypatch.setattr(discovery, "run", lambda cmd, **kw: "[]")
    monkeypatch.setattr(discovery, "interface_exists", lambda iface: next(checks))
    monkeypatch.setattr(cli, "CaptureManager", FakeMgr)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    FakeMgr.last = None
    return CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "sidecar",
                                        "--target", "web", "--no-auto-enrich", *extra])


def test_sidecar_refuses_a_host_network_target(tmp_path, monkeypatch):
    result = _run_with_bridges(tmp_path, monkeypatch, ["docker0"])
    assert result.exit_code == 1
    assert "--network host" in result.output and "--allow-host-network" in result.output
    assert FakeMgr.last is None


def test_sidecar_captures_a_host_network_target_when_allowed(tmp_path, monkeypatch):
    result = _run_with_bridges(tmp_path, monkeypatch, ["docker0"], "--allow-host-network")
    assert result.exit_code == 3 and FakeMgr.last.detached  # ran its loop


def test_sidecar_without_bridges_starts_normally(tmp_path, monkeypatch):
    result = _run_with_bridges(tmp_path, monkeypatch, [])
    assert result.exit_code == 3 and FakeMgr.last.detached
