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

    def enforce_retention(self):
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
