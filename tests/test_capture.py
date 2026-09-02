"""Tests for CaptureManager, using a fake tcpdump subprocess so no real
tcpdump binary or network access is needed."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from nettap.capture import CaptureManager
from nettap.discovery import ContainerNetInfo


def _info(cid="c1", name="web", veth="veth1", host_net=False):
    return ContainerNetInfo(
        container_id=cid, name=name, image="nginx", veth=veth,
        ip_addresses={}, networks=["bridge"], labels={}, sandbox_key="sb1",
        uses_host_network=host_net,
    )


class _FakeProc:
    def __init__(self, returncode=None):
        self._returncode = returncode
        self.pid = 4242
        self.stderr = None  # skips the stderr-pump thread in tests

    def poll(self):
        return self._returncode

    def terminate(self):
        self._returncode = 0

    def wait(self, timeout=None):
        return self._returncode

    def kill(self):
        self._returncode = -9


@pytest.fixture
def mgr(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tcpdump")
    return CaptureManager(str(tmp_path))


@patch("nettap.capture.subprocess.Popen")
def test_attach_starts_a_process_and_status_reflects_it(mock_popen, mgr):
    mock_popen.return_value = _FakeProc()
    session = mgr.attach(_info())
    assert session is not None
    assert mgr.is_attached("c1")
    status = mgr.status()
    assert len(status) == 1
    assert status[0]["container"] == "web"
    assert status[0]["alive"] is True


@patch("nettap.capture.subprocess.Popen")
def test_attach_skips_host_network_containers(mock_popen, mgr):
    session = mgr.attach(_info(host_net=True))
    assert session is None
    mock_popen.assert_not_called()


@patch("nettap.capture.subprocess.Popen")
def test_attach_skips_unresolved_veth(mock_popen, mgr):
    session = mgr.attach(_info(veth=None))
    assert session is None
    mock_popen.assert_not_called()


@patch("nettap.capture.subprocess.Popen")
def test_attach_is_idempotent(mock_popen, mgr):
    mock_popen.return_value = _FakeProc()
    s1 = mgr.attach(_info())
    s2 = mgr.attach(_info())
    assert s1 is s2
    assert mock_popen.call_count == 1


@patch("nettap.capture.subprocess.Popen")
def test_detach_terminates_and_removes(mock_popen, mgr):
    mock_popen.return_value = _FakeProc()
    mgr.attach(_info())
    mgr.detach("c1")
    assert not mgr.is_attached("c1")


@patch("nettap.capture.subprocess.Popen")
def test_restart_dead_replaces_exited_process(mock_popen, mgr):
    dead = _FakeProc(returncode=1)
    alive = _FakeProc(returncode=None)
    mock_popen.side_effect = [dead, alive]

    mgr.attach(_info())
    assert mgr.status()[0]["alive"] is False  # tcpdump already exited

    restarted = mgr.restart_dead()
    assert len(restarted) == 1
    assert mgr.status()[0]["alive"] is True
    assert mock_popen.call_count == 2


@patch("nettap.capture.subprocess.Popen")
def test_restart_dead_is_noop_when_all_alive(mock_popen, mgr):
    mock_popen.return_value = _FakeProc()
    mgr.attach(_info())
    assert mgr.restart_dead() == []
    assert mock_popen.call_count == 1
