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
    assert mock_popen.call_count == 2  # interface + embedded-DNS capture, once


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
    mock_popen.side_effect = [dead, _FakeProc(), alive, _FakeProc()]

    mgr.attach(_info())
    assert mgr.status()[0]["alive"] is False  # tcpdump already exited

    restarted = mgr.restart_dead()
    assert len(restarted) == 1
    assert mgr.status()[0]["alive"] is True
    assert mock_popen.call_count == 4  # both captures started again


@patch("nettap.capture.subprocess.Popen")
def test_restart_dead_is_noop_when_all_alive(mock_popen, mgr):
    mock_popen.return_value = _FakeProc()
    mgr.attach(_info())
    assert mgr.restart_dead() == []
    assert mock_popen.call_count == 2


# --- orphan handling -------------------------------------------------------

from nettap import capture  # noqa: E402


@patch("nettap.capture.subprocess.Popen")
def test_attach_sets_parent_death_signal_when_available(mock_popen, mgr, monkeypatch):
    mock_popen.return_value = _FakeProc()
    monkeypatch.setattr(capture, "_prctl", lambda *a: 0)
    mgr.attach(_info())
    assert callable(mock_popen.call_args.kwargs["preexec_fn"])


@patch("nettap.capture.subprocess.Popen")
def test_attach_skips_parent_death_signal_off_linux(mock_popen, mgr, monkeypatch):
    mock_popen.return_value = _FakeProc()
    monkeypatch.setattr(capture, "_prctl", None)
    mgr.attach(_info())
    assert mock_popen.call_args.kwargs["preexec_fn"] is None


PATTERN = "/data/pcap/web_%Y%m%d%H%M%S.pcap"


def _reap(monkeypatch, cmdlines, rows):
    killed = []
    monkeypatch.setattr(capture, "_cmdline", lambda pid: cmdlines.get(pid))
    monkeypatch.setattr(capture.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    return capture.reap_orphans(rows), killed


def test_reap_orphans_kills_matching_tcpdump(monkeypatch):
    rows = [{"pid": 100, "pcap_pattern": PATTERN, "container_name": "web"}]
    cmd = {100: f"tcpdump -i veth1 -w {PATTERN} -G 60 -U -n"}
    result, killed = _reap(monkeypatch, cmd, rows)
    assert result == [100]
    assert killed == [(100, capture.signal.SIGTERM)]


def test_reap_orphans_accepts_full_tcpdump_path(monkeypatch):
    rows = [{"pid": 100, "pcap_pattern": PATTERN, "container_name": "web"}]
    result, _ = _reap(monkeypatch, {100: f"/usr/bin/tcpdump -i veth1 -w {PATTERN}"}, rows)
    assert result == [100]


def test_reap_orphans_leaves_reused_pid_alone(monkeypatch):
    rows = [{"pid": 100, "pcap_pattern": PATTERN, "container_name": "web"},
            {"pid": 101, "pcap_pattern": PATTERN, "container_name": "web"}]
    cmd = {100: "nginx: worker process",
           101: "tcpdump -i veth9 -w /data/pcap/other_%Y%m%d%H%M%S.pcap"}
    result, killed = _reap(monkeypatch, cmd, rows)
    assert result == [] and killed == []


def test_reap_orphans_skips_dead_and_incomplete_rows(monkeypatch):
    rows = [{"pid": 100, "pcap_pattern": PATTERN},  # not running
            {"pid": None, "pcap_pattern": PATTERN},
            {"pid": 102, "pcap_pattern": None}]
    result, killed = _reap(monkeypatch, {102: "tcpdump -i x"}, rows)
    assert result == [] and killed == []


def test_cmdline_of_this_process():
    import os
    assert "python" in (capture._cmdline(os.getpid()) or "").lower()


@patch("nettap.capture.subprocess.Popen")
def test_tcpdump_keeps_root_only_with_parent_death_signal(mock_popen, mgr, monkeypatch):
    mock_popen.return_value = _FakeProc()
    monkeypatch.setattr(capture, "_prctl", lambda *a: 0)
    mgr.attach(_info())
    assert mock_popen.call_args_list[0].args[0][-2:] == ["-Z", "root"]

    monkeypatch.setattr(capture, "_prctl", None)
    mock_popen.reset_mock()
    mgr.attach(_info(cid="c2", name="db"))
    assert all("-Z" not in c.args[0] for c in mock_popen.call_args_list)


# --- embedded-DNS capture on lo --------------------------------------------

def _cmds(mock_popen):
    return [c.args[0] for c in mock_popen.call_args_list]


@patch("nettap.capture.subprocess.Popen")
def test_watch_captures_embedded_dns_inside_the_container_netns(mock_popen, mgr):
    mock_popen.return_value = _FakeProc()
    session = mgr.attach(_info())
    main, dns = _cmds(mock_popen)
    assert main[:3] == ["tcpdump", "-i", "veth1"]
    assert dns[:5] == ["nsenter", "--net=sb1", "tcpdump", "-i", "lo"]
    assert dns[-2:] == ["host", "127.0.0.11"]
    assert session.dns_pcap_pattern.endswith("/web_%Y%m%d%H%M%S.dns.pcap")
    assert session.dns_pcap_pattern in dns
    assert mgr.status()[0]["dns_pcap_pattern"] == session.dns_pcap_pattern


@patch("nettap.capture.subprocess.Popen")
def test_sidecar_captures_embedded_dns_on_its_own_lo(mock_popen, tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tcpdump")
    mock_popen.return_value = _FakeProc()
    CaptureManager(str(tmp_path), own_netns=True).attach(
        ContainerNetInfo("web", "web", "", "eth0", {}, [], {}, None, False))
    _, dns = _cmds(mock_popen)
    assert dns[:3] == ["tcpdump", "-i", "lo"] and dns[-2:] == ["host", "127.0.0.11"]


@patch("nettap.capture.subprocess.Popen")
def test_no_dns_capture_without_a_way_into_the_netns(mock_popen, mgr):
    mock_popen.return_value = _FakeProc()
    info = _info()
    info.sandbox_key = None
    session = mgr.attach(info)
    assert mock_popen.call_count == 1 and session.dns_pcap_pattern is None


@patch("nettap.capture.subprocess.Popen")
def test_restart_dead_restarts_only_a_dead_dns_capture(mock_popen, mgr):
    main = _FakeProc()
    mock_popen.side_effect = [main, _FakeProc(returncode=1), _FakeProc()]
    mgr.attach(_info())
    session = mgr._sessions["c1"]
    assert mgr.restart_dead() == [session]  # so the caller saves the new dns pid
    assert mock_popen.call_count == 3
    assert mgr._sessions["c1"].process is main
    assert mgr._sessions["c1"].dns_process.poll() is None


@patch("nettap.capture.subprocess.Popen")
def test_detach_stops_both_captures(mock_popen, mgr):
    procs = [_FakeProc(), _FakeProc()]
    mock_popen.side_effect = procs
    mgr.attach(_info())
    mgr.detach("c1")
    assert [p.poll() for p in procs] == [0, 0]


def test_pcap_files_only_matches_its_own_capture(tmp_path):
    for name in ["web_20261108000001.pcap", "web_20261108000002.pcap",
                 "web_20261108000001.dns.pcap", "web_2_20261108000001.pcap", "web_x.pcap"]:
        (tmp_path / name).write_bytes(b"")
    main = str(tmp_path / "web_%Y%m%d%H%M%S.pcap")
    dns = str(tmp_path / "web_%Y%m%d%H%M%S.dns.pcap")
    assert [p.rsplit("/", 1)[1] for p in capture.pcap_files(main)] == [
        "web_20261108000001.pcap", "web_20261108000002.pcap"]
    assert [p.rsplit("/", 1)[1] for p in capture.pcap_files(dns)] == ["web_20261108000001.dns.pcap"]


def test_capture_name():
    assert capture.capture_name("/d/web_20261108000001.pcap") == "web"
    assert capture.capture_name("/d/my_app.1_20261108000001.dns.pcap") == "my_app.1"
    assert capture.capture_name("/d/random.pcap") is None


def test_reap_orphans_also_kills_the_dns_tcpdump(monkeypatch):
    dns_pattern = "/data/pcap/web_%Y%m%d%H%M%S.dns.pcap"
    rows = [{"pid": 100, "pcap_pattern": PATTERN, "dns_pid": 101,
             "dns_pcap_pattern": dns_pattern, "container_name": "web"}]
    cmd = {100: f"tcpdump -i eth0 -w {PATTERN}",
           101: f"tcpdump -i lo -w {dns_pattern} host 127.0.0.11"}
    result, _ = _reap(monkeypatch, cmd, rows)
    assert result == [100, 101]


def test_reap_orphans_does_not_mix_up_main_and_dns_patterns(monkeypatch):
    # pid 101 is now the main tcpdump of a newer run, not the old dns capture
    rows = [{"pid": None, "pcap_pattern": PATTERN, "dns_pid": 101,
             "dns_pcap_pattern": "/data/pcap/web_%Y%m%d%H%M%S.dns.pcap"}]
    result, _ = _reap(monkeypatch, {101: f"tcpdump -i eth0 -w {PATTERN}"}, rows)
    assert result == []
