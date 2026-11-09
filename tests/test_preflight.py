"""Clear one-line errors for common setup mistakes (TODO.md, stage 2):
missing capabilities, no Docker socket, a target that doesn't exist, a
data dir that isn't writable, and missing tools."""
from __future__ import annotations

import os
import stat
from unittest.mock import MagicMock

import docker
import pytest
from click.testing import CliRunner

from nettap import cli, discovery, preflight, storage

needs_non_root = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")

# CapEff of `docker run --cap-drop NET_RAW` (Docker 29.7.2, seen 2026-11-09)
CAPS_WITHOUT_NET_RAW = "00000000a80405fb"
# Docker's default set plus NET_ADMIN and SYS_ADMIN
CAPS_FOR_WATCH = format(0xa80425fb | 1 << 12 | 1 << 21, "016x")


def _invoke(*args):
    return CliRunner().invoke(cli.cli, list(args))


def _one_line_error(result, *expected):
    assert result.exit_code == 1, result.output
    out = result.output.strip()
    assert out.startswith("Error: ") and "\n" not in out, out
    for text in expected:
        assert text in out, out
    return out


def _status_file(tmp_path, cap_eff):
    p = tmp_path / "status"
    p.write_text(f"Name:\tnettap\nCapInh:\t0000000000000000\nCapEff:\t{cap_eff}\n")
    return str(p)


# --- missing capabilities -----------------------------------------------------

def test_missing_net_raw_is_found(tmp_path):
    status = _status_file(tmp_path, CAPS_WITHOUT_NET_RAW)
    assert preflight.missing_caps(["NET_RAW", "SYS_ADMIN"], status_path=status,
                                  euid=0, platform="linux") == ["NET_RAW", "SYS_ADMIN"]


def test_all_caps_present(tmp_path):
    status = _status_file(tmp_path, CAPS_FOR_WATCH)
    assert preflight.missing_caps(["NET_RAW", "SYS_ADMIN"], status_path=status,
                                  euid=0, platform="linux") == []


def test_caps_not_checked_for_non_root_or_off_linux(tmp_path):
    status = _status_file(tmp_path, "0000000000000000")
    assert preflight.missing_caps(["NET_RAW"], status_path=status, euid=1000,
                                  platform="linux") == []
    assert preflight.missing_caps(["NET_RAW"], status_path=status, euid=0,
                                  platform="darwin") == []


def test_unreadable_status_skips_the_check(tmp_path):
    assert preflight.missing_caps(["NET_RAW"], status_path=str(tmp_path / "nope"),
                                  euid=0, platform="linux") == []


def test_require_caps_message_names_the_fix(tmp_path):
    status = _status_file(tmp_path, CAPS_WITHOUT_NET_RAW)
    with pytest.raises(preflight.SetupError) as e:
        preflight.require_caps(["NET_RAW"], status_path=status, euid=0, platform="linux")
    assert str(e.value.message) == (
        "missing Linux capability NET_RAW - start the nettap container with "
        "--cap-add NET_RAW (or cap_add: [NET_RAW] in docker-compose.yml)")


def test_sidecar_without_net_raw_exits_with_the_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "missing_caps", lambda needed, **kw: ["NET_RAW"])
    monkeypatch.setattr(cli, "CaptureManager", lambda *a, **kw: pytest.fail("must not start"))
    result = _invoke("--data-dir", str(tmp_path), "sidecar", "--target", "web")
    _one_line_error(result, "--cap-add NET_RAW")


def test_watch_checks_for_sys_admin(tmp_path, monkeypatch):
    asked = []
    monkeypatch.setattr(preflight, "missing_caps",
                        lambda needed, **kw: asked.extend(needed) or ["SYS_ADMIN"])
    result = _invoke("--data-dir", str(tmp_path), "watch")
    _one_line_error(result, "--cap-add SYS_ADMIN")
    assert asked == ["NET_RAW", "SYS_ADMIN"]


# --- Docker socket ------------------------------------------------------------

def test_no_docker_socket(tmp_path):
    sock = str(tmp_path / "docker.sock")
    with pytest.raises(preflight.SetupError) as e:
        preflight.docker_client(env={}, sock=sock, need="--docker-api")
    assert e.value.message == (f"--docker-api needs the Docker API, but there's no {sock} "
                               f"here - mount it with -v {sock}:{sock}")


@needs_non_root
def test_docker_socket_without_permission(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.touch()
    sock.chmod(0)
    with pytest.raises(preflight.SetupError) as e:
        preflight.docker_client(env={}, sock=str(sock))
    assert "isn't readable and writable by this user" in e.value.message
    assert "docker group" in e.value.message


def test_docker_host_not_answering(monkeypatch):
    client = MagicMock()
    client.ping.side_effect = ConnectionError("connection refused")
    monkeypatch.setattr(docker, "from_env", lambda: client)
    with pytest.raises(preflight.SetupError) as e:
        preflight.docker_client(env={"DOCKER_HOST": "tcp://10.0.0.1:2375"})
    assert "tcp://10.0.0.1:2375 isn't answering (connection refused)" in e.value.message


def test_watch_without_docker_socket_exits_with_the_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "DOCKER_SOCK", str(tmp_path / "docker.sock"))
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    result = _invoke("--data-dir", str(tmp_path / "data"), "watch")
    _one_line_error(result, "no ", "docker.sock", "mount it with -v ")


def test_sidecars_without_docker_socket_exits_with_the_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "DOCKER_SOCK", str(tmp_path / "docker.sock"))
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    result = _invoke("--data-dir", str(tmp_path), "sidecars", "--label", "monitor=true")
    _one_line_error(result, "nettap sidecars needs the Docker API")


# --- a target that doesn't exist ----------------------------------------------

def _container(name, cid, status="running"):
    c = MagicMock()
    c.name, c.id, c.short_id, c.status = name, cid, cid[:12], status
    return c


def _docker_with(monkeypatch, *containers):
    client = MagicMock()
    client.containers.list.return_value = list(containers)
    monkeypatch.setattr(cli, "_docker_client", lambda **kw: client)


def _desired_refs(tmp_path):
    return storage.list_desired_refs(storage.connect(str(tmp_path / "nettap.db")))


def test_attach_unknown_container_fails_and_records_nothing(tmp_path, monkeypatch):
    _docker_with(monkeypatch, _container("web", "a" * 64), _container("db", "b" * 64, "exited"))
    result = _invoke("--data-dir", str(tmp_path), "attach", "web", "wbe")
    _one_line_error(result, "no container named or with ID 'wbe'", "running containers: web",
                    "--allow-missing")
    assert _desired_refs(tmp_path) == []


def test_attach_accepts_names_ids_and_stopped_containers(tmp_path, monkeypatch):
    _docker_with(monkeypatch, _container("web", "a" * 64), _container("db", "b" * 64, "exited"))
    result = _invoke("--data-dir", str(tmp_path), "attach", "web", "b" * 12)
    assert result.exit_code == 0, result.output
    assert sorted(_desired_refs(tmp_path)) == sorted(["web", "b" * 12])


def test_attach_allow_missing(tmp_path, monkeypatch):
    _docker_with(monkeypatch)
    result = _invoke("--data-dir", str(tmp_path), "attach", "--allow-missing", "later")
    assert result.exit_code == 0, result.output
    assert _desired_refs(tmp_path) == ["later"]


def test_attach_without_docker_warns_but_records(tmp_path, monkeypatch):
    def no_docker(**kw):
        raise preflight.SetupError("nettap needs the Docker API, but there's no /x here")
    monkeypatch.setattr(cli, "_docker_client", no_docker)
    result = _invoke("--data-dir", str(tmp_path), "attach", "web")
    assert result.exit_code == 0
    assert "warning: can't check that web exists" in result.output
    assert _desired_refs(tmp_path) == ["web"]


def test_sidecar_whose_target_isnt_there_exits_with_the_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "interface_exists", lambda iface: False)
    result = _invoke("--data-dir", str(tmp_path), "sidecar", "--target", "web")
    _one_line_error(result, "no interface 'eth0' here", "--network container:<target>")


def test_report_for_unknown_container_exits_non_zero(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    conn.execute("INSERT INTO containers (container_id, name) VALUES ('a', 'web')")
    conn.commit()
    result = _invoke("--data-dir", str(tmp_path), "report", "--container", "wbe")
    assert result.exit_code == 1
    assert "No data for a container named 'wbe'" in result.output


# --- a data dir that isn't writable -------------------------------------------

@needs_non_root
def test_unwritable_data_dir(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    data.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(preflight.SetupError) as e:
            preflight.require_writable_dir(data)
    finally:
        data.chmod(0o700)
    assert e.value.message.startswith(f"can't write to data directory '{data}' (Permission denied)")


@needs_non_root
def test_sidecar_with_unwritable_data_dir_exits_with_the_fix(tmp_path):
    parent = tmp_path / "ro"
    parent.mkdir()
    parent.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        result = _invoke("--data-dir", str(parent / "data"), "sidecar", "--target", "web")
    finally:
        parent.chmod(0o700)
    _one_line_error(result, "can't write to data directory", "--data-dir")


@needs_non_root
def test_status_with_uncreatable_data_dir_exits_with_the_fix(tmp_path):
    parent = tmp_path / "ro"
    parent.mkdir()
    parent.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        result = _invoke("--data-dir", str(parent / "data"), "status")
    finally:
        parent.chmod(0o700)
    _one_line_error(result, "can't open the database", "--data-dir")


# --- missing tools ------------------------------------------------------------

def test_enrich_without_tshark(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "which", lambda tool: None)
    result = _invoke("--data-dir", str(tmp_path), "enrich")
    _one_line_error(result, "tshark not found on PATH", "docker build -t nettap .")


def test_sidecar_without_tcpdump(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "which", lambda tool: None if tool == "tcpdump" else "/x")
    result = _invoke("--data-dir", str(tmp_path), "sidecar", "--target", "web",
                     "--no-auto-enrich")
    _one_line_error(result, "tcpdump not found on PATH")


def test_nested_connection_errors_are_shortened(monkeypatch):
    client = MagicMock()
    client.ping.side_effect = Exception(
        "Error while fetching server API version: HTTPConnectionPool(host='127.0.0.1', "
        "port=1): Max retries exceeded with url: /version (Caused by NewConnectionError("
        "\"HTTPConnection(host='127.0.0.1', port=1): Failed to establish a new connection: "
        "[Errno 61] Connection refused\"))")
    monkeypatch.setattr(docker, "from_env", lambda: client)
    with pytest.raises(preflight.SetupError) as e:
        preflight.docker_client(env={"DOCKER_HOST": "tcp://127.0.0.1:1"})
    assert e.value.message == ("nettap needs the Docker API, but tcp://127.0.0.1:1 isn't "
                               "answering (Connection refused) - check that Docker is "
                               "running there, or unset DOCKER_HOST")
