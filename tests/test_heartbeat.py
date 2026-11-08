"""`status` flags live_sessions rows whose daemon stopped heartbeating, i.e.
died without cleaning up (TODO.md, "Nice-to-haves")."""
import time

from click.testing import CliRunner

from nettap import cli, controller, storage
from nettap.discovery import ContainerNetInfo


def _info(cid="c1", name="web"):
    return ContainerNetInfo(cid, name, "nginx", "veth1", {}, [], {}, None, False)


def _db(tmp_path):
    return storage.connect(str(tmp_path / "nettap.db"))


def test_heartbeat_refreshes_only_the_given_rows(tmp_path):
    conn = _db(tmp_path)
    storage.set_live_session(conn, _info("c1", "web"), "w.pcap", 1)
    storage.set_live_session(conn, _info("c2", "db"), "d.pcap", 2)
    conn.execute("UPDATE live_sessions SET updated_at = 0")
    storage.heartbeat_live_sessions(conn, ["c1"], 5.0)
    rows = {r["container_id"]: r for r in storage.list_live_sessions(conn)}
    assert rows["c1"]["updated_at"] > time.time() - 5 and rows["c1"]["heartbeat_interval"] == 5.0
    assert rows["c2"]["updated_at"] == 0 and rows["c2"]["heartbeat_interval"] is None
    storage.heartbeat_live_sessions(conn, [], 5.0)  # no-op, no SQL error


def test_is_stale():
    now = 1000.0
    assert not storage.is_stale({"updated_at": now - 24, "heartbeat_interval": 5}, now)
    assert storage.is_stale({"updated_at": now - 26, "heartbeat_interval": 5}, now)
    # a slow poll interval gets proportionally more slack
    assert not storage.is_stale({"updated_at": now - 300, "heartbeat_interval": 120}, now)
    # no heartbeat recorded yet (or a row from an older nettap): not judged
    assert not storage.is_stale({"updated_at": 0, "heartbeat_interval": None}, now)


def test_connect_adds_heartbeat_column_to_old_table(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE live_sessions (container_id TEXT PRIMARY KEY, updated_at REAL)")
    old.commit()
    old.close()
    cols = {r["name"] for r in storage.connect(path).execute("PRAGMA table_info(live_sessions)")}
    assert "heartbeat_interval" in cols


def _status(tmp_path):
    return CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "status"])


def test_status_flags_stale_rows_only(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    storage.set_live_session(conn, _info("c1", "web"), "w.pcap", 1)
    storage.set_live_session(conn, _info("c2", "db"), "d.pcap", 2)
    storage.heartbeat_live_sessions(conn, ["c1", "c2"], 5.0)
    conn.execute("UPDATE live_sessions SET updated_at = ? WHERE container_id = 'c2'",
                 (time.time() - 600,))
    conn.commit()
    lines = {l.split()[0]: l for l in _status(tmp_path).output.splitlines()}
    assert "STALE" not in lines["web"]
    assert "STALE: no heartbeat for 10m" in lines["db"]


class _Mgr:
    def attached_ids(self):
        return {"c1"}

    def restart_dead(self):
        raise RuntimeError("boom")


def test_controller_heartbeats_even_when_the_iteration_fails(tmp_path, monkeypatch):
    conn = _db(tmp_path)
    storage.set_live_session(conn, _info(), "w.pcap", 1)
    conn.execute("UPDATE live_sessions SET updated_at = 0")
    conn.commit()
    passes = iter([False, True])
    monkeypatch.setattr(controller.time, "sleep", lambda s: None)
    controller.run(None, conn, _Mgr(), controller.Selector(), poll_interval=7.0,
                   stop_flag=lambda: next(passes))
    row = storage.list_live_sessions(conn)[0]
    assert row["updated_at"] > 0 and row["heartbeat_interval"] == 7.0
