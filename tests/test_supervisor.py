import itertools

import pytest

import nettap

from nettap import supervisor
from nettap.supervisor import (SELECTOR_LABEL, TARGET_ID_LABEL, TARGET_LABEL, SidecarSpec,
                               Supervisor)

_ids = itertools.count(1)


def ts(second: int) -> str:
    return f"2026-11-09T10:00:{second:02d}.000000000Z"


class FakeContainer:
    def __init__(self, client, name, labels=None, status="running", started=0,
                 finished=0, exit_code=0, network_mode="bridge", cid=None):
        self.client, self.name = client, name
        self.id = cid or f"id{next(_ids):04d}"
        self.labels = labels or {}
        self.status = status
        self.exit_code = exit_code
        self.started, self.finished = started, finished
        self.network_mode = network_mode
        self.calls = []

    @property
    def attrs(self):
        return {"State": {"StartedAt": ts(self.started), "FinishedAt": ts(self.finished),
                          "ExitCode": self.exit_code},
                "HostConfig": {"NetworkMode": self.network_mode},
                "Config": {"Hostname": self.id[:12], "Image": "nettap:test"},
                "Mounts": self.client.mounts.get(self.id, [])}

    def start(self):
        self.calls.append("start")
        self.status = "running"

    def restart(self):
        self.calls.append("restart")

    def stop(self, timeout=None):
        self.calls.append("stop")
        self.status = "exited"

    def remove(self, force=False):
        self.calls.append("remove")
        self.client.items.remove(self)


class FakeContainers:
    def __init__(self, client):
        self.client = client

    def list(self, all=False):
        return [c for c in self.client.items if all or c.status == "running"]

    def get(self, ref):
        for c in self.client.items:
            if c.id == ref or c.id[:12] == ref or c.name == ref:
                return c
        raise LookupError(ref)

    def run(self, **kwargs):
        self.client.runs.append(kwargs)
        c = FakeContainer(self.client, kwargs["name"], labels=kwargs["labels"], started=99)
        self.client.items.append(c)
        return c


class FakeClient:
    def __init__(self):
        self.items, self.runs, self.mounts = [], [], {}
        self.containers = FakeContainers(self)

    def add(self, name, **kw):
        c = FakeContainer(self, name, **kw)
        self.items.append(c)
        return c


SELECTOR = {"monitor": "true"}
SPEC = SidecarSpec(image="nettap:test", data_source="/srv/data", sidecar_args=["--rotate-seconds", "60"])


def sidecar_for(client, target, **kw):
    labels = {TARGET_LABEL: target.name, TARGET_ID_LABEL: target.id,
              SELECTOR_LABEL: "monitor=true"}
    return client.add(f"nettap-sidecar-{target.name}", labels=labels, **kw)


@pytest.fixture
def client():
    return FakeClient()


def test_creates_a_sidecar_for_each_matching_container(client):
    web = client.add("web", labels=SELECTOR)
    client.add("db")  # no label

    actions = Supervisor(client, SELECTOR, SPEC).reconcile()

    assert actions == [("create", "web")]
    [run] = client.runs
    assert run["name"] == "nettap-sidecar-web"
    assert run["network_mode"] == f"container:{web.id}"
    assert run["command"] == ["sidecar", "--target", "web", "--rotate-seconds", "60"]
    assert run["volumes"] == {"/srv/data": {"bind": "/data", "mode": "rw"}}
    assert set(run["cap_add"]) == {"NET_ADMIN", "NET_RAW"}
    assert run["labels"] == {TARGET_LABEL: "web", TARGET_ID_LABEL: web.id,
                             SELECTOR_LABEL: "monitor=true"}


def test_nothing_to_do_when_the_sidecar_is_running(client):
    web = client.add("web", labels=SELECTOR, started=10)
    sidecar_for(client, web, started=11)

    assert Supervisor(client, SELECTOR, SPEC).reconcile() == []


def test_starts_a_sidecar_that_exited_because_its_target_stopped(client):
    web = client.add("web", labels=SELECTOR, started=10)
    sc = sidecar_for(client, web, status="exited", exit_code=3, started=5, finished=20)

    assert Supervisor(client, SELECTOR, SPEC).reconcile() == [("start", "web")]
    assert sc.calls == ["start"]


def test_restarts_a_running_sidecar_older_than_its_target(client):
    # `docker restart web`, before the sidecar noticed eth0 is gone
    web = client.add("web", labels=SELECTOR, started=30)
    sc = sidecar_for(client, web, started=10)

    assert Supervisor(client, SELECTOR, SPEC).reconcile() == [("restart", "web")]
    assert sc.calls == ["restart"]


def test_recreates_the_sidecar_of_a_recreated_target(client):
    sup = Supervisor(client, SELECTOR, SPEC)
    old = client.add("web", labels=SELECTOR)
    sc = sidecar_for(client, old, status="exited", exit_code=3)
    client.items.remove(old)
    new = client.add("web", labels=SELECTOR)

    assert sup.reconcile() == [("remove", "web"), ("create", "web")]
    assert sc.calls == ["remove"]
    assert client.runs[-1]["network_mode"] == f"container:{new.id}"


def test_leaves_a_crashed_sidecar_alone_until_its_target_restarts(client, caplog):
    web = client.add("web", labels=SELECTOR, started=10)
    sc = sidecar_for(client, web, status="exited", exit_code=1, started=11, finished=12)
    sup = Supervisor(client, SELECTOR, SPEC)

    assert sup.reconcile() == []
    assert sup.reconcile() == []
    assert sc.calls == []
    assert sum("exited with code 1" in r.message for r in caplog.records) == 1

    web.started = 40  # the target restarted after the sidecar stopped
    assert sup.reconcile() == [("start", "web")]


def test_keeps_the_sidecar_of_a_stopped_target(client):
    web = client.add("web", labels=SELECTOR, status="exited")
    sc = sidecar_for(client, web, status="exited", exit_code=3)

    assert Supervisor(client, SELECTOR, SPEC).reconcile() == []
    assert sc in client.items


def test_removes_the_sidecar_of_a_removed_target(client):
    web = client.add("web", labels=SELECTOR)
    sc = sidecar_for(client, web, status="exited", exit_code=3)
    client.items.remove(web)

    assert Supervisor(client, SELECTOR, SPEC).reconcile() == [("remove", "web")]
    assert sc not in client.items


def test_removes_the_sidecar_of_a_target_that_lost_its_label(client):
    web = client.add("web", labels={})
    sidecar_for(client, web)

    assert Supervisor(client, SELECTOR, SPEC).reconcile() == [("remove", "web")]


def test_ignores_sidecars_of_another_selector(client):
    web = client.add("web", labels={"team": "a"})
    other = sidecar_for(client, web)
    other.labels[SELECTOR_LABEL] = "team=a"

    assert Supervisor(client, SELECTOR, SPEC).reconcile() == []
    assert other in client.items


def test_skips_host_network_and_shared_netns_targets(client):
    client.add("hostnet", labels=SELECTOR, network_mode="host")
    client.add("joined", labels=SELECTOR, network_mode="container:abc")

    assert Supervisor(client, SELECTOR, SPEC).reconcile() == []


def test_never_targets_itself_or_a_sidecar(client):
    me = client.add("supervisor", labels=SELECTOR)
    web = client.add("web", labels=SELECTOR, started=1)
    sc = sidecar_for(client, web, started=2)
    sc.labels.update(SELECTOR)  # e.g. a label set on the image

    assert Supervisor(client, SELECTOR, SPEC, exclude_ids={me.id}).reconcile() == []


def test_docker_api_mounts_the_socket(client):
    web = client.add("web", labels=SELECTOR)
    spec = SidecarSpec(image="i", data_source="vol", docker_api=True)

    kw = spec.run_kwargs(web, "monitor=true")

    assert kw["command"][-1] == "--docker-api"
    assert kw["volumes"]["/var/run/docker.sock"]["bind"] == "/var/run/docker.sock"


def test_remove_all_stops_then_removes_only_its_own_sidecars(client):
    web = client.add("web", labels=SELECTOR)
    sc = sidecar_for(client, web)
    other = sidecar_for(client, client.add("api", labels={"team": "a"}))
    other.labels[SELECTOR_LABEL] = "team=a"

    Supervisor(client, SELECTOR, SPEC).remove_all()

    assert sc.calls == ["stop", "remove"]
    assert other in client.items


def test_a_selector_is_required(client):
    with pytest.raises(ValueError):
        Supervisor(client, {}, SPEC)


def test_default_spec_outside_a_container(client, monkeypatch, tmp_path):
    monkeypatch.setattr(supervisor.socket, "gethostname", lambda: "my-laptop")
    monkeypatch.delenv("NETTAP_IMAGE", raising=False)

    # the published image of the installed version, so a pip install works
    assert supervisor.default_spec(client, str(tmp_path)) == (
        f"ghcr.io/danisherror/nettap:{nettap.__version__}", str(tmp_path))
    monkeypatch.setenv("NETTAP_IMAGE", "nettap")
    assert supervisor.default_spec(client, str(tmp_path)) == ("nettap", str(tmp_path))


@pytest.mark.parametrize("mount,source", [
    ({"Type": "bind", "Source": "/home/me/data", "Destination": "/data"}, "/home/me/data"),
    ({"Type": "volume", "Name": "nettap-data", "Source": "/var/lib/docker/volumes/x",
      "Destination": "/data"}, "nettap-data"),
])
def test_default_spec_uses_its_own_image_and_data_mount(client, monkeypatch, mount, source):
    me = client.add("supervisor")
    client.mounts[me.id] = [mount]
    monkeypatch.setattr(supervisor.socket, "gethostname", lambda: me.id[:12])

    assert supervisor.default_spec(client, "/data") == ("nettap:test", source)


def test_default_spec_needs_the_data_dir_mounted(client, monkeypatch):
    me = client.add("supervisor")
    monkeypatch.setattr(supervisor.socket, "gethostname", lambda: me.id[:12])

    with pytest.raises(RuntimeError, match="nothing is mounted at /data"):
        supervisor.default_spec(client, "/data")
