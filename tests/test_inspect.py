"""nettap inspect, against a fake Docker client."""
import threading

import docker
import pytest

from nettap import inspector
from nettap.inspector import InspectError, InspectSpec


class FakeContainer:
    def __init__(self, client, image, command, kw, script=None):
        self.client, self.image, self.command, self.kw = client, image, command, kw
        self.name = kw.get("name") or f"helper-{len(client.created)}"
        self.id = f"id-{self.name}"
        self.status = "running"
        self.attrs = {"State": {"ExitCode": 0}}
        self.script = script or {}
        self.removed = self.stopped = False
        self.reloads = 0

    def reload(self):
        self.reloads += 1
        exit_after = self.script.get("exit_after_reloads")
        if exit_after is not None and self.reloads >= exit_after:
            self.status = "exited"
            self.attrs["State"]["ExitCode"] = self.script.get("exit_code", 0)

    def logs(self, **kw):
        return self.script.get("logs", b"")

    def stop(self, timeout=10):
        self.stopped = True
        self.status = "exited"
        self.client.events.append(("stop", self.name))

    def remove(self, force=False):
        self.removed = True
        self.client.events.append(("remove", self.name))

    def start(self):
        self.client.events.append(("start", self.name))

    def wait(self):
        return {"StatusCode": self.script.get("code", 0)}


class FakeClient:
    def __init__(self, have_image=True, sidecar_logs=b"tcpdump: listening on eth0\n",
                 target_script=None, helper_codes=None):
        self.created, self.events, self.pulled = [], [], []
        self.have_image = have_image
        self.sidecar_logs = sidecar_logs
        self.target_script = target_script or {}
        self.helper_codes = list(helper_codes or [])
        client = self

        class Images:
            def get(self, image):
                if not client.have_image:
                    raise docker.errors.ImageNotFound("nope")

            def pull(self, repo, tag=None):
                client.pulled.append((repo, tag))

        class Containers:
            def run(self, image, command=None, **kw):
                is_sidecar = command and command[0] == "sidecar"
                script = {"logs": client.sidecar_logs} if is_sidecar else client.target_script
                c = FakeContainer(client, image, command, kw, script)
                client.created.append(c)
                client.events.append(("run", c.name))
                return c

            def create(self, image, command=None, **kw):
                code = client.helper_codes.pop(0) if client.helper_codes else 0
                c = FakeContainer(client, image, command, kw,
                                  {"code": code, "logs": b"report text\n"})
                client.created.append(c)
                return c

        self.images, self.containers = Images(), Containers()


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(inspector, "SETTLE_SECONDS", 0)
    monkeypatch.setattr(inspector.time, "sleep", lambda s: None)


def _spec(**kw):
    return InspectSpec(**{"image": "nginx:alpine", "name": "run1", "duration": 0.2,
                          "data_source": "/tmp/data", **kw})


def test_run_name():
    assert inspector.run_name("nginx:alpine", now=0).startswith("nginx-alpine-1970")
    assert inspector.run_name("ghcr.io/a/b:1.2@sha256:abc", now=0).startswith("ghcr.io-a-b-1.2-")


def test_parse_publish():
    assert inspector.parse_publish(["8080:80", "53/udp", "127.0.0.1:9000:90"]) == {
        "80/tcp": 8080, "53/udp": None, "90/tcp": ("127.0.0.1", 9000)}
    with pytest.raises(ValueError):
        inspector.parse_publish(["a:b"])


def test_happy_path_order_and_cleanup():
    client = FakeClient()
    result = inspector.inspect(client, _spec(command=["sh", "-c", "wget x"], publish={"80/tcp": 8080}),
                               echo=lambda *_: None)
    sidecar, target = client.created[0], client.created[1]
    # the capture starts first and owns the network namespace
    assert sidecar.command[:3] == ["sidecar", "--target", "run1"]
    assert sidecar.kw["ports"] == {"80/tcp": 8080}
    assert target.kw["network_mode"] == f"container:{sidecar.id}"
    assert target.command == ["sh", "-c", "wget x"]
    # the image is stopped before the sidecar, so its last packets are captured
    assert client.events.index(("stop", target.name)) < client.events.index(("stop", sidecar.name))
    helpers = [c.command for c in client.created[2:]]
    assert helpers[0] == ["enrich"]
    assert helpers[1] == ["report", "--container", "run1"]
    assert helpers[2][-4:] == ["--format", "html", "--out", "/data/run1_report.html"]
    assert all(c.removed for c in client.created)
    assert result["report_text"] == "report text\n"
    assert result["exit_code"] is None


def test_image_exiting_early_ends_the_run():
    client = FakeClient(target_script={"exit_after_reloads": 1, "exit_code": 3, "logs": b"boom"})
    out = []
    result = inspector.inspect(client, _spec(duration=60), echo=out.append)
    assert result["exit_code"] == 3
    assert any("exited with code 3" in line for line in out)
    assert any("boom" in line for line in out)
    assert not client.created[1].stopped


def test_compare_is_passed_to_report():
    client = FakeClient()
    inspector.inspect(client, _spec(baseline="run0"), echo=lambda *_: None)
    assert client.created[3].command == ["report", "--container", "run1", "--compare", "run0"]


def test_pulls_missing_image():
    client = FakeClient(have_image=False)
    inspector.inspect(client, _spec(image="alpine"), echo=lambda *_: None)
    assert client.pulled == [("alpine", "latest")]


def test_sidecar_never_listening_fails_and_cleans_up(monkeypatch):
    client = FakeClient(sidecar_logs=b"")
    clock = iter(range(0, 1000, 10))
    monkeypatch.setattr(inspector.time, "time", lambda: next(clock))
    with pytest.raises(InspectError, match="didn't start capturing"):
        inspector.inspect(client, _spec(), echo=lambda *_: None)
    assert len(client.created) == 1 and client.created[0].removed


def test_enrich_failure_is_reported():
    client = FakeClient(helper_codes=[1])
    with pytest.raises(InspectError, match="nettap enrich failed"):
        inspector.inspect(client, _spec(), echo=lambda *_: None)
    assert all(c.removed for c in client.created)


def test_keep_containers():
    client = FakeClient()
    inspector.inspect(client, _spec(keep_containers=True), echo=lambda *_: None)
    assert not client.created[0].removed and not client.created[1].removed


def test_stop_before_target_starts_still_cleans_up():
    client = FakeClient()
    stop = threading.Event()
    stop.set()
    result = inspector.inspect(client, _spec(), stop=stop, echo=lambda *_: None)
    assert len([c for c in client.created if c.kw.get("name")]) == 1  # no target
    assert result["exit_code"] is None


def test_cli_rejects_typos_and_passes_args_after_double_dash(monkeypatch):
    from click.testing import CliRunner

    from nettap import cli as cli_mod

    seen = {}
    monkeypatch.setattr(cli_mod, "_docker_client", lambda need="": FakeClient())

    def fake_inspect(client, spec, stop, echo):
        seen["spec"] = spec
        return {"name": spec.name, "exit_code": 0, "ran_seconds": 1,
                "report_text": "ok", "report_html": f"/data/{spec.name}_report.html"}

    monkeypatch.setattr(inspector, "inspect", fake_inspect)
    base = ["--data-dir", "/tmp/nettap-test-data", "inspect", "--nettap-image", "n",
            "--data-volume", "vol"]
    r = CliRunner().invoke(cli_mod.cli, base + ["alpine", "--duraton", "5m"])
    assert r.exit_code == 2 and "No such option" in r.output
    r = CliRunner().invoke(cli_mod.cli, base + ["alpine", "--duration", "2m", "--name", "x1",
                                                "--", "sh", "-c", "echo hi"])
    assert r.exit_code == 0, r.output
    assert seen["spec"].command == ["sh", "-c", "echo hi"]
    assert seen["spec"].duration == 120
    assert "HTML report: x1_report.html in the Docker volume vol" in r.output
    r = CliRunner().invoke(cli_mod.cli, base + ["alpine", "--name", "bad name"])
    assert r.exit_code == 2
