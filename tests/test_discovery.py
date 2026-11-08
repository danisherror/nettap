from unittest.mock import MagicMock, patch

from nettap import discovery


def test_ifindex_to_name(tmp_path, monkeypatch):
    net_dir = tmp_path / "net"
    (net_dir / "eth0").mkdir(parents=True)
    (net_dir / "eth0" / "ifindex").write_text("7\n")
    (net_dir / "veth123").mkdir(parents=True)
    (net_dir / "veth123" / "ifindex").write_text("42\n")

    monkeypatch.setattr(discovery, "NET_CLASS_DIR", str(net_dir))
    assert discovery._ifindex_to_name(42) == "veth123"
    assert discovery._ifindex_to_name(999) is None


@patch("nettap.discovery.run")
def test_peer_ifindex(mock_run):
    mock_run.return_value = "42\n"
    assert discovery._peer_ifindex("/var/run/docker/netns/abc") == 42
    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args[0] == "nsenter"
    assert "--net=/var/run/docker/netns/abc" in args


@patch("nettap.discovery.run", side_effect=RuntimeError("boom"))
def test_peer_ifindex_failure_returns_none(mock_run):
    assert discovery._peer_ifindex("/does/not/exist") is None


def _fake_container(id_="abc123", name="web", image="nginx:latest",
                     sandbox_key="/var/run/docker/netns/abc123",
                     networks=None, labels=None, host_mode=False):
    attrs = {
        "NetworkSettings": {
            "SandboxKey": sandbox_key,
            "Networks": networks or {"bridge": {"IPAddress": "172.17.0.2"}},
            "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
        },
        "Config": {"Image": image, "Labels": labels or {}},
        "HostConfig": {"NetworkMode": "host" if host_mode else "bridge"},
    }
    c = MagicMock()
    c.id = id_
    c.name = name
    c.attrs = attrs
    return c


def test_inspect_container_resolves_veth(monkeypatch):
    client = MagicMock()
    client.containers.get.return_value = _fake_container()
    monkeypatch.setattr(discovery, "resolve_veth", lambda sandbox_key: "veth999")

    info = discovery.inspect_container(client, "abc123")
    assert info.name == "web"
    assert info.veth == "veth999"
    assert info.ip_addresses == {"bridge": "172.17.0.2"}
    assert info.published_ports == [{"host_port": 8080, "container_port": 80, "protocol": "tcp"}]
    assert not info.uses_host_network


def test_inspect_container_host_network_skips_veth(monkeypatch):
    client = MagicMock()
    client.containers.get.return_value = _fake_container(host_mode=True)
    called = []
    monkeypatch.setattr(discovery, "resolve_veth", lambda sandbox_key: called.append(1) or "shouldnt-happen")

    info = discovery.inspect_container(client, "abc123")
    assert info.veth is None
    assert info.uses_host_network
    assert called == []


def test_published_ports_reads_docker_inspect_bindings():
    from nettap.discovery import published_ports
    ports = {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"},
                        {"HostIp": "::", "HostPort": "18080"}],
             "443/tcp": None, "53/udp": [{"HostIp": "", "HostPort": "5353"}]}
    assert published_ports(ports) == [
        {"host_port": 5353, "container_port": 53, "protocol": "udp"},
        {"host_port": 18080, "container_port": 80, "protocol": "tcp"}]
    assert published_ports(None) == []
