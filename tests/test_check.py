"""nettap check: allowlist parsing, which destinations count, exit codes."""
import json

import pytest
from click.testing import CliRunner

from nettap import check, storage
from nettap.cli import cli
from nettap.discovery import ContainerNetInfo

WEB, DB, OTHER = "172.18.0.2", "172.18.0.3", "172.18.0.4"


def _flow(src, dst, sport, dport, length=100, transport="tcp", **kw):
    return {"ts": 1000, "container_id": "c1", "container_name": "web", "src_ip": src,
            "dst_ip": dst, "src_port": sport, "dst_port": dport, "protocol": "TCP",
            "length": length, "dns_query": None, "tls_sni": None, "pcap_file": "a.pcap",
            "transport": transport, **kw}


def _seed(conn):
    for cid, name, ip in (("c1", "web", WEB), ("c2", "db", DB), ("c3", "other", OTHER)):
        storage.upsert_container(conn, ContainerNetInfo(cid, name, "img", "eth0", {"n": ip}, ["n"],
                                                        {}, None, False))
    storage.insert_flows(conn, [
        # web -> db and the reply
        _flow(WEB, DB, 41000, 5432, 500), _flow(DB, WEB, 5432, 41000, 300),
        # web -> other
        _flow(WEB, OTHER, 41001, 80, 200),
        # web -> api.stripe.com over TLS, named by SNI
        _flow(WEB, "54.1.1.1", 41002, 443, 3000, tls_sni="api.stripe.com"),
        # web -> an address named only by a DNS answer
        _flow("127.0.0.1", "127.0.0.11", 50000, 53, 80, transport="udp", dns_query="files.example.org",
              dns_answers=json.dumps(["9.9.9.9"])),
        _flow(WEB, "9.9.9.9", 41003, 443, 700),
        # a client connecting IN to web's port 8080: not a destination by default
        _flow("172.18.0.50", WEB, 45000, 8080, 400), _flow(WEB, "172.18.0.50", 8080, 45000, 900),
        # noise that is always allowed
        _flow("fe80::1", "ff02::1", None, None, 90, transport="icmpv6"),
        _flow(None, None, None, None, 42, transport=None),
    ])


def test_parse_allowlist():
    allow = check.parse_allowlist("""
        # comment
        db
        API.Stripe.com.   # trailing dot and case don't matter
        *.example.org
        10.0.0.0/8
        2001:db8::1
    """)
    assert allow.match_name("db") == "db"
    assert allow.match_name("api.stripe.com") == "api.stripe.com"
    assert allow.match_name("files.example.org") == "*.example.org"
    assert allow.match_name("a.b.example.org") == "*.example.org"
    assert allow.match_name("example.org") is None
    assert allow.match_name("badexample.org") is None
    assert allow.match_ip("10.1.2.3") == "10.0.0.0/8"
    assert allow.match_ip("2001:db8::1") == "2001:db8::1/128"
    assert allow.match_ip("11.0.0.1") is None


@pytest.mark.parametrize("bad", ["*", "*.", "foo*.com", "a b", "*.*.com"])
def test_parse_allowlist_rejects_bad_entries(bad):
    with pytest.raises(ValueError, match="line 1"):
        check.parse_allowlist(bad)


def test_destinations_skip_inbound_and_noise(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    dests = {r["ip"]: r for r in check.destinations(conn, "web")}
    assert set(dests) == {DB, OTHER, "54.1.1.1", "9.9.9.9"}
    assert dests[DB]["containers"] == {"db"}
    assert dests[DB]["bytes"] == 800  # both directions
    assert dests["54.1.1.1"]["hostnames"] == {"api.stripe.com"}
    assert dests["9.9.9.9"]["hostnames"] == {"files.example.org"}
    assert dests["54.1.1.1"]["ports"] == {"tcp/443"}
    everything = {r["ip"] for r in check.destinations(conn, "web", direction="all")}
    assert "172.18.0.50" in everything


def test_unclear_direction_counts_as_outgoing():
    assert check._opened_by(41000, 443) == "us"
    assert check._opened_by(8080, 45000) == "them"
    assert check._opened_by(50051, 45000) == "unclear"  # both ephemeral
    assert check._opened_by(80, 443) == "unclear"
    assert check._opened_by(None, None) == "unclear"


def test_check_flags_only_disallowed(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    allow = check.parse_allowlist("db\napi.stripe.com\n*.example.org")
    results = check.check(conn, "web", allow)
    assert [(r["destination"], r["allowed"]) for r in results][0] == ("other", False)
    assert {r["destination"]: r["matched"] for r in results if r["allowed"]} == {
        "db": "db", "api.stripe.com": "api.stripe.com", "files.example.org": "*.example.org"}


def test_published_port_peer_matched_by_container_name(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    storage.upsert_container(conn, ContainerNetInfo("c1", "web", "img", "eth0", {"n": WEB}, ["n"],
                                                    {}, None, False))
    api = ContainerNetInfo("c9", "api", "img", "eth0", {"n": "172.19.0.5"}, ["n"], {}, None, False,
                           published_ports=[{"host_port": 8080, "protocol": "tcp"}])
    storage.upsert_container(conn, api)
    storage.insert_flows(conn, [_flow(WEB, "192.168.65.254", 41000, 8080, 500)])
    results = check.check(conn, "web", check.parse_allowlist("api"))
    assert [(r["destination"], r["allowed"]) for r in results] == [("api", True)]


def _invoke(*args):
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def test_cli_exit_codes(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    _seed(conn)
    allow = tmp_path / "allow.txt"
    allow.write_text("db\napi.stripe.com\n*.example.org\n")
    base = ["--data-dir", str(tmp_path), "check", "--container", "web", "--allow", str(allow)]

    result = _invoke(*base)
    assert result.exit_code == 1
    assert "FAIL: web contacted 1 destination not on the allowlist" in result.output
    assert "other (172.18.0.4)" in result.output

    result = _invoke(*base, "--allow-entry", "other")
    assert result.exit_code == 0, result.output
    assert result.output.startswith("OK:")

    result = _invoke(*base, "--format", "json")
    data = json.loads(result.output)
    assert data["ok"] is False and [r["destination"] for r in data["disallowed"]] == ["other"]


def test_cli_cannot_check_exits_2(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    _seed(conn)
    d = ["--data-dir", str(tmp_path), "check"]
    # no allowlist
    assert _invoke(*d, "--container", "web").exit_code == 2
    # unknown container
    result = _invoke(*d, "--container", "nope", "--allow-entry", "db")
    assert result.exit_code == 2 and "no data for a container named 'nope'" in result.output
    # known, but no traffic in range
    result = _invoke(*d, "--container", "web", "--allow-entry", "db", "--since", "5000")
    assert result.exit_code == 2 and "no traffic captured" in result.output
    # a bad entry
    result = _invoke(*d, "--container", "web", "--allow-entry", "foo*bar")
    assert result.exit_code == 2 and "not a hostname" in result.output
    # a container with no flows at all (only metadata)
    result = _invoke(*d, "--container", "db", "--allow-entry", "web")
    assert result.exit_code == 2
