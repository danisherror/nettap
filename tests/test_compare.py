"""report --compare / --since / --until: storage.window, compare.compare and
the "What changed" section."""
import pytest
from click.testing import CliRunner

from nettap import compare, report, storage
from nettap.cli import cli
from nettap.discovery import ContainerNetInfo
from nettap.utils import parse_duration, parse_time


def _flow(ts, name, src, dst, dport, length, sport=40000, **kw):
    return {"ts": ts, "container_id": name, "container_name": name, "src_ip": src,
            "dst_ip": dst, "src_port": sport, "dst_port": dport, "protocol": "TCP",
            "length": length, "dns_query": None, "tls_sni": None, "pcap_file": "x.pcap",
            "transport": "tcp", **kw}


def _seed(conn):
    for cid, name, ip in (("c1", "web-old", "172.18.0.2"), ("c2", "web-new", "172.18.0.3"),
                          ("c3", "db", "172.18.0.9")):
        storage.upsert_container(conn, ContainerNetInfo(cid, name, "img", "eth0", {"n": ip}, ["n"],
                                                        {}, None, False))
    storage.insert_flows(conn, [
        # old run: db, example.com (big), gone.example
        _flow(100, "web-old", "172.18.0.2", "172.18.0.9", 5432, 1000),
        _flow(101, "web-old", "172.18.0.2", "93.184.216.34", 443, 50_000, tls_sni="example.com"),
        _flow(102, "web-old", "172.18.0.2", "1.1.1.1", 443, 2000, tls_sni="gone.example"),
        _flow(103, "web-old", "172.18.0.2", "8.8.8.8", 53, 80, dns_query="gone.example",
              protocol="DNS", transport="udp"),
        # new run: db, example.com on another address (CDN) and much smaller, new.example
        _flow(200, "web-new", "172.18.0.3", "172.18.0.9", 5432, 1200),
        _flow(201, "web-new", "172.18.0.3", "93.184.216.99", 443, 5_000, tls_sni="example.com"),
        _flow(202, "web-new", "172.18.0.3", "2.2.2.2", 443, 3000, tls_sni="new.example"),
    ])


def test_parse_duration_and_time():
    assert parse_duration("90") == 90
    assert parse_duration("5m") == 300
    assert parse_duration("2h") == 7200
    assert parse_time("15m", now=10_000) == 10_000 - 900
    assert parse_time("1762700000") == 1762700000
    assert parse_time("2026-11-09T00:00:00+00:00") == 1794182400
    assert parse_time("2026-11-09T00:00:00Z") == 1794182400
    with pytest.raises(ValueError):
        parse_time("yesterday")
    with pytest.raises(ValueError):
        parse_duration("-5m")


def test_window_keeps_only_flows_in_range(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    view = storage.window(conn, since=101, until=200)
    assert [r[0] for r in view.execute("SELECT ts FROM flows ORDER BY ts")] == [101, 102, 103]
    # container metadata comes along, so names still resolve
    assert view.execute("SELECT COUNT(*) FROM containers").fetchone()[0] == 3
    assert storage.window(conn) is conn


def test_compare_lists_new_gone_and_changed(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    diff = compare.compare(report.build_report(conn, "web-old"), report.build_report(conn, "web-new"),
                           "web-old", "web-new")
    assert diff["changed"]
    s = {x["key"]: x for x in diff["sections"]}
    assert [r["name"] for r in s["internet"]["new"]] == ["new.example"]
    assert [r["name"] for r in s["internet"]["gone"]] == ["gone.example", "8.8.8.8"]
    # matched by hostname although the address changed; 50 KB -> 5 KB is a big change
    assert [(r["name"], r["before_bytes"], r["after_bytes"]) for r in s["internet"]["changed"]] == \
        [("example.com", 50_000, 5_000)]
    # db: 1000 -> 1200 bytes is not a big change
    assert not (s["containers"]["new"] or s["containers"]["gone"] or s["containers"]["changed"])
    assert [r["name"] for r in s["dns"]["gone"]] == ["gone.example"]


def test_compare_identical_reports_is_unchanged(tmp_path):
    conn = storage.connect(str(tmp_path / "n.db"))
    _seed(conn)
    r = report.build_report(conn, "web-old")
    diff = compare.compare(r, r, "a", "b")
    assert not diff["changed"]
    assert "nothing" in "\n".join(report.changes_text(diff))


def test_small_absolute_change_is_ignored():
    assert not compare._big_change(100, 900)        # 9x, but under 10 KB
    assert compare._big_change(20_000, 60_000)
    assert not compare._big_change(20_000, 30_000)  # 1.5x
    assert compare._big_change(0, 20_000)


def _invoke(*args):
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def test_report_compare_html_has_what_changed_section(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    _seed(conn)
    out = tmp_path / "r.html"
    result = _invoke("--data-dir", str(tmp_path), "report", "--container", "web-new",
                     "--compare", "web-old", "--format", "html", "--out", str(out))
    assert result.exit_code == 0, result.output
    html = out.read_text()
    assert "What changed compared to web-old" in html
    assert "new.example" in html and "gone.example" in html
    assert html.index("What changed") < html.index("Other containers it talked to")


def test_report_time_split_of_one_container(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    _seed(conn)
    storage.insert_flows(conn, [_flow(300, "web-old", "172.18.0.2", "3.3.3.3", 443, 4000,
                                      tls_sni="later.example")])
    result = _invoke("--data-dir", str(tmp_path), "report", "--container", "web-old",
                     "--baseline-until", "300", "--since", "300")
    assert result.exit_code == 0, result.output
    assert "What changed compared to web-old before" in result.output
    assert "new: later.example" in result.output
    assert "no longer contacted: example.com" in result.output


def test_report_compare_with_itself_is_a_usage_error(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    _seed(conn)
    result = _invoke("--data-dir", str(tmp_path), "report", "--container", "web-old",
                     "--compare", "web-old")
    assert result.exit_code == 2
    assert "nothing to compare" in result.output


def test_report_compare_unknown_baseline(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    _seed(conn)
    result = _invoke("--data-dir", str(tmp_path), "report", "--container", "web-old",
                     "--compare", "nope")
    assert result.exit_code == 1
    assert "no data for a container named 'nope'" in result.output


def test_report_since_filters(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    _seed(conn)
    result = _invoke("--data-dir", str(tmp_path), "report", "--container", "web-old",
                     "--since", "102")
    assert "gone.example" in result.output
    assert "example.com (" not in result.output


def test_multicast_is_not_a_change():
    base = {"local_destinations": [{"dst_ip": "ff02::1:ff00:1", "bytes": 86, "hint": "multicast"}]}
    cur = {"local_destinations": [{"dst_ip": "ff02::1:ff00:2", "bytes": 86, "hint": "multicast"},
                                  {"dst_ip": "192.168.65.7", "bytes": 300, "hint": "dns"}]}
    for r in (base, cur):
        r.update(container="x", start=1, end=2, total_bytes=1, packet_count=1)
    s = {x["key"]: x for x in compare.compare(base, cur, "a", "b")["sections"]}
    assert [r["name"] for r in s["local"]["new"]] == ["192.168.65.7"]
    assert s["local"]["gone"] == []
