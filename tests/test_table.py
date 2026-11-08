"""`nettap analyze ... --format table` (TODO.md, "Nice-to-haves")."""
import json

from click.testing import CliRunner

from nettap import cli, storage
from nettap.utils import format_table


def test_format_table_aligns_and_humanizes():
    out = format_table([
        {"dst_ip": "1.1.1.1", "bytes": 2048, "packets": 3},
        {"dst_ip": "93.184.216.34", "bytes": 10, "packets": 120},
    ]).splitlines()
    assert out[0].split() == ["dst_ip", "bytes", "packets"]
    assert set(out[1]) <= {"-", " "}
    assert out[2].split() == ["1.1.1.1", "2.0", "KB", "3"]
    # numbers right-aligned, so the columns line up
    assert out[2].index("3") == out[3].index("120") + 2
    assert len({len(l) for l in out}) == 1


def test_format_table_mixed_keys_none_long_and_hostile_values():
    out = format_table([
        {"dst_ip": "8.8.8.8", "hostname": None},
        {"dst_ip": "10.0.0.1", "hint": "x" * 100, "hostname": "evil\x1b[31m"},
    ], max_width=20)
    header = out.splitlines()[0].split()
    assert header == ["dst_ip", "hostname", "hint"]
    assert "x" * 17 + "..." in out and "x" * 18 not in out
    assert "\x1b" not in out and "evil\\x1b[31m" in out


def test_format_table_empty():
    assert format_table([]) == "(no rows)"


def _seed(tmp_path):
    conn = storage.connect(str(tmp_path / "nettap.db"))
    storage.insert_flows(conn, [
        {"ts": 1, "container_id": "c1", "container_name": "web", "src_ip": "172.18.0.2",
         "dst_ip": "93.184.216.34", "src_port": 4000, "dst_port": 443, "protocol": "TLS",
         "length": 1500, "dns_query": None, "tls_sni": "example.com", "pcap_file": "a.pcap"},
    ])


def _run(tmp_path, *args):
    return CliRunner().invoke(cli.cli, ["--data-dir", str(tmp_path), "analyze", *args])


def test_analyze_defaults_to_json(tmp_path):
    _seed(tmp_path)
    rows = json.loads(_run(tmp_path, "external").output)
    assert rows[0]["hostname"] == "example.com" and rows[0]["bytes"] == 1500


def test_every_analyze_command_takes_format_table(tmp_path):
    _seed(tmp_path)
    for args in (["top-talkers"], ["matrix"], ["dns"], ["external"], ["protocols"]):
        result = _run(tmp_path, *args, "--format", "table")
        assert result.exit_code == 0, (args, result.output)
    out = _run(tmp_path, "external", "--format", "table").output
    assert "example.com" in out and "1.5 KB" in out
    assert _run(tmp_path, "dns", "--format", "table").output.strip() == "(no rows)"
