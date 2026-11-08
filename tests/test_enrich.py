"""parse_pcap: IPv6 addresses, ICMP errors with a quoted inner IP header, and
non-IP frames such as ARP."""
import json
import shutil
import socket
import struct
from unittest import mock

import pytest

from nettap import enrich

# tshark output (4.x) for an ARP frame, an IPv6 ICMPv6 packet, an ICMP error
# (ip.src/ip.dst repeated from the quoted inner header), a DNS response and an
# HTTP request, using the current FIELDS order with -E occurrence=a and
# aggregator=|.
TSHARK_OUT = (
    '"1000.0",,,,,,,,,"ARP","42",,,,,\n'
    '"1001.0",,,"fe80::1","ff02::2",,,,,"ICMPv6","62",,,,,\n'
    '"1003.0","10.0.0.1|172.17.0.2","172.17.0.2|93.184.216.34",,,,"5555",,"53","ICMP","70",,,,,\n'
    '"1004.0","192.168.65.7","172.17.0.2",,,,"53",,"40000","DNS","120","example.com",,'
    '"172.66.147.243|104.20.23.154|172.66.147.243",,\n'
    '"1005.0","172.17.0.2","172.66.147.243",,,"40001",,"80",,"HTTP","140",,,,,"example.com"\n'
)


def _by_proto(rows):
    return {r["protocol"]: r for r in rows}


@mock.patch("nettap.enrich.require_tshark")
@mock.patch("nettap.enrich.subprocess.run")
def test_parse_pcap_ipv6_and_first_occurrence(mock_run, _req):
    mock_run.return_value = mock.Mock(returncode=0, stdout=TSHARK_OUT, stderr="")
    rows = _by_proto(enrich.parse_pcap("x.pcap", "c1", "web"))

    cmd = mock_run.call_args[0][0]
    assert "occurrence=a" in cmd and "aggregator=|" in cmd
    assert "ipv6.src" in cmd and "ipv6.dst" in cmd

    assert (rows["ICMPv6"]["src_ip"], rows["ICMPv6"]["dst_ip"]) == ("fe80::1", "ff02::2")
    assert (rows["ICMP"]["src_ip"], rows["ICMP"]["dst_ip"]) == ("10.0.0.1", "172.17.0.2")
    assert rows["ARP"]["src_ip"] is None and rows["ARP"]["dst_ip"] is None
    assert rows["ICMP"]["src_port"] == 5555


@mock.patch("nettap.enrich.require_tshark")
@mock.patch("nettap.enrich.subprocess.run")
def test_parse_pcap_dns_answers_and_http_host(mock_run, _req):
    mock_run.return_value = mock.Mock(returncode=0, stdout=TSHARK_OUT, stderr="")
    rows = _by_proto(enrich.parse_pcap("x.pcap", "c1", "web"))
    assert json.loads(rows["DNS"]["dns_answers"]) == ["172.66.147.243", "104.20.23.154"]
    assert rows["DNS"]["dns_query"] == "example.com"
    assert rows["HTTP"]["http_host"] == "example.com"
    assert rows["ARP"]["dns_answers"] is None and rows["ARP"]["http_host"] is None


def _write_pcap(path):
    """Minimal pcap: ARP request, IPv6 UDP packet, ICMP port-unreachable
    quoting an inner IPv4/UDP header."""
    def eth(ethertype, payload):
        return b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", ethertype) + payload

    def ip4(src, dst, proto, payload):
        return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                           socket.inet_aton(src), socket.inet_aton(dst)) + payload

    def udp(sport, dport, data=b""):
        return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data

    arp = eth(0x0806, struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + b"\x04" * 6
              + socket.inet_aton("172.17.0.2") + b"\0" * 6 + socket.inet_aton("172.17.0.1"))
    v6 = eth(0x86DD, struct.pack("!IHBB", 6 << 28, 12, 17, 64)
             + socket.inet_pton(socket.AF_INET6, "2001:db8::2")
             + socket.inet_pton(socket.AF_INET6, "2606:4700::1") + udp(5000, 443, b"abcd"))
    inner = ip4("172.17.0.2", "93.184.216.34", 17, udp(5555, 53))
    icmp_err = eth(0x0800, ip4("10.0.0.1", "172.17.0.2", 1, struct.pack("!BBHI", 3, 3, 0, 0) + inner))

    def qname(name):
        return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"

    def answer(rtype, rdata):  # name is a pointer to the question at offset 12
        return struct.pack("!HHHIH", 0xC00C, rtype, 1, 60, len(rdata)) + rdata

    dns = (struct.pack("!HHHHHH", 1, 0x8180, 1, 3, 0, 0) + qname("example.com")
           + struct.pack("!HH", 1, 1)
           + answer(1, socket.inet_aton("172.66.147.243"))
           + answer(1, socket.inet_aton("104.20.23.154"))
           + answer(28, socket.inet_pton(socket.AF_INET6, "2606:4700::6812:1")))
    dns_resp = eth(0x0800, ip4("192.168.65.7", "172.17.0.2", 17, udp(53, 40000, dns)))
    http = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n"
    tcp = struct.pack("!HHIIBBHHH", 40001, 80, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + http
    http_req = eth(0x0800, ip4("172.17.0.2", "172.66.147.243", 6, tcp))

    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate([arp, v6, icmp_err, dns_resp, http_req]):
            f.write(struct.pack("<IIII", 1000 + i, 0, len(pkt), len(pkt)) + pkt)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_parse_pcap_with_real_tshark(tmp_path):
    pcap = tmp_path / "t.pcap"
    _write_pcap(pcap)
    rows = enrich.parse_pcap(str(pcap), "c1", "web")
    by_src = {r["src_ip"]: r for r in rows}

    assert set(by_src) == {None, "2001:db8::2", "10.0.0.1", "192.168.65.7", "172.17.0.2"}
    assert by_src[None]["protocol"] == "ARP"
    assert by_src["2001:db8::2"]["dst_ip"] == "2606:4700::1"
    assert by_src["10.0.0.1"]["dst_ip"] == "172.17.0.2"
    assert json.loads(by_src["192.168.65.7"]["dns_answers"]) == [
        "172.66.147.243", "104.20.23.154", "2606:4700::6812:1"]
    assert by_src["172.17.0.2"]["http_host"] == "example.com"
