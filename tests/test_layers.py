import struct

from pktanalyzer import builders as B
from pktanalyzer.layers import (
    ARP,
    DNS,
    ICMPv4,
    IPv4,
    TCP,
    UDP,
    checksum16,
    dissect,
)


def test_checksum_of_valid_header_is_zero():
    # A real IPv4 header (checksum field filled in) checksums to 0.
    pkt = B.ipv4("192.0.2.1", "192.0.2.2", 6, b"")
    assert checksum16(pkt[:20]) == 0


def test_dissect_ethernet_ipv4_tcp():
    frame = B.frame_tcp("10.0.0.1", "10.0.0.2", 1234, 80, flags=B.SYN, seq=42)
    d = dissect(frame)
    assert d.eth.ethertype == 0x0800
    assert isinstance(d.ip4, IPv4)
    assert d.ip4.src == "10.0.0.1" and d.ip4.dst == "10.0.0.2"
    assert d.ip4.protocol == 6 and d.ip4.checksum_ok
    assert isinstance(d.tcp, TCP)
    assert d.tcp.dst_port == 80 and d.tcp.seq == 42
    assert d.tcp.flag_set == {"SYN"}
    assert d.protocol_name == "TCP"


def test_dissect_udp_and_dns_query():
    frame = B.frame_dns_query("10.0.0.1", "8.8.8.8", "www.example.com")
    d = dissect(frame)
    assert isinstance(d.udp, UDP) and d.udp.dst_port == 53
    assert isinstance(d.dns, DNS)
    assert d.dns.questions == ["www.example.com"]
    assert d.dns.is_response is False
    assert d.protocol_name == "DNS"


def test_dissect_icmp():
    d = dissect(B.frame_icmp("10.0.0.1", "1.1.1.1", request=True))
    assert isinstance(d.icmp, ICMPv4)
    assert d.icmp.type == 8 and d.icmp.code == 0


def test_dissect_arp():
    d = dissect(B.frame_arp("10.0.0.1", "10.0.0.254"))
    assert isinstance(d.arp, ARP)
    assert d.arp.op == 1
    assert d.arp.sender_ip == "10.0.0.1"
    assert d.arp.target_ip == "10.0.0.254"
    assert d.protocol_name == "ARP"


def test_vlan_tag_is_skipped():
    inner = B.ipv4("10.0.0.1", "10.0.0.2", 17, B.udp("10.0.0.1", "10.0.0.2", 9, 9))
    frame = (B._mac(B.MAC_B) + B._mac(B.MAC_A) + struct.pack("!H", 0x8100)
             + struct.pack("!HH", 0x0064, 0x0800) + inner)
    d = dissect(frame)
    assert d.eth.vlan == 0x64
    assert isinstance(d.ip4, IPv4) and isinstance(d.udp, UDP)


def test_ipv6_udp():
    # build a minimal IPv6 + UDP by hand (UDP checksum left as 0 -> not checked)
    udp = struct.pack("!HHHH", 5000, 53, 8, 0)
    v6 = struct.pack("!IHBB", (6 << 28), len(udp), 17, 64)
    v6 += b"\x00" * 15 + b"\x01"          # src ::1
    v6 += b"\x00" * 15 + b"\x01"          # dst ::1
    frame = B._mac(B.MAC_B) + B._mac(B.MAC_A) + struct.pack("!H", 0x86DD) + v6 + udp
    d = dissect(frame)
    assert d.ip6 is not None and d.ip6.next_header == 17
    assert d.udp is not None and d.udp.dst_port == 53


def test_bad_ipv4_checksum_flagged():
    frame = bytearray(B.frame_tcp("10.0.0.1", "10.0.0.2", 1, 2))
    frame[14 + 10] ^= 0xFF          # corrupt the IPv4 checksum byte
    d = dissect(bytes(frame))
    assert d.ip4.checksum_ok is False


def test_truncated_frame_does_not_crash():
    assert dissect(b"\x00\x01\x02") is not None
    assert dissect(b"") is not None
