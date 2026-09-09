"""Construct raw packet bytes with correct checksums.

Used by the test fixtures and ``pktanalyzer gen`` to synthesize a ``.pcap``
without needing a live network. Deliberately minimal — enough headers to
exercise every dissector.
"""

from __future__ import annotations

import socket
import struct

from .layers import PROTO_ICMP, PROTO_TCP, PROTO_UDP, checksum16


def eth(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return _mac(dst) + _mac(src) + struct.pack("!H", ethertype) + payload


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def ipv4(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64,
         ident: int = 0, dont_fragment: bool = True) -> bytes:
    ver_ihl = 0x45
    total = 20 + len(payload)
    flags_frag = 0x4000 if dont_fragment else 0
    header = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, ident, flags_frag,
                         ttl, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    csum = checksum16(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def _l4_checksum(src: str, dst: str, proto: int, l4: bytes) -> int:
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + \
        struct.pack("!BBH", 0, proto, len(l4))
    return checksum16(pseudo + l4)


def tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, *,
        seq: int = 0, ack: int = 0, flags: int = 0x02, window: int = 64240,
        payload: bytes = b"") -> bytes:
    offset = 5  # 20-byte header, no options
    off_flags = (offset << 12) | flags
    seg = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, off_flags,
                      window, 0, 0) + payload
    csum = _l4_checksum(src_ip, dst_ip, PROTO_TCP, seg)
    seg = seg[:16] + struct.pack("!H", csum) + seg[18:]
    return seg


SYN = 0x02
SYN_ACK = 0x12
ACK = 0x10
FIN_ACK = 0x11
RST = 0x04
PSH_ACK = 0x18


def udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    dgram = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    csum = _l4_checksum(src_ip, dst_ip, PROTO_UDP, dgram) or 0xFFFF
    return dgram[:6] + struct.pack("!H", csum) + dgram[8:]


def icmp_echo(request: bool = True, ident: int = 1, seq: int = 1,
              data: bytes = b"ping") -> bytes:
    t = 8 if request else 0
    msg = struct.pack("!BBHHH", t, 0, 0, ident, seq) + data
    csum = checksum16(msg)
    return msg[:2] + struct.pack("!H", csum) + msg[4:]


def dns_query(name: str, txid: int = 0x1234, qtype: int = 1) -> bytes:
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + q


def arp_request(sender_mac: str, sender_ip: str, target_ip: str) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + _mac(sender_mac) + \
        socket.inet_aton(sender_ip) + _mac("00:00:00:00:00:00") + \
        socket.inet_aton(target_ip)


# -- convenience: full Ethernet frames -------------------------------
MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


def frame_tcp(src_ip, dst_ip, sport, dport, **kw) -> bytes:
    return eth(MAC_B, MAC_A, 0x0800,
              ipv4(src_ip, dst_ip, PROTO_TCP, tcp(src_ip, dst_ip, sport, dport, **kw)))


def frame_udp(src_ip, dst_ip, sport, dport, payload=b"") -> bytes:
    return eth(MAC_B, MAC_A, 0x0800,
              ipv4(src_ip, dst_ip, PROTO_UDP, udp(src_ip, dst_ip, sport, dport, payload)))


def frame_dns_query(src_ip, dst_ip, name, sport=40000) -> bytes:
    return frame_udp(src_ip, dst_ip, sport, 53, dns_query(name))


def frame_icmp(src_ip, dst_ip, request=True) -> bytes:
    return eth(MAC_B, MAC_A, 0x0800,
              ipv4(src_ip, dst_ip, PROTO_ICMP, icmp_echo(request)))


def frame_arp(sender_ip, target_ip) -> bytes:
    return eth("ff:ff:ff:ff:ff:ff", MAC_A, 0x0806,
              arp_request(MAC_A, sender_ip, target_ip))
