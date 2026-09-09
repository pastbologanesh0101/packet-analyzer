"""Protocol dissectors: raw bytes -> a stack of layer objects.

Each layer is a small dataclass. :func:`dissect` returns a :class:`Dissection`
holding the list of layers plus quick accessors (``.ip``, ``.tcp``, ...).

Supported: Ethernet II (+ 802.1Q VLAN), ARP, IPv4 (+ options), IPv6,
TCP (+ flags), UDP, ICMPv4, DNS (names only).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

ETH_IP4 = 0x0800
ETH_ARP = 0x0806
ETH_IP6 = 0x86DD
ETH_VLAN = 0x8100

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


# ---- helpers ----------------------------------------------------------
def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def checksum16(data: bytes) -> int:
    """Standard 16-bit one's-complement Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class DecodeError(Exception):
    pass


# ---- layers ---------------------------------------------------------
@dataclass
class Ethernet:
    dst: str
    src: str
    ethertype: int
    vlan: int | None = None
    payload: bytes = b""


@dataclass
class ARP:
    op: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


@dataclass
class IPv4:
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    frag_offset: int
    ttl: int
    protocol: int
    checksum: int
    checksum_ok: bool
    src: str
    dst: str
    payload: bytes = b""
    version: int = 4


@dataclass
class IPv6:
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    src: str
    dst: str
    payload: bytes = b""
    version: int = 6

    @property
    def protocol(self) -> int:
        return self.next_header


_TCP_FLAGS = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
              ("ACK", 0x10), ("URG", 0x20), ("ECE", 0x40), ("CWR", 0x80)]


@dataclass
class TCP:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    payload: bytes = b""

    @property
    def flag_set(self) -> set[str]:
        return {name for name, bit in _TCP_FLAGS if self.flags & bit}

    def flag_str(self) -> str:
        short = {"FIN": "F", "SYN": "S", "RST": "R", "PSH": "P", "ACK": "A", "URG": "U"}
        s = "".join(short[n] for n, b in _TCP_FLAGS if n in short and self.flags & b)
        return s or "."


@dataclass
class UDP:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes = b""


@dataclass
class ICMPv4:
    type: int
    code: int
    checksum: int
    rest: bytes = b""


@dataclass
class DNS:
    txid: int
    is_response: bool
    questions: list[str] = field(default_factory=list)
    qtypes: list[int] = field(default_factory=list)


# ---- dissection container ---------------------------------------
@dataclass
class Dissection:
    layers: list = field(default_factory=list)
    length: int = 0          # bytes of the original frame

    def _find(self, *classes):
        for layer in self.layers:
            if isinstance(layer, classes):
                return layer
        return None

    eth = property(lambda self: self._find(Ethernet))
    arp = property(lambda self: self._find(ARP))
    ip = property(lambda self: self._find(IPv4, IPv6))
    ip4 = property(lambda self: self._find(IPv4))
    ip6 = property(lambda self: self._find(IPv6))
    tcp = property(lambda self: self._find(TCP))
    udp = property(lambda self: self._find(UDP))
    icmp = property(lambda self: self._find(ICMPv4))
    dns = property(lambda self: self._find(DNS))

    @property
    def protocol_name(self) -> str:
        """The most specific protocol identified."""
        for layer in reversed(self.layers):
            name = type(layer).__name__
            if name != "Ethernet":
                return "IPv4" if name == "IPv4" else name
        return "Ethernet"


# ---- parsers ---------------------------------------------------
def _parse_dns(payload: bytes) -> DNS | None:
    if len(payload) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    dns = DNS(txid=txid, is_response=bool(flags & 0x8000))
    off = 12
    try:
        for _ in range(qd):
            labels = []
            while True:
                if off >= len(payload):
                    return dns
                ln = payload[off]
                off += 1
                if ln == 0:
                    break
                if ln & 0xC0:            # compression pointer -> stop cleanly
                    off += 1
                    break
                labels.append(payload[off:off + ln].decode("ascii", "replace"))
                off += ln
            qtype, _qclass = struct.unpack("!HH", payload[off:off + 4])
            off += 4
            dns.questions.append(".".join(labels))
            dns.qtypes.append(qtype)
    except (struct.error, IndexError):
        pass
    return dns


def _parse_l4(proto: int, data: bytes, layers: list) -> None:
    if proto == PROTO_TCP and len(data) >= 20:
        sp, dp, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", data[:20])
        data_offset = (off_flags >> 12) * 4
        flags = off_flags & 0x1FF
        payload = data[data_offset:] if data_offset <= len(data) else b""
        tcp = TCP(sp, dp, seq, ack, data_offset, flags, win, csum, payload)
        layers.append(tcp)
        if 53 in (sp, dp):
            d = _parse_dns(payload[2:] if len(payload) > 2 else b"")
            if d:
                layers.append(d)
    elif proto == PROTO_UDP and len(data) >= 8:
        sp, dp, ln, csum = struct.unpack("!HHHH", data[:8])
        udp = UDP(sp, dp, ln, csum, data[8:])
        layers.append(udp)
        if 53 in (sp, dp):
            d = _parse_dns(udp.payload)
            if d:
                layers.append(d)
    elif proto == PROTO_ICMP and len(data) >= 4:
        t, c, csum = struct.unpack("!BBH", data[:4])
        layers.append(ICMPv4(t, c, csum, data[4:]))


def _parse_ipv4(data: bytes, layers: list) -> None:
    if len(data) < 20:
        raise DecodeError("short IPv4 header")
    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    tos = data[1]
    total_len, ident, flags_frag, = struct.unpack("!HHH", data[2:8])
    ttl, proto, csum = data[8], data[9], struct.unpack("!H", data[10:12])[0]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    header = data[:ihl] if ihl <= len(data) else data[:20]
    ok = checksum16(header) == 0
    payload = data[ihl:total_len] if 0 < total_len <= len(data) else data[ihl:]
    layers.append(IPv4(ihl, tos, total_len, ident, flags_frag >> 13,
                       flags_frag & 0x1FFF, ttl, proto, csum, ok, src, dst, payload))
    if (flags_frag & 0x1FFF) == 0 and not (flags_frag & 0x2000):  # not a fragment
        _parse_l4(proto, payload, layers)


def _parse_ipv6(data: bytes, layers: list) -> None:
    if len(data) < 40:
        raise DecodeError("short IPv6 header")
    vtf, plen, nh, hlim = struct.unpack("!IHBB", data[:8])
    tc = (vtf >> 20) & 0xFF
    flow = vtf & 0xFFFFF
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    payload = data[40:40 + plen] if plen else data[40:]
    layers.append(IPv6(tc, flow, plen, nh, hlim, src, dst, payload))
    _parse_l4(nh, payload, layers)


def _parse_arp(data: bytes, layers: list) -> None:
    if len(data) < 28:
        raise DecodeError("short ARP")
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
    sha = mac(data[8:14])
    spa = socket.inet_ntoa(data[14:18])
    tha = mac(data[18:24])
    tpa = socket.inet_ntoa(data[24:28])
    layers.append(ARP(op, sha, spa, tha, tpa))


def dissect(frame: bytes, linktype: int = 1) -> Dissection:
    """Decode one link-layer frame."""
    d = Dissection(length=len(frame))
    try:
        if linktype == 101:  # LINKTYPE_RAW = bare IP
            if frame and frame[0] >> 4 == 6:
                _parse_ipv6(frame, d.layers)
            else:
                _parse_ipv4(frame, d.layers)
            return d
        if len(frame) < 14:
            raise DecodeError("short Ethernet frame")
        dst, src = mac(frame[0:6]), mac(frame[6:12])
        etype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        vlan = None
        if etype == ETH_VLAN and len(frame) >= 18:
            vlan = struct.unpack("!H", frame[14:16])[0] & 0x0FFF
            etype = struct.unpack("!H", frame[16:18])[0]
            off = 18
        payload = frame[off:]
        d.layers.append(Ethernet(dst, src, etype, vlan, payload))
        if etype == ETH_IP4:
            _parse_ipv4(payload, d.layers)
        elif etype == ETH_IP6:
            _parse_ipv6(payload, d.layers)
        elif etype == ETH_ARP:
            _parse_arp(payload, d.layers)
    except DecodeError:
        pass  # keep whatever layers we managed to decode
    return d
