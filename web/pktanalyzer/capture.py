"""Live capture via a raw ``AF_PACKET`` socket (Linux only).

Requires ``CAP_NET_RAW`` (run as root). On any other platform, or without the
capability, it raises a clear error pointing at pcap-file analysis instead.
"""

from __future__ import annotations

import socket
import sys
import time
from typing import Iterator

from .layers import Dissection, dissect
from .pcap import Packet

ETH_P_ALL = 0x0003


def live_packets(iface: str | None = None, count: int = 0,
                 timeout: float | None = None) -> Iterator[Packet]:
    if not sys.platform.startswith("linux"):
        raise RuntimeError(
            "live capture needs Linux AF_PACKET sockets; "
            "on this platform capture with tcpdump/wireshark and analyse the .pcap"
        )
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        raise RuntimeError("live capture requires root / CAP_NET_RAW") from None
    if iface:
        s.bind((iface, 0))
    s.settimeout(timeout)
    start = time.time()
    i = 0
    try:
        while count == 0 or i < count:
            try:
                frame = s.recv(65535)
            except socket.timeout:
                return
            yield Packet(i, time.time(), len(frame), len(frame), frame, 1)
            i += 1
            if timeout and time.time() - start > timeout:
                return
    finally:
        s.close()


def live_dissections(iface=None, count=0, timeout=None) -> Iterator[tuple[float, Dissection]]:
    for pkt in live_packets(iface, count, timeout):
        yield pkt.ts, dissect(pkt.data, pkt.linktype)
