"""Reader and writer for the classic ``.pcap`` file format (not pcapng).

Layout::

    global header  (24 bytes)
      magic          u32   0xA1B2C3D4 (usec) or 0xA1B2C3D4-swapped, or
                           0xA1B23C4D (nsec)
      version_major  u16   2
      version_minor  u16   4
      thiszone       i32   GMT offset, usually 0
      sigfigs        u32   0
      snaplen        u32
      network        u32   link-layer type (1 = Ethernet)
    then, repeated:
      record header  (16 bytes)
        ts_sec       u32
        ts_frac      u32   microseconds or nanoseconds
        incl_len     u32   bytes captured in the file
        orig_len     u32   bytes on the wire
      packet data    incl_len bytes

Endianness is discovered from the magic number.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import BinaryIO, Iterator

MAGIC_US = 0xA1B2C3D4
MAGIC_NS = 0xA1B23C4D
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101


@dataclass
class Packet:
    index: int
    ts: float               # seconds since epoch, float
    caplen: int
    wirelen: int
    data: bytes             # link-layer frame (or raw IP for LINKTYPE_RAW)
    linktype: int

    @property
    def truncated(self) -> bool:
        return self.caplen < self.wirelen


class PcapReader:
    def __init__(self, fileobj: BinaryIO):
        self._f = fileobj
        hdr = self._f.read(24)
        if len(hdr) < 24:
            raise ValueError("file too short to be a pcap")
        (magic,) = struct.unpack("<I", hdr[:4])
        if magic in (MAGIC_US, MAGIC_NS):
            self.endian = "<"
            self.nsec = magic == MAGIC_NS
        elif struct.unpack(">I", hdr[:4])[0] in (MAGIC_US, MAGIC_NS):
            self.endian = ">"
            self.nsec = struct.unpack(">I", hdr[:4])[0] == MAGIC_NS
        else:
            raise ValueError(f"not a pcap file (magic {magic:#010x})")
        (self.ver_major, self.ver_minor, _tz, _sig, self.snaplen,
         self.linktype) = struct.unpack(self.endian + "HHiIII", hdr[4:24])

    def __iter__(self) -> Iterator[Packet]:
        rec = struct.Struct(self.endian + "IIII")
        i = 0
        while True:
            raw = self._f.read(16)
            if len(raw) == 0:
                return
            if len(raw) < 16:
                raise ValueError("truncated record header")
            ts_sec, ts_frac, incl, orig = rec.unpack(raw)
            data = self._f.read(incl)
            if len(data) < incl:
                raise ValueError("truncated packet data")
            ts = ts_sec + ts_frac / (1e9 if self.nsec else 1e6)
            yield Packet(i, ts, incl, orig, data, self.linktype)
            i += 1

    @classmethod
    def open(cls, path: str) -> "PcapReader":
        return cls(open(path, "rb"))

    def close(self) -> None:
        self._f.close()


class PcapWriter:
    """Minimal writer — used by the packet builders and the test fixtures."""

    def __init__(self, fileobj: BinaryIO, linktype: int = LINKTYPE_ETHERNET,
                 snaplen: int = 65535):
        self._f = fileobj
        self._f.write(struct.pack("<IHHiIII", MAGIC_US, 2, 4, 0, 0, snaplen, linktype))

    def write(self, data: bytes, ts: float | None = None) -> None:
        ts = time.time() if ts is None else ts
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        self._f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        self._f.write(data)

    def close(self) -> None:
        self._f.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def read_pcap(path: str) -> list[Packet]:
    r = PcapReader.open(path)
    try:
        return list(r)
    finally:
        r.close()
