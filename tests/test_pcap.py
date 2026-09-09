import io
import struct

import pytest

from pktanalyzer import builders as B
from pktanalyzer.pcap import PcapReader, PcapWriter, read_pcap


def test_write_then_read_roundtrip(tmp_path):
    path = tmp_path / "c.pcap"
    frames = [
        B.frame_tcp("10.0.0.1", "10.0.0.2", 1000, 80, flags=B.SYN),
        B.frame_udp("10.0.0.1", "8.8.8.8", 40000, 53, b"hi"),
        B.frame_arp("10.0.0.1", "10.0.0.9"),
    ]
    with open(path, "wb") as f:
        w = PcapWriter(f)
        for i, fr in enumerate(frames):
            w.write(fr, ts=1_700_000_000 + i)

    pkts = read_pcap(str(path))
    assert [p.data for p in pkts] == frames
    assert [round(p.ts) for p in pkts] == [1_700_000_000, 1_700_000_001, 1_700_000_002]
    assert pkts[0].index == 0 and pkts[2].index == 2


def test_reads_big_endian_pcap():
    body = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = B.frame_tcp("1.2.3.4", "5.6.7.8", 1, 2)
    body += struct.pack(">IIII", 111, 222, len(frame), len(frame)) + frame
    pkts = list(PcapReader(io.BytesIO(body)))
    assert len(pkts) == 1 and pkts[0].data == frame
    assert pkts[0].ts == pytest.approx(111 + 222 / 1e6)


def test_nanosecond_magic():
    body = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    body += struct.pack("<IIII", 5, 500_000_000, 4, 4) + b"abcd"
    pkts = list(PcapReader(io.BytesIO(body)))
    assert pkts[0].ts == pytest.approx(5.5)


def test_rejects_non_pcap():
    with pytest.raises(ValueError):
        PcapReader(io.BytesIO(b"not a pcap file at all........"))


def test_truncated_record_raises():
    body = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body += struct.pack("<IIII", 1, 2, 100, 100) + b"only ten b"
    with pytest.raises(ValueError):
        list(PcapReader(io.BytesIO(body)))
