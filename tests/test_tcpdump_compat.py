"""Cross-check: the .pcap files we write are readable by the real tcpdump,
and it agrees on the packet count."""

import shutil
import subprocess

import pytest

from pktanalyzer.cli import main
from pktanalyzer.pcap import read_pcap

tcpdump = shutil.which("tcpdump")
pytestmark = pytest.mark.skipif(not tcpdump, reason="tcpdump not installed")


def test_tcpdump_reads_our_pcap(tmp_path):
    pcap = tmp_path / "demo.pcap"
    assert main(["gen", str(pcap)]) == 0

    out = subprocess.run(
        [tcpdump, "-r", str(pcap), "-n", "-q"],
        capture_output=True, text=True, check=True,
    )
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    assert len(lines) == len(read_pcap(str(pcap)))     # same packet count

    combined = out.stdout + out.stderr
    assert "10.0.0.1" in combined
    assert "truncated" not in combined.lower()
    assert "malformed" not in combined.lower()
