# TCP/IP Packet Analyzer

**▶ Live demo: https://packet-analyzer-playground.vercel.app** — drop a `.pcap` in the browser (or use the bundled sample) and get the protocol breakdown, top talkers, flow table and a per-packet decode (runs on a Vercel Python function; code in [`web/`](web/)).

A network traffic analyzer built from scratch in pure Python — its own `.pcap`
reader, its own protocol dissectors (no `scapy`, `dpkt`, or `libpcap`), and a
statistics engine. Point it at a capture and get a tcpdump-style decode plus
conversation/flow analysis.

The `.pcap` files it writes are read correctly by the real **`tcpdump`**
(checked in CI).

## Quick start

```bash
git clone https://github.com/pastbologanesh0101/packet-analyzer
cd packet-analyzer
pip install -e ".[dev]"
pytest -q                              # 22 tests

pktanalyzer gen  demo.pcap             # synthesize a capture (no network needed)
pktanalyzer read demo.pcap             # summary
pktanalyzer read demo.pcap --verbose   # per-packet decode
pktanalyzer flows demo.pcap            # conversation table
pktanalyzer read demo.pcap --json      # machine-readable
sudo pktanalyzer live eth0 --count 500 # live capture (Linux + root)
```

```
$ pktanalyzer read demo.pcap

14 packets, 827 bytes, 0.41s (34.15 pkt/s)

protocols:
  TCP            9  (548 B)
  DNS            2  (145 B)
  ICMPv4         2  (92 B)
  ARP            1  (42 B)

top talkers (bytes):
  10.0.0.1                551
  10.0.0.2                188

TCP flags: {'SYN': 2, 'ACK': 8, 'PSH': 3, 'FIN': 2}   retransmits(guess): 1

DNS queries:
  example.com  x1
  api.github.com  x1

$ pktanalyzer flows demo.pcap
proto endpoint A         endpoint B         pkts   bytes   dur(s)  flags
TCP   10.0.0.1:51000     10.0.0.2:443          9     548    0.410  SYN=2 FIN=2
UDP   10.0.0.1:40000     8.8.8.8:53            2     145    0.020
```

## Concepts demonstrated

| Area | Where | What it shows |
|---|---|---|
| **File formats** | `pktanalyzer/pcap.py` | Hand-parsed classic `.pcap`: global header, endianness discovered from the magic number, µs vs. ns timestamps, per-record framing, truncation detection. A writer too — used to synthesize captures. |
| **Protocol layering** | `pktanalyzer/layers.py` | Recursive dissection **Ethernet II → (802.1Q VLAN) → ARP / IPv4 / IPv6 → TCP / UDP / ICMPv4 → DNS**. IPv4 options (via IHL), IPv6 fixed header, TCP data-offset and flag bits, DNS name decompression-aware label parsing. |
| **The Internet checksum** | `checksum16` + `builders.py` | The 16-bit one's-complement sum: computed for IPv4 headers and TCP/UDP (with the pseudo-header), *verified* on every parsed IPv4 packet — bad checksums are counted. |
| **Traffic analysis** | `pktanalyzer/analyze.py` | Protocol distribution (packets & bytes), top talkers, destination-port histogram, TCP flag census, a naive **retransmission** detector (repeated seq with payload), and DNS query extraction. |
| **Flow tracking** | `pktanalyzer/analyze.py` | 5-tuple conversations with a canonical key, **bidirectional** byte/packet counts, duration, and per-flow SYN/FIN/RST tallies. |
| **Raw sockets** | `pktanalyzer/capture.py` | Live capture with `AF_PACKET` on Linux; a clear, actionable error on other platforms. |
| **Packet crafting** | `pktanalyzer/builders.py` | Build valid Ethernet/IPv4/IPv6/TCP/UDP/ICMP/DNS/ARP bytes with correct checksums — powers both the tests and `pktanalyzer gen`. |

## How dissection works

`dissect(frame)` returns a `Dissection` — a list of layer objects plus
accessors (`.ip`, `.tcp`, `.dns`, ...). Each parser consumes its header and
hands the remaining bytes to the next, stopping cleanly on a short/blank
buffer so a truncated capture never raises:

```python
from pktanalyzer import dissect, read_pcap

for pkt in read_pcap("demo.pcap"):
    d = dissect(pkt.data)
    if d.tcp and "SYN" in d.tcp.flag_set:
        print(pkt.ts, d.ip.src, "->", f"{d.ip.dst}:{d.tcp.dst_port}")
```

## Interop check

`tests/test_tcpdump_compat.py` generates a capture with the builders and runs
the system `tcpdump -r` over it, asserting the packet count matches and that
`tcpdump` reports no `truncated` / `malformed` packets — i.e. the files are
genuinely well-formed, not just self-consistent.

## Limitations

- **IPv4 reassembly is not done** — fragmented packets are counted but their L4
  payload isn't stitched.
- DNS parsing extracts **question names/types only** (no answer records), and
  stops at the first compression pointer.
- No TLS/HTTP application parsing; no pcapng; no TCP stream reassembly.
- The retransmission heuristic is "same direction, same seq, has payload" — it
  will over-count keep-alives and under-count true loss.
- Live capture is Linux-only.

## Project layout

```
pktanalyzer/
  pcap.py       .pcap reader + writer
  layers.py     Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS dissectors, checksum16
  builders.py   craft valid packet bytes (checksums included)
  analyze.py    Analyzer: protocol/talker/port stats, flow table, retransmits
  capture.py    live AF_PACKET capture (Linux)
  cli.py        read / flows / gen / live
examples/
  sample.pcap   a synthesized capture
tests/          pcap / layers / analyze / tcpdump cross-check
```

## License

MIT
