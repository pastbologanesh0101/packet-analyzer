"""``pktanalyzer`` command line.

    pktanalyzer read   capture.pcap [--json] [--verbose]
    pktanalyzer flows  capture.pcap [--sort bytes|packets|duration]
    pktanalyzer gen    sample.pcap          # synthesize a demo capture
    pktanalyzer live   eth0  --count 200    # Linux + root only
"""

from __future__ import annotations

import argparse
import json
import sys

from .analyze import Analyzer, analyze_pcap
from .layers import dissect
from .pcap import PcapReader, PcapWriter


def _fmt_ep(ep):
    return f"{ep[0]}:{ep[1]}"


def cmd_read(ns) -> int:
    if ns.verbose:
        reader = PcapReader.open(ns.pcap)
        for pkt in reader:
            d = dissect(pkt.data, pkt.linktype)
            line = f"{pkt.ts:.6f}  {d.protocol_name:<6} {pkt.wirelen:>5}B  "
            ip = d.ip
            if ip is not None:
                line += f"{ip.src} -> {ip.dst}"
                l4 = d.tcp or d.udp
                if l4 is not None:
                    line += f"  :{l4.src_port}->:{l4.dst_port}"
                if d.tcp is not None:
                    line += f"  [{d.tcp.flag_str()}] seq={d.tcp.seq}"
                if d.dns is not None and d.dns.questions:
                    line += f"  dns? {', '.join(d.dns.questions)}"
            elif d.arp is not None:
                a = d.arp
                line += f"ARP {'who-has' if a.op == 1 else 'is-at'} {a.target_ip} tell {a.sender_ip}"
            print(line)
        reader.close()

    az = analyze_pcap(ns.pcap)
    rep = az.report()
    if ns.json:
        print(json.dumps(rep, indent=2))
        return 0

    print(f"\n{rep['packets']} packets, {rep['bytes']} bytes, "
          f"{rep['duration_s']}s ({rep['avg_pps']} pkt/s)\n")
    print("protocols:")
    for name, n in rep["protocols"]:
        print(f"  {name:<8} {n:>7}  ({dict(rep['protocol_bytes']).get(name, 0)} B)")
    print("\ntop talkers (bytes):")
    for ip, b in rep["top_talkers"]:
        print(f"  {ip:<16} {b:>10}")
    print("\ntop destination ports:")
    for port, n in rep["top_ports"]:
        print(f"  {port:<6} {n:>7}")
    if rep["tcp_flags"]:
        print(f"\nTCP flags: {rep['tcp_flags']}   retransmits(guess): {rep['tcp_retransmits']}")
    if rep["bad_ipv4_checksums"]:
        print(f"bad IPv4 checksums: {rep['bad_ipv4_checksums']}")
    if rep["dns_queries"]:
        print("\nDNS queries:")
        for name, n in rep["dns_queries"]:
            print(f"  {name}  x{n}")
    print(f"\n{rep['flows']} flows (see `pktanalyzer flows {ns.pcap}`)")
    return 0


def cmd_flows(ns) -> int:
    az = analyze_pcap(ns.pcap)
    print(f"{'proto':<5} {'endpoint A':<22} {'endpoint B':<22} "
          f"{'pkts':>6} {'bytes':>9} {'dur(s)':>8}  flags")
    for f in az.flow_table(ns.sort)[:ns.top]:
        flags = []
        if f.syn:
            flags.append(f"SYN={f.syn}")
        if f.fin:
            flags.append(f"FIN={f.fin}")
        if f.rst:
            flags.append(f"RST={f.rst}")
        print(f"{f.proto:<5} {_fmt_ep(f.a):<22} {_fmt_ep(f.b):<22} "
              f"{f.packets:>6} {f.bytes:>9} {f.duration:>8.3f}  {' '.join(flags)}")
    return 0


def cmd_gen(ns) -> int:
    from . import builders as B

    frames: list[tuple[float, bytes]] = []
    t = 1_700_000_000.0

    # a TCP handshake + data + teardown between 10.0.0.1 and 10.0.0.2:443
    c, s = "10.0.0.1", "10.0.0.2"
    frames.append((t + 0.00, B.frame_tcp(c, s, 51000, 443, flags=B.SYN, seq=1000)))
    frames.append((t + 0.01, B.frame_tcp(s, c, 443, 51000, flags=B.SYN_ACK, seq=5000, ack=1001)))
    frames.append((t + 0.02, B.frame_tcp(c, s, 51000, 443, flags=B.ACK, seq=1001, ack=5001)))
    frames.append((t + 0.03, B.frame_tcp(c, s, 51000, 443, flags=B.PSH_ACK, seq=1001, ack=5001,
                                         payload=b"GET / HTTP/1.1\r\n\r\n")))
    frames.append((t + 0.05, B.frame_tcp(s, c, 443, 51000, flags=B.PSH_ACK, seq=5001, ack=1019,
                                         payload=b"HTTP/1.1 200 OK\r\n\r\n<html/>")))
    frames.append((t + 0.06, B.frame_tcp(c, s, 51000, 443, flags=B.ACK, seq=1019, ack=5027)))
    # a retransmission of the request
    frames.append((t + 0.30, B.frame_tcp(c, s, 51000, 443, flags=B.PSH_ACK, seq=1001, ack=5027,
                                         payload=b"GET / HTTP/1.1\r\n\r\n")))
    frames.append((t + 0.40, B.frame_tcp(c, s, 51000, 443, flags=B.FIN_ACK, seq=1019, ack=5027)))
    frames.append((t + 0.41, B.frame_tcp(s, c, 443, 51000, flags=B.FIN_ACK, seq=5027, ack=1020)))

    # DNS lookups
    frames.append((t + 0.10, B.frame_dns_query(c, "8.8.8.8", "example.com")))
    frames.append((t + 0.12, B.frame_dns_query(c, "8.8.8.8", "api.github.com")))
    # ICMP ping
    frames.append((t + 0.20, B.frame_icmp(c, "1.1.1.1", request=True)))
    frames.append((t + 0.21, B.frame_icmp("1.1.1.1", c, request=False)))
    # ARP
    frames.append((t + 0.005, B.frame_arp("10.0.0.1", "10.0.0.254")))

    frames.sort(key=lambda x: x[0])
    with open(ns.pcap, "wb") as fh:
        w = PcapWriter(fh)
        for ts, data in frames:
            w.write(data, ts)
    print(f"wrote {len(frames)} packets to {ns.pcap}", file=sys.stderr)
    return 0


def cmd_live(ns) -> int:
    from .capture import live_dissections

    az = Analyzer()
    try:
        for ts, d in live_dissections(ns.iface, ns.count, ns.timeout):
            az.add(ts, d)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(az.report(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pktanalyzer")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("read"); s.add_argument("pcap")
    s.add_argument("--json", action="store_true")
    s.add_argument("--verbose", "-v", action="store_true")
    s.set_defaults(func=cmd_read)

    s = sub.add_parser("flows"); s.add_argument("pcap")
    s.add_argument("--sort", default="bytes", choices=["bytes", "packets", "duration"])
    s.add_argument("--top", type=int, default=20)
    s.set_defaults(func=cmd_flows)

    s = sub.add_parser("gen"); s.add_argument("pcap")
    s.set_defaults(func=cmd_gen)

    s = sub.add_parser("live"); s.add_argument("iface", nargs="?")
    s.add_argument("--count", type=int, default=0)
    s.add_argument("--timeout", type=float, default=None)
    s.set_defaults(func=cmd_live)
    return p


def main(argv=None) -> int:
    ns = build_parser().parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
