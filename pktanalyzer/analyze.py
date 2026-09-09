"""Aggregate statistics over a stream of dissected packets.

Feed :class:`Analyzer` ``(timestamp, Dissection)`` pairs (see
:func:`analyze_pcap`); read the summary out of :meth:`report`.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .layers import DNS, TCP, UDP, Dissection


@dataclass
class Flow:
    proto: str
    a: tuple            # (ip, port) — the endpoint seen first
    b: tuple
    packets_ab: int = 0
    packets_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn: int = 0
    fin: int = 0
    rst: int = 0

    @property
    def packets(self) -> int:
        return self.packets_ab + self.packets_ba

    @property
    def bytes(self) -> int:
        return self.bytes_ab + self.bytes_ba

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts


class Analyzer:
    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_packets: Counter = Counter()
        self.proto_bytes: Counter = Counter()
        self.talker_bytes: Counter = Counter()
        self.talker_packets: Counter = Counter()
        self.port_packets: Counter = Counter()
        self.tcp_flags: Counter = Counter()
        self.bad_checksums = 0
        self.dns_queries: Counter = Counter()
        self.flows: dict[tuple, Flow] = {}
        self._seen_seq: dict[tuple, set] = defaultdict(set)
        self.tcp_retransmits = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None

    # -- ingest -------------------------------------------
    def add(self, ts: float, d: Dissection) -> None:
        self.total_packets += 1
        self.total_bytes += d.length
        self.first_ts = ts if self.first_ts is None else self.first_ts
        self.last_ts = ts

        name = d.protocol_name
        self.proto_packets[name] += 1
        self.proto_bytes[name] += d.length

        ip = d.ip
        if ip is not None:
            if d.ip4 is not None and not d.ip4.checksum_ok:
                self.bad_checksums += 1
            self.talker_bytes[ip.src] += d.length
            self.talker_bytes[ip.dst] += 0
            self.talker_packets[ip.src] += 1

        l4 = d.tcp or d.udp
        if l4 is not None and ip is not None:
            self.port_packets[l4.dst_port] += 1
            self._update_flow(ts, d, ip, l4)

        if isinstance(d.dns, DNS) and not d.dns.is_response:
            for q in d.dns.questions:
                if q:
                    self.dns_queries[q] += 1

        if isinstance(d.tcp, TCP):
            for f in d.tcp.flag_set:
                self.tcp_flags[f] += 1

    def _update_flow(self, ts, d, ip, l4) -> None:
        proto = "TCP" if isinstance(l4, TCP) else "UDP"
        ep1 = (ip.src, l4.src_port)
        ep2 = (ip.dst, l4.dst_port)
        key = (proto, *sorted([ep1, ep2]))
        flow = self.flows.get(key)
        if flow is None:
            a, b = sorted([ep1, ep2])
            flow = Flow(proto, a, b, first_ts=ts)
            self.flows[key] = flow
        flow.last_ts = ts
        forward = ep1 == flow.a
        if forward:
            flow.packets_ab += 1
            flow.bytes_ab += d.length
        else:
            flow.packets_ba += 1
            flow.bytes_ba += d.length
        if isinstance(l4, TCP):
            fs = l4.flag_set
            flow.syn += "SYN" in fs
            flow.fin += "FIN" in fs
            flow.rst += "RST" in fs
            if l4.payload:
                seqkey = (key, forward)
                if l4.seq in self._seen_seq[seqkey]:
                    self.tcp_retransmits += 1
                else:
                    self._seen_seq[seqkey].add(l4.seq)

    # -- output -----------------------------------------
    def report(self, top: int = 10) -> dict:
        dur = (self.last_ts - self.first_ts) if self.first_ts is not None else 0.0
        return {
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "duration_s": round(dur, 6),
            "avg_pps": round(self.total_packets / dur, 2) if dur else 0,
            "protocols": self.proto_packets.most_common(),
            "protocol_bytes": self.proto_bytes.most_common(),
            "top_talkers": self.talker_bytes.most_common(top),
            "top_ports": self.port_packets.most_common(top),
            "tcp_flags": dict(self.tcp_flags),
            "tcp_retransmits": self.tcp_retransmits,
            "bad_ipv4_checksums": self.bad_checksums,
            "dns_queries": self.dns_queries.most_common(top),
            "flows": len(self.flows),
        }

    def flow_table(self, sort_by: str = "bytes") -> list[Flow]:
        return sorted(self.flows.values(),
                      key=lambda f: getattr(f, sort_by), reverse=True)


def analyze_pcap(path: str) -> Analyzer:
    from .layers import dissect
    from .pcap import PcapReader

    az = Analyzer()
    reader = PcapReader.open(path)
    try:
        for pkt in reader:
            az.add(pkt.ts, dissect(pkt.data, pkt.linktype))
    finally:
        reader.close()
    return az
