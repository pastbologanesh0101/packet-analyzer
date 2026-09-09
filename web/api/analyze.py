"""Vercel serverless function: parse a .pcap and return the traffic analysis.

POST {"sample": true}                         -> analyse the bundled capture
POST {"pcap_b64": "<base64 of a .pcap>"}      -> analyse an uploaded capture
Optional: {"verbose": 40} -> also return a per-packet decode of the first N.
"""

from http.server import BaseHTTPRequestHandler
import base64
import io
import json

from pktanalyzer.analyze import Analyzer
from pktanalyzer.layers import dissect
from pktanalyzer.pcap import PcapReader

MAX_PCAP = 5 * 1024 * 1024
MAX_PACKETS = 50_000

# The bundled demo capture (examples/sample.pcap), embedded so the function
# needs no extra files: a TCP handshake + request + retransmit + teardown,
# two DNS lookups, an ICMP echo pair and an ARP request.
SAMPLE_B64 = (
    "1MOyoQIABAAAAAAAAAAAAP//AAABAAAAAPFTZQAAAAA2AAAANgAAAAIAAAAACwIAAAAACggARQAAKAAA"
    "QABABibOCgAAAQoAAALHOAG7AAAD6AAAAABQAvrw1BMAAADxU2WIEwAAKgAAACoAAAD///////8CAAAA"
    "AAoIBgABCAAGBAABAgAAAAAKCgAAAQAAAAAAAAoAAP4A8VNlECcAADYAAAA2AAAAAgAAAAALAgAAAAAK"
    "CABFAAAoAABAAEAGJs4KAAACCgAAAQG7xzgAABOIAAAD6VAS+vDAegAAAPFTZSBOAAA2AAAANgAAAAIA"
    "AAAACwIAAAAACggARQAAKAAAQABABibOCgAAAQoAAALHOAG7AAAD6QAAE4lQEPrwwHsAAADxU2UwdQAA"
    "SAAAAEgAAAACAAAAAAsCAAAAAAoIAEUAADoAAEAAQAYmvAoAAAEKAAACxzgBuwAAA+kAABOJUBj68OHA"
    "AABHRVQgLyBIVFRQLzEuMQ0KDQoA8VNlUMMAAFAAAABQAAAAAgAAAAALAgAAAAAKCABFAABCAABAAEAG"
    "JrQKAAACCgAAAQG7xzgAABOJAAAD+1AY+vDxGQAASFRUUC8xLjEgMjAwIE9LDQoNCjxodG1sLz4A8VNl"
    "YOoAADYAAAA2AAAAAgAAAAALAgAAAAAKCABFAAAoAABAAEAGJs4KAAABCgAAAsc4AbsAAAP7AAATo1AQ"
    "+vDATwAAAPFTZaCGAQBHAAAARwAAAAIAAAAACwIAAAAACggARQAAOQAAQABAESCkCgAAAQgICAicQAA1"
    "ACVnfBI0AQAAAQAAAAAAAAdleGFtcGxlA2NvbQAAAQABAPFTZcDUAQBKAAAASgAAAAIAAAAACwIAAAAA"
    "CggARQAAPAAAQABAESChCgAAAQgICAicQAA1ACi3UhI0AQAAAQAAAAAAAANhcGkGZ2l0aHViA2NvbQAA"
    "AQABAPFTZUANAwAuAAAALgAAAAIAAAAACwIAAAAACggARQAAIAAAQABAAS7bCgAAAQEBAQEIABktAAEA"
    "AXBpbmcA8VNlUDQDAC4AAAAuAAAAAgAAAAALAgAAAAAKCABFAAAgAABAAEABLtsBAQEBCgAAAQAAIS0A"
    "AQABcGluZwDxU2XgkwQASAAAAEgAAAACAAAAAAsCAAAAAAoIAEUAADoAAEAAQAYmvAoAAAEKAAACxzgB"
    "uwAAA+kAABOjUBj68OGmAABHRVQgLyBIVFRQLzEuMQ0KDQoA8VNlgBoGADYAAAA2AAAAAgAAAAALAgAA"
    "AAAKCABFAAAoAABAAEAGJs4KAAABCgAAAsc4AbsAAAP7AAATo1AR+vDATgAAAPFTZZBBBgA2AAAANgAA"
    "AAIAAAAACwIAAAAACggARQAAKAAAQABABibOCgAAAgoAAAEBu8c4AAATowAAA/xQEfrwwE0AAA=="
)


def analyse(data: bytes, verbose: int) -> dict:
    reader = PcapReader(io.BytesIO(data))
    az = Analyzer()
    lines = []
    for i, pkt in enumerate(reader):
        if i >= MAX_PACKETS:
            break
        d = dissect(pkt.data, pkt.linktype)
        az.add(pkt.ts, d)
        if verbose and i < verbose:
            lines.append(_line(pkt, d))

    rep = az.report()
    flows = [{
        "proto": f.proto, "a": f"{f.a[0]}:{f.a[1]}", "b": f"{f.b[0]}:{f.b[1]}",
        "packets": f.packets, "bytes": f.bytes, "duration": round(f.duration, 3),
        "syn": f.syn, "fin": f.fin, "rst": f.rst,
    } for f in az.flow_table("bytes")[:25]]

    return {"ok": True, "report": rep, "flows": flows, "verbose": lines}


def _line(pkt, d) -> str:
    s = f"{pkt.ts:.6f}  {d.protocol_name:<6} {pkt.wirelen:>4}B  "
    ip = d.ip
    if ip is not None:
        s += f"{ip.src} -> {ip.dst}"
        l4 = d.tcp or d.udp
        if l4:
            s += f"  :{l4.src_port}->:{l4.dst_port}"
        if d.tcp:
            s += f"  [{d.tcp.flag_str()}] seq={d.tcp.seq}"
        if d.dns and d.dns.questions:
            s += f"  dns? {', '.join(d.dns.questions)}"
    elif d.arp is not None:
        a = d.arp
        s += f"ARP {'who-has' if a.op == 1 else 'is-at'} {a.target_ip} tell {a.sender_ip}"
    return s


def handle(body: dict) -> dict:
    verbose = max(0, min(int(body.get("verbose", 0) or 0), 200))
    if body.get("sample"):
        return analyse(base64.b64decode(SAMPLE_B64), verbose)
    b64 = body.get("pcap_b64")
    if not b64:
        return {"ok": False, "text": "send {sample:true} or {pcap_b64:...}"}
    try:
        data = base64.b64decode(b64, validate=True)
    except Exception:
        return {"ok": False, "text": "pcap_b64 is not valid base64"}
    if len(data) > MAX_PCAP:
        return {"ok": False, "text": f"file too large (limit {MAX_PCAP // 1024} KB)"}
    try:
        return analyse(data, verbose)
    except ValueError as e:
        return {"ok": False, "text": f"not a readable pcap: {e}"}


class handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_OPTIONS(self):  # noqa: N802
        self._send(204, {})

    def do_POST(self):  # noqa: N802
        try:
            n = int(self.headers.get("Content-Length") or 0)
            self._send(200, handle(json.loads(self.rfile.read(n) or b"{}")))
        except Exception as e:  # noqa: BLE001
            self._send(200, {"ok": False, "text": f"{type(e).__name__}: {e}"})

    def do_GET(self):  # noqa: N802
        self._send(200, {"ok": True, "text": "POST {sample:true} or {pcap_b64:...}"})
