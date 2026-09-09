from pktanalyzer import builders as B
from pktanalyzer.analyze import Analyzer
from pktanalyzer.layers import dissect


def feed(frames_with_ts):
    az = Analyzer()
    for ts, fr in frames_with_ts:
        az.add(ts, dissect(fr))
    return az


def test_protocol_and_talker_counts():
    az = feed([
        (0.0, B.frame_tcp("10.0.0.1", "10.0.0.2", 5000, 443, flags=B.SYN)),
        (0.1, B.frame_tcp("10.0.0.2", "10.0.0.1", 443, 5000, flags=B.SYN_ACK)),
        (0.2, B.frame_dns_query("10.0.0.1", "8.8.8.8", "example.com")),
        (0.3, B.frame_icmp("10.0.0.1", "1.1.1.1")),
    ])
    rep = az.report()
    assert rep["packets"] == 4
    protos = dict(rep["protocols"])
    assert protos["TCP"] == 2 and protos["DNS"] == 1 and protos["ICMPv4"] == 1
    talkers = dict(rep["top_talkers"])
    assert talkers["10.0.0.1"] > 0
    assert rep["tcp_flags"]["SYN"] == 2


def test_flow_bidirectional_accounting():
    frames = [
        (0.0, B.frame_tcp("10.0.0.1", "10.0.0.2", 51000, 80, flags=B.SYN, seq=1)),
        (0.1, B.frame_tcp("10.0.0.2", "10.0.0.1", 80, 51000, flags=B.SYN_ACK, seq=1, ack=2)),
        (0.2, B.frame_tcp("10.0.0.1", "10.0.0.2", 51000, 80, flags=B.PSH_ACK, seq=2, ack=2,
                          payload=b"x" * 100)),
        (0.9, B.frame_tcp("10.0.0.1", "10.0.0.2", 51000, 80, flags=B.FIN_ACK, seq=102, ack=2)),
    ]
    az = feed(frames)
    assert len(az.flows) == 1
    flow = az.flow_table()[0]
    assert flow.proto == "TCP"
    assert flow.packets == 4
    assert flow.packets_ab == 3 and flow.packets_ba == 1
    assert flow.syn == 2 and flow.fin == 1
    assert round(flow.duration, 1) == 0.9
    assert flow.bytes_ab > flow.bytes_ba


def test_retransmission_detection():
    payload = b"GET / HTTP/1.1\r\n\r\n"
    frames = [
        (0.0, B.frame_tcp("10.0.0.1", "10.0.0.2", 4000, 80, flags=B.PSH_ACK, seq=1000, payload=payload)),
        (0.5, B.frame_tcp("10.0.0.1", "10.0.0.2", 4000, 80, flags=B.PSH_ACK, seq=1000, payload=payload)),
        (1.0, B.frame_tcp("10.0.0.1", "10.0.0.2", 4000, 80, flags=B.PSH_ACK, seq=1018, payload=payload)),
    ]
    az = feed(frames)
    assert az.tcp_retransmits == 1        # the second seq=1000 is a retransmit


def test_dns_query_names_collected():
    az = feed([
        (0.0, B.frame_dns_query("10.0.0.1", "8.8.8.8", "example.com")),
        (0.1, B.frame_dns_query("10.0.0.1", "8.8.8.8", "example.com")),
        (0.2, B.frame_dns_query("10.0.0.1", "8.8.8.8", "api.github.com")),
    ])
    assert dict(az.report()["dns_queries"]) == {"example.com": 2, "api.github.com": 1}


def test_top_ports():
    az = feed([(i * 0.01, B.frame_tcp("10.0.0.1", "10.0.0.2", 40000 + i, 443))
               for i in range(5)] +
              [(0.5, B.frame_tcp("10.0.0.1", "10.0.0.2", 41000, 22))])
    ports = dict(az.report()["top_ports"])
    assert ports[443] == 5 and ports[22] == 1


def test_full_pipeline_on_generated_pcap(tmp_path):
    from pktanalyzer.cli import main
    from pktanalyzer.analyze import analyze_pcap

    pcap = tmp_path / "demo.pcap"
    assert main(["gen", str(pcap)]) == 0
    az = analyze_pcap(str(pcap))
    rep = az.report()
    assert rep["packets"] >= 14
    assert "TCP" in dict(rep["protocols"])
    assert "DNS" in dict(rep["protocols"])
    assert dict(rep["protocols"]).get("ARP", 0) == 1
    assert rep["tcp_retransmits"] >= 1
    assert any(name == "example.com" for name, _ in rep["dns_queries"])
