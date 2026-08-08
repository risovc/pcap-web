"""Comprehensive TCP state machine, stream reconstruction, and diagnostic engine.

Analyzes:
- 5-tuple bidirectional stream reconstruction
- 3-way handshake timing & initial Round-Trip-Time (iRTT)
- Fast Retransmissions vs Timeout-based Retransmissions (RTO) vs Spurious Retransmissions
- Duplicate ACKs & Fast Retransmission trigger points
- Out-of-Order segments
- Zero Window alerts, Zero Window Probes, and Receiver Stalls
- Connection Termination & Abortive RST flags
- Stream & capture-wide health scoring (0-100)
- Actionable root-cause diagnostic summaries
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.pcap_parser import Packet, TCPHeader


class AnomalyType:
    HANDSHAKE_TIMEOUT = "HANDSHAKE_TIMEOUT"
    HANDSHAKE_REFUSED = "HANDSHAKE_REFUSED"
    FAST_RETRANSMISSION = "FAST_RETRANSMISSION"
    RTO_RETRANSMISSION = "RTO_RETRANSMISSION"
    SPURIOUS_RETRANSMISSION = "SPURIOUS_RETRANSMISSION"
    RETRANSMISSION = "RETRANSMISSION"
    DUPLICATE_ACK = "DUPLICATE_ACK"
    OUT_OF_ORDER = "OUT_OF_ORDER"
    ZERO_WINDOW = "ZERO_WINDOW"
    ZERO_WINDOW_PROBE = "ZERO_WINDOW_PROBE"
    ZERO_WINDOW_PROBE_ACK = "ZERO_WINDOW_PROBE_ACK"
    WINDOW_UPDATE = "WINDOW_UPDATE"
    RST_ABORT = "RST_ABORT"
    RST_REFUSED = "RST_REFUSED"
    HIGH_LATENCY = "HIGH_LATENCY"


@dataclass
class Anomaly:
    packet_index: int
    timestamp: float
    relative_time_ms: float
    anomaly_type: str
    severity: str  # "CRITICAL", "WARNING", "INFO"
    title: str
    description: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int


@dataclass
class AnalyzedPacket:
    packet_index: int
    timestamp: float
    relative_time_ms: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    direction: str  # "C->S" (Client to Server) or "S->C" (Server to Client)
    seq_num: int
    ack_num: int
    rel_seq: int
    rel_ack: int
    payload_len: int
    flags: Dict[str, bool]
    flags_str: str
    window_size: int
    effective_window: int
    anomalies: List[Anomaly] = field(default_factory=list)
    rtt_ms: Optional[float] = None
    summary: str = ""


@dataclass
class TCPStream:
    stream_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    start_time: float
    end_time: float
    duration_ms: float
    total_packets: int
    client_to_server_packets: int
    server_to_client_packets: int
    total_bytes: int
    client_bytes: int
    server_bytes: int
    # Diagnostics
    handshake_completed: bool
    handshake_irtt_ms: Optional[float] = None
    retransmission_count: int = 0
    fast_retransmit_count: int = 0
    rto_retransmit_count: int = 0
    dup_ack_count: int = 0
    out_of_order_count: int = 0
    zero_window_count: int = 0
    zero_window_stall_ms: float = 0.0
    rst_count: int = 0
    is_aborted: bool = False
    is_cleanly_closed: bool = False
    health_score: int = 100
    health_status: str = "HEALTHY"  # HEALTHY, DEGRADED, CRITICAL
    anomalies: List[Anomaly] = field(default_factory=list)
    packets: List[AnalyzedPacket] = field(default_factory=list)
    # Timeline metrics
    throughput_timeline: List[Dict[str, Any]] = field(default_factory=list)
    rtt_timeline: List[Dict[str, Any]] = field(default_factory=list)
    window_timeline: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Conversation:
    ip_a: str
    ip_b: str
    total_packets: int
    total_bytes: int
    tcp_streams: int
    start_time: float
    end_time: float
    sample_ports: List[int] = field(default_factory=list)


@dataclass
class DiagnosticSummary:
    health_score: int
    health_status: str
    total_streams: int
    total_packets: int
    total_bytes: int
    duration_seconds: float
    retransmissions_total: int
    retransmission_rate_pct: float
    duplicate_acks_total: int
    zero_window_events_total: int
    zero_window_total_stall_ms: float
    rst_aborts_total: int
    avg_rtt_ms: Optional[float]
    max_rtt_ms: Optional[float]
    critical_issues: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def discover_conversations(packets: List[Packet]) -> List[Conversation]:
    """Fast scan discovering all IP talker pairs and their communication volume."""
    conv_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for pkt in packets:
        if not pkt.ip:
            continue
        ip1, ip2 = (pkt.ip.src_ip, pkt.ip.dst_ip)
        key = (ip1, ip2) if ip1 <= ip2 else (ip2, ip1)

        if key not in conv_map:
            conv_map[key] = {
                "ip_a": key[0],
                "ip_b": key[1],
                "total_packets": 0,
                "total_bytes": 0,
                "stream_keys": set(),
                "start_time": pkt.timestamp,
                "end_time": pkt.timestamp,
                "ports": set(),
            }

        c = conv_map[key]
        c["total_packets"] += 1
        c["total_bytes"] += pkt.original_len or pkt.captured_len
        c["start_time"] = min(c["start_time"], pkt.timestamp)
        c["end_time"] = max(c["end_time"], pkt.timestamp)

        if pkt.is_tcp and pkt.tcp:
            s_key = (pkt.ip.src_ip, pkt.tcp.src_port, pkt.ip.dst_ip, pkt.tcp.dst_port)
            c["stream_keys"].add(
                (s_key[0], s_key[1], s_key[2], s_key[3])
                if (s_key[0], s_key[1]) <= (s_key[2], s_key[3])
                else (s_key[2], s_key[3], s_key[0], s_key[1])
            )
            c["ports"].add(pkt.tcp.src_port)
            c["ports"].add(pkt.tcp.dst_port)

    conversations = []
    for c in conv_map.values():
        conversations.append(
            Conversation(
                ip_a=c["ip_a"],
                ip_b=c["ip_b"],
                total_packets=c["total_packets"],
                total_bytes=c["total_bytes"],
                tcp_streams=len(c["stream_keys"]),
                start_time=c["start_time"],
                end_time=c["end_time"],
                sample_ports=sorted(list(c["ports"]))[:10],
            )
        )

    conversations.sort(key=lambda x: x.total_packets, reverse=True)
    return conversations


class TCPStreamAnalyzer:
    """Detailed state machine and diagnostic analysis for a single TCP stream."""

    def __init__(
        self,
        stream_id: int,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        base_timestamp: float,
    ):
        self.stream_id = stream_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.base_timestamp = base_timestamp

        # Directional state tracking
        self.client_initial_seq: Optional[int] = None
        self.server_initial_seq: Optional[int] = None
        self.client_wscale: int = 0
        self.server_wscale: int = 0

        # Sequence & ACK tracking per direction
        self.sent_segments: Dict[str, List[Dict[str, Any]]] = {"C->S": [], "S->C": []}
        self.highest_seq: Dict[str, int] = {"C->S": 0, "S->C": 0}
        self.expected_next_seq: Dict[str, int] = {"C->S": 0, "S->C": 0}
        self.highest_ack: Dict[str, int] = {"C->S": 0, "S->C": 0}
        self.last_ack_num: Dict[str, Optional[int]] = {"C->S": None, "S->C": None}
        self.dup_ack_count_map: Dict[str, int] = {"C->S": 0, "S->C": 0}

        # Zero window tracking
        self.in_zero_window: Dict[str, bool] = {"C->S": False, "S->C": False}
        self.zero_window_start_time: Dict[str, Optional[float]] = {"C->S": None, "S->C": None}
        self.total_zero_window_stall_ms = 0.0

        # Handshake state
        self.syn_time: Optional[float] = None
        self.syn_ack_time: Optional[float] = None
        self.handshake_ack_time: Optional[float] = None
        self.handshake_completed = False
        self.handshake_irtt_ms: Optional[float] = None

        # Data & Anomalies
        self.packets: List[AnalyzedPacket] = []
        self.anomalies: List[Anomaly] = []
        self.retransmissions = 0
        self.fast_retransmits = 0
        self.rto_retransmits = 0
        self.dup_acks = 0
        self.out_of_order = 0
        self.zero_windows = 0
        self.rst_count = 0
        self.is_aborted = False
        self.is_cleanly_closed = False

        self.rtt_samples: List[Tuple[float, float]] = []  # (timestamp, rtt_ms)
        self.throughput_buckets: Dict[int, int] = {}  # second_offset -> bytes

    def process_packet(self, pkt: Packet) -> AnalyzedPacket:
        tcp = pkt.tcp
        ip = pkt.ip
        assert tcp is not None and ip is not None

        # Determine direction
        if ip.src_ip == self.client_ip and tcp.src_port == self.client_port:
            direction = "C->S"
            peer_direction = "S->C"
        else:
            direction = "S->C"
            peer_direction = "C->S"

        rel_time_ms = (pkt.timestamp - self.base_timestamp) * 1000.0

        # Initialize sequence numbers
        if tcp.flags.get("SYN"):
            if direction == "C->S" and self.client_initial_seq is None:
                self.client_initial_seq = tcp.seq_num
                if tcp.window_scale is not None:
                    self.client_wscale = tcp.window_scale
            elif direction == "S->C" and self.server_initial_seq is None:
                self.server_initial_seq = tcp.seq_num
                if tcp.window_scale is not None:
                    self.server_wscale = tcp.window_scale

        c_init = self.client_initial_seq if self.client_initial_seq is not None else 0
        s_init = self.server_initial_seq if self.server_initial_seq is not None else 0

        if direction == "C->S":
            rel_seq = (tcp.seq_num - c_init) & 0xFFFFFFFF
            rel_ack = (tcp.ack_num - s_init) & 0xFFFFFFFF if tcp.flags.get("ACK") and s_init else 0
            wscale = self.client_wscale
        else:
            rel_seq = (tcp.seq_num - s_init) & 0xFFFFFFFF
            rel_ack = (tcp.ack_num - c_init) & 0xFFFFFFFF if tcp.flags.get("ACK") and c_init else 0
            wscale = self.server_wscale

        effective_win = tcp.window_size << wscale if (not tcp.flags.get("SYN")) else tcp.window_size

        packet_anomalies: List[Anomaly] = []
        measured_rtt_ms: Optional[float] = None

        # 1. Handshake tracking
        if tcp.flags.get("SYN") and not tcp.flags.get("ACK"):
            self.syn_time = pkt.timestamp
        elif tcp.flags.get("SYN") and tcp.flags.get("ACK"):
            self.syn_ack_time = pkt.timestamp
            if self.syn_time:
                self.handshake_irtt_ms = (self.syn_ack_time - self.syn_time) * 1000.0
                measured_rtt_ms = self.handshake_irtt_ms
                if self.handshake_irtt_ms > 250.0:
                    a = Anomaly(
                        packet_index=pkt.packet_index,
                        timestamp=pkt.timestamp,
                        relative_time_ms=rel_time_ms,
                        anomaly_type=AnomalyType.HIGH_LATENCY,
                        severity="WARNING",
                        title="High Handshake Latency",
                        description=f"Server SYN-ACK latency was {self.handshake_irtt_ms:.1f}ms (expected < 100ms)",
                        src_ip=ip.src_ip,
                        dst_ip=ip.dst_ip,
                        src_port=tcp.src_port,
                        dst_port=tcp.dst_port,
                    )
                    packet_anomalies.append(a)
        elif not self.handshake_completed and self.syn_ack_time and tcp.flags.get("ACK") and not tcp.flags.get("SYN"):
            self.handshake_ack_time = pkt.timestamp
            self.handshake_completed = True

        # 2. Connection Abort (RST)
        if tcp.flags.get("RST"):
            self.rst_count += 1
            self.is_aborted = True
            if self.syn_time and not self.handshake_completed:
                a = Anomaly(
                    packet_index=pkt.packet_index,
                    timestamp=pkt.timestamp,
                    relative_time_ms=rel_time_ms,
                    anomaly_type=AnomalyType.RST_REFUSED,
                    severity="CRITICAL",
                    title="Connection Refused (RST on Handshake)",
                    description="Server actively refused connection attempt. Port is likely closed or filtered.",
                    src_ip=ip.src_ip,
                    dst_ip=ip.dst_ip,
                    src_port=tcp.src_port,
                    dst_port=tcp.dst_port,
                )
            else:
                a = Anomaly(
                    packet_index=pkt.packet_index,
                    timestamp=pkt.timestamp,
                    relative_time_ms=rel_time_ms,
                    anomaly_type=AnomalyType.RST_ABORT,
                    severity="CRITICAL",
                    title="Abrupt Connection Reset (RST)",
                    description="Connection terminated abruptly by peer via TCP RST flag without clean FIN handshake.",
                    src_ip=ip.src_ip,
                    dst_ip=ip.dst_ip,
                    src_port=tcp.src_port,
                    dst_port=tcp.dst_port,
                )
            packet_anomalies.append(a)

        # 3. Clean FIN Teardown
        if tcp.flags.get("FIN"):
            self.is_cleanly_closed = True

        # 4. Zero Window & Stalls
        if not tcp.flags.get("SYN") and not tcp.flags.get("RST"):
            if tcp.window_size == 0:
                if not self.in_zero_window[direction]:
                    self.in_zero_window[direction] = True
                    self.zero_window_start_time[direction] = pkt.timestamp
                    self.zero_windows += 1
                    a = Anomaly(
                        packet_index=pkt.packet_index,
                        timestamp=pkt.timestamp,
                        relative_time_ms=rel_time_ms,
                        anomaly_type=AnomalyType.ZERO_WINDOW,
                        severity="CRITICAL",
                        title="TCP Zero Window (Receiver Buffer Full)",
                        description=f"{ip.src_ip} announced a Zero Window. It cannot accept any further payload data.",
                        src_ip=ip.src_ip,
                        dst_ip=ip.dst_ip,
                        src_port=tcp.src_port,
                        dst_port=tcp.dst_port,
                    )
                    packet_anomalies.append(a)
            elif self.in_zero_window[direction] and tcp.window_size > 0:
                # Window update recovery
                self.in_zero_window[direction] = False
                stall_dur = 0.0
                if self.zero_window_start_time[direction]:
                    stall_dur = (pkt.timestamp - self.zero_window_start_time[direction]) * 1000.0
                    self.total_zero_window_stall_ms += stall_dur
                a = Anomaly(
                    packet_index=pkt.packet_index,
                    timestamp=pkt.timestamp,
                    relative_time_ms=rel_time_ms,
                    anomaly_type=AnomalyType.WINDOW_UPDATE,
                    severity="INFO",
                    title="TCP Window Update",
                    description=f"{ip.src_ip} reopened its receive window ({effective_win} bytes) after {stall_dur:.1f}ms stall.",
                    src_ip=ip.src_ip,
                    dst_ip=ip.dst_ip,
                    src_port=tcp.src_port,
                    dst_port=tcp.dst_port,
                )
                packet_anomalies.append(a)

        # 5. Zero Window Probe detection
        if self.in_zero_window[peer_direction] and tcp.payload_len <= 1 and not tcp.flags.get("SYN") and not tcp.flags.get("RST"):
            if tcp.payload_len == 1:
                a = Anomaly(
                    packet_index=pkt.packet_index,
                    timestamp=pkt.timestamp,
                    relative_time_ms=rel_time_ms,
                    anomaly_type=AnomalyType.ZERO_WINDOW_PROBE,
                    severity="WARNING",
                    title="Zero Window Probe",
                    description="Sender transmitted a 1-byte probe segment to query receiver window status.",
                    src_ip=ip.src_ip,
                    dst_ip=ip.dst_ip,
                    src_port=tcp.src_port,
                    dst_port=tcp.dst_port,
                )
                packet_anomalies.append(a)

        # 6. Duplicate ACK Detection
        if tcp.flags.get("ACK") and tcp.payload_len == 0 and not tcp.flags.get("SYN") and not tcp.flags.get("FIN") and not tcp.flags.get("RST"):
            if self.last_ack_num[direction] == tcp.ack_num:
                self.dup_ack_count_map[direction] += 1
                self.dup_acks += 1
                dup_num = self.dup_ack_count_map[direction]
                severity = "CRITICAL" if dup_num >= 3 else "WARNING"
                title = f"TCP Duplicate ACK #{dup_num}" + (" (Fast Retransmit Trigger)" if dup_num == 3 else "")
                a = Anomaly(
                    packet_index=pkt.packet_index,
                    timestamp=pkt.timestamp,
                    relative_time_ms=rel_time_ms,
                    anomaly_type=AnomalyType.DUPLICATE_ACK,
                    severity=severity,
                    title=title,
                    description=f"Duplicate ACK expecting Seq={rel_ack}. Receiver is signaling missing packet in transit.",
                    src_ip=ip.src_ip,
                    dst_ip=ip.dst_ip,
                    src_port=tcp.src_port,
                    dst_port=tcp.dst_port,
                )
                packet_anomalies.append(a)
            else:
                self.last_ack_num[direction] = tcp.ack_num
                self.dup_ack_count_map[direction] = 0
        else:
            if tcp.flags.get("ACK"):
                self.last_ack_num[direction] = tcp.ack_num
                self.dup_ack_count_map[direction] = 0

        # 7. Retransmission & Out-of-Order Detection
        if tcp.payload_len > 0 and not tcp.flags.get("SYN"):
            seq_end = tcp.seq_num + tcp.payload_len
            prev_segments = self.sent_segments[direction]

            # Check if this sequence range was already transmitted OR if seq < highest_seq
            is_retransmit = False
            matching_prev: Optional[Dict[str, Any]] = None
            for seg in prev_segments:
                if seg["seq"] == tcp.seq_num and seg["len"] == tcp.payload_len:
                    is_retransmit = True
                    matching_prev = seg
                    break

            if not is_retransmit and tcp.seq_num < self.highest_seq[direction]:
                is_retransmit = True

            if is_retransmit:
                self.retransmissions += 1
                time_delta_ms = (pkt.timestamp - matching_prev["time"]) * 1000.0 if matching_prev else 0.0

                # Check if 3 dup ACKs were received on peer direction
                peer_dup_acks = self.dup_ack_count_map[peer_direction]
                if peer_dup_acks >= 3:
                    self.fast_retransmits += 1
                    ref_text = f" ({time_delta_ms:.1f}ms after original packet #{matching_prev['index']})" if matching_prev else " (packet dropped upstream)"
                    a = Anomaly(
                        packet_index=pkt.packet_index,
                        timestamp=pkt.timestamp,
                        relative_time_ms=rel_time_ms,
                        anomaly_type=AnomalyType.FAST_RETRANSMISSION,
                        severity="CRITICAL",
                        title="TCP Fast Retransmission",
                        description=f"Retransmitted {tcp.payload_len} bytes (Seq={rel_seq}) triggered by {peer_dup_acks} duplicate ACKs{ref_text}.",
                        src_ip=ip.src_ip,
                        dst_ip=ip.dst_ip,
                        src_port=tcp.src_port,
                        dst_port=tcp.dst_port,
                    )
                elif time_delta_ms > 150.0:
                    self.rto_retransmits += 1
                    a = Anomaly(
                        packet_index=pkt.packet_index,
                        timestamp=pkt.timestamp,
                        relative_time_ms=rel_time_ms,
                        anomaly_type=AnomalyType.RTO_RETRANSMISSION,
                        severity="CRITICAL",
                        title="TCP Retransmission (RTO Timeout)",
                        description=f"Retransmitted {tcp.payload_len} bytes (Seq={rel_seq}) after RTO timeout of {time_delta_ms:.1f}ms (Original packet #{matching_prev['index'] if matching_prev else 'N/A'}).",
                        src_ip=ip.src_ip,
                        dst_ip=ip.dst_ip,
                        src_port=tcp.src_port,
                        dst_port=tcp.dst_port,
                    )
                else:
                    a = Anomaly(
                        packet_index=pkt.packet_index,
                        timestamp=pkt.timestamp,
                        relative_time_ms=rel_time_ms,
                        anomaly_type=AnomalyType.RETRANSMISSION,
                        severity="CRITICAL",
                        title="TCP Retransmission",
                        description=f"Retransmission of {tcp.payload_len} bytes (Seq={rel_seq}, delta {time_delta_ms:.1f}ms).",
                        src_ip=ip.src_ip,
                        dst_ip=ip.dst_ip,
                        src_port=tcp.src_port,
                        dst_port=tcp.dst_port,
                    )
                packet_anomalies.append(a)
            else:
                # Out-of-order check
                exp_seq = self.expected_next_seq[direction]
                if exp_seq > 0 and tcp.seq_num < exp_seq and tcp.seq_num > self.highest_seq[direction]:
                    self.out_of_order += 1
                    a = Anomaly(
                        packet_index=pkt.packet_index,
                        timestamp=pkt.timestamp,
                        relative_time_ms=rel_time_ms,
                        anomaly_type=AnomalyType.OUT_OF_ORDER,
                        severity="WARNING",
                        title="TCP Out-Of-Order Segment",
                        description=f"Packet arrived out of sequence order (Seq={rel_seq}, Expected={exp_seq - (c_init if direction=='C->S' else s_init)}).",
                        src_ip=ip.src_ip,
                        dst_ip=ip.dst_ip,
                        src_port=tcp.src_port,
                        dst_port=tcp.dst_port,
                    )
                    packet_anomalies.append(a)

                # Record segment
                prev_segments.append({
                    "index": pkt.packet_index,
                    "seq": tcp.seq_num,
                    "len": tcp.payload_len,
                    "time": pkt.timestamp,
                })
                self.expected_next_seq[direction] = max(self.expected_next_seq[direction], seq_end)
                self.highest_seq[direction] = max(self.highest_seq[direction], tcp.seq_num)

        # 8. RTT sample calculation from data-to-ACK
        if tcp.flags.get("ACK") and not tcp.flags.get("SYN"):
            peer_segs = self.sent_segments[peer_direction]
            for seg in reversed(peer_segs):
                if seg["seq"] + seg["len"] == tcp.ack_num and not seg.get("rtt_calculated"):
                    sample_rtt = (pkt.timestamp - seg["time"]) * 1000.0
                    if 0.1 <= sample_rtt <= 5000.0:
                        measured_rtt_ms = sample_rtt
                        self.rtt_samples.append((pkt.timestamp, sample_rtt))
                        seg["rtt_calculated"] = True
                    break

        # Track throughput bucket
        sec_bucket = int(pkt.timestamp - self.base_timestamp)
        self.throughput_buckets[sec_bucket] = (
            self.throughput_buckets.get(sec_bucket, 0) + (pkt.original_len or pkt.captured_len)
        )

        # Summary line for UI
        summary_flags = tcp.flags_str
        summary_info = f"[{summary_flags}] Seq={rel_seq} Ack={rel_ack} Win={effective_win} Len={tcp.payload_len}"
        if packet_anomalies:
            summary_info += f" ⚠️ {packet_anomalies[0].title}"

        analyzed_pkt = AnalyzedPacket(
            packet_index=pkt.packet_index,
            timestamp=pkt.timestamp,
            relative_time_ms=rel_time_ms,
            src_ip=ip.src_ip,
            dst_ip=ip.dst_ip,
            src_port=tcp.src_port,
            dst_port=tcp.dst_port,
            direction=direction,
            seq_num=tcp.seq_num,
            ack_num=tcp.ack_num,
            rel_seq=rel_seq,
            rel_ack=rel_ack,
            payload_len=tcp.payload_len,
            flags=tcp.flags,
            flags_str=summary_flags,
            window_size=tcp.window_size,
            effective_window=effective_win,
            anomalies=packet_anomalies,
            rtt_ms=measured_rtt_ms,
            summary=summary_info,
        )

        self.packets.append(analyzed_pkt)
        self.anomalies.extend(packet_anomalies)
        return analyzed_pkt

    def finalize(self) -> TCPStream:
        if not self.packets:
            start_t = self.base_timestamp
            end_t = self.base_timestamp
        else:
            start_t = self.packets[0].timestamp
            end_t = self.packets[-1].timestamp

        dur_ms = (end_t - start_t) * 1000.0

        c_to_s = sum(1 for p in self.packets if p.direction == "C->S")
        s_to_c = len(self.packets) - c_to_s

        c_bytes = sum(p.payload_len for p in self.packets if p.direction == "C->S")
        s_bytes = sum(p.payload_len for p in self.packets if p.direction == "S->C")
        total_bytes = sum(p.payload_len for p in self.packets)

        # Calculate Health Score (0-100)
        score = 100
        total_pkts = max(1, len(self.packets))
        retransmit_rate = (self.retransmissions / total_pkts) * 100.0

        # Retransmission deductions
        if retransmit_rate > 0:
            score -= min(40, int(retransmit_rate * 5))

        # RST Abort deductions
        if self.is_aborted:
            score -= 30

        # Zero Window deductions
        if self.zero_windows > 0:
            score -= min(25, self.zero_windows * 10)

        # Handshake failure
        if not self.handshake_completed and len(self.packets) > 1:
            score -= 20

        # Latency penalty
        if self.handshake_irtt_ms and self.handshake_irtt_ms > 200:
            score -= min(15, int((self.handshake_irtt_ms - 200) / 50) * 5)

        score = max(0, min(100, score))
        health_status = "HEALTHY" if score >= 85 else ("DEGRADED" if score >= 60 else "CRITICAL")

        # Build timelines
        tp_timeline = []
        for sec in sorted(self.throughput_buckets.keys()):
            tp_timeline.append({
                "time_sec": sec,
                "bytes_per_sec": self.throughput_buckets[sec],
                "kbps": round((self.throughput_buckets[sec] * 8) / 1000.0, 2),
            })

        rtt_timeline = []
        for ts, rtt in self.rtt_samples:
            rtt_timeline.append({
                "time_ms": round((ts - self.base_timestamp) * 1000.0, 2),
                "rtt_ms": round(rtt, 2),
            })

        win_timeline = []
        for p in self.packets:
            win_timeline.append({
                "time_ms": round(p.relative_time_ms, 2),
                "direction": p.direction,
                "window_size": p.effective_window,
            })

        return TCPStream(
            stream_id=self.stream_id,
            client_ip=self.client_ip,
            client_port=self.client_port,
            server_ip=self.server_ip,
            server_port=self.server_port,
            start_time=start_t,
            end_time=end_t,
            duration_ms=round(dur_ms, 2),
            total_packets=len(self.packets),
            client_to_server_packets=c_to_s,
            server_to_client_packets=s_to_c,
            total_bytes=total_bytes,
            client_bytes=c_bytes,
            server_bytes=s_bytes,
            handshake_completed=self.handshake_completed,
            handshake_irtt_ms=round(self.handshake_irtt_ms, 2) if self.handshake_irtt_ms else None,
            retransmission_count=self.retransmissions,
            fast_retransmit_count=self.fast_retransmits,
            rto_retransmit_count=self.rto_retransmits,
            dup_ack_count=self.dup_acks,
            out_of_order_count=self.out_of_order,
            zero_window_count=self.zero_windows,
            zero_window_stall_ms=round(self.total_zero_window_stall_ms, 2),
            rst_count=self.rst_count,
            is_aborted=self.is_aborted,
            is_cleanly_closed=self.is_cleanly_closed,
            health_score=score,
            health_status=health_status,
            anomalies=self.anomalies,
            packets=self.packets,
            throughput_timeline=tp_timeline,
            rtt_timeline=rtt_timeline,
            window_timeline=win_timeline,
        )


def analyze_pcap_flow(
    packets: List[Packet],
    client_ip: Optional[str] = None,
    server_ip: Optional[str] = None,
    client_port: Optional[int] = None,
    server_port: Optional[int] = None,
) -> Tuple[List[TCPStream], DiagnosticSummary]:
    """Reconstructs and analyzes all TCP streams matching the optional IP/port filters."""
    if not packets:
        return [], DiagnosticSummary(
            health_score=100,
            health_status="HEALTHY",
            total_streams=0,
            total_packets=0,
            total_bytes=0,
            duration_seconds=0.0,
            retransmissions_total=0,
            retransmission_rate_pct=0.0,
            duplicate_acks_total=0,
            zero_window_events_total=0,
            zero_window_total_stall_ms=0.0,
            rst_aborts_total=0,
            avg_rtt_ms=None,
            max_rtt_ms=None,
        )

    base_ts = packets[0].timestamp

    # 1. Filter packets if IP specified
    filtered_packets: List[Packet] = []
    for pkt in packets:
        if not pkt.is_tcp or not pkt.ip or not pkt.tcp:
            continue

        src, dst = pkt.ip.src_ip, pkt.ip.dst_ip
        sport, dport = pkt.tcp.src_port, pkt.tcp.dst_port

        if client_ip and server_ip:
            matches_fwd = (src == client_ip and dst == server_ip)
            matches_rev = (src == server_ip and dst == client_ip)
            if not (matches_fwd or matches_rev):
                continue
            if client_port:
                if matches_fwd and sport != client_port:
                    continue
                if matches_rev and dport != client_port:
                    continue
            if server_port:
                if matches_fwd and dport != server_port:
                    continue
                if matches_rev and sport != server_port:
                    continue
        elif client_ip:
            if src != client_ip and dst != client_ip:
                continue
        elif server_ip:
            if src != server_ip and dst != server_ip:
                continue

        filtered_packets.append(pkt)

    if not filtered_packets:
        return [], DiagnosticSummary(
            health_score=100,
            health_status="HEALTHY",
            total_streams=0,
            total_packets=0,
            total_bytes=0,
            duration_seconds=0.0,
            retransmissions_total=0,
            retransmission_rate_pct=0.0,
            duplicate_acks_total=0,
            zero_window_events_total=0,
            zero_window_total_stall_ms=0.0,
            rst_aborts_total=0,
            avg_rtt_ms=None,
            max_rtt_ms=None,
        )

    # 2. Group into streams
    stream_map: Dict[Tuple[str, int, str, int], TCPStreamAnalyzer] = {}
    stream_list: List[TCPStreamAnalyzer] = []
    stream_id_counter = 0

    for pkt in filtered_packets:
        ip, tcp = pkt.ip, pkt.tcp
        assert ip is not None and tcp is not None

        ep1 = (ip.src_ip, tcp.src_port)
        ep2 = (ip.dst_ip, tcp.dst_port)
        canon_key = (ep1[0], ep1[1], ep2[0], ep2[1]) if ep1 <= ep2 else (ep2[0], ep2[1], ep1[0], ep1[1])

        if canon_key not in stream_map:
            # Client is first SYN sender or first observed packet sender
            if client_ip and server_ip:
                c_ip = client_ip
                s_ip = server_ip
                c_port = tcp.src_port if ip.src_ip == client_ip else tcp.dst_port
                s_port = tcp.dst_port if ip.src_ip == client_ip else tcp.src_port
            elif tcp.flags.get("SYN") and not tcp.flags.get("ACK"):
                c_ip, c_port = ip.src_ip, tcp.src_port
                s_ip, s_port = ip.dst_ip, tcp.dst_port
            else:
                c_ip, c_port = ip.src_ip, tcp.src_port
                s_ip, s_port = ip.dst_ip, tcp.dst_port

            analyzer = TCPStreamAnalyzer(
                stream_id=stream_id_counter,
                client_ip=c_ip,
                client_port=c_port,
                server_ip=s_ip,
                server_port=s_port,
                base_timestamp=base_ts,
            )
            stream_map[canon_key] = analyzer
            stream_list.append(analyzer)
            stream_id_counter += 1

        stream_map[canon_key].process_packet(pkt)

    # 3. Finalize streams
    finalized_streams = [s.finalize() for s in stream_list]

    # 4. Global capture diagnostics summary
    total_pkts = len(filtered_packets)
    total_bytes = sum(p.original_len or p.captured_len for p in filtered_packets)
    dur_sec = (filtered_packets[-1].timestamp - filtered_packets[0].timestamp) if len(filtered_packets) > 1 else 0.0

    total_retrans = sum(s.retransmission_count for s in finalized_streams)
    retrans_rate = (total_retrans / total_pkts * 100.0) if total_pkts > 0 else 0.0
    total_dup_acks = sum(s.dup_ack_count for s in finalized_streams)
    total_zero_wins = sum(s.zero_window_count for s in finalized_streams)
    total_stall_ms = sum(s.zero_window_stall_ms for s in finalized_streams)
    total_rsts = sum(s.rst_count for s in finalized_streams)

    all_rtts: List[float] = []
    for s in finalized_streams:
        for sample in s.rtt_timeline:
            all_rtts.append(sample["rtt_ms"])

    avg_rtt = round(sum(all_rtts) / len(all_rtts), 2) if all_rtts else None
    max_rtt = round(max(all_rtts), 2) if all_rtts else None

    # Calculate overall health score
    health_score = int(sum(s.health_score for s in finalized_streams) / len(finalized_streams)) if finalized_streams else 100
    health_status = "HEALTHY" if health_score >= 85 else ("DEGRADED" if health_score >= 60 else "CRITICAL")

    critical_issues = []
    warnings = []
    recommendations = []

    if total_retrans > 0:
        if retrans_rate > 5.0:
            critical_issues.append({
                "type": "RETRANSMISSION_STORM",
                "title": f"Severe Packet Loss & Retransmission Rate ({retrans_rate:.1f}%)",
                "detail": f"{total_retrans} packet retransmissions detected out of {total_pkts} total packets.",
            })
            recommendations.append("Investigate physical link drops, congested intermediate routers, or MTU black holes causing packet loss.")
        else:
            warnings.append({
                "type": "RETRANSMISSIONS",
                "title": f"Minor Packet Retransmissions ({total_retrans} pkts, {retrans_rate:.1f}%)",
                "detail": "Some packets required retransmission. Check wireless/WAN link quality.",
            })

    if total_zero_wins > 0:
        critical_issues.append({
            "type": "ZERO_WINDOW_STALL",
            "title": f"TCP Zero Window Receiver Bottleneck ({total_zero_wins} events)",
            "detail": f"Receiver advertised 0 bytes available window, causing {total_stall_ms:.1f}ms total pipeline stall.",
        })
        recommendations.append("Receiver application is CPU or I/O bound and cannot process incoming socket buffer fast enough. Increase receive buffer (SO_RCVBUF) or optimize receiver processing loop.")

    if total_rsts > 0:
        critical_issues.append({
            "type": "CONNECTION_ABORT",
            "title": f"Abrupt TCP RST Resets ({total_rsts} resets)",
            "detail": "Connections were forcefully terminated with RST flags instead of clean FIN teardowns.",
        })
        recommendations.append("Check if firewall/NAT state timeouts dropped the connection or if backend process crashed / closed listening socket abruptly.")

    if avg_rtt and avg_rtt > 150.0:
        warnings.append({
            "type": "HIGH_RTT",
            "title": f"Elevated Round Trip Time (Avg: {avg_rtt:.1f}ms, Max: {max_rtt:.1f}ms)",
            "detail": "Network latency is noticeably high, impacting TCP throughput and BDP.",
        })
        recommendations.append("Enable TCP Window Scaling (RFC 1323) and BBR congestion control to improve throughput across high-latency links.")

    if not critical_issues and not warnings:
        recommendations.append("All analyzed TCP streams exhibit healthy 3-way handshakes, smooth sequence progression, zero packet loss, and clean connection closures.")

    summary = DiagnosticSummary(
        health_score=health_score,
        health_status=health_status,
        total_streams=len(finalized_streams),
        total_packets=total_pkts,
        total_bytes=total_bytes,
        duration_seconds=round(dur_sec, 3),
        retransmissions_total=total_retrans,
        retransmission_rate_pct=round(retrans_rate, 2),
        duplicate_acks_total=total_dup_acks,
        zero_window_events_total=total_zero_wins,
        zero_window_total_stall_ms=round(total_stall_ms, 2),
        rst_aborts_total=total_rsts,
        avg_rtt_ms=avg_rtt,
        max_rtt_ms=max_rtt,
        critical_issues=critical_issues,
        warnings=warnings,
        recommendations=recommendations,
    )

    return finalized_streams, summary
