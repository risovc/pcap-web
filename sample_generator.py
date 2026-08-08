"""Synthetic PCAP generator creating 4 realistic packet captures for testing & demonstration:
1. Normal healthy web flow (HTTP transaction with clean FIN teardown)
2. Retransmissions & Packet Loss storm (Duplicate ACKs, Fast Retransmission, RTO timeout)
3. Zero-Window receiver buffer stall (Zero window alert, zero window probes, window update recovery)
4. RST connection abort & refused port (Connection Refused and mid-stream Abort)
"""

from __future__ import annotations

import os
import socket
import struct
from typing import List, Optional, Tuple


def _ip_checksum(header: bytes) -> int:
    if len(header) % 2 == 1:
        header += b"\x00"
    s = sum(struct.unpack(f"!{len(header)//2}H", header))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _tcp_checksum(src_ip: str, dst_ip: str, tcp_segment: bytes) -> int:
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    length = len(tcp_segment)
    pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, 6, length)
    combined = pseudo + tcp_segment
    if len(combined) % 2 == 1:
        combined += b"\x00"
    s = sum(struct.unpack(f"!{len(combined)//2}H", combined))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_raw_packet(
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    win_size: int = 65535,
    payload: bytes = b"",
    options: bytes = b"",
) -> bytes:
    # 1. Ethernet Header (14 bytes)
    eth_dst = bytes.fromhex(dst_mac.replace(":", ""))
    eth_src = bytes.fromhex(src_mac.replace(":", ""))
    eth_header = eth_dst + eth_src + struct.pack("!H", 0x0800)

    # 2. TCP Header
    data_offset_words = (20 + len(options)) // 4
    offset_flags = (data_offset_words << 12) | (flags & 0x01FF)
    tcp_hdr_no_cksum = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_flags,
        win_size & 0xFFFF,
        0,  # checksum placeholder
        0,  # urgent pointer
    ) + options

    cksum = _tcp_checksum(src_ip, dst_ip, tcp_hdr_no_cksum + payload)
    tcp_hdr = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_flags,
        win_size & 0xFFFF,
        cksum,
        0,
    ) + options

    tcp_segment = tcp_hdr + payload

    # 3. IPv4 Header
    total_len = 20 + len(tcp_segment)
    ip_hdr_no_cksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # ver 4, ihl 5 (20 bytes)
        0,     # DSCP/ECN
        total_len,
        0x1234,  # ident
        0x4000,  # Don't Fragment
        64,      # TTL
        6,       # TCP
        0,       # checksum placeholder
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_cksum = _ip_checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0x1234,
        0x4000,
        64,
        6,
        ip_cksum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    return eth_header + ip_hdr + tcp_segment


def write_pcap_file(filepath: str, packets: List[Tuple[float, bytes]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "wb") as f:
        # PCAP Global Header (24 bytes)
        # magic (0xa1b2c3d4), v_maj (2), v_min (4), thiszone (0), sigfigs (0), snaplen (65535), network (1 = Ethernet)
        f.write(struct.pack("=IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, pkt_bytes in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            caplen = len(pkt_bytes)
            origlen = len(pkt_bytes)
            # Packet Header (16 bytes)
            f.write(struct.pack("=IIII", sec, usec, caplen, origlen))
            f.write(pkt_bytes)


# TCP Flag Bitmasks
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10


def generate_normal_web_pcap(filepath: str) -> str:
    """Generates a healthy, optimal HTTP/1.1 flow."""
    c_mac, s_mac = "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"
    c_ip, s_ip = "192.168.1.100", "10.0.0.50"
    c_port, s_port = 52140, 80

    t0 = 1723120000.0  # Base timestamp
    pkts: List[Tuple[float, bytes]] = []

    c_seq = 1000
    s_seq = 5000

    # 1. Handshake SYN
    pkts.append((t0 + 0.000, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, 0, FLAG_SYN, win_size=65535)))
    # 2. Handshake SYN-ACK (18ms RTT)
    pkts.append((t0 + 0.018, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq + 1, FLAG_SYN | FLAG_ACK, win_size=65535)))
    c_seq += 1
    s_seq += 1
    # 3. Handshake ACK
    pkts.append((t0 + 0.019, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, win_size=65535)))

    # 4. HTTP GET Request
    http_req = b"GET /index.html HTTP/1.1\r\nHost: 10.0.0.50\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
    pkts.append((t0 + 0.025, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_PSH | FLAG_ACK, payload=http_req)))
    c_seq += len(http_req)

    # 5. Server ACK
    pkts.append((t0 + 0.040, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK)))

    # 6. HTTP Response Part 1
    http_res_1 = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1024\r\nServer: nginx\r\n\r\n<!DOCTYPE html><html><head><title>Test App</title></head><body><h1>Hello World</h1>"
    pkts.append((t0 + 0.045, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_PSH | FLAG_ACK, payload=http_res_1)))
    s_seq += len(http_res_1)

    # 7. HTTP Response Part 2
    http_res_2 = b"<p>This is a healthy high-throughput packet flow with clean sequence numbers.</p></body></html>" + (b"A" * 800)
    pkts.append((t0 + 0.050, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_PSH | FLAG_ACK, payload=http_res_2)))
    s_seq += len(http_res_2)

    # 8. Client ACK
    pkts.append((t0 + 0.065, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK)))

    # 9. Clean Teardown FIN from Server
    pkts.append((t0 + 0.080, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_FIN | FLAG_ACK)))
    s_seq += 1
    # 10. Client ACK of FIN
    pkts.append((t0 + 0.095, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK)))
    # 11. Client FIN
    pkts.append((t0 + 0.096, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_FIN | FLAG_ACK)))
    c_seq += 1
    # 12. Server final ACK
    pkts.append((t0 + 0.110, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK)))

    write_pcap_file(filepath, pkts)
    return filepath


def generate_packet_loss_pcap(filepath: str) -> str:
    """Generates a flow with packet loss, 3x Duplicate ACKs, Fast Retransmit, and an RTO timeout retransmission."""
    c_mac, s_mac = "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"
    c_ip, s_ip = "192.168.1.105", "10.0.0.80"
    c_port, s_port = 54320, 443

    t0 = 1723120100.0
    pkts: List[Tuple[float, bytes]] = []

    c_seq = 2000
    s_seq = 8000

    # Handshake
    pkts.append((t0 + 0.000, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, 0, FLAG_SYN)))
    pkts.append((t0 + 0.025, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq + 1, FLAG_SYN | FLAG_ACK)))
    c_seq += 1
    s_seq += 1
    pkts.append((t0 + 0.026, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK)))

    # Client sends Data Block 1 (500 bytes) -> Arrives
    d1 = b"X" * 500
    pkts.append((t0 + 0.030, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, payload=d1)))
    c_seq_d1 = c_seq
    c_seq += 500

    # Server ACKs Block 1
    pkts.append((t0 + 0.055, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK)))

    # Client sends Data Block 2 (500 bytes) -> DROPPED IN TRANSIT (not added to capture)
    c_seq_d2 = c_seq
    d2 = b"Y" * 500
    c_seq += 500

    # Client sends Data Block 3 (500 bytes) -> Arrives out-of-order at server
    d3 = b"Z" * 500
    pkts.append((t0 + 0.060, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, payload=d3)))
    c_seq += 500

    # Server receives Block 3, notices gap, sends Dup ACK #1 (expecting Block 2 at c_seq_d2)
    pkts.append((t0 + 0.085, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq_d2, FLAG_ACK)))

    # Client sends Data Block 4 (500 bytes) -> Arrives
    d4 = b"W" * 500
    pkts.append((t0 + 0.070, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, payload=d4)))
    c_seq += 500

    # Server receives Block 4, sends Dup ACK #2
    pkts.append((t0 + 0.095, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq_d2, FLAG_ACK)))

    # Client sends Data Block 5 (500 bytes) -> Arrives
    d5 = b"V" * 500
    pkts.append((t0 + 0.080, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, payload=d5)))
    c_seq += 500

    # Server receives Block 5, sends Dup ACK #3 (Triggers Fast Retransmission!)
    pkts.append((t0 + 0.105, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq_d2, FLAG_ACK)))

    # Client receives 3 Dup ACKs -> Triggers Fast Retransmit of Block 2!
    pkts.append((t0 + 0.130, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq_d2, s_seq, FLAG_ACK, payload=d2)))

    # Server receives retransmitted Block 2, ACKs all cumulative data up to c_seq!
    pkts.append((t0 + 0.155, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK)))

    # Now let's simulate an RTO Timeout Retransmission for Block 6
    d6 = b"Q" * 600
    c_seq_d6 = c_seq
    pkts.append((t0 + 0.200, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, payload=d6)))
    c_seq += 600
    # Packet lost, no dup ACKs follow. Sender RTO timer expires after 250ms -> Retransmits Block 6
    pkts.append((t0 + 0.450, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq_d6, s_seq, FLAG_ACK, payload=d6)))
    # Server ACKs
    pkts.append((t0 + 0.475, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK)))

    write_pcap_file(filepath, pkts)
    return filepath


def generate_zero_window_pcap(filepath: str) -> str:
    """Generates a flow demonstrating receiver buffer exhaustion, Zero Window alerts, probes, and recovery."""
    c_mac, s_mac = "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"
    c_ip, s_ip = "10.1.1.20", "10.1.1.99"
    c_port, s_port = 48900, 9000

    t0 = 1723120200.0
    pkts: List[Tuple[float, bytes]] = []

    c_seq = 3000
    s_seq = 9000

    # Handshake
    pkts.append((t0 + 0.000, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, 0, FLAG_SYN, win_size=16384)))
    pkts.append((t0 + 0.010, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq + 1, FLAG_SYN | FLAG_ACK, win_size=8192)))
    c_seq += 1
    s_seq += 1
    pkts.append((t0 + 0.011, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, win_size=16384)))

    # Sender transmits fast burst
    d1 = b"B" * 4096
    pkts.append((t0 + 0.015, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, payload=d1)))
    c_seq += 4096

    # Receiver buffer shrinking
    pkts.append((t0 + 0.025, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK, win_size=4096)))

    # Sender sends next burst
    d2 = b"C" * 4096
    pkts.append((t0 + 0.030, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, payload=d2)))
    c_seq += 4096

    # Receiver buffer completely full -> Advertises ZERO WINDOW!
    pkts.append((t0 + 0.040, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK, win_size=0)))

    # Sender cannot send data. Waits 100ms, then sends 1-byte Zero Window Probe
    probe_byte = b"P"
    pkts.append((t0 + 0.140, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq - 1, s_seq, FLAG_ACK, payload=probe_byte)))

    # Receiver still stalled -> Responds with Zero Window Probe ACK (win=0)
    pkts.append((t0 + 0.150, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK, win_size=0)))

    # Sender waits another 150ms and sends probe #2
    pkts.append((t0 + 0.300, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq - 1, s_seq, FLAG_ACK, payload=probe_byte)))

    # Receiver application finally consumed data -> Sends WINDOW UPDATE (win=16384)!
    pkts.append((t0 + 0.310, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK, win_size=16384)))

    # Sender resumes normal transmission
    d3 = b"D" * 1024
    pkts.append((t0 + 0.315, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port, s_port, c_seq, s_seq, FLAG_ACK, payload=d3)))
    c_seq += 1024
    pkts.append((t0 + 0.325, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port, c_port, s_seq, c_seq, FLAG_ACK, win_size=15360)))

    write_pcap_file(filepath, pkts)
    return filepath


def generate_rst_abort_pcap(filepath: str) -> str:
    """Generates a flow demonstrating connection refused (RST on SYN) and mid-stream RST abort."""
    c_mac, s_mac = "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"
    c_ip, s_ip = "172.16.0.5", "172.16.0.200"

    t0 = 1723120300.0
    pkts: List[Tuple[float, bytes]] = []

    # Stream 1: Port Refused (Client attempts port 9090 -> Server RST)
    c_port1, s_port1 = 60100, 9090
    pkts.append((t0 + 0.000, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port1, s_port1, 1000, 0, FLAG_SYN)))
    pkts.append((t0 + 0.005, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port1, c_port1, 0, 1001, FLAG_RST | FLAG_ACK)))

    # Stream 2: Active connection aborted mid-stream by server crash / reset
    c_port2, s_port2 = 60102, 8080
    c_seq = 4000
    s_seq = 7000

    pkts.append((t0 + 0.020, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port2, s_port2, c_seq, 0, FLAG_SYN)))
    pkts.append((t0 + 0.035, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port2, c_port2, s_seq, c_seq + 1, FLAG_SYN | FLAG_ACK)))
    c_seq += 1
    s_seq += 1
    pkts.append((t0 + 0.036, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port2, s_port2, c_seq, s_seq, FLAG_ACK)))

    # Data exchange
    req = b"POST /api/upload HTTP/1.1\r\nHost: 172.16.0.200\r\nContent-Length: 500\r\n\r\n" + (b"K" * 400)
    pkts.append((t0 + 0.050, build_raw_packet(c_mac, s_mac, c_ip, s_ip, c_port2, s_port2, c_seq, s_seq, FLAG_PSH | FLAG_ACK, payload=req)))
    c_seq += len(req)

    # Server process crashes during processing -> Sends RST flag!
    pkts.append((t0 + 0.075, build_raw_packet(s_mac, c_mac, s_ip, c_ip, s_port2, c_port2, s_seq, c_seq, FLAG_RST | FLAG_ACK)))

    write_pcap_file(filepath, pkts)
    return filepath


def ensure_sample_pcaps(output_dir: str) -> Dict[str, str]:
    """Generates all 4 sample PCAPs if they do not exist and returns their paths."""
    os.makedirs(output_dir, exist_ok=True)
    samples = {
        "normal_web": os.path.join(output_dir, "sample_normal_web.pcap"),
        "packet_loss": os.path.join(output_dir, "sample_packet_loss_retransmissions.pcap"),
        "zero_window": os.path.join(output_dir, "sample_zero_window_stall.pcap"),
        "rst_abort": os.path.join(output_dir, "sample_rst_abort.pcap"),
    }

    generate_normal_web_pcap(samples["normal_web"])
    generate_packet_loss_pcap(samples["packet_loss"])
    generate_zero_window_pcap(samples["zero_window"])
    generate_rst_abort_pcap(samples["rst_abort"])

    return samples
