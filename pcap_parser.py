"""Pure-Python binary PCAP and PCAPNG parser with zero external dependencies.

Supports:
- Classic PCAP format (microsecond & nanosecond timestamps, standard & byte-swapped endianness)
- PCAPNG format (Section Header, Interface Description, Enhanced Packet, Simple Packet blocks)
- Link types: Ethernet II, 802.1Q VLAN, Linux Cooked SLL (v1) & SLL2 (v2), Raw IP, Loopback/Null
- Protocols: IPv4, IPv6, TCP (with full TCP options decoding), UDP, ICMP
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple

# PCAP Magic Byte Sequences
PCAP_MAGIC_MICRO_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_MICRO_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NANO_BE = b"\xa1\xb2\x3c\x4d"
PCAP_MAGIC_NANO_LE = b"\x4d\x3c\xb2\xa1"

# PCAPNG Block Types
PCAPNG_BLOCK_SHB = 0x0A0D0D0A  # Section Header Block
PCAPNG_BLOCK_IDB = 0x00000001  # Interface Description Block
PCAPNG_BLOCK_EPB = 0x00000006  # Enhanced Packet Block
PCAPNG_BLOCK_SPB = 0x00000003  # Simple Packet Block

# Link Types (DLT)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 12
LINKTYPE_RAW_ALT = 14
LINKTYPE_RAW_ALT2 = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_LOOPBACK = 108

# EtherTypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_ARP = 0x0806

# IP Protocols
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

# TCP Option Kinds
TCP_OPT_EOL = 0
TCP_OPT_NOP = 1
TCP_OPT_MSS = 2
TCP_OPT_WSCALE = 3
TCP_OPT_SACK_PERM = 4
TCP_OPT_SACK = 5
TCP_OPT_TIMESTAMP = 8


@dataclass
class TCPOption:
    kind: int
    name: str
    length: int
    data: bytes
    decoded: Any = None


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int  # Header length in bytes
    flags_raw: int
    flags: Dict[str, bool]
    window_size: int
    checksum: int
    urgent_pointer: int
    options: List[TCPOption] = field(default_factory=list)
    payload: bytes = b""
    payload_len: int = 0
    # Decoded options cache
    mss: Optional[int] = None
    window_scale: Optional[int] = None
    sack_permitted: bool = False
    sack_blocks: List[Tuple[int, int]] = field(default_factory=list)
    timestamp_val: Optional[int] = None
    timestamp_echo: Optional[int] = None

    @property
    def flags_str(self) -> str:
        active = []
        for name in ["SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"]:
            if self.flags.get(name):
                active.append(name)
        return "|".join(active) if active else "NONE"


@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes = b""


@dataclass
class IPHeader:
    version: int
    src_ip: str
    dst_ip: str
    proto: int
    proto_name: str
    ttl: int
    identification: int = 0
    flags_df: bool = False
    flags_mf: bool = False
    fragment_offset: int = 0
    total_length: int = 0
    traffic_class: int = 0  # IPv6 / DSCP


@dataclass
class EthernetHeader:
    src_mac: str
    dst_mac: str
    ethertype: int
    vlan_id: Optional[int] = None


@dataclass
class Packet:
    packet_index: int
    timestamp: float  # Epoch timestamp in seconds with microsecond/nanosecond float precision
    captured_len: int
    original_len: int
    raw_data: bytes
    link_type: int
    eth: Optional[EthernetHeader] = None
    ip: Optional[IPHeader] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None
    error: Optional[str] = None

    @property
    def is_tcp(self) -> bool:
        return self.ip is not None and self.tcp is not None

    @property
    def stream_key(self) -> Optional[Tuple[str, int, str, int]]:
        """Returns ordered 4-tuple for bidirectional stream matching."""
        if not self.is_tcp or not self.ip or not self.tcp:
            return None
        ep1 = (self.ip.src_ip, self.tcp.src_port)
        ep2 = (self.ip.dst_ip, self.tcp.dst_port)
        return (ep1[0], ep1[1], ep2[0], ep2[1]) if ep1 <= ep2 else (ep2[0], ep2[1], ep1[0], ep1[1])


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _decode_tcp_options(opt_bytes: bytes) -> List[TCPOption]:
    options: List[TCPOption] = []
    i = 0
    length = len(opt_bytes)

    while i < length:
        kind = opt_bytes[i]
        if kind == TCP_OPT_EOL:
            options.append(TCPOption(kind=kind, name="EOL", length=1, data=b""))
            break
        if kind == TCP_OPT_NOP:
            options.append(TCPOption(kind=kind, name="NOP", length=1, data=b""))
            i += 1
            continue

        if i + 1 >= length:
            break
        opt_len = opt_bytes[i + 1]
        if opt_len < 2 or i + opt_len > length:
            break

        data = opt_bytes[i + 2 : i + opt_len]
        decoded = None
        name = f"Option_{kind}"

        if kind == TCP_OPT_MSS:
            name = "MSS"
            if len(data) == 2:
                decoded = struct.unpack("!H", data)[0]
        elif kind == TCP_OPT_WSCALE:
            name = "Window Scale"
            if len(data) == 1:
                decoded = data[0]
        elif kind == TCP_OPT_SACK_PERM:
            name = "SACK Permitted"
            decoded = True
        elif kind == TCP_OPT_SACK:
            name = "SACK"
            blocks = []
            for b in range(0, len(data), 8):
                if b + 8 <= len(data):
                    left, right = struct.unpack("!II", data[b : b + 8])
                    blocks.append((left, right))
            decoded = blocks
        elif kind == TCP_OPT_TIMESTAMP:
            name = "Timestamp"
            if len(data) == 8:
                ts_val, ts_echo = struct.unpack("!II", data)
                decoded = {"ts_val": ts_val, "ts_echo": ts_echo}

        options.append(TCPOption(kind=kind, name=name, length=opt_len, data=data, decoded=decoded))
        i += opt_len

    return options


def parse_tcp(data: bytes) -> Optional[TCPHeader]:
    if len(data) < 20:
        return None

    src_port, dst_port, seq_num, ack_num, offset_flags, win_size, checksum, urg_ptr = struct.unpack(
        "!HHIIHHHH", data[:20]
    )

    data_offset = (offset_flags >> 12) * 4
    if data_offset < 20 or len(data) < data_offset:
        return None

    flags_raw = offset_flags & 0x01FF
    flags = {
        "FIN": bool(flags_raw & 0x0001),
        "SYN": bool(flags_raw & 0x0002),
        "RST": bool(flags_raw & 0x0004),
        "PSH": bool(flags_raw & 0x0008),
        "ACK": bool(flags_raw & 0x0010),
        "URG": bool(flags_raw & 0x0020),
        "ECE": bool(flags_raw & 0x0040),
        "CWR": bool(flags_raw & 0x0080),
        "NS": bool(flags_raw & 0x0100),
    }

    opt_bytes = data[20:data_offset]
    options = _decode_tcp_options(opt_bytes) if opt_bytes else []
    payload = data[data_offset:]

    mss = None
    window_scale = None
    sack_permitted = False
    sack_blocks = []
    ts_val = None
    ts_echo = None

    for opt in options:
        if opt.kind == TCP_OPT_MSS and isinstance(opt.decoded, int):
            mss = opt.decoded
        elif opt.kind == TCP_OPT_WSCALE and isinstance(opt.decoded, int):
            window_scale = opt.decoded
        elif opt.kind == TCP_OPT_SACK_PERM:
            sack_permitted = True
        elif opt.kind == TCP_OPT_SACK and isinstance(opt.decoded, list):
            sack_blocks = opt.decoded
        elif opt.kind == TCP_OPT_TIMESTAMP and isinstance(opt.decoded, dict):
            ts_val = opt.decoded.get("ts_val")
            ts_echo = opt.decoded.get("ts_echo")

    return TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=ack_num,
        data_offset=data_offset,
        flags_raw=flags_raw,
        flags=flags,
        window_size=win_size,
        checksum=checksum,
        urgent_pointer=urg_ptr,
        options=options,
        payload=payload,
        payload_len=len(payload),
        mss=mss,
        window_scale=window_scale,
        sack_permitted=sack_permitted,
        sack_blocks=sack_blocks,
        timestamp_val=ts_val,
        timestamp_echo=ts_echo,
    )


def parse_udp(data: bytes) -> Optional[UDPHeader]:
    if len(data) < 8:
        return None
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    return UDPHeader(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=checksum,
        payload=data[8:],
    )


def parse_ipv4(data: bytes) -> Tuple[Optional[IPHeader], bytes]:
    if len(data) < 20:
        return None, b""

    ver_ihl, dscp_ecn, total_len, ident, flags_frag, ttl, proto, _ = struct.unpack(
        "!BBHHHBBH", data[:12]
    )

    version = (ver_ihl >> 4) & 0x0F
    ihl = (ver_ihl & 0x0F) * 4

    if version != 4 or ihl < 20 or len(data) < ihl:
        return None, b""

    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    flags_df = bool(flags_frag & 0x4000)
    flags_mf = bool(flags_frag & 0x2000)
    frag_offset = (flags_frag & 0x1FFF) * 8

    proto_names = {IPPROTO_TCP: "TCP", IPPROTO_UDP: "UDP", IPPROTO_ICMP: "ICMP"}
    proto_name = proto_names.get(proto, f"Proto_{proto}")

    ip_header = IPHeader(
        version=4,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        proto_name=proto_name,
        ttl=ttl,
        identification=ident,
        flags_df=flags_df,
        flags_mf=flags_mf,
        fragment_offset=frag_offset,
        total_length=total_len if total_len > 0 else len(data),
        traffic_class=dscp_ecn,
    )
    return ip_header, data[ihl:]


def parse_ipv6(data: bytes) -> Tuple[Optional[IPHeader], bytes]:
    if len(data) < 40:
        return None, b""

    v_tc_fl, payload_len, next_header, hop_limit = struct.unpack("!IHBB", data[:8])
    version = (v_tc_fl >> 28) & 0x0F
    if version != 6:
        return None, b""

    traffic_class = (v_tc_fl >> 20) & 0xFF
    src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    proto_names = {IPPROTO_TCP: "TCP", IPPROTO_UDP: "UDP", IPPROTO_ICMPV6: "ICMPv6"}
    proto_name = proto_names.get(next_header, f"Proto_{next_header}")

    ip_header = IPHeader(
        version=6,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=next_header,
        proto_name=proto_name,
        ttl=hop_limit,
        total_length=payload_len + 40,
        traffic_class=traffic_class,
    )
    return ip_header, data[40:]


def parse_packet_data(raw_data: bytes, link_type: int, index: int, timestamp: float, orig_len: int) -> Packet:
    packet = Packet(
        packet_index=index,
        timestamp=timestamp,
        captured_len=len(raw_data),
        original_len=orig_len,
        raw_data=raw_data,
        link_type=link_type,
    )

    data = raw_data
    ethertype = None

    if link_type == LINKTYPE_ETHERNET:
        if len(data) < 14:
            packet.error = "Truncated Ethernet frame"
            return packet
        dst_mac = _format_mac(data[:6])
        src_mac = _format_mac(data[6:12])
        ethertype = struct.unpack("!H", data[12:14])[0]
        data = data[14:]
        vlan_id = None

        # Handle 802.1Q / 802.1ad VLAN tags
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and len(data) >= 4:
            tci, next_proto = struct.unpack("!HH", data[:4])
            vlan_id = tci & 0x0FFF
            ethertype = next_proto
            data = data[4:]

        packet.eth = EthernetHeader(src_mac=src_mac, dst_mac=dst_mac, ethertype=ethertype, vlan_id=vlan_id)

    elif link_type == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            packet.error = "Truncated SLL frame"
            return packet
        ethertype = struct.unpack("!H", data[14:16])[0]
        data = data[16:]

    elif link_type == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            packet.error = "Truncated SLL2 frame"
            return packet
        ethertype = struct.unpack("!H", data[0:2])[0]
        data = data[20:]

    elif link_type in (LINKTYPE_NULL, LINKTYPE_LOOPBACK):
        if len(data) < 4:
            packet.error = "Truncated Loopback frame"
            return packet
        family = struct.unpack("=I", data[:4])[0]
        data = data[4:]
        ethertype = ETHERTYPE_IPV4 if family == 2 else ETHERTYPE_IPV6

    elif link_type in (LINKTYPE_RAW, LINKTYPE_RAW_ALT, LINKTYPE_RAW_ALT2):
        if len(data) >= 1:
            ver = (data[0] >> 4) & 0x0F
            ethertype = ETHERTYPE_IPV4 if ver == 4 else (ETHERTYPE_IPV6 if ver == 6 else None)

    # Parse IP layer
    payload = b""
    if ethertype == ETHERTYPE_IPV4 or (ethertype is None and len(data) > 0 and ((data[0] >> 4) == 4)):
        ip_header, payload = parse_ipv4(data)
        packet.ip = ip_header
    elif ethertype == ETHERTYPE_IPV6 or (ethertype is None and len(data) > 0 and ((data[0] >> 4) == 6)):
        ip_header, payload = parse_ipv6(data)
        packet.ip = ip_header

    # Parse Transport layer
    if packet.ip:
        if packet.ip.proto == IPPROTO_TCP:
            packet.tcp = parse_tcp(payload)
        elif packet.ip.proto == IPPROTO_UDP:
            packet.udp = parse_udp(payload)

    return packet


class PcapReader:
    """Reads classic PCAP and PCAPNG files."""

    def __init__(self, source: BinaryIO | str):
        if isinstance(source, str):
            self.file: BinaryIO = open(source, "rb")
            self._should_close = True
        else:
            self.file = source
            self._should_close = False

        self.is_pcapng = False
        self.endianness = "<"
        self.is_nanosecond = False
        self.link_type = LINKTYPE_ETHERNET
        self.interfaces: List[Dict[str, Any]] = []

        self._detect_format()

    def _detect_format(self) -> None:
        magic_bytes = self.file.read(4)
        if len(magic_bytes) < 4:
            raise ValueError("File too short to be a valid PCAP")

        if magic_bytes == b"\x0a\x0d\x0d\x0a" or magic_bytes == b"\x0a\x0d\x0d\x0a":
            self.is_pcapng = True
            self.file.seek(0)
            self._init_pcapng()
        elif magic_bytes == PCAP_MAGIC_MICRO_BE:
            self.is_pcapng = False
            self.endianness = ">"
            self.is_nanosecond = False
            self._init_classic_pcap()
        elif magic_bytes == PCAP_MAGIC_MICRO_LE:
            self.is_pcapng = False
            self.endianness = "<"
            self.is_nanosecond = False
            self._init_classic_pcap()
        elif magic_bytes == PCAP_MAGIC_NANO_BE:
            self.is_pcapng = False
            self.endianness = ">"
            self.is_nanosecond = True
            self._init_classic_pcap()
        elif magic_bytes == PCAP_MAGIC_NANO_LE:
            self.is_pcapng = False
            self.endianness = "<"
            self.is_nanosecond = True
            self._init_classic_pcap()
        else:
            magic_hex = magic_bytes.hex()
            raise ValueError(f"Unrecognized PCAP format: magic=0x{magic_hex}")

    def _init_classic_pcap(self) -> None:
        header_data = self.file.read(20)  # Read remaining 20 bytes of 24-byte global header
        if len(header_data) < 20:
            raise ValueError("Truncated PCAP global header")

        v_maj, v_min, tz, sigfigs, snaplen, network = struct.unpack(
            f"{self.endianness}HHiIII", header_data
        )

        self.link_type = network
        self.snaplen = snaplen

    def _init_pcapng(self) -> None:
        self.interfaces = []
        self.endianness = "<"

    def __iter__(self) -> Iterator[Packet]:
        if self.is_pcapng:
            yield from self._iter_pcapng()
        else:
            yield from self._iter_classic_pcap()

    def _iter_classic_pcap(self) -> Iterator[Packet]:
        index = 0
        while True:
            hdr_bytes = self.file.read(16)
            if len(hdr_bytes) < 16:
                break

            ts_sec, ts_usec, caplen, origlen = struct.unpack(f"{self.endianness}IIII", hdr_bytes)
            raw_data = self.file.read(caplen)
            if len(raw_data) < caplen:
                break

            divisor = 1_000_000_000.0 if self.is_nanosecond else 1_000_000.0
            timestamp = float(ts_sec) + (float(ts_usec) / divisor)

            index += 1
            yield parse_packet_data(raw_data, self.link_type, index, timestamp, origlen)

    def _iter_pcapng(self) -> Iterator[Packet]:
        index = 0
        while True:
            hdr = self.file.read(8)
            if len(hdr) < 8:
                break

            block_type, block_total_len = struct.unpack(f"{self.endianness}II", hdr)

            if block_type == PCAPNG_BLOCK_SHB:
                shb_body = self.file.read(block_total_len - 8)
                if len(shb_body) >= 4:
                    bom = shb_body[:4]
                    if bom == b"\x1A\x2B\x3C\x4D":
                        self.endianness = ">"
                    elif bom == b"\x4D\x3C\x2B\x1A":
                        self.endianness = "<"
                self.interfaces = []
                continue

            if block_total_len < 12:
                break

            body_len = block_total_len - 12
            body = self.file.read(body_len)
            trailing_len = self.file.read(4)

            if len(body) < body_len or len(trailing_len) < 4:
                break

            if block_type == PCAPNG_BLOCK_IDB:
                if len(body) >= 4:
                    link_type, _ = struct.unpack(f"{self.endianness}HH", body[:4])
                    tsresol = 6
                    opt_bytes = body[8:]
                    oi = 0
                    while oi + 4 <= len(opt_bytes):
                        ocode, olen = struct.unpack(f"{self.endianness}HH", opt_bytes[oi : oi + 4])
                        if ocode == 0:
                            break
                        oval = opt_bytes[oi + 4 : oi + 4 + olen]
                        if ocode == 9 and len(oval) >= 1:
                            tsresol = oval[0]
                        pad = (4 - (olen % 4)) % 4
                        oi += 4 + olen + pad

                    self.interfaces.append({"link_type": link_type, "tsresol": tsresol})

            elif block_type == PCAPNG_BLOCK_EPB:
                if len(body) >= 20:
                    interface_id, ts_high, ts_low, caplen, origlen = struct.unpack(
                        f"{self.endianness}IIIII", body[:20]
                    )
                    raw_data = body[20 : 20 + caplen]

                    link_type = LINKTYPE_ETHERNET
                    tsresol = 6
                    if 0 <= interface_id < len(self.interfaces):
                        link_type = self.interfaces[interface_id]["link_type"]
                        tsresol = self.interfaces[interface_id]["tsresol"]

                    ts_raw = (ts_high << 32) | ts_low
                    if tsresol & 0x80:
                        timestamp = float(ts_raw) / float(1 << (tsresol & 0x7F))
                    else:
                        timestamp = float(ts_raw) / float(10**tsresol)

                    index += 1
                    yield parse_packet_data(raw_data, link_type, index, timestamp, origlen)

            elif block_type == PCAPNG_BLOCK_SPB:
                if len(body) >= 4:
                    origlen = struct.unpack(f"{self.endianness}I", body[:4])[0]
                    raw_data = body[4:]
                    link_type = self.interfaces[0]["link_type"] if self.interfaces else LINKTYPE_ETHERNET
                    index += 1
                    yield parse_packet_data(raw_data, link_type, index, 0.0, origlen)

    def close(self) -> None:
        if self._should_close and self.file:
            self.file.close()


def read_pcap(filepath_or_stream: BinaryIO | str) -> List[Packet]:
    reader = PcapReader(filepath_or_stream)
    try:
        return list(reader)
    finally:
        reader.close()
