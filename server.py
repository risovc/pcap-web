"""High-performance multi-threaded HTTP server and REST API for PCAP Flow Analyzer.

Endpoints:
- POST /api/upload           : Upload PCAP/PCAPNG file, auto-detect conversations
- GET  /api/conversations    : List detected IP talker pairs with packet & byte counts
- POST /api/analyze          : Analyze flows matching client_ip / server_ip / ports
- GET  /api/samples          : List available built-in sample captures
- POST /api/load-sample      : Load a sample capture directly into active session
- GET  /api/packet-detail    : Retrieve decoded headers & hex dump for specific packet
- GET  /api/export-report    : Export complete JSON diagnostics report
- GET  /*                    : Static web application assets (HTML, CSS, JS)
"""

from __future__ import annotations

import argparse
import http.server
import json
import mimetypes
import os
import socketserver
import struct
import tempfile
import urllib.parse
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from engine.pcap_parser import Packet, PcapReader, read_pcap
from engine.sample_generator import ensure_sample_pcaps
from engine.tcp_analyzer import (
    DiagnosticSummary,
    TCPStream,
    analyze_pcap_flow,
    discover_conversations,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")


class SessionStore:
    def __init__(self):
        self.filename: str = ""
        self.raw_data: bytes = b""
        self.packets: List[Packet] = []
        self.conversations: List[Any] = []
        self.last_analysis: Optional[Dict[str, Any]] = None
        self.sample_files: Dict[str, str] = {}
        self._init_samples()

    def _init_samples(self):
        self.sample_files = ensure_sample_pcaps(SAMPLES_DIR)

    def load_pcap_data(self, filename: str, data: bytes) -> Dict[str, Any]:
        self.filename = filename
        self.raw_data = data
        temp_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        try:
            temp_f.write(data)
            temp_f.close()
            self.packets = read_pcap(temp_f.name)
        finally:
            if os.path.exists(temp_f.name):
                os.remove(temp_f.name)

        self.conversations = discover_conversations(self.packets)
        self.last_analysis = None

        first_ts = self.packets[0].timestamp if self.packets else 0.0
        last_ts = self.packets[-1].timestamp if self.packets else 0.0

        return {
            "filename": self.filename,
            "total_packets": len(self.packets),
            "total_bytes": len(self.raw_data),
            "duration_seconds": round(last_ts - first_ts, 3) if len(self.packets) > 1 else 0.0,
            "conversations": [asdict(c) for c in self.conversations],
        }

    def load_sample_by_key(self, sample_key: str) -> Dict[str, Any]:
        if sample_key not in self.sample_files:
            raise KeyError(f"Sample '{sample_key}' not found")
        fpath = self.sample_files[sample_key]
        with open(fpath, "rb") as f:
            data = f.read()
        return self.load_pcap_data(os.path.basename(fpath), data)


GLOBAL_SESSION = SessionStore()


def _format_hex_dump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_bytes:<48}   {ascii_chars}")
    return "\n".join(lines)


class PcapFlowAPIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def _send_json(self, status_code: int, data: Any):
        payload = json.dumps(data, default=lambda o: asdict(o) if hasattr(o, "__dict__") or hasattr(o, "__dataclass_fields__") else str(o)).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def _send_error_json(self, status_code: int, message: str):
        self._send_json(status_code, {"error": message, "success": False})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/samples":
            sample_list = [
                {
                    "key": "normal_web",
                    "title": "Healthy Web Flow",
                    "badge": "Optimal (100% Health)",
                    "description": "Standard HTTP/1.1 transaction with 3-way handshake, payload data, and clean FIN-ACK teardown.",
                },
                {
                    "key": "packet_loss",
                    "title": "Packet Loss & Retransmission Storm",
                    "badge": "Severe Loss & Retransmits",
                    "description": "Mid-stream packet loss triggering 3x Duplicate ACKs, Fast Retransmission, and RTO timeout retransmission.",
                },
                {
                    "key": "zero_window",
                    "title": "Zero-Window Receiver Buffer Stall",
                    "badge": "Receiver Buffer Freeze",
                    "description": "High-throughput sender filling slow receiver buffer, Zero Window alerts, probing, and window recovery.",
                },
                {
                    "key": "rst_abort",
                    "title": "TCP RST Abort & Port Refused",
                    "badge": "Connection Abort & Refusal",
                    "description": "Server actively refusing closed port with RST-ACK and abrupt mid-stream connection reset.",
                },
            ]
            self._send_json(200, {"samples": sample_list, "success": True})
            return

        if path == "/api/conversations":
            if not GLOBAL_SESSION.packets:
                self._send_json(200, {"conversations": [], "filename": "", "success": True})
                return
            self._send_json(200, {
                "filename": GLOBAL_SESSION.filename,
                "total_packets": len(GLOBAL_SESSION.packets),
                "conversations": [asdict(c) for c in GLOBAL_SESSION.conversations],
                "success": True,
            })
            return

        if path == "/api/packet-detail":
            pkt_idx_str = query.get("packet_index", ["0"])[0]
            try:
                pkt_idx = int(pkt_idx_str)
            except ValueError:
                self._send_error_json(400, "Invalid packet_index")
                return

            matching_pkt = next((p for p in GLOBAL_SESSION.packets if p.packet_index == pkt_idx), None)
            if not matching_pkt:
                self._send_error_json(404, f"Packet #{pkt_idx} not found")
                return

            raw_bytes = matching_pkt.raw_data
            hex_dump = _format_hex_dump(raw_bytes)

            options_decoded = []
            if matching_pkt.tcp and matching_pkt.tcp.options:
                for opt in matching_pkt.tcp.options:
                    options_decoded.append({
                        "kind": opt.kind,
                        "name": opt.name,
                        "length": opt.length,
                        "decoded": opt.decoded,
                    })

            self._send_json(200, {
                "packet_index": matching_pkt.packet_index,
                "timestamp": matching_pkt.timestamp,
                "captured_len": matching_pkt.captured_len,
                "original_len": matching_pkt.original_len,
                "link_type": matching_pkt.link_type,
                "ethernet": asdict(matching_pkt.eth) if matching_pkt.eth else None,
                "ip": asdict(matching_pkt.ip) if matching_pkt.ip else None,
                "tcp": {
                    "src_port": matching_pkt.tcp.src_port,
                    "dst_port": matching_pkt.tcp.dst_port,
                    "seq_num": matching_pkt.tcp.seq_num,
                    "ack_num": matching_pkt.tcp.ack_num,
                    "data_offset": matching_pkt.tcp.data_offset,
                    "flags": matching_pkt.tcp.flags,
                    "flags_str": matching_pkt.tcp.flags_str,
                    "window_size": matching_pkt.tcp.window_size,
                    "checksum": matching_pkt.tcp.checksum,
                    "urgent_pointer": matching_pkt.tcp.urgent_pointer,
                    "options": options_decoded,
                    "payload_len": matching_pkt.tcp.payload_len,
                } if matching_pkt.tcp else None,
                "hex_dump": hex_dump,
                "success": True,
            })
            return

        if path == "/api/export-report":
            if not GLOBAL_SESSION.last_analysis:
                self._send_error_json(400, "No active analysis to export. Please run an analysis first.")
                return
            report = {
                "filename": GLOBAL_SESSION.filename,
                "analysis": GLOBAL_SESSION.last_analysis,
            }
            self._send_json(200, report)
            return

        # Serve static UI files
        if path == "/" or path == "":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            content_length = int(self.headers.get("Content-Length", 0))

            if content_length <= 0:
                self._send_error_json(400, "Empty payload received")
                return

            raw_body = self.rfile.read(content_length)

            if "multipart/form-data" in content_type:
                boundary = None
                for part in content_type.split(";"):
                    part = part.strip()
                    if part.lower().startswith("boundary="):
                        boundary = part[9:].strip('"').encode("utf-8")
                        break

                if not boundary:
                    self._send_error_json(400, "Missing boundary in multipart request")
                    return

                boundary_sep = b"--" + boundary
                parts = raw_body.split(boundary_sep)
                file_data = None
                filename = "uploaded.pcap"

                for p in parts:
                    p = p.strip()
                    if not p or p == b"--":
                        continue
                    if b"\r\n\r\n" in p:
                        hdr_bytes, body_content = p.split(b"\r\n\r\n", 1)
                        hdr_text = hdr_bytes.decode("utf-8", errors="ignore")
                        for line in hdr_text.split("\r\n"):
                            if "content-disposition" in line.lower():
                                for item in line.split(";"):
                                    item = item.strip()
                                    if item.lower().startswith("filename="):
                                        filename = item[9:].strip('"')
                                        file_data = body_content
                                        break

                if file_data is None:
                    self._send_error_json(400, "Missing file data in multipart payload")
                    return
            else:
                # Raw binary upload
                filename = self.headers.get("X-Filename", "uploaded.pcap")
                file_data = raw_body

            try:
                meta = GLOBAL_SESSION.load_pcap_data(filename, file_data)
                self._send_json(200, {"metadata": meta, "success": True})
            except Exception as e:
                self._send_error_json(400, f"Failed to parse PCAP file: {str(e)}")
            return

        if path == "/api/load-sample":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except Exception:
                body = {}

            sample_key = body.get("sample_key", "normal_web")
            try:
                meta = GLOBAL_SESSION.load_sample_by_key(sample_key)
                self._send_json(200, {"metadata": meta, "success": True})
            except Exception as e:
                self._send_error_json(400, f"Error loading sample: {str(e)}")
            return

        if path == "/api/analyze":
            if not GLOBAL_SESSION.packets:
                self._send_error_json(400, "No PCAP loaded. Please upload a file or load a sample first.")
                return

            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except Exception:
                body = {}

            client_ip = body.get("client_ip")
            server_ip = body.get("server_ip")
            client_port = body.get("client_port")
            server_port = body.get("server_port")

            if client_port:
                try:
                    client_port = int(client_port)
                except ValueError:
                    client_port = None
            if server_port:
                try:
                    server_port = int(server_port)
                except ValueError:
                    server_port = None

            try:
                streams, summary = analyze_pcap_flow(
                    GLOBAL_SESSION.packets,
                    client_ip=client_ip,
                    server_ip=server_ip,
                    client_port=client_port,
                    server_port=server_port,
                )

                # Format response
                result = {
                    "summary": asdict(summary),
                    "streams": [asdict(s) for s in streams],
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "success": True,
                }
                GLOBAL_SESSION.last_analysis = result
                self._send_json(200, result)
            except Exception as e:
                self._send_error_json(500, f"Analysis error: {str(e)}")
            return

        self._send_error_json(404, f"API endpoint {path} not found")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    # Ensure sample pcaps exist at startup
    GLOBAL_SESSION._init_samples()

    # Pre-load normal_web sample by default so web app is instantly populated
    try:
        GLOBAL_SESSION.load_sample_by_key("normal_web")
    except Exception as e:
        print(f"Warning: Could not preload sample: {e}")

    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, PcapFlowAPIHandler)
    print(f"================================================================")
    print(f"🚀 PCAP Flow Analyzer Web App running at http://localhost:{port}")
    print(f"================================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP Flow Analyzer Web Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
