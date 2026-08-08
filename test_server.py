"""Integration tests for PCAP Flow Analyzer REST API and HTTP Server."""

from __future__ import annotations

import json
import os
import threading
import time
import unittest
import urllib.request
from typing import Any, Dict

from engine.sample_generator import generate_normal_web_pcap
from server import PcapFlowAPIHandler, ThreadedHTTPServer, GLOBAL_SESSION


class TestServerAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 8899
        cls.server = ThreadedHTTPServer(("127.0.0.1", cls.port), PcapFlowAPIHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _http_get(self, path: str) -> Dict[str, Any]:
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            content_type = resp.headers.get("Content-Type", "")
            data = resp.read()
            if "application/json" in content_type:
                return json.loads(data.decode("utf-8"))
            return {"raw": data, "status": resp.status}

    def _http_post(self, path: str, payload: Dict[str, Any] | bytes, is_json: bool = True) -> Dict[str, Any]:
        url = f"http://127.0.0.1:{self.port}{path}"
        if is_json:
            data_bytes = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
        else:
            data_bytes = payload if isinstance(payload, bytes) else b""
            headers = {"Content-Type": "application/octet-stream", "X-Filename": "test_upload.pcap"}

        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_static_index_html(self):
        res = self._http_get("/")
        self.assertIn(b"PCAP Flow Analyzer", res["raw"])
        self.assertIn(b"svg", res["raw"])

    def test_samples_endpoint(self):
        res = self._http_get("/api/samples")
        self.assertTrue(res["success"])
        self.assertEqual(len(res["samples"]), 4)
        sample_keys = [s["key"] for s in res["samples"]]
        self.assertIn("normal_web", sample_keys)
        self.assertIn("packet_loss", sample_keys)
        self.assertIn("zero_window", sample_keys)
        self.assertIn("rst_abort", sample_keys)

    def test_load_sample_and_analyze(self):
        # 1. Load packet_loss sample
        load_res = self._http_post("/api/load-sample", {"sample_key": "packet_loss"})
        self.assertTrue(load_res["success"])
        meta = load_res["metadata"]
        self.assertGreater(meta["total_packets"], 5)
        self.assertGreaterEqual(len(meta["conversations"]), 1)

        # 2. Run analysis on conversation
        conv = meta["conversations"][0]
        analyze_res = self._http_post("/api/analyze", {
            "client_ip": conv["ip_a"],
            "server_ip": conv["ip_b"],
        })
        self.assertTrue(analyze_res["success"])
        self.assertIn("summary", analyze_res)
        self.assertIn("streams", analyze_res)
        summary = analyze_res["summary"]
        self.assertGreater(summary["retransmissions_total"], 0)
        self.assertLess(summary["health_score"], 95)

        # 3. Test packet detail inspection
        detail_res = self._http_get("/api/packet-detail?packet_index=1")
        self.assertTrue(detail_res["success"])
        self.assertEqual(detail_res["packet_index"], 1)
        self.assertIsNotNone(detail_res["tcp"])
        self.assertIsNotNone(detail_res["hex_dump"])

        # 4. Test export report
        export_res = self._http_get("/api/export-report")
        self.assertIn("analysis", export_res)
        self.assertIn("filename", export_res)

    def test_upload_multipart_pcap(self):
        # Generate a temporary pcap file
        sample_path = GLOBAL_SESSION.sample_files["normal_web"]
        with open(sample_path, "rb") as f:
            pcap_bytes = f.read()

        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="my_capture.pcap"\r\n'
            f"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n"
        ).encode("utf-8") + pcap_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        url = f"http://127.0.0.1:{self.port}/api/upload"
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        self.assertTrue(data["success"])
        self.assertEqual(data["metadata"]["filename"], "my_capture.pcap")
        self.assertGreaterEqual(data["metadata"]["total_packets"], 10)


if __name__ == "__main__":
    unittest.main()
