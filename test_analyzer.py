"""Unit and integration tests for PCAP parser and TCP flow diagnostic engine."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from engine.pcap_parser import PcapReader, read_pcap
from engine.sample_generator import (
    ensure_sample_pcaps,
    generate_normal_web_pcap,
    generate_packet_loss_pcap,
    generate_rst_abort_pcap,
    generate_zero_window_pcap,
)
from engine.tcp_analyzer import (
    AnomalyType,
    analyze_pcap_flow,
    discover_conversations,
)


class TestPcapEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.samples = ensure_sample_pcaps(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_normal_web_flow(self):
        pcap_file = self.samples["normal_web"]
        packets = read_pcap(pcap_file)
        self.assertGreaterEqual(len(packets), 10)

        # Check conversation discovery
        convs = discover_conversations(packets)
        self.assertEqual(len(convs), 1)
        self.assertEqual(convs[0].ip_a, "10.0.0.50")
        self.assertEqual(convs[0].ip_b, "192.168.1.100")

        # Analyze flow
        streams, summary = analyze_pcap_flow(packets, client_ip="192.168.1.100", server_ip="10.0.0.50")
        self.assertEqual(len(streams), 1)
        s = streams[0]

        self.assertTrue(s.handshake_completed)
        self.assertIsNotNone(s.handshake_irtt_ms)
        self.assertEqual(s.retransmission_count, 0)
        self.assertEqual(s.dup_ack_count, 0)
        self.assertEqual(s.zero_window_count, 0)
        self.assertFalse(s.is_aborted)
        self.assertTrue(s.is_cleanly_closed)
        self.assertEqual(s.health_score, 100)
        self.assertEqual(summary.health_status, "HEALTHY")

    def test_packet_loss_and_retransmissions(self):
        pcap_file = self.samples["packet_loss"]
        packets = read_pcap(pcap_file)

        streams, summary = analyze_pcap_flow(packets, client_ip="192.168.1.105", server_ip="10.0.0.80")
        self.assertEqual(len(streams), 1)
        s = streams[0]

        self.assertTrue(s.handshake_completed)
        self.assertGreaterEqual(s.dup_ack_count, 3)
        self.assertGreaterEqual(s.retransmission_count, 2)
        self.assertEqual(s.fast_retransmit_count, 1)
        self.assertEqual(s.rto_retransmit_count, 1)

        # Verify anomaly types in packet list
        anomaly_types = [a.anomaly_type for a in s.anomalies]
        self.assertIn(AnomalyType.DUPLICATE_ACK, anomaly_types)
        self.assertIn(AnomalyType.FAST_RETRANSMISSION, anomaly_types)
        self.assertIn(AnomalyType.RTO_RETRANSMISSION, anomaly_types)

        # Health score must reflect degradation
        self.assertLess(s.health_score, 90)
        self.assertIn(summary.health_status, ("DEGRADED", "CRITICAL"))

    def test_zero_window_receiver_stall(self):
        pcap_file = self.samples["zero_window"]
        packets = read_pcap(pcap_file)

        streams, summary = analyze_pcap_flow(packets, client_ip="10.1.1.20", server_ip="10.1.1.99")
        self.assertEqual(len(streams), 1)
        s = streams[0]

        self.assertGreaterEqual(s.zero_window_count, 1)
        self.assertGreater(s.zero_window_stall_ms, 0.0)

        anomaly_types = [a.anomaly_type for a in s.anomalies]
        self.assertIn(AnomalyType.ZERO_WINDOW, anomaly_types)
        self.assertIn(AnomalyType.ZERO_WINDOW_PROBE, anomaly_types)
        self.assertIn(AnomalyType.WINDOW_UPDATE, anomaly_types)

    def test_rst_connection_abort(self):
        pcap_file = self.samples["rst_abort"]
        packets = read_pcap(pcap_file)

        # Analyze all streams for 172.16.0.5 <-> 172.16.0.200
        streams, summary = analyze_pcap_flow(packets, client_ip="172.16.0.5", server_ip="172.16.0.200")
        self.assertEqual(len(streams), 2)

        # Stream 1: Port Refused (Port 9090)
        s_refused = next(s for s in streams if s.server_port == 9090 or s.client_port == 9090)
        self.assertTrue(s_refused.is_aborted)
        self.assertFalse(s_refused.handshake_completed)
        self.assertIn(AnomalyType.RST_REFUSED, [a.anomaly_type for a in s_refused.anomalies])

        # Stream 2: Mid-stream Abort (Port 8080)
        s_aborted = next(s for s in streams if s.server_port == 8080 or s.client_port == 8080)
        self.assertTrue(s_aborted.is_aborted)
        self.assertTrue(s_aborted.handshake_completed)
        self.assertIn(AnomalyType.RST_ABORT, [a.anomaly_type for a in s_aborted.anomalies])

    def test_empty_and_filtered_queries(self):
        packets = read_pcap(self.samples["normal_web"])
        # Query non-existent IP
        streams, summary = analyze_pcap_flow(packets, client_ip="8.8.8.8", server_ip="1.1.1.1")
        self.assertEqual(len(streams), 0)
        self.assertEqual(summary.total_streams, 0)


if __name__ == "__main__":
    unittest.main()
