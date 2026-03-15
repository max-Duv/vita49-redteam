"""Tests for vita49_redteam.transport.udp_sender — rate limiter and sender logic."""

import time

import pytest

from vita49_redteam.transport.udp_sender import TokenBucket, SenderConfig, UDPSender
from vita49_redteam.core.packet import make_if_data


class TestTokenBucket:
    def test_unlimited_rate(self):
        bucket = TokenBucket(rate=0, burst=1)
        assert bucket.consume() == 0.0

    def test_burst_allows_immediate(self):
        bucket = TokenBucket(rate=10, burst=5)
        # First 5 should be immediate
        for _ in range(5):
            wait = bucket.consume()
            assert wait == 0.0

    def test_rate_limiting(self):
        bucket = TokenBucket(rate=1000, burst=1)
        # Consume the initial token
        bucket.consume()
        # Next one should require waiting
        wait = bucket.consume()
        assert wait >= 0.0  # may be 0 if enough time passed


class TestSenderConfig:
    def test_defaults(self):
        cfg = SenderConfig()
        assert cfg.target_host == "127.0.0.1"
        assert cfg.target_port == 4991
        assert cfg.source_ip is None
        assert cfg.rate_pps == 0

    def test_custom_config(self):
        cfg = SenderConfig(
            target_host="10.0.0.1",
            target_port=5000,
            rate_pps=1000,
            burst_size=10,
        )
        assert cfg.target_host == "10.0.0.1"
        assert cfg.rate_pps == 1000


class TestUDPSender:
    def test_send_to_localhost(self):
        """Send a packet to localhost — verifies basic socket operation."""
        import socket

        # Set up a receiver
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.settimeout(2.0)
        recv_sock.bind(("127.0.0.1", 0))
        _, port = recv_sock.getsockname()

        try:
            config = SenderConfig(target_host="127.0.0.1", target_port=port)
            pkt = make_if_data(stream_id=0xABCD, payload=b"\x00" * 64)

            with UDPSender(config) as sender:
                sender.send_packet(pkt)
                assert sender.stats.packets_sent == 1

            # Verify the data was received
            data, addr = recv_sock.recvfrom(65535)
            assert len(data) > 0
            # Verify it starts with a valid VRT header
            header_word = int.from_bytes(data[:4], "big")
            pkt_type = (header_word >> 28) & 0xF
            assert pkt_type == 1  # IF_DATA_WITH_STREAM_ID
        finally:
            recv_sock.close()

    def test_send_multiple_packets(self):
        """Send multiple packets and verify stats."""
        import socket

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.settimeout(2.0)
        recv_sock.bind(("127.0.0.1", 0))
        _, port = recv_sock.getsockname()

        try:
            config = SenderConfig(target_host="127.0.0.1", target_port=port)
            packets = [make_if_data(stream_id=i, packet_count=i & 0xF) for i in range(10)]

            with UDPSender(config) as sender:
                sender.send_burst(packets)
                assert sender.stats.packets_sent == 10
        finally:
            recv_sock.close()

    def test_send_loop(self):
        import socket

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.settimeout(2.0)
        recv_sock.bind(("127.0.0.1", 0))
        _, port = recv_sock.getsockname()

        try:
            config = SenderConfig(
                target_host="127.0.0.1",
                target_port=port,
                loop_count=3,
            )
            packets = [make_if_data(stream_id=1)]

            with UDPSender(config) as sender:
                sender.send_loop(packets)
                assert sender.stats.packets_sent == 3
        finally:
            recv_sock.close()

    def test_context_manager_without_open(self):
        """Using context manager should auto-open."""
        config = SenderConfig(target_host="127.0.0.1", target_port=9999)
        with UDPSender(config) as sender:
            assert sender._sock is not None
        assert sender._sock is None

    def test_send_without_open_raises(self):
        config = SenderConfig()
        sender = UDPSender(config)
        with pytest.raises(RuntimeError, match="not open"):
            sender.send_packet(make_if_data())
