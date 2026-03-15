"""Raw-socket UDP transmitter with rate control, source IP spoofing, and burst mode.

Designed for red-team operations requiring precise control over packet timing
and crafted source addresses. Requires root / Administrator / CAP_NET_RAW.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Sequence

from vita49_redteam.core.constants import MAX_UDP_PAYLOAD, VRT_DEFAULT_PORT
from vita49_redteam.core.packet import VRTPacket

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------
class TokenBucket:
    """Token-bucket algorithm for precise rate control.

    Args:
        rate: Tokens (packets) per second.  0 = unlimited.
        burst: Maximum token accumulation (burst size).
    """

    def __init__(self, rate: float = 0, burst: int = 1) -> None:
        self.rate = rate
        self.burst = max(burst, 1)
        self._tokens: float = float(burst)
        self._last_time: float = time.monotonic()

    def consume(self, count: int = 1) -> float:
        """Consume *count* tokens, returning the sleep time needed (may be 0)."""
        if self.rate <= 0:
            return 0.0

        now = time.monotonic()
        elapsed = now - self._last_time
        self._last_time = now
        self._tokens = min(self._tokens + elapsed * self.rate, float(self.burst))

        if self._tokens >= count:
            self._tokens -= count
            return 0.0

        # Need to wait for tokens to refill
        deficit = count - self._tokens
        wait = deficit / self.rate
        self._tokens = 0
        return wait


# ---------------------------------------------------------------------------
# UDP Sender configuration
# ---------------------------------------------------------------------------
@dataclass
class SenderConfig:
    """Configuration for the UDP transmitter."""

    target_host: str = "127.0.0.1"
    target_port: int = VRT_DEFAULT_PORT
    source_ip: str | None = None  # None = kernel default; set for spoofing
    source_port: int = 0  # 0 = ephemeral
    rate_pps: float = 0  # packets/sec, 0 = unlimited
    burst_size: int = 1
    ttl: int = 64
    loop_count: int = 1  # times to repeat the packet list
    inter_burst_delay: float = 0.0  # seconds between bursts


# ---------------------------------------------------------------------------
# UDP Sender
# ---------------------------------------------------------------------------
class UDPSender:
    """Transmit crafted VITA 49 packets over UDP.

    Supports two modes:
    - **Normal mode**: standard UDP socket, no spoofing.
    - **Raw mode**: raw IP socket with full header control (requires privileges).

    The raw mode is automatically selected when ``config.source_ip`` is set.
    """

    def __init__(self, config: SenderConfig | None = None) -> None:
        self.config = config or SenderConfig()
        self._bucket = TokenBucket(self.config.rate_pps, self.config.burst_size)
        self._sock: socket.socket | None = None
        self._raw = self.config.source_ip is not None
        self._stats = _SendStats()

    # -- Context manager --------------------------------------------------
    def __enter__(self) -> UDPSender:
        self.open()
        return self

    def __exit__(self, *exc) -> None:  # noqa: ANN002
        self.close()

    # -- Socket lifecycle -------------------------------------------------
    def open(self) -> None:
        if self._raw:
            self._sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
            )
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self.config.source_port:
                self._sock.bind(("", self.config.source_port))

        self._sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_TTL, self.config.ttl
        )
        logger.info(
            "Opened %s socket → %s:%d",
            "raw" if self._raw else "UDP",
            self.config.target_host,
            self.config.target_port,
        )

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None
        logger.info("Sender closed. %s", self._stats)

    # -- Sending ----------------------------------------------------------
    def send_packet(self, pkt: VRTPacket) -> None:
        """Send a single VRTPacket."""
        data = pkt.pack()
        self._send_bytes(data)

    def send_raw(self, data: bytes) -> None:
        """Send raw bytes (already serialized VRT payload)."""
        self._send_bytes(data)

    def send_burst(self, packets: Sequence[VRTPacket]) -> None:
        """Send a burst of packets in rapid succession."""
        for pkt in packets:
            self.send_packet(pkt)

    def send_loop(self, packets: Sequence[VRTPacket]) -> None:
        """Send packets list *loop_count* times with rate control."""
        for loop_idx in range(self.config.loop_count):
            for pkt in packets:
                self.send_packet(pkt)
            if (
                self.config.inter_burst_delay > 0
                and loop_idx < self.config.loop_count - 1
            ):
                time.sleep(self.config.inter_burst_delay)

    @property
    def stats(self) -> _SendStats:
        return self._stats

    # -- Internal ---------------------------------------------------------
    def _send_bytes(self, vrt_payload: bytes) -> None:
        if self._sock is None:
            raise RuntimeError("Socket not open — call open() or use context manager")

        if len(vrt_payload) > MAX_UDP_PAYLOAD:
            logger.warning(
                "Payload %d bytes exceeds max UDP payload %d",
                len(vrt_payload),
                MAX_UDP_PAYLOAD,
            )

        # Rate limiting
        wait = self._bucket.consume()
        if wait > 0:
            time.sleep(wait)

        if self._raw:
            ip_packet = self._build_ip_udp(vrt_payload)
            self._sock.sendto(ip_packet, (self.config.target_host, 0))
        else:
            self._sock.sendto(
                vrt_payload, (self.config.target_host, self.config.target_port)
            )

        self._stats.packets_sent += 1
        self._stats.bytes_sent += len(vrt_payload)

    def _build_ip_udp(self, payload: bytes) -> bytes:
        """Construct raw IP + UDP headers wrapping *payload*."""
        src_ip = self.config.source_ip or "0.0.0.0"
        dst_ip = self.config.target_host
        src_port = self.config.source_port or 12345
        dst_port = self.config.target_port

        # UDP header
        udp_len = 8 + len(payload)
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)  # checksum=0

        # IP header (20 bytes, no options)
        ip_total_len = 20 + udp_len
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,  # version=4, IHL=5
            0,  # DSCP / ECN
            ip_total_len,
            0,  # identification
            0,  # flags + fragment offset
            self.config.ttl,
            socket.IPPROTO_UDP,
            0,  # checksum (kernel fills on many OS)
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )

        return ip_hdr + udp_hdr + payload


@dataclass
class _SendStats:
    """Transmission statistics."""

    packets_sent: int = 0
    bytes_sent: int = 0

    def __str__(self) -> str:
        return f"Sent {self.packets_sent} packets ({self.bytes_sent} bytes)"
