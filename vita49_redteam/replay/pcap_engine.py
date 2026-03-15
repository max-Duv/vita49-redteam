"""PCAP loader with per-field modification, timestamp adjustment, and replay scheduling.

Loads VITA 49 PCAP captures, parses VRT packets, allows field-level modifications
(timestamps, stream IDs, payloads), and replays them over UDP with original or
modified inter-packet timing.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from scapy.all import PcapReader, PcapWriter, UDP, wrpcap

from vita49_redteam.core.packet import VRTPacket
from vita49_redteam.transport.udp_sender import SenderConfig, UDPSender

logger = logging.getLogger(__name__)


@dataclass
class CapturedVRTPacket:
    """A single VRT packet extracted from a PCAP with its timing metadata."""

    timestamp: float  # PCAP frame timestamp (epoch seconds)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    raw_vrt: bytes  # Raw VRT payload (UDP payload)
    parsed: VRTPacket | None = None

    def parse(self) -> VRTPacket:
        if self.parsed is None:
            self.parsed = VRTPacket.unpack(self.raw_vrt)
        return self.parsed


# Type alias for modification callbacks
ModifyFunc = Callable[[CapturedVRTPacket, int], CapturedVRTPacket]


def load_pcap(pcap_path: str | Path) -> list[CapturedVRTPacket]:
    """Load VRT packets from a PCAP file.

    Extracts all UDP packets and attempts to parse them as VRT. Non-VRT
    packets (parsing failures) are still included with ``parsed=None``.
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    captured: list[CapturedVRTPacket] = []

    with PcapReader(str(pcap_path)) as reader:
        for scapy_pkt in reader:
            if not scapy_pkt.haslayer(UDP):
                continue

            udp_layer = scapy_pkt[UDP]
            raw_payload = bytes(udp_layer.payload)
            if not raw_payload:
                continue

            src_ip = scapy_pkt.sprintf("%IP.src%") if scapy_pkt.haslayer("IP") else ""
            dst_ip = scapy_pkt.sprintf("%IP.dst%") if scapy_pkt.haslayer("IP") else ""

            cap = CapturedVRTPacket(
                timestamp=float(scapy_pkt.time),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=udp_layer.sport,
                dst_port=udp_layer.dport,
                raw_vrt=raw_payload,
            )

            try:
                cap.parse()
            except Exception:
                logger.debug("Could not parse VRT from packet at ts=%.6f", cap.timestamp)

            captured.append(cap)

    logger.info("Loaded %d UDP packets from %s", len(captured), pcap_path)
    return captured


# ---------------------------------------------------------------------------
# Field-level modification helpers
# ---------------------------------------------------------------------------

def modify_stream_id(new_stream_id: int) -> ModifyFunc:
    """Return a modifier that overwrites the Stream ID."""

    def _modify(cap: CapturedVRTPacket, idx: int) -> CapturedVRTPacket:
        pkt = cap.parse()
        pkt.stream_id = new_stream_id
        cap.raw_vrt = pkt.pack()
        cap.parsed = pkt
        return cap

    return _modify


def modify_timestamps(
    time_offset: int = 0,
    fractional_offset: int = 0,
) -> ModifyFunc:
    """Return a modifier that adjusts integer/fractional timestamps."""

    def _modify(cap: CapturedVRTPacket, idx: int) -> CapturedVRTPacket:
        pkt = cap.parse()
        pkt.integer_timestamp = (pkt.integer_timestamp + time_offset) & 0xFFFFFFFF
        pkt.fractional_timestamp = (
            pkt.fractional_timestamp + fractional_offset
        ) & 0xFFFFFFFFFFFFFFFF
        cap.raw_vrt = pkt.pack()
        cap.parsed = pkt
        return cap

    return _modify


def modify_payload(new_payload: bytes) -> ModifyFunc:
    """Return a modifier that replaces the VRT payload."""

    def _modify(cap: CapturedVRTPacket, idx: int) -> CapturedVRTPacket:
        pkt = cap.parse()
        pkt.payload = new_payload
        cap.raw_vrt = pkt.pack()
        cap.parsed = pkt
        return cap

    return _modify


def modify_raw(transform: Callable[[bytes], bytes]) -> ModifyFunc:
    """Return a modifier that applies an arbitrary byte transform to the raw VRT."""

    def _modify(cap: CapturedVRTPacket, idx: int) -> CapturedVRTPacket:
        cap.raw_vrt = transform(cap.raw_vrt)
        cap.parsed = None  # invalidate cached parse
        return cap

    return _modify


# ---------------------------------------------------------------------------
# Replay engine
# ---------------------------------------------------------------------------

@dataclass
class ReplayConfig:
    """Configuration for PCAP replay."""

    preserve_timing: bool = True  # Replay with original inter-packet delays
    speed_multiplier: float = 1.0  # >1 = faster, <1 = slower
    modifiers: list[ModifyFunc] = field(default_factory=list)
    loop_count: int = 1


class PcapReplayEngine:
    """Load, modify, and replay VITA 49 PCAP captures over UDP."""

    def __init__(
        self,
        sender_config: SenderConfig | None = None,
        replay_config: ReplayConfig | None = None,
    ) -> None:
        self.sender_config = sender_config or SenderConfig()
        self.replay_config = replay_config or ReplayConfig()

    def replay(self, packets: list[CapturedVRTPacket]) -> int:
        """Replay captured packets with optional modifications.

        Returns the total number of packets sent.
        """
        if not packets:
            logger.warning("No packets to replay")
            return 0

        # Apply modifiers
        modified = list(packets)
        for mod_func in self.replay_config.modifiers:
            modified = [mod_func(cap, idx) for idx, cap in enumerate(modified)]

        total_sent = 0
        with UDPSender(self.sender_config) as sender:
            for _loop in range(self.replay_config.loop_count):
                prev_ts = modified[0].timestamp

                for cap in modified:
                    # Inter-packet delay
                    if self.replay_config.preserve_timing and total_sent > 0:
                        delta = (cap.timestamp - prev_ts) / self.replay_config.speed_multiplier
                        if delta > 0:
                            time.sleep(delta)
                    prev_ts = cap.timestamp

                    sender.send_raw(cap.raw_vrt)
                    total_sent += 1

        logger.info("Replay complete: %d packets sent", total_sent)
        return total_sent

    def replay_file(self, pcap_path: str | Path) -> int:
        """Load a PCAP and replay it. Convenience wrapper."""
        packets = load_pcap(pcap_path)
        return self.replay(packets)


def save_modified_pcap(
    original_path: str | Path,
    output_path: str | Path,
    modifiers: list[ModifyFunc],
) -> int:
    """Load a PCAP, apply modifiers, save to a new PCAP file.

    Returns the number of packets written.
    """
    from scapy.all import IP, Ether, PcapReader as _Reader

    original_path = Path(original_path)
    output_path = Path(output_path)
    packets = load_pcap(original_path)

    for mod_func in modifiers:
        packets = [mod_func(cap, idx) for idx, cap in enumerate(packets)]

    # Rebuild Scapy packets for PCAP output
    scapy_pkts = []
    for cap in packets:
        pkt = (
            Ether()
            / IP(src=cap.src_ip, dst=cap.dst_ip)
            / UDP(sport=cap.src_port, dport=cap.dst_port)
            / cap.raw_vrt
        )
        pkt.time = cap.timestamp
        scapy_pkts.append(pkt)

    wrpcap(str(output_path), scapy_pkts)
    logger.info("Saved %d packets to %s", len(scapy_pkts), output_path)
    return len(scapy_pkts)
