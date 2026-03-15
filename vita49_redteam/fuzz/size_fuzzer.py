"""VRT-204: Truncated & Oversized Packet Generator.

Generate packets truncated at various byte offsets and oversized packets
up to 65535 bytes, all with valid VRT headers. Tests receiver robustness
against unexpected packet sizes at the network layer.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Iterator

from vita49_redteam.core.constants import PacketType, MAX_UDP_PAYLOAD
from vita49_redteam.core.packet import VRTPacket


@dataclass
class SizeGenConfig:
    """Configuration for truncated/oversized packet generation."""
    stream_id: int = 0x00000001
    base_payload_size: int = 256
    # Truncation offsets (bytes from start to keep)
    truncation_offsets: list[int] | None = None
    # Oversized target sizes (total bytes)
    oversized_targets: list[int] | None = None


_DEFAULT_TRUNCATION_OFFSETS = [
    0,   # empty
    1,   # mid-header-word
    2,   # mid-header-word
    3,   # mid-header-word
    4,   # just the header word
    5,   # header + 1 byte of stream id
    6,
    7,
    8,   # header + stream id
    10,  # mid-timestamp
    12,  # header + stream id + 1 word
    16,  # header + stream id + class id (partial)
    20,  # header + stream id + class id
]

_DEFAULT_OVERSIZED_TARGETS = [
    1500,   # typical MTU
    2000,
    4096,
    8192,
    16384,
    32768,
    65507,  # max UDP payload
    65535,  # absolute max
]


class SizeGenerator:
    """Generate truncated and oversized VRT packets.

    Truncated packets are created by serializing a valid packet and
    slicing it at specific byte offsets. Oversized packets pad a valid
    header with additional data beyond what the header declares.
    """

    def __init__(self, config: SizeGenConfig | None = None) -> None:
        self.config = config or SizeGenConfig()

    def _base_packet(self, payload_size: int | None = None) -> VRTPacket:
        sz = payload_size if payload_size is not None else self.config.base_payload_size
        return VRTPacket(
            packet_type=PacketType.IF_DATA_WITH_STREAM_ID,
            stream_id=self.config.stream_id,
            payload=b"\x00" * sz,
        )

    def generate(self) -> Iterator[tuple[str, bytes]]:
        """Yield (description, raw_bytes) tuples for all size test cases."""
        yield from self._truncated()
        yield from self._oversized()
        yield from self._progressive_truncation()

    def generate_count(self, count: int) -> list[tuple[str, bytes]]:
        cases = []
        for item in self.generate():
            cases.append(item)
            if len(cases) >= count:
                break
        return cases

    # -- Truncated packets -------------------------------------------------

    def _truncated(self) -> Iterator[tuple[str, bytes]]:
        pkt = self._base_packet()
        full_bytes = pkt.pack()
        offsets = self.config.truncation_offsets or _DEFAULT_TRUNCATION_OFFSETS

        for offset in offsets:
            if offset > len(full_bytes):
                continue
            truncated = full_bytes[:offset]
            yield f"truncated:{offset}_bytes_of_{len(full_bytes)}", truncated

    # -- Oversized packets -------------------------------------------------

    def _oversized(self) -> Iterator[tuple[str, bytes]]:
        targets = self.config.oversized_targets or _DEFAULT_OVERSIZED_TARGETS

        for target_size in targets:
            # Build a valid header, then pad to target size
            pkt = self._base_packet(payload_size=0)
            header_bytes = pkt.pack()  # just header + stream id
            pad_needed = target_size - len(header_bytes)
            if pad_needed <= 0:
                continue
            # Keep the header's packet_size field honest for the first word
            raw = header_bytes + os.urandom(pad_needed)
            yield f"oversized:{target_size}_bytes_header_size={pkt.compute_packet_size_words()}w", raw

        # Oversized with valid packet_size field (size matches the large payload)
        for target_size in [4096, 16384, 65507]:
            payload_bytes = target_size - 8  # header(4) + stream_id(4)
            if payload_bytes <= 0:
                continue
            pkt = self._base_packet(payload_size=payload_bytes)
            yield f"oversized_valid:{target_size}_bytes", pkt.pack()

    # -- Progressive truncation (every 4-byte boundary) --------------------

    def _progressive_truncation(self) -> Iterator[tuple[str, bytes]]:
        """Truncate at every word boundary through the packet."""
        pkt = self._base_packet()
        full_bytes = pkt.pack()
        total_words = len(full_bytes) // 4

        for word_idx in range(total_words):
            offset = word_idx * 4
            truncated = full_bytes[:offset]
            yield f"progressive_trunc:word_{word_idx}_of_{total_words}", truncated
