"""VRT-202: Payload Size Mismatch Tests.

Craft packets where the declared header Packet Size field mismatches
the actual UDP payload length — undersized, oversized, and zero-length
variants. Designed to trigger crashes, hangs, or memory issues on the receiver.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterator

from vita49_redteam.core.constants import PacketType
from vita49_redteam.core.packet import VRTPacket


@dataclass
class PayloadMismatchConfig:
    """Configuration for payload size mismatch generation."""
    base_payload_size: int = 256
    stream_id: int = 0x00000001
    include_undersized: bool = True
    include_oversized: bool = True
    include_zero_length: bool = True
    include_off_by_one: bool = True
    include_extreme: bool = True


class PayloadSizeFuzzer:
    """Generate packets with declared-vs-actual size mismatches.

    The VITA 49 header's Packet Size field (16 bits, in 32-bit words)
    should equal the total packet length. This fuzzer deliberately
    produces mismatches to test receiver robustness.
    """

    def __init__(self, config: PayloadMismatchConfig | None = None) -> None:
        self.config = config or PayloadMismatchConfig()

    def _base_packet(self, payload_size: int | None = None) -> VRTPacket:
        sz = payload_size if payload_size is not None else self.config.base_payload_size
        return VRTPacket(
            packet_type=PacketType.IF_DATA_WITH_STREAM_ID,
            stream_id=self.config.stream_id,
            payload=b"\x00" * sz,
        )

    def generate(self) -> Iterator[tuple[str, bytes]]:
        """Yield (description, raw_bytes) tuples.

        Returns raw bytes rather than VRTPacket because some cases
        involve truncated or extended raw data that can't be represented
        as a valid VRTPacket serialisation.
        """
        if self.config.include_undersized:
            yield from self._undersized()
        if self.config.include_oversized:
            yield from self._oversized()
        if self.config.include_zero_length:
            yield from self._zero_length()
        if self.config.include_off_by_one:
            yield from self._off_by_one()
        if self.config.include_extreme:
            yield from self._extreme()

    def generate_count(self, count: int) -> list[tuple[str, bytes]]:
        """Collect up to *count* mismatch cases."""
        cases = []
        for item in self.generate():
            cases.append(item)
            if len(cases) >= count:
                break
        return cases

    # -- Undersized: header says bigger than actual payload ----------------

    def _undersized(self) -> Iterator[tuple[str, bytes]]:
        for inflate_words in [1, 2, 4, 8, 16, 100, 0x7FFF]:
            pkt = self._base_packet()
            real_size = pkt.compute_packet_size_words()
            declared = real_size + inflate_words
            pkt.with_packet_size_override(declared)
            raw = pkt.pack()
            yield (
                f"undersized:declared={declared}_actual={real_size}_delta=+{inflate_words}w",
                raw,
            )

    # -- Oversized: header says smaller than actual payload ----------------

    def _oversized(self) -> Iterator[tuple[str, bytes]]:
        for deflate_words in [1, 2, 4, 8]:
            pkt = self._base_packet()
            real_size = pkt.compute_packet_size_words()
            declared = max(1, real_size - deflate_words)
            pkt.with_packet_size_override(declared)
            raw = pkt.pack()
            yield (
                f"oversized:declared={declared}_actual={real_size}_delta=-{deflate_words}w",
                raw,
            )

    # -- Zero-length variations --------------------------------------------

    def _zero_length(self) -> Iterator[tuple[str, bytes]]:
        # Header says size=0
        pkt = self._base_packet()
        pkt.with_packet_size_override(0)
        yield "zero_size:declared=0", pkt.pack()

        # Header says size=1 (just the header word, no payload at all)
        pkt = self._base_packet()
        pkt.with_packet_size_override(1)
        yield "header_only:declared=1", pkt.pack()

        # Empty payload but correct size
        pkt = self._base_packet(payload_size=0)
        yield "empty_payload:correct_size", pkt.pack()

        # Empty payload with inflated size
        pkt = self._base_packet(payload_size=0)
        pkt.with_packet_size_override(100)
        yield "empty_payload:declared=100", pkt.pack()

    # -- Off-by-one --------------------------------------------------------

    def _off_by_one(self) -> Iterator[tuple[str, bytes]]:
        pkt = self._base_packet()
        real_size = pkt.compute_packet_size_words()

        # Size - 1
        pkt_minus = self._base_packet()
        pkt_minus.with_packet_size_override(real_size - 1)
        yield f"off_by_one:size-1={real_size - 1}", pkt_minus.pack()

        # Size + 1
        pkt_plus = self._base_packet()
        pkt_plus.with_packet_size_override(real_size + 1)
        yield f"off_by_one:size+1={real_size + 1}", pkt_plus.pack()

        # Append 1-3 extra bytes (non-word-aligned)
        raw = pkt.pack()
        for extra in [1, 2, 3]:
            yield f"off_by_one:extra_{extra}_bytes", raw + os.urandom(extra)

    # -- Extreme cases -----------------------------------------------------

    def _extreme(self) -> Iterator[tuple[str, bytes]]:
        # Max packet size field (0xFFFF = 65535 words)
        pkt = self._base_packet()
        pkt.with_packet_size_override(0xFFFF)
        yield "extreme:max_size_field=0xFFFF", pkt.pack()

        # Tiny payload with large declared size
        pkt = self._base_packet(payload_size=4)
        pkt.with_packet_size_override(0x8000)
        yield "extreme:4byte_payload_size=0x8000", pkt.pack()

        # Huge payload (near UDP max) with small declared size
        pkt = self._base_packet(payload_size=8192)
        pkt.with_packet_size_override(2)
        yield "extreme:8k_payload_size=2", pkt.pack()

        # Payload that's not word-aligned
        pkt = VRTPacket(
            packet_type=PacketType.IF_DATA_WITH_STREAM_ID,
            stream_id=self.config.stream_id,
            payload=b"\xAA" * 13,  # 13 bytes, not word-aligned
        )
        yield "extreme:non_aligned_13_bytes", pkt.pack()
