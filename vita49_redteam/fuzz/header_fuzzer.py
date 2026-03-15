"""VRT-201: Header Field Fuzzer — fuzz all VITA 49 header fields.

Generates packets with fuzzed header values: boundary values, bit-flips,
type confusion, and random mutations across Packet Type, TSI, TSF,
Packet Count, Packet Size, Stream ID, and Class ID.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterator

from vita49_redteam.core.constants import (
    HDR_CLASS_ID_BIT,
    HDR_PACKET_TYPE_SHIFT,
    HDR_TSF_SHIFT,
    HDR_TSI_SHIFT,
    PacketType,
    TSF,
    TSI,
)
from vita49_redteam.core.packet import VRTPacket


class FuzzStrategy(IntEnum):
    """Fuzzing strategies for header fields."""
    BOUNDARY = 0       # Min/max/edge values
    BIT_FLIP = 1       # Single and multi-bit flips
    TYPE_CONFUSION = 2 # Wrong field types / reserved bits
    RANDOM = 3         # Purely random values


@dataclass
class HeaderFuzzConfig:
    """Configuration for the header field fuzzer."""
    strategies: list[FuzzStrategy] = field(
        default_factory=lambda: list(FuzzStrategy)
    )
    fuzz_packet_type: bool = True
    fuzz_tsi: bool = True
    fuzz_tsf: bool = True
    fuzz_packet_count: bool = True
    fuzz_packet_size: bool = True
    fuzz_stream_id: bool = True
    fuzz_class_id: bool = True
    fuzz_reserved_bits: bool = True
    base_payload_size: int = 64
    seed: int | None = None


# ---------------------------------------------------------------------------
# Boundary values for each field
# ---------------------------------------------------------------------------
PACKET_TYPE_BOUNDARIES = [0x0, 0x7, 0x8, 0xF]  # valid range 0-7; 8-15 reserved
TSI_BOUNDARIES = [0, 1, 2, 3]  # full 2-bit range
TSF_BOUNDARIES = [0, 1, 2, 3]
PACKET_COUNT_BOUNDARIES = [0, 1, 0xE, 0xF]  # 4-bit mod-16
PACKET_SIZE_BOUNDARIES = [0x0000, 0x0001, 0x0002, 0x7FFF, 0xFFFF]
STREAM_ID_BOUNDARIES = [0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
CLASS_ID_OUI_BOUNDARIES = [0x000000, 0x0012A2, 0x7FFFFF, 0xFFFFFF]


def _bit_flips_32(base: int) -> list[int]:
    """Generate single-bit flips across a 32-bit value."""
    return [(base ^ (1 << b)) & 0xFFFFFFFF for b in range(32)]


def _bit_flips_16(base: int) -> list[int]:
    """Generate single-bit flips across a 16-bit value."""
    return [(base ^ (1 << b)) & 0xFFFF for b in range(16)]


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


class HeaderFuzzer:
    """Generates fuzzed VRT packets targeting header fields.

    Yields VRTPacket instances with mutations applied to header fields
    based on the configured strategies.
    """

    def __init__(self, config: HeaderFuzzConfig | None = None) -> None:
        self.config = config or HeaderFuzzConfig()
        if self.config.seed is not None:
            self._rng_state = self.config.seed
        else:
            self._rng_state = int.from_bytes(os.urandom(4), "big")

    def _rand_u32(self) -> int:
        # Simple LCG for reproducibility when seeded
        self._rng_state = (self._rng_state * 1103515245 + 12345) & 0xFFFFFFFF
        return self._rng_state

    def _rand_u16(self) -> int:
        return self._rand_u32() & 0xFFFF

    def _rand_u4(self) -> int:
        return self._rand_u32() & 0xF

    def _base_packet(self) -> VRTPacket:
        """Create a valid base packet for mutation."""
        return VRTPacket(
            packet_type=PacketType.IF_DATA_WITH_STREAM_ID,
            stream_id=0x00000001,
            payload=b"\x00" * self.config.base_payload_size,
        )

    # -- Strategy generators -----------------------------------------------

    def generate(self) -> Iterator[tuple[str, VRTPacket]]:
        """Yield (description, packet) tuples for all configured fuzz cases."""
        for strategy in self.config.strategies:
            if strategy == FuzzStrategy.BOUNDARY:
                yield from self._boundary_cases()
            elif strategy == FuzzStrategy.BIT_FLIP:
                yield from self._bit_flip_cases()
            elif strategy == FuzzStrategy.TYPE_CONFUSION:
                yield from self._type_confusion_cases()
            elif strategy == FuzzStrategy.RANDOM:
                yield from self._random_cases()

    def generate_count(self, count: int) -> list[tuple[str, VRTPacket]]:
        """Collect up to *count* fuzz cases."""
        cases = []
        for item in self.generate():
            cases.append(item)
            if len(cases) >= count:
                break
        return cases

    # -- Boundary strategy -------------------------------------------------

    def _boundary_cases(self) -> Iterator[tuple[str, VRTPacket]]:
        if self.config.fuzz_packet_type:
            for val in PACKET_TYPE_BOUNDARIES:
                pkt = self._base_packet()
                header = pkt.build_header_word()
                header = (header & ~(0xF << HDR_PACKET_TYPE_SHIFT)) | ((val & 0xF) << HDR_PACKET_TYPE_SHIFT)
                pkt.with_raw_header(header)
                yield f"boundary:packet_type=0x{val:X}", pkt

        if self.config.fuzz_tsi:
            for val in TSI_BOUNDARIES:
                pkt = self._base_packet()
                header = pkt.build_header_word()
                header = (header & ~(0x3 << HDR_TSI_SHIFT)) | ((val & 0x3) << HDR_TSI_SHIFT)
                pkt.with_raw_header(header)
                yield f"boundary:tsi={val}", pkt

        if self.config.fuzz_tsf:
            for val in TSF_BOUNDARIES:
                pkt = self._base_packet()
                header = pkt.build_header_word()
                header = (header & ~(0x3 << HDR_TSF_SHIFT)) | ((val & 0x3) << HDR_TSF_SHIFT)
                pkt.with_raw_header(header)
                yield f"boundary:tsf={val}", pkt

        if self.config.fuzz_packet_count:
            for val in PACKET_COUNT_BOUNDARIES:
                pkt = self._base_packet()
                pkt.packet_count = val & 0xF
                yield f"boundary:packet_count={val}", pkt

        if self.config.fuzz_packet_size:
            for val in PACKET_SIZE_BOUNDARIES:
                pkt = self._base_packet()
                pkt.with_packet_size_override(val)
                yield f"boundary:packet_size=0x{val:04X}", pkt

        if self.config.fuzz_stream_id:
            for val in STREAM_ID_BOUNDARIES:
                pkt = self._base_packet()
                pkt.stream_id = val
                yield f"boundary:stream_id=0x{val:08X}", pkt

        if self.config.fuzz_class_id:
            for oui in CLASS_ID_OUI_BOUNDARIES:
                pkt = self._base_packet()
                pkt.with_class_id(oui=oui, info_class=0xFFFF, pkt_class=0xFFFF)
                yield f"boundary:class_id_oui=0x{oui:06X}", pkt

    # -- Bit-flip strategy -------------------------------------------------

    def _bit_flip_cases(self) -> Iterator[tuple[str, VRTPacket]]:
        base_pkt = self._base_packet()
        base_header = base_pkt.build_header_word()

        for flipped in _bit_flips_32(base_header):
            pkt = self._base_packet()
            pkt.with_raw_header(flipped)
            bit = (base_header ^ flipped).bit_length() - 1
            yield f"bitflip:header_bit{bit}=0x{flipped:08X}", pkt

        if self.config.fuzz_stream_id:
            base_sid = 0x00000001
            for flipped in _bit_flips_32(base_sid):
                pkt = self._base_packet()
                pkt.stream_id = flipped
                bit = (base_sid ^ flipped).bit_length() - 1
                yield f"bitflip:stream_id_bit{bit}=0x{flipped:08X}", pkt

    # -- Type confusion strategy -------------------------------------------

    def _type_confusion_cases(self) -> Iterator[tuple[str, VRTPacket]]:
        # Reserved packet types (8-15)
        for pt in range(8, 16):
            pkt = self._base_packet()
            header = pkt.build_header_word()
            header = (header & ~(0xF << HDR_PACKET_TYPE_SHIFT)) | ((pt & 0xF) << HDR_PACKET_TYPE_SHIFT)
            pkt.with_raw_header(header)
            yield f"type_confusion:reserved_pkt_type=0x{pt:X}", pkt

        if self.config.fuzz_reserved_bits:
            # Set reserved bits 21-20 in header
            for bit in [20, 21]:
                pkt = self._base_packet()
                header = pkt.build_header_word()
                header |= (1 << bit)
                pkt.with_raw_header(header)
                yield f"type_confusion:reserved_bit{bit}_set", pkt

        # Context packet with data payload
        pkt = self._base_packet()
        pkt.packet_type = PacketType.IF_CONTEXT
        pkt.payload = b"\xff" * 128
        yield "type_confusion:context_with_data_payload", pkt

        # Data packet with class_id set but C bit clear
        pkt = self._base_packet()
        pkt.class_id_present = False
        header = pkt.build_header_word()
        # Append class ID bytes manually after header
        pkt.with_raw_header(header & ~HDR_CLASS_ID_BIT)
        yield "type_confusion:class_id_bytes_without_c_bit", pkt

    # -- Random strategy ---------------------------------------------------

    def _random_cases(self, count: int = 50) -> Iterator[tuple[str, VRTPacket]]:
        for i in range(count):
            pkt = self._base_packet()
            header = self._rand_u32()
            # Force a plausible packet size in the low 16 bits so it
            # still makes it through most parsers' first check
            actual_size = pkt.compute_packet_size_words()
            header = (header & 0xFFFF0000) | (actual_size & 0xFFFF)
            pkt.with_raw_header(header)
            pkt.stream_id = self._rand_u32()
            yield f"random:case_{i}:header=0x{header:08X}", pkt

        # Fully random headers (size also randomised)
        for i in range(20):
            pkt = self._base_packet()
            pkt.with_raw_header(self._rand_u32())
            pkt.stream_id = self._rand_u32()
            yield f"random_full:case_{i}", pkt
