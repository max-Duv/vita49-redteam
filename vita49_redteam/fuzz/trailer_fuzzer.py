"""VRT-203: Trailer Field Fuzzer.

Fuzz all VITA 49 trailer indicator and enable bits: calibrated time,
valid data, reference lock, AGC/MGC, detected signal, spectral inversion,
over-range, sample loss, user-defined bits, and associated context packet count.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterator

from vita49_redteam.core.constants import PacketType, TrailerBits
from vita49_redteam.core.packet import Trailer, VRTPacket


# Named bit positions in the trailer word
_TRAILER_BIT_NAMES: list[tuple[str, int]] = [
    ("calibrated_time_enable", 31),
    ("valid_data_enable", 30),
    ("reference_lock_enable", 29),
    ("agc_mgc_enable", 28),
    ("detected_signal_enable", 27),
    ("spectral_inversion_enable", 26),
    ("over_range_enable", 25),
    ("sample_loss_enable", 24),
    ("user_11_enable", 23),
    ("user_10_enable", 22),
    ("user_9_enable", 21),
    ("user_8_enable", 20),
    ("calibrated_time", 19),
    ("valid_data", 18),
    ("reference_lock", 17),
    ("agc_mgc", 16),
    ("detected_signal", 15),
    ("spectral_inversion", 14),
    ("over_range", 13),
    ("sample_loss", 12),
    ("user_11", 11),
    ("user_10", 10),
    ("user_9", 9),
    ("user_8", 8),
    # Bits 7 is the E bit (associated context packet count enable)
    ("assoc_context_enable", 7),
]


@dataclass
class TrailerFuzzConfig:
    """Configuration for trailer fuzzer."""
    fuzz_individual_bits: bool = True
    fuzz_enable_indicator_mismatch: bool = True
    fuzz_all_bits_set: bool = True
    fuzz_walking_ones: bool = True
    fuzz_random: bool = True
    fuzz_context_count: bool = True
    base_payload_size: int = 64
    stream_id: int = 0x00000001
    random_count: int = 30
    seed: int | None = None


class TrailerFuzzer:
    """Generate packets with fuzzed trailer words.

    All generated packets have the T (trailer) bit set in the header
    and carry a deliberately mutated trailer word.
    """

    def __init__(self, config: TrailerFuzzConfig | None = None) -> None:
        self.config = config or TrailerFuzzConfig()
        if self.config.seed is not None:
            self._rng = self.config.seed
        else:
            self._rng = int.from_bytes(os.urandom(4), "big")

    def _rand_u32(self) -> int:
        self._rng = (self._rng * 1103515245 + 12345) & 0xFFFFFFFF
        return self._rng

    def _base_packet(self, trailer_raw: int = 0) -> VRTPacket:
        pkt = VRTPacket(
            packet_type=PacketType.IF_DATA_WITH_STREAM_ID,
            stream_id=self.config.stream_id,
            payload=b"\x00" * self.config.base_payload_size,
        )
        pkt.with_trailer(raw=trailer_raw)
        return pkt

    def generate(self) -> Iterator[tuple[str, VRTPacket]]:
        """Yield (description, packet) tuples for trailer fuzz cases."""
        if self.config.fuzz_individual_bits:
            yield from self._individual_bits()
        if self.config.fuzz_enable_indicator_mismatch:
            yield from self._enable_indicator_mismatch()
        if self.config.fuzz_all_bits_set:
            yield from self._all_bits_set()
        if self.config.fuzz_walking_ones:
            yield from self._walking_ones()
        if self.config.fuzz_context_count:
            yield from self._context_count()
        if self.config.fuzz_random:
            yield from self._random()

    def generate_count(self, count: int) -> list[tuple[str, VRTPacket]]:
        cases = []
        for item in self.generate():
            cases.append(item)
            if len(cases) >= count:
                break
        return cases

    # -- Individual bit setting -------------------------------------------

    def _individual_bits(self) -> Iterator[tuple[str, VRTPacket]]:
        """Set each named trailer bit individually."""
        for name, bit_pos in _TRAILER_BIT_NAMES:
            trailer_val = 1 << bit_pos
            pkt = self._base_packet(trailer_val)
            yield f"individual:{name}_bit{bit_pos}", pkt

    # -- Enable/indicator mismatch ----------------------------------------

    def _enable_indicator_mismatch(self) -> Iterator[tuple[str, VRTPacket]]:
        """Set enable bits without corresponding indicator bits, and vice versa."""
        # Enable pairs: (enable_bit, indicator_bit)
        pairs = [
            ("calibrated_time", 31, 19),
            ("valid_data", 30, 18),
            ("reference_lock", 29, 17),
            ("agc_mgc", 28, 16),
            ("detected_signal", 27, 15),
            ("spectral_inversion", 26, 14),
            ("over_range", 25, 13),
            ("sample_loss", 24, 12),
        ]
        for name, enable_bit, indicator_bit in pairs:
            # Enable set, indicator clear
            val = 1 << enable_bit
            pkt = self._base_packet(val)
            yield f"mismatch:{name}_enable_only", pkt

            # Indicator set, enable clear
            val = 1 << indicator_bit
            pkt = self._base_packet(val)
            yield f"mismatch:{name}_indicator_only", pkt

    # -- All bits set / clear ---------------------------------------------

    def _all_bits_set(self) -> Iterator[tuple[str, VRTPacket]]:
        # All 1s
        pkt = self._base_packet(0xFFFFFFFF)
        yield "all_bits:0xFFFFFFFF", pkt

        # All 0s (valid but boring — included for completeness)
        pkt = self._base_packet(0x00000000)
        yield "all_bits:0x00000000", pkt

        # All enable bits set, all indicators clear
        val = 0xFFF00000
        pkt = self._base_packet(val)
        yield "all_bits:enables_only=0xFFF00000", pkt

        # All indicators set, all enables clear
        val = 0x000FFF00
        pkt = self._base_packet(val)
        yield "all_bits:indicators_only=0x000FFF00", pkt

    # -- Walking ones across all 32 bits -----------------------------------

    def _walking_ones(self) -> Iterator[tuple[str, VRTPacket]]:
        for bit in range(32):
            pkt = self._base_packet(1 << bit)
            yield f"walking_one:bit{bit}", pkt

    # -- Associated context packet count -----------------------------------

    def _context_count(self) -> Iterator[tuple[str, VRTPacket]]:
        """Fuzz the 7-bit associated context packet count (bits 6-0)."""
        for count_val in [0, 1, 63, 64, 127]:
            # With E bit (bit 7) set
            trailer_val = (1 << 7) | (count_val & 0x7F)
            pkt = self._base_packet(trailer_val)
            yield f"context_count:e_bit_set_count={count_val}", pkt

            # Without E bit
            trailer_val = count_val & 0x7F
            pkt = self._base_packet(trailer_val)
            yield f"context_count:e_bit_clear_count={count_val}", pkt

    # -- Random trailer words ----------------------------------------------

    def _random(self) -> Iterator[tuple[str, VRTPacket]]:
        for i in range(self.config.random_count):
            val = self._rand_u32()
            pkt = self._base_packet(val)
            yield f"random:trailer=0x{val:08X}", pkt
