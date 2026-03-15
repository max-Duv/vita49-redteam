"""Core VITA 49 packet builder with struct-based serialization.

Provides a dataclass-based builder pattern that can construct valid VITA 49.0 and
49.2 packets (IF Data, IF Context, Extension Data/Context) with full header field
control. Designed for performance-critical paths such as high-rate flooding.

All fields default to valid values; red-team operators explicitly override
specific fields per test case.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Self

from vita49_redteam.core.constants import (
    CLASS_ID_SIZE_WORDS,
    HDR_CLASS_ID_BIT,
    HDR_PACKET_COUNT_MASK,
    HDR_PACKET_COUNT_SHIFT,
    HDR_PACKET_SIZE_MASK,
    HDR_PACKET_TYPE_SHIFT,
    HDR_TRAILER_BIT,
    HDR_TSF_SHIFT,
    HDR_TSI_SHIFT,
    MAX_PACKET_SIZE_WORDS,
    MIN_HEADER_WORDS,
    TRAILER_SIZE_WORDS,
    OUI,
    PacketType,
    TSF,
    TSI,
)


@dataclass
class ClassID:
    """VITA 49 Class Identifier (8 bytes / 2 words)."""

    oui: int = OUI.VITA
    information_class_code: int = 0x0000
    packet_class_code: int = 0x0000

    def pack(self) -> bytes:
        """Serialize to 8 bytes (2 × 32-bit words), big-endian."""
        word1 = (self.oui & 0x00FFFFFF) << 8  # pad byte 0 + OUI in bytes 1-3
        word2 = ((self.information_class_code & 0xFFFF) << 16) | (
            self.packet_class_code & 0xFFFF
        )
        return struct.pack("!II", word1, word2)

    @classmethod
    def unpack(cls, data: bytes) -> ClassID:
        """Deserialize from 8 bytes."""
        word1, word2 = struct.unpack("!II", data[:8])
        return cls(
            oui=(word1 >> 8) & 0x00FFFFFF,
            information_class_code=(word2 >> 16) & 0xFFFF,
            packet_class_code=word2 & 0xFFFF,
        )


@dataclass
class Trailer:
    """VITA 49 Trailer word for data packets (1 word / 4 bytes)."""

    raw: int = 0x00000000

    # Convenience properties for common indicator flags
    @property
    def calibrated_time_enable(self) -> bool:
        return bool(self.raw & (1 << 31))

    @property
    def valid_data_enable(self) -> bool:
        return bool(self.raw & (1 << 30))

    @property
    def valid_data(self) -> bool:
        return bool(self.raw & (1 << 18))

    @property
    def sample_loss(self) -> bool:
        return bool(self.raw & (1 << 12))

    @property
    def associated_context_packet_count(self) -> int:
        return self.raw & 0x7F  # bits 6-0

    def pack(self) -> bytes:
        return struct.pack("!I", self.raw & 0xFFFFFFFF)

    @classmethod
    def unpack(cls, data: bytes) -> Trailer:
        (word,) = struct.unpack("!I", data[:4])
        return cls(raw=word)


@dataclass
class VRTPacket:
    """VITA 49 packet with builder-pattern methods for field-level control.

    All fields default to a minimal valid IF Data packet with Stream ID.
    Override any field to craft specific test packets.
    """

    # --- Header fields ---
    packet_type: PacketType = PacketType.IF_DATA_WITH_STREAM_ID
    class_id_present: bool = False
    trailer_present: bool = False
    tsi: TSI = TSI.NONE
    tsf: TSF = TSF.NONE
    packet_count: int = 0  # 4-bit mod-16
    # packet_size is computed automatically unless overridden
    packet_size_override: int | None = None

    # --- Stream ID (present when packet_type requires it) ---
    stream_id: int = 0x00000001

    # --- Class ID (present when class_id_present=True) ---
    class_id: ClassID = field(default_factory=ClassID)

    # --- Timestamps ---
    integer_timestamp: int = 0  # 32-bit; present when TSI != NONE
    fractional_timestamp: int = 0  # 64-bit; present when TSF != NONE

    # --- Payload (raw bytes) ---
    payload: bytes = b""

    # --- Trailer ---
    trailer: Trailer = field(default_factory=Trailer)

    # --- Raw header override (for injecting malformed headers) ---
    raw_header_override: int | None = None

    # ------------------------------------------------------------------
    # Builder helpers (return self for chaining)
    # ------------------------------------------------------------------
    def with_packet_type(self, pt: PacketType) -> Self:
        self.packet_type = pt
        return self

    def with_stream_id(self, sid: int) -> Self:
        self.stream_id = sid & 0xFFFFFFFF
        return self

    def with_class_id(
        self,
        oui: int = OUI.VITA,
        info_class: int = 0,
        pkt_class: int = 0,
    ) -> Self:
        self.class_id_present = True
        self.class_id = ClassID(oui, info_class, pkt_class)
        return self

    def with_timestamps(
        self,
        tsi: TSI = TSI.UTC,
        tsf: TSF = TSF.REAL_TIME,
        integer_ts: int = 0,
        fractional_ts: int = 0,
    ) -> Self:
        self.tsi = tsi
        self.tsf = tsf
        self.integer_timestamp = integer_ts
        self.fractional_timestamp = fractional_ts
        return self

    def with_trailer(self, raw: int = 0) -> Self:
        self.trailer_present = True
        self.trailer = Trailer(raw=raw)
        return self

    def with_payload(self, data: bytes) -> Self:
        self.payload = data
        return self

    def with_packet_count(self, count: int) -> Self:
        self.packet_count = count & 0xF
        return self

    def with_packet_size_override(self, size: int) -> Self:
        """Override computed packet size — useful for size-mismatch fuzzing."""
        self.packet_size_override = size
        return self

    def with_raw_header(self, header_word: int) -> Self:
        """Inject a completely raw 32-bit header word (bypasses all field logic)."""
        self.raw_header_override = header_word
        return self

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------
    def _has_stream_id(self) -> bool:
        return self.packet_type.has_stream_id()

    def compute_packet_size_words(self) -> int:
        """Compute the correct Packet Size in 32-bit words."""
        words = MIN_HEADER_WORDS  # header word

        if self._has_stream_id():
            words += 1  # Stream ID

        if self.class_id_present:
            words += CLASS_ID_SIZE_WORDS

        if self.tsi != TSI.NONE:
            words += 1  # Integer Timestamp

        if self.tsf != TSF.NONE:
            words += 2  # Fractional Timestamp (64-bit)

        # Payload: pad to 32-bit boundary
        payload_words = (len(self.payload) + 3) // 4
        words += payload_words

        if self.trailer_present:
            words += TRAILER_SIZE_WORDS

        return words

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def build_header_word(self) -> int:
        """Construct the 32-bit header word from individual fields."""
        if self.raw_header_override is not None:
            return self.raw_header_override & 0xFFFFFFFF

        pkt_size = (
            self.packet_size_override
            if self.packet_size_override is not None
            else self.compute_packet_size_words()
        )
        pkt_size = pkt_size & HDR_PACKET_SIZE_MASK

        header = 0
        header |= (self.packet_type & 0xF) << HDR_PACKET_TYPE_SHIFT
        if self.class_id_present:
            header |= HDR_CLASS_ID_BIT
        if self.trailer_present:
            header |= HDR_TRAILER_BIT
        header |= (self.tsi & 0x3) << HDR_TSI_SHIFT
        header |= (self.tsf & 0x3) << HDR_TSF_SHIFT
        header |= (self.packet_count & 0xF) << HDR_PACKET_COUNT_SHIFT
        header |= pkt_size

        return header

    def pack(self) -> bytes:
        """Serialize the complete packet to bytes (big-endian)."""
        parts: list[bytes] = []

        # Header word
        parts.append(struct.pack("!I", self.build_header_word()))

        # Stream ID
        if self._has_stream_id():
            parts.append(struct.pack("!I", self.stream_id & 0xFFFFFFFF))

        # Class ID
        if self.class_id_present:
            parts.append(self.class_id.pack())

        # Integer Timestamp
        if self.tsi != TSI.NONE:
            parts.append(struct.pack("!I", self.integer_timestamp & 0xFFFFFFFF))

        # Fractional Timestamp (64 bits)
        if self.tsf != TSF.NONE:
            parts.append(struct.pack("!Q", self.fractional_timestamp & 0xFFFFFFFFFFFFFFFF))

        # Payload (pad to 32-bit boundary)
        parts.append(self.payload)
        pad_len = (4 - len(self.payload) % 4) % 4
        if pad_len:
            parts.append(b"\x00" * pad_len)

        # Trailer
        if self.trailer_present:
            parts.append(self.trailer.pack())

        return b"".join(parts)

    # ------------------------------------------------------------------
    # Deserialization
    # ------------------------------------------------------------------
    @classmethod
    def unpack(cls, data: bytes) -> VRTPacket:
        """Deserialize a VITA 49 packet from raw bytes."""
        if len(data) < 4:
            raise ValueError(f"Packet too short: {len(data)} bytes (minimum 4)")

        offset = 0
        (header_word,) = struct.unpack("!I", data[offset : offset + 4])
        offset += 4

        pkt_type = PacketType((header_word >> HDR_PACKET_TYPE_SHIFT) & 0xF)
        class_id_present = bool(header_word & HDR_CLASS_ID_BIT)
        trailer_present = bool(header_word & HDR_TRAILER_BIT)
        tsi_val = TSI((header_word >> HDR_TSI_SHIFT) & 0x3)
        tsf_val = TSF((header_word >> HDR_TSF_SHIFT) & 0x3)
        pkt_count = (header_word & HDR_PACKET_COUNT_MASK) >> HDR_PACKET_COUNT_SHIFT
        pkt_size = header_word & HDR_PACKET_SIZE_MASK

        pkt = cls(
            packet_type=pkt_type,
            class_id_present=class_id_present,
            trailer_present=trailer_present,
            tsi=tsi_val,
            tsf=tsf_val,
            packet_count=pkt_count,
        )

        # Stream ID
        if pkt._has_stream_id():
            if offset + 4 > len(data):
                raise ValueError("Truncated packet: missing Stream ID")
            (pkt.stream_id,) = struct.unpack("!I", data[offset : offset + 4])
            offset += 4

        # Class ID
        if class_id_present:
            if offset + 8 > len(data):
                raise ValueError("Truncated packet: missing Class ID")
            pkt.class_id = ClassID.unpack(data[offset : offset + 8])
            offset += 8

        # Integer Timestamp
        if tsi_val != TSI.NONE:
            if offset + 4 > len(data):
                raise ValueError("Truncated packet: missing Integer Timestamp")
            (pkt.integer_timestamp,) = struct.unpack("!I", data[offset : offset + 4])
            offset += 4

        # Fractional Timestamp
        if tsf_val != TSF.NONE:
            if offset + 8 > len(data):
                raise ValueError("Truncated packet: missing Fractional Timestamp")
            (pkt.fractional_timestamp,) = struct.unpack("!Q", data[offset : offset + 8])
            offset += 8

        # Payload and Trailer
        # Total packet bytes = pkt_size * 4
        total_bytes = pkt_size * 4
        trailer_bytes = 4 if trailer_present else 0
        payload_end = min(len(data), total_bytes) - trailer_bytes
        if payload_end < offset:
            payload_end = offset  # degenerate case
        pkt.payload = data[offset:payload_end]

        if trailer_present:
            trailer_offset = payload_end
            if trailer_offset + 4 <= len(data):
                pkt.trailer = Trailer.unpack(data[trailer_offset : trailer_offset + 4])

        return pkt

    def __repr__(self) -> str:
        size = self.compute_packet_size_words()
        parts = [
            f"VRTPacket(type={self.packet_type.name}",
            f"stream_id=0x{self.stream_id:08X}",
            f"count={self.packet_count}",
            f"size={size}w/{size * 4}B",
        ]
        if self.class_id_present:
            parts.append(f"class_id=OUI:0x{self.class_id.oui:06X}")
        if self.tsi != TSI.NONE:
            parts.append(f"tsi={self.tsi.name}:{self.integer_timestamp}")
        if self.tsf != TSF.NONE:
            parts.append(f"tsf={self.tsf.name}:{self.fractional_timestamp}")
        if self.trailer_present:
            parts.append(f"trailer=0x{self.trailer.raw:08X}")
        parts.append(f"payload={len(self.payload)}B")
        return ", ".join(parts) + ")"


# ---------------------------------------------------------------------------
# Convenience factory functions
# ---------------------------------------------------------------------------

def make_if_data(
    stream_id: int = 0x0001,
    payload: bytes = b"",
    packet_count: int = 0,
    tsi: TSI = TSI.NONE,
    tsf: TSF = TSF.NONE,
    integer_ts: int = 0,
    fractional_ts: int = 0,
) -> VRTPacket:
    """Create a standard IF Data packet with Stream ID."""
    pkt = VRTPacket(
        packet_type=PacketType.IF_DATA_WITH_STREAM_ID,
        stream_id=stream_id,
        packet_count=packet_count,
        tsi=tsi,
        tsf=tsf,
        integer_timestamp=integer_ts,
        fractional_timestamp=fractional_ts,
        payload=payload,
    )
    return pkt


def make_if_context(
    stream_id: int = 0x0001,
    context_indicator_field: int = 0,
    context_fields: bytes = b"",
    packet_count: int = 0,
    tsi: TSI = TSI.UTC,
    integer_ts: int = 0,
) -> VRTPacket:
    """Create an IF Context packet.

    The payload should contain the Context Indicator Field (CIF) followed
    by the context field values indicated by the set bits.
    """
    # Pack CIF + remaining context fields as the "payload"
    cif_bytes = struct.pack("!I", context_indicator_field)
    pkt = VRTPacket(
        packet_type=PacketType.IF_CONTEXT,
        stream_id=stream_id,
        packet_count=packet_count,
        tsi=tsi,
        integer_timestamp=integer_ts,
        payload=cif_bytes + context_fields,
    )
    return pkt


def make_ext_data(
    stream_id: int = 0x0001,
    payload: bytes = b"",
    packet_count: int = 0,
) -> VRTPacket:
    """Create an Extension Data packet with Stream ID."""
    return VRTPacket(
        packet_type=PacketType.EXT_DATA_WITH_STREAM_ID,
        stream_id=stream_id,
        packet_count=packet_count,
        payload=payload,
    )
