"""VITA 49 protocol constants, enumerations, and field definitions.

Covers VITA 49.0 (ANSI/VITA 49.0-2015) and VITA 49.2 (ANSI/VITA 49.2-2017).
"""

from __future__ import annotations

import enum


# ---------------------------------------------------------------------------
# Packet Type (4 bits, Header Word bits 31-28)
# ---------------------------------------------------------------------------
class PacketType(enum.IntEnum):
    """VITA 49 Packet Type codes (Header bits 31-28)."""

    IF_DATA_WITHOUT_STREAM_ID = 0x0
    IF_DATA_WITH_STREAM_ID = 0x1
    EXT_DATA_WITHOUT_STREAM_ID = 0x2
    EXT_DATA_WITH_STREAM_ID = 0x3
    IF_CONTEXT = 0x4
    EXT_CONTEXT = 0x5
    # VITA 49.1 Command packets
    COMMAND = 0x6
    COMMAND_RESPONSE = 0x7

    def has_stream_id(self) -> bool:
        return self in (
            PacketType.IF_DATA_WITH_STREAM_ID,
            PacketType.EXT_DATA_WITH_STREAM_ID,
            PacketType.IF_CONTEXT,
            PacketType.EXT_CONTEXT,
            PacketType.COMMAND,
            PacketType.COMMAND_RESPONSE,
        )

    def is_data(self) -> bool:
        return self.value <= 0x3

    def is_context(self) -> bool:
        return self in (PacketType.IF_CONTEXT, PacketType.EXT_CONTEXT)

    def is_command(self) -> bool:
        return self in (PacketType.COMMAND, PacketType.COMMAND_RESPONSE)


# ---------------------------------------------------------------------------
# Timestamp Integer (TSI) — Header bits 25-24
# ---------------------------------------------------------------------------
class TSI(enum.IntEnum):
    """Timestamp-Integer type (Header bits 25-24)."""

    NONE = 0b00
    UTC = 0b01
    GPS = 0b10
    OTHER = 0b11


# ---------------------------------------------------------------------------
# Timestamp Fractional (TSF) — Header bits 23-22
# ---------------------------------------------------------------------------
class TSF(enum.IntEnum):
    """Timestamp-Fractional type (Header bits 23-22)."""

    NONE = 0b00
    SAMPLE_COUNT = 0b01
    REAL_TIME = 0b10  # picoseconds
    FREE_RUNNING = 0b11


# ---------------------------------------------------------------------------
# Context Indicator Field bit positions (IF Context Packet, Word 1)
# ---------------------------------------------------------------------------
class ContextIndicator(enum.IntFlag):
    """Bit flags for the Context Indicator Field (CIF0) in IF Context packets."""

    CHANGE_INDICATOR = 1 << 31
    REFERENCE_POINT_ID = 1 << 30
    BANDWIDTH = 1 << 29
    IF_REF_FREQUENCY = 1 << 28
    RF_REF_FREQUENCY = 1 << 27
    RF_REF_FREQUENCY_OFFSET = 1 << 26
    IF_BAND_OFFSET = 1 << 25
    REFERENCE_LEVEL = 1 << 24
    GAIN = 1 << 23
    OVER_RANGE_COUNT = 1 << 22
    SAMPLE_RATE = 1 << 21
    TIMESTAMP_ADJUSTMENT = 1 << 20
    TIMESTAMP_CALIBRATION_TIME = 1 << 19
    TEMPERATURE = 1 << 18
    DEVICE_ID = 1 << 17
    STATE_EVENT_INDICATORS = 1 << 16
    DATA_PACKET_PAYLOAD_FORMAT = 1 << 15
    FORMATTED_GPS = 1 << 14
    FORMATTED_INS = 1 << 13
    ECEF_EPHEMERIS = 1 << 12
    RELATIVE_EPHEMERIS = 1 << 11
    EPHEMERIS_REFERENCE_ID = 1 << 10
    GPS_ASCII = 1 << 9
    CONTEXT_ASSOCIATION_LISTS = 1 << 8
    # Bits 7-1 reserved in 49.0; CIF1-CIF7 enable in 49.2
    CIF7_ENABLE = 1 << 7
    CIF3_ENABLE = 1 << 3
    CIF2_ENABLE = 1 << 2
    CIF1_ENABLE = 1 << 1


# ---------------------------------------------------------------------------
# Trailer Indicator bits (Data packets, last word when T=1)
# ---------------------------------------------------------------------------
class TrailerBits(enum.IntFlag):
    """Bit flags for the Trailer word in IF/Ext Data packets."""

    # Enable bits (bits 31-20)
    CALIBRATED_TIME_ENABLE = 1 << 31
    VALID_DATA_ENABLE = 1 << 30
    REFERENCE_LOCK_ENABLE = 1 << 29
    AGC_MGC_ENABLE = 1 << 28
    DETECTED_SIGNAL_ENABLE = 1 << 27
    SPECTRAL_INVERSION_ENABLE = 1 << 26
    OVER_RANGE_ENABLE = 1 << 25
    SAMPLE_LOSS_ENABLE = 1 << 24
    # Bits 23-20: user-defined enable bits
    USER_DEFINED_11_ENABLE = 1 << 23
    USER_DEFINED_10_ENABLE = 1 << 22
    USER_DEFINED_9_ENABLE = 1 << 21
    USER_DEFINED_8_ENABLE = 1 << 20

    # Indicator bits (bits 19-8)
    CALIBRATED_TIME = 1 << 19
    VALID_DATA = 1 << 18
    REFERENCE_LOCK = 1 << 17
    AGC_MGC = 1 << 16
    DETECTED_SIGNAL = 1 << 15
    SPECTRAL_INVERSION = 1 << 14
    OVER_RANGE = 1 << 13
    SAMPLE_LOSS = 1 << 12
    USER_DEFINED_11 = 1 << 11
    USER_DEFINED_10 = 1 << 10
    USER_DEFINED_9 = 1 << 9
    USER_DEFINED_8 = 1 << 8

    # Associated Context Packet Count (bits 7-0 hold the count, not flags)


# ---------------------------------------------------------------------------
# Well-known OUIs for Class ID
# ---------------------------------------------------------------------------
class OUI(enum.IntEnum):
    """Organizationally Unique Identifiers commonly seen in VITA 49 Class IDs."""

    VITA = 0x00_12_A2  # VITA standards body
    IEEE = 0x00_00_5E  # IEEE
    NULL = 0x00_00_00


# ---------------------------------------------------------------------------
# Header field positions and masks
# ---------------------------------------------------------------------------
# Header Word 0 layout (32 bits, big-endian):
#   [31:28] Packet Type  (4 bits)
#   [27]    C — Class ID present
#   [26]    T — Trailer present (data) / Indicators (context)
#   [25:24] TSI
#   [23:22] TSF
#   [21:20] Reserved (49.0) / Spectrum or other (49.2)
#   [19:16] Packet Count (4-bit mod-16 rolling counter)
#   [15:0]  Packet Size  (in 32-bit words, includes header)

HDR_PACKET_TYPE_SHIFT = 28
HDR_PACKET_TYPE_MASK = 0xF << HDR_PACKET_TYPE_SHIFT

HDR_CLASS_ID_BIT = 1 << 27
HDR_TRAILER_BIT = 1 << 26

HDR_TSI_SHIFT = 24
HDR_TSI_MASK = 0x3 << HDR_TSI_SHIFT

HDR_TSF_SHIFT = 22
HDR_TSF_MASK = 0x3 << HDR_TSF_SHIFT

HDR_PACKET_COUNT_SHIFT = 16
HDR_PACKET_COUNT_MASK = 0xF << HDR_PACKET_COUNT_SHIFT

HDR_PACKET_SIZE_MASK = 0xFFFF

# Class ID is 2 words (64 bits):
#   Word 1: [31:8] padding/reserved, [7:0] OUI[23:16]...
#   Actually: Word 1 = 0x00 || OUI (24 bits) || 0x00 (pad)
#   In practice:
#     Word 1 bits [31:8] = 0x00 + OUI (24 bits shifted), bits [7:0] = 0
#     The standard packs it as:
#       Byte 0: 0x00 (pad)
#       Bytes 1-3: OUI (24 bits)
#     Word 2:
#       Bytes 0-1: Information Class Code (16 bits)
#       Bytes 2-3: Packet Class Code (16 bits)

CLASS_ID_SIZE_WORDS = 2  # 8 bytes

# Trailer is always exactly 1 word
TRAILER_SIZE_WORDS = 1

# Minimum header size is 1 word
MIN_HEADER_WORDS = 1

# Maximum packet size is 65535 words (per 16-bit Packet Size field)
MAX_PACKET_SIZE_WORDS = 0xFFFF

# VRT default port (common convention, not standardized)
VRT_DEFAULT_PORT = 4991

# Maximum payload in a single UDP datagram
MAX_UDP_PAYLOAD = 65507
