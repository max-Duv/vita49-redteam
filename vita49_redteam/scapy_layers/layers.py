"""Scapy custom layers for VITA 49 (VRT) packet crafting, dissection, and sniffing.

Layers:
    VRT_Header  — Base VITA 49 header (always present). Bound to UDP dport 4991.
    VRT_Trailer — Optional trailer for data packets (when T bit is set).

Usage:
    from scapy.all import IP, UDP, send, sniff
    from vita49_redteam.scapy_layers.layers import VRT_Header

    # Craft an IF Data packet with Stream ID
    pkt = IP(dst="192.168.1.100") / UDP(dport=4991) / VRT_Header(
        pkt_type=1,      # IF Data with Stream ID
        stream_id=0x0001,
        payload=bytes(1024),
    )
    send(pkt)

    # Sniff VRT traffic
    sniff(filter="udp port 4991", prn=lambda p: p[VRT_Header].show())
"""

from __future__ import annotations

import struct

from scapy.fields import (
    BitEnumField,
    BitField,
    ConditionalField,
    IntField,
    LongField,
    PacketField,
    StrLenField,
    XIntField,
    XShortField,
)
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers

from vita49_redteam.core.constants import VRT_DEFAULT_PORT

# ---------------------------------------------------------------------------
# Packet Type enumeration for Scapy display
# ---------------------------------------------------------------------------
_PKT_TYPE_NAMES = {
    0: "IF_Data",
    1: "IF_Data+SID",
    2: "Ext_Data",
    3: "Ext_Data+SID",
    4: "IF_Context",
    5: "Ext_Context",
    6: "Command",
    7: "Cmd_Response",
}

_TSI_NAMES = {0: "None", 1: "UTC", 2: "GPS", 3: "Other"}
_TSF_NAMES = {0: "None", 1: "SampleCount", 2: "RealTime", 3: "FreeRunning"}


def _has_stream_id(pkt: Packet) -> bool:
    """Return True if this packet type carries a Stream ID."""
    return pkt.pkt_type in (1, 3, 4, 5, 6, 7)


def _has_class_id(pkt: Packet) -> bool:
    return pkt.class_id_present == 1


def _has_integer_ts(pkt: Packet) -> bool:
    return pkt.tsi != 0


def _has_fractional_ts(pkt: Packet) -> bool:
    return pkt.tsf != 0


def _vrt_data_len(pkt: Packet) -> int:
    """Compute VRT data length in bytes from packet_size and known header fields."""
    total_bytes = pkt.packet_size * 4
    header_bytes = 4  # header word

    if _has_stream_id(pkt):
        header_bytes += 4
    if _has_class_id(pkt):
        header_bytes += 8
    if _has_integer_ts(pkt):
        header_bytes += 4
    if _has_fractional_ts(pkt):
        header_bytes += 8
    if pkt.trailer_present:
        header_bytes += 4  # trailer word at end

    data_bytes = total_bytes - header_bytes
    return max(data_bytes, 0)


# ---------------------------------------------------------------------------
# VRT Trailer Layer
# ---------------------------------------------------------------------------
class VRT_Trailer(Packet):
    """VITA 49 Trailer word (32 bits)."""

    name = "VRT Trailer"
    fields_desc = [
        BitField("calibrated_time_en", 0, 1),
        BitField("valid_data_en", 0, 1),
        BitField("reference_lock_en", 0, 1),
        BitField("agc_mgc_en", 0, 1),
        BitField("detected_signal_en", 0, 1),
        BitField("spectral_inversion_en", 0, 1),
        BitField("over_range_en", 0, 1),
        BitField("sample_loss_en", 0, 1),
        BitField("user_def_11_en", 0, 1),
        BitField("user_def_10_en", 0, 1),
        BitField("user_def_9_en", 0, 1),
        BitField("user_def_8_en", 0, 1),
        BitField("calibrated_time", 0, 1),
        BitField("valid_data", 0, 1),
        BitField("reference_lock", 0, 1),
        BitField("agc_mgc", 0, 1),
        BitField("detected_signal", 0, 1),
        BitField("spectral_inversion", 0, 1),
        BitField("over_range", 0, 1),
        BitField("sample_loss", 0, 1),
        BitField("user_def_11", 0, 1),
        BitField("user_def_10", 0, 1),
        BitField("user_def_9", 0, 1),
        BitField("user_def_8", 0, 1),
        BitField("assoc_context_pkt_count_en", 0, 1),
        BitField("assoc_context_pkt_count", 0, 7),
    ]


# ---------------------------------------------------------------------------
# VRT Header Layer
# ---------------------------------------------------------------------------
class VRT_Header(Packet):
    """VITA 49 packet header and variable-length fields.

    Handles both data and context packet types. Automatically computes
    ``packet_size`` from the content on build if left at the default (0).
    """

    name = "VRT Header"
    fields_desc = [
        # --- Header word (32 bits) ---
        BitEnumField("pkt_type", 1, 4, _PKT_TYPE_NAMES),
        BitField("class_id_present", 0, 1),
        BitField("trailer_present", 0, 1),
        BitEnumField("tsi", 0, 2, _TSI_NAMES),
        BitEnumField("tsf", 0, 2, _TSF_NAMES),
        BitField("reserved", 0, 2),
        BitField("packet_count", 0, 4),
        BitField("packet_size", 0, 16),
        # --- Conditional fields ---
        ConditionalField(XIntField("stream_id", 0x00000001), _has_stream_id),
        ConditionalField(
            XIntField("class_id_oui", 0x0012A200), _has_class_id
        ),  # pad + OUI
        ConditionalField(
            XShortField("info_class_code", 0x0000), _has_class_id
        ),
        ConditionalField(
            XShortField("pkt_class_code", 0x0000), _has_class_id
        ),
        ConditionalField(IntField("integer_timestamp", 0), _has_integer_ts),
        ConditionalField(LongField("fractional_timestamp", 0), _has_fractional_ts),
        # --- VRT Data (payload) ---
        StrLenField("vrt_data", b"", length_from=_vrt_data_len),
        # --- Trailer ---
        ConditionalField(
            PacketField("trailer", VRT_Trailer(), VRT_Trailer),
            lambda pkt: pkt.trailer_present == 1,
        ),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        """Auto-compute packet_size if left at 0."""
        total = pkt + pay
        if self.packet_size == 0:
            size_words = len(total) // 4
            # Replace bytes 2-3 (packet_size field) in header word
            header_word = struct.unpack("!I", total[:4])[0]
            header_word = (header_word & 0xFFFF0000) | (size_words & 0xFFFF)
            total = struct.pack("!I", header_word) + total[4:]
        return total


# ---------------------------------------------------------------------------
# Bind VRT to UDP on the conventional VRT port
# ---------------------------------------------------------------------------
bind_layers(UDP, VRT_Header, dport=VRT_DEFAULT_PORT)
bind_layers(UDP, VRT_Header, sport=VRT_DEFAULT_PORT)
