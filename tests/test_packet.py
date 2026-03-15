"""Tests for vita49_redteam.core.packet — round-trip encode/decode and builder."""

import struct

import pytest

from vita49_redteam.core.constants import PacketType, TSI, TSF, OUI
from vita49_redteam.core.packet import (
    ClassID,
    Trailer,
    VRTPacket,
    make_if_data,
    make_if_context,
    make_ext_data,
)


# ======================================================================
# ClassID
# ======================================================================

class TestClassID:
    def test_round_trip(self):
        cid = ClassID(oui=OUI.VITA, information_class_code=0x1234, packet_class_code=0x5678)
        data = cid.pack()
        assert len(data) == 8
        cid2 = ClassID.unpack(data)
        assert cid2.oui == OUI.VITA
        assert cid2.information_class_code == 0x1234
        assert cid2.packet_class_code == 0x5678

    def test_null_oui(self):
        cid = ClassID(oui=0)
        data = cid.pack()
        cid2 = ClassID.unpack(data)
        assert cid2.oui == 0


# ======================================================================
# Trailer
# ======================================================================

class TestTrailer:
    def test_round_trip(self):
        t = Trailer(raw=0xC0040000)
        data = t.pack()
        assert len(data) == 4
        t2 = Trailer.unpack(data)
        assert t2.raw == 0xC0040000

    def test_valid_data_flags(self):
        # valid_data_enable | valid_data
        t = Trailer(raw=(1 << 30) | (1 << 18))
        assert t.valid_data_enable
        assert t.valid_data


# ======================================================================
# VRTPacket — minimal packets
# ======================================================================

class TestVRTPacketMinimal:
    def test_default_if_data_with_stream_id(self):
        pkt = VRTPacket()
        data = pkt.pack()
        # Header (4) + Stream ID (4) = 8 bytes = 2 words
        assert len(data) == 8
        assert pkt.compute_packet_size_words() == 2

    def test_if_data_without_stream_id(self):
        pkt = VRTPacket(packet_type=PacketType.IF_DATA_WITHOUT_STREAM_ID)
        data = pkt.pack()
        assert len(data) == 4  # Header only
        assert pkt.compute_packet_size_words() == 1

    def test_header_word_packet_type(self):
        pkt = VRTPacket(packet_type=PacketType.IF_CONTEXT)
        word = pkt.build_header_word()
        pkt_type_field = (word >> 28) & 0xF
        assert pkt_type_field == PacketType.IF_CONTEXT


# ======================================================================
# VRTPacket — round-trip encode/decode
# ======================================================================

class TestVRTPacketRoundTrip:
    def test_if_data_empty_payload(self):
        original = make_if_data(stream_id=0xDEADBEEF)
        data = original.pack()
        decoded = VRTPacket.unpack(data)
        assert decoded.packet_type == PacketType.IF_DATA_WITH_STREAM_ID
        assert decoded.stream_id == 0xDEADBEEF
        assert decoded.payload == b""

    def test_if_data_with_payload(self):
        payload = b"\x01\x02\x03\x04" * 64  # 256 bytes
        original = make_if_data(stream_id=0x0042, payload=payload)
        data = original.pack()
        decoded = VRTPacket.unpack(data)
        assert decoded.stream_id == 0x0042
        assert decoded.payload == payload

    def test_if_data_unaligned_payload(self):
        """Payload not aligned to 4 bytes — should be padded on pack."""
        payload = b"\xAA\xBB\xCC"  # 3 bytes
        original = make_if_data(payload=payload)
        data = original.pack()
        # Should be padded to 4 bytes in the wire format
        assert len(data) % 4 == 0
        decoded = VRTPacket.unpack(data)
        # Decoded payload includes padding bytes
        assert decoded.payload[:3] == payload

    def test_if_data_with_timestamps(self):
        original = make_if_data(
            stream_id=0x0001,
            tsi=TSI.UTC,
            tsf=TSF.REAL_TIME,
            integer_ts=1700000000,
            fractional_ts=123456789012,
        )
        data = original.pack()
        decoded = VRTPacket.unpack(data)
        assert decoded.tsi == TSI.UTC
        assert decoded.tsf == TSF.REAL_TIME
        assert decoded.integer_timestamp == 1700000000
        assert decoded.fractional_timestamp == 123456789012

    def test_if_context_round_trip(self):
        cif = 0x28000000  # RF_REF_FREQUENCY + BANDWIDTH
        context_fields = struct.pack("!qq", 1_000_000_000, 20_000_000)  # 64-bit fixed-point
        original = make_if_context(
            stream_id=0x0010,
            context_indicator_field=cif,
            context_fields=context_fields,
            tsi=TSI.UTC,
            integer_ts=1700000000,
        )
        data = original.pack()
        decoded = VRTPacket.unpack(data)
        assert decoded.packet_type == PacketType.IF_CONTEXT
        assert decoded.stream_id == 0x0010
        assert decoded.tsi == TSI.UTC

    def test_ext_data_round_trip(self):
        original = make_ext_data(stream_id=0xFF00, payload=b"\xDE\xAD" * 10)
        data = original.pack()
        decoded = VRTPacket.unpack(data)
        assert decoded.packet_type == PacketType.EXT_DATA_WITH_STREAM_ID
        assert decoded.stream_id == 0xFF00

    def test_packet_with_class_id(self):
        pkt = VRTPacket()
        pkt.with_class_id(oui=0x0012A2, info_class=0xABCD, pkt_class=0x1234)
        data = pkt.pack()
        decoded = VRTPacket.unpack(data)
        assert decoded.class_id_present
        assert decoded.class_id.oui == 0x0012A2
        assert decoded.class_id.information_class_code == 0xABCD
        assert decoded.class_id.packet_class_code == 0x1234

    def test_packet_with_trailer(self):
        pkt = VRTPacket()
        pkt.with_trailer(raw=0xC0040000)
        data = pkt.pack()
        decoded = VRTPacket.unpack(data)
        assert decoded.trailer_present
        assert decoded.trailer.raw == 0xC0040000

    def test_full_packet_all_fields(self):
        """A packet with every optional field present."""
        pkt = VRTPacket(
            packet_type=PacketType.IF_DATA_WITH_STREAM_ID,
            stream_id=0xCAFEBABE,
            tsi=TSI.GPS,
            tsf=TSF.SAMPLE_COUNT,
            integer_timestamp=999999,
            fractional_timestamp=555555,
            packet_count=7,
            payload=b"\x00" * 128,
        )
        pkt.with_class_id(oui=0xABCDEF, info_class=0x1111, pkt_class=0x2222)
        pkt.with_trailer(raw=0xFFFFFFFF)

        data = pkt.pack()
        decoded = VRTPacket.unpack(data)
        assert decoded.stream_id == 0xCAFEBABE
        assert decoded.tsi == TSI.GPS
        assert decoded.tsf == TSF.SAMPLE_COUNT
        assert decoded.integer_timestamp == 999999
        assert decoded.fractional_timestamp == 555555
        assert decoded.packet_count == 7
        assert decoded.class_id_present
        assert decoded.class_id.oui == 0xABCDEF
        assert decoded.trailer_present


# ======================================================================
# VRTPacket — builder pattern
# ======================================================================

class TestVRTPacketBuilder:
    def test_chaining(self):
        pkt = (
            VRTPacket()
            .with_packet_type(PacketType.EXT_DATA_WITH_STREAM_ID)
            .with_stream_id(0x1234)
            .with_payload(b"\xAA" * 32)
            .with_packet_count(5)
        )
        assert pkt.packet_type == PacketType.EXT_DATA_WITH_STREAM_ID
        assert pkt.stream_id == 0x1234
        assert pkt.packet_count == 5

    def test_raw_header_override(self):
        pkt = VRTPacket().with_raw_header(0xDEADBEEF)
        word = pkt.build_header_word()
        assert word == 0xDEADBEEF

    def test_packet_size_override(self):
        pkt = VRTPacket().with_packet_size_override(9999)
        word = pkt.build_header_word()
        size_field = word & 0xFFFF
        assert size_field == 9999


# ======================================================================
# VRTPacket — error cases
# ======================================================================

class TestVRTPacketErrors:
    def test_unpack_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            VRTPacket.unpack(b"\x00\x00")

    def test_unpack_truncated_stream_id(self):
        # IF Data with Stream ID (type=1) but only 4 bytes (no stream id)
        header = (1 << 28) | 2  # type=1, size=2 words
        data = struct.pack("!I", header)
        with pytest.raises(ValueError, match="Stream ID"):
            VRTPacket.unpack(data)

    def test_repr(self):
        pkt = make_if_data(stream_id=0xBEEF, payload=b"\x00" * 16)
        r = repr(pkt)
        assert "VRTPacket" in r
        assert "0000BEEF" in r
