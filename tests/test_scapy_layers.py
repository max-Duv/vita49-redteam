"""Tests for vita49_redteam.scapy_layers.layers — Scapy VRT layer."""

import struct

import pytest

# Scapy layers must be imported to register
from vita49_redteam.scapy_layers.layers import VRT_Header, VRT_Trailer


class TestVRTHeader:
    def test_build_minimal_if_data(self):
        """Build a minimal IF Data packet with Stream ID."""
        pkt = VRT_Header(pkt_type=1, stream_id=0x0042, vrt_data=b"")
        raw = bytes(pkt)
        assert len(raw) >= 8  # header + stream_id

    def test_packet_type_in_header(self):
        pkt = VRT_Header(pkt_type=4)  # IF Context
        raw = bytes(pkt)
        header_word = struct.unpack("!I", raw[:4])[0]
        pkt_type_field = (header_word >> 28) & 0xF
        assert pkt_type_field == 4

    def test_class_id_conditional(self):
        """Class ID fields should appear when class_id_present=1."""
        pkt = VRT_Header(pkt_type=1, class_id_present=1, stream_id=1)
        raw = bytes(pkt)
        # Header(4) + StreamID(4) + ClassID(8) = 16 min
        assert len(raw) >= 16

    def test_timestamps_conditional(self):
        """Timestamp fields should appear based on TSI/TSF."""
        pkt = VRT_Header(
            pkt_type=1,
            tsi=1,  # UTC
            tsf=2,  # RealTime
            stream_id=1,
            integer_timestamp=1000,
            fractional_timestamp=500,
        )
        raw = bytes(pkt)
        # Header(4) + StreamID(4) + IntTS(4) + FracTS(8) = 20
        assert len(raw) >= 20

    def test_auto_packet_size(self):
        """packet_size should be auto-computed when left at 0."""
        vrt_data = b"\x00" * 64
        pkt = VRT_Header(pkt_type=1, stream_id=1, vrt_data=vrt_data)
        raw = bytes(pkt)
        header_word = struct.unpack("!I", raw[:4])[0]
        pkt_size = header_word & 0xFFFF
        expected_words = len(raw) // 4
        assert pkt_size == expected_words

    def test_payload_round_trip(self):
        """Build and dissect a packet, verify vrt_data is preserved."""
        vrt_data = b"\xDE\xAD\xBE\xEF" * 8
        pkt = VRT_Header(pkt_type=1, stream_id=0xABCD, vrt_data=vrt_data)
        raw = bytes(pkt)

        # Re-dissect
        pkt2 = VRT_Header(raw)
        assert pkt2.pkt_type == 1
        assert pkt2.stream_id == 0xABCD
        assert bytes(pkt2.vrt_data) == vrt_data


class TestVRTTrailer:
    def test_build_trailer(self):
        t = VRT_Trailer(valid_data_en=1, valid_data=1)
        raw = bytes(t)
        assert len(raw) == 4

    def test_trailer_bits(self):
        t = VRT_Trailer(
            calibrated_time_en=1,
            calibrated_time=1,
            sample_loss_en=1,
            sample_loss=1,
        )
        raw = bytes(t)
        word = struct.unpack("!I", raw[:4])[0]
        assert word & (1 << 31)  # calibrated_time_en
        assert word & (1 << 19)  # calibrated_time
        assert word & (1 << 24)  # sample_loss_en
        assert word & (1 << 12)  # sample_loss
