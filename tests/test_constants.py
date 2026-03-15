"""Tests for vita49_redteam.core.constants — enum sanity checks."""

from vita49_redteam.core.constants import (
    ContextIndicator,
    OUI,
    PacketType,
    TSF,
    TSI,
    TrailerBits,
    HDR_PACKET_TYPE_SHIFT,
    HDR_CLASS_ID_BIT,
    HDR_TRAILER_BIT,
)


class TestPacketType:
    def test_values(self):
        assert PacketType.IF_DATA_WITHOUT_STREAM_ID == 0
        assert PacketType.IF_DATA_WITH_STREAM_ID == 1
        assert PacketType.IF_CONTEXT == 4
        assert PacketType.COMMAND == 6

    def test_has_stream_id(self):
        assert not PacketType.IF_DATA_WITHOUT_STREAM_ID.has_stream_id()
        assert PacketType.IF_DATA_WITH_STREAM_ID.has_stream_id()
        assert not PacketType.EXT_DATA_WITHOUT_STREAM_ID.has_stream_id()
        assert PacketType.EXT_DATA_WITH_STREAM_ID.has_stream_id()
        assert PacketType.IF_CONTEXT.has_stream_id()

    def test_is_data(self):
        assert PacketType.IF_DATA_WITH_STREAM_ID.is_data()
        assert not PacketType.IF_CONTEXT.is_data()

    def test_is_context(self):
        assert PacketType.IF_CONTEXT.is_context()
        assert PacketType.EXT_CONTEXT.is_context()
        assert not PacketType.IF_DATA_WITH_STREAM_ID.is_context()


class TestTSI:
    def test_values(self):
        assert TSI.NONE == 0
        assert TSI.UTC == 1
        assert TSI.GPS == 2
        assert TSI.OTHER == 3


class TestTSF:
    def test_values(self):
        assert TSF.NONE == 0
        assert TSF.SAMPLE_COUNT == 1
        assert TSF.REAL_TIME == 2
        assert TSF.FREE_RUNNING == 3


class TestOUI:
    def test_vita_oui(self):
        assert OUI.VITA == 0x0012A2


class TestHeaderConstants:
    def test_packet_type_shift(self):
        assert HDR_PACKET_TYPE_SHIFT == 28

    def test_class_id_bit(self):
        assert HDR_CLASS_ID_BIT == (1 << 27)

    def test_trailer_bit(self):
        assert HDR_TRAILER_BIT == (1 << 26)
