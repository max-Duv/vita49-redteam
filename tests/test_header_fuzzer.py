"""Tests for VRT-201: Header Field Fuzzer."""

import pytest

from vita49_redteam.fuzz.header_fuzzer import (
    FuzzStrategy,
    HeaderFuzzConfig,
    HeaderFuzzer,
    PACKET_TYPE_BOUNDARIES,
    STREAM_ID_BOUNDARIES,
    _bit_flips_32,
)
from vita49_redteam.core.constants import PacketType


class TestBitFlips:
    def test_bit_flips_32_count(self):
        flips = _bit_flips_32(0)
        assert len(flips) == 32

    def test_bit_flips_32_single_bit_diff(self):
        base = 0x12345678
        for flipped in _bit_flips_32(base):
            diff = base ^ flipped
            assert diff.bit_count() == 1


class TestHeaderFuzzer:
    def test_boundary_generates_cases(self):
        cfg = HeaderFuzzConfig(strategies=[FuzzStrategy.BOUNDARY])
        fuzzer = HeaderFuzzer(cfg)
        cases = list(fuzzer.generate())
        # At minimum: packet_type + tsi + tsf + packet_count + packet_size + stream_id + class_id
        assert len(cases) >= 20
        for desc, pkt in cases:
            assert isinstance(desc, str)
            assert "boundary:" in desc

    def test_bit_flip_generates_cases(self):
        cfg = HeaderFuzzConfig(strategies=[FuzzStrategy.BIT_FLIP])
        fuzzer = HeaderFuzzer(cfg)
        cases = list(fuzzer.generate())
        # 32 header bit flips + 32 stream_id bit flips = 64
        assert len(cases) == 64
        for desc, pkt in cases:
            assert "bitflip:" in desc

    def test_type_confusion_generates_cases(self):
        cfg = HeaderFuzzConfig(strategies=[FuzzStrategy.TYPE_CONFUSION])
        fuzzer = HeaderFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) >= 10
        for desc, pkt in cases:
            assert "type_confusion:" in desc

    def test_random_generates_cases(self):
        cfg = HeaderFuzzConfig(strategies=[FuzzStrategy.RANDOM])
        fuzzer = HeaderFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) == 70  # 50 random + 20 fully random
        for desc, pkt in cases:
            assert "random" in desc

    def test_all_strategies(self):
        cfg = HeaderFuzzConfig(strategies=list(FuzzStrategy))
        fuzzer = HeaderFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) > 100

    def test_generate_count_limits(self):
        cfg = HeaderFuzzConfig(strategies=list(FuzzStrategy))
        fuzzer = HeaderFuzzer(cfg)
        cases = fuzzer.generate_count(5)
        assert len(cases) == 5

    def test_seed_reproducibility(self):
        cfg1 = HeaderFuzzConfig(strategies=[FuzzStrategy.RANDOM], seed=42)
        cfg2 = HeaderFuzzConfig(strategies=[FuzzStrategy.RANDOM], seed=42)
        c1 = [pkt.build_header_word() for _, pkt in HeaderFuzzer(cfg1).generate()]
        c2 = [pkt.build_header_word() for _, pkt in HeaderFuzzer(cfg2).generate()]
        assert c1 == c2

    def test_packets_serialize(self):
        fuzzer = HeaderFuzzer(HeaderFuzzConfig(strategies=list(FuzzStrategy)))
        for desc, pkt in fuzzer.generate():
            raw = pkt.pack()
            assert isinstance(raw, bytes)
            assert len(raw) >= 4  # at least a header word

    def test_selective_field_fuzzing(self):
        cfg = HeaderFuzzConfig(
            strategies=[FuzzStrategy.BOUNDARY],
            fuzz_packet_type=True,
            fuzz_tsi=False,
            fuzz_tsf=False,
            fuzz_packet_count=False,
            fuzz_packet_size=False,
            fuzz_stream_id=False,
            fuzz_class_id=False,
        )
        fuzzer = HeaderFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert all("packet_type" in desc for desc, _ in cases)
