"""Tests for VRT-203: Trailer Field Fuzzer."""

import struct

import pytest

from vita49_redteam.fuzz.trailer_fuzzer import TrailerFuzzConfig, TrailerFuzzer
from vita49_redteam.core.constants import HDR_TRAILER_BIT


class TestTrailerFuzzer:
    def test_generates_cases(self):
        fuzzer = TrailerFuzzer()
        cases = list(fuzzer.generate())
        assert len(cases) > 50

    def test_all_packets_have_trailer_bit(self):
        fuzzer = TrailerFuzzer()
        for desc, pkt in fuzzer.generate():
            assert pkt.trailer_present is True
            raw = pkt.pack()
            header = struct.unpack("!I", raw[:4])[0]
            assert header & HDR_TRAILER_BIT, f"T bit not set for: {desc}"

    def test_individual_bits(self):
        cfg = TrailerFuzzConfig(
            fuzz_individual_bits=True,
            fuzz_enable_indicator_mismatch=False,
            fuzz_all_bits_set=False,
            fuzz_walking_ones=False,
            fuzz_random=False,
            fuzz_context_count=False,
        )
        fuzzer = TrailerFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) == 25  # 25 named trailer bits

    def test_enable_indicator_mismatch(self):
        cfg = TrailerFuzzConfig(
            fuzz_individual_bits=False,
            fuzz_enable_indicator_mismatch=True,
            fuzz_all_bits_set=False,
            fuzz_walking_ones=False,
            fuzz_random=False,
            fuzz_context_count=False,
        )
        fuzzer = TrailerFuzzer(cfg)
        cases = list(fuzzer.generate())
        # 8 pairs × 2 (enable-only + indicator-only) = 16
        assert len(cases) == 16

    def test_walking_ones(self):
        cfg = TrailerFuzzConfig(
            fuzz_individual_bits=False,
            fuzz_enable_indicator_mismatch=False,
            fuzz_all_bits_set=False,
            fuzz_walking_ones=True,
            fuzz_random=False,
            fuzz_context_count=False,
        )
        fuzzer = TrailerFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) == 32

    def test_context_count_values(self):
        cfg = TrailerFuzzConfig(
            fuzz_individual_bits=False,
            fuzz_enable_indicator_mismatch=False,
            fuzz_all_bits_set=False,
            fuzz_walking_ones=False,
            fuzz_random=False,
            fuzz_context_count=True,
        )
        fuzzer = TrailerFuzzer(cfg)
        cases = list(fuzzer.generate())
        # 5 count values × 2 (with/without E bit) = 10
        assert len(cases) == 10

    def test_seed_reproducibility(self):
        cfg1 = TrailerFuzzConfig(seed=99, fuzz_individual_bits=False, fuzz_enable_indicator_mismatch=False,
                                  fuzz_all_bits_set=False, fuzz_walking_ones=False, fuzz_context_count=False)
        cfg2 = TrailerFuzzConfig(seed=99, fuzz_individual_bits=False, fuzz_enable_indicator_mismatch=False,
                                  fuzz_all_bits_set=False, fuzz_walking_ones=False, fuzz_context_count=False)
        c1 = [pkt.trailer.raw for _, pkt in TrailerFuzzer(cfg1).generate()]
        c2 = [pkt.trailer.raw for _, pkt in TrailerFuzzer(cfg2).generate()]
        assert c1 == c2

    def test_all_bits_set_cases(self):
        cfg = TrailerFuzzConfig(
            fuzz_individual_bits=False,
            fuzz_enable_indicator_mismatch=False,
            fuzz_all_bits_set=True,
            fuzz_walking_ones=False,
            fuzz_random=False,
            fuzz_context_count=False,
        )
        fuzzer = TrailerFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) == 4
        # First should be all-1s
        assert cases[0][1].trailer.raw == 0xFFFFFFFF

    def test_generate_count(self):
        fuzzer = TrailerFuzzer()
        cases = fuzzer.generate_count(3)
        assert len(cases) == 3

    def test_packets_serialize(self):
        fuzzer = TrailerFuzzer()
        for desc, pkt in fuzzer.generate():
            raw = pkt.pack()
            assert isinstance(raw, bytes)
            assert len(raw) >= 8  # header + at minimum some data
