"""Tests for VRT-202: Payload Size Mismatch Fuzzer."""

import struct

import pytest

from vita49_redteam.fuzz.payload_fuzzer import PayloadMismatchConfig, PayloadSizeFuzzer


class TestPayloadSizeFuzzer:
    def test_generates_cases(self):
        fuzzer = PayloadSizeFuzzer()
        cases = list(fuzzer.generate())
        assert len(cases) > 20

    def test_all_cases_are_bytes(self):
        fuzzer = PayloadSizeFuzzer()
        for desc, raw in fuzzer.generate():
            assert isinstance(desc, str)
            assert isinstance(raw, bytes)

    def test_undersized_declared_bigger(self):
        cfg = PayloadMismatchConfig(
            include_undersized=True,
            include_oversized=False,
            include_zero_length=False,
            include_off_by_one=False,
            include_extreme=False,
        )
        fuzzer = PayloadSizeFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) > 0
        for desc, raw in cases:
            assert "undersized:" in desc
            # Parse header word to see declared size
            header_word = struct.unpack("!I", raw[:4])[0]
            declared_size = header_word & 0xFFFF
            actual_words = len(raw) // 4
            assert declared_size > actual_words

    def test_oversized_declared_smaller(self):
        cfg = PayloadMismatchConfig(
            include_undersized=False,
            include_oversized=True,
            include_zero_length=False,
            include_off_by_one=False,
            include_extreme=False,
        )
        fuzzer = PayloadSizeFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) > 0
        for desc, raw in cases:
            assert "oversized:" in desc

    def test_zero_length_variations(self):
        cfg = PayloadMismatchConfig(
            include_undersized=False,
            include_oversized=False,
            include_zero_length=True,
            include_off_by_one=False,
            include_extreme=False,
        )
        fuzzer = PayloadSizeFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) == 4

    def test_off_by_one(self):
        cfg = PayloadMismatchConfig(
            include_undersized=False,
            include_oversized=False,
            include_zero_length=False,
            include_off_by_one=True,
            include_extreme=False,
        )
        fuzzer = PayloadSizeFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) == 5  # size-1, size+1, +1byte, +2bytes, +3bytes

    def test_extreme_cases(self):
        cfg = PayloadMismatchConfig(
            include_undersized=False,
            include_oversized=False,
            include_zero_length=False,
            include_off_by_one=False,
            include_extreme=True,
        )
        fuzzer = PayloadSizeFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) == 4

    def test_generate_count(self):
        fuzzer = PayloadSizeFuzzer()
        cases = fuzzer.generate_count(5)
        assert len(cases) == 5

    def test_custom_payload_size(self):
        cfg = PayloadMismatchConfig(base_payload_size=512)
        fuzzer = PayloadSizeFuzzer(cfg)
        cases = list(fuzzer.generate())
        assert len(cases) > 0
