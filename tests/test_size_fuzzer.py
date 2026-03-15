"""Tests for VRT-204: Truncated & Oversized Packet Generator."""

import pytest

from vita49_redteam.fuzz.size_fuzzer import SizeGenConfig, SizeGenerator


class TestSizeGenerator:
    def test_generates_cases(self):
        gen = SizeGenerator()
        cases = list(gen.generate())
        assert len(cases) > 20

    def test_all_cases_are_bytes(self):
        gen = SizeGenerator()
        for desc, raw in gen.generate():
            assert isinstance(desc, str)
            assert isinstance(raw, bytes)

    def test_truncated_includes_zero_length(self):
        gen = SizeGenerator()
        cases = list(gen.generate())
        descs = [d for d, _ in cases]
        assert any("truncated:0_bytes" in d for d in descs)

    def test_truncated_monotonic_sizes(self):
        cfg = SizeGenConfig(truncation_offsets=[0, 4, 8, 12, 16])
        gen = SizeGenerator(cfg)
        cases = list(gen.generate())
        truncated = [(d, r) for d, r in cases if "truncated:" in d and "progressive" not in d]
        sizes = [len(r) for _, r in truncated]
        assert sizes == [0, 4, 8, 12, 16]

    def test_oversized_larger_than_header(self):
        gen = SizeGenerator()
        cases = list(gen.generate())
        for desc, raw in cases:
            if "oversized:" in desc and "oversized_valid:" not in desc:
                assert len(raw) > 8  # at least bigger than header+stream_id

    def test_progressive_truncation(self):
        gen = SizeGenerator()
        cases = list(gen.generate())
        progressive = [(d, r) for d, r in cases if "progressive_trunc:" in d]
        assert len(progressive) >= 2
        # Each should be on a 4-byte (word) boundary
        for desc, raw in progressive:
            assert len(raw) % 4 == 0

    def test_generate_count(self):
        gen = SizeGenerator()
        cases = gen.generate_count(5)
        assert len(cases) == 5

    def test_oversized_valid_large_payload(self):
        gen = SizeGenerator()
        cases = list(gen.generate())
        valid_oversized = [(d, r) for d, r in cases if "oversized_valid:" in d]
        assert len(valid_oversized) >= 1
        for desc, raw in valid_oversized:
            assert len(raw) >= 1000
