"""Tests for VRT-205: Crash & Hang Detection Harness."""

import pytest

from vita49_redteam.fuzz.harness import (
    CrashHarness,
    FuzzModule,
    HarnessConfig,
    HarnessResult,
    TargetStatus,
)


class TestHarnessConfig:
    def test_defaults(self):
        cfg = HarnessConfig()
        assert cfg.target_host == "127.0.0.1"
        assert cfg.probe_interval == 10
        assert cfg.rate_pps == 100
        assert cfg.max_cases == 0
        assert FuzzModule.ALL in cfg.modules

    def test_custom_config(self):
        cfg = HarnessConfig(
            target_host="10.0.0.1",
            target_port=5000,
            modules=[FuzzModule.HEADER],
            max_cases=50,
            rate_pps=500,
            seed=42,
        )
        assert cfg.target_host == "10.0.0.1"
        assert cfg.target_port == 5000
        assert cfg.max_cases == 50


class TestHarnessResult:
    def test_empty_result(self):
        r = HarnessResult()
        assert r.total_cases_sent == 0
        assert r.failures_detected == 0
        assert r.timeouts_detected == 0

    def test_summary_string(self):
        r = HarnessResult(
            total_cases_sent=100,
            total_bytes_sent=50000,
            start_time=0.0,
            end_time=10.0,
        )
        s = r.summary()
        assert "Cases sent" in s
        assert "100" in s
        assert "Duration" in s


class TestCrashHarness:
    def test_case_collection_header_only(self):
        cfg = HarnessConfig(
            modules=[FuzzModule.HEADER],
            max_cases=10,
        )
        harness = CrashHarness(cfg)
        cases = harness._collect_cases()
        assert len(cases) == 10
        for desc, raw in cases:
            assert isinstance(raw, bytes)

    def test_case_collection_all_modules(self):
        cfg = HarnessConfig(
            modules=[FuzzModule.ALL],
            max_cases=20,
        )
        harness = CrashHarness(cfg)
        cases = harness._collect_cases()
        assert len(cases) == 20

    def test_case_collection_no_limit(self):
        cfg = HarnessConfig(
            modules=[FuzzModule.TRAILER],
            max_cases=0,
        )
        harness = CrashHarness(cfg)
        cases = harness._collect_cases()
        assert len(cases) > 50

    def test_probe_localhost(self):
        """Probing localhost UDP should return ALIVE (UDP is connectionless)."""
        cfg = HarnessConfig(target_host="127.0.0.1", probe_timeout=0.5)
        harness = CrashHarness(cfg)
        status = harness.probe_target()
        assert status in (TargetStatus.ALIVE, TargetStatus.REFUSED)

    def test_stop_flag_during_run(self):
        """Stop mid-run via a background thread."""
        import threading

        cfg = HarnessConfig(
            modules=[FuzzModule.HEADER],
            max_cases=500,
            rate_pps=0,
            probe_interval=100,
        )
        harness = CrashHarness(cfg)
        # Schedule stop after a tiny delay
        timer = threading.Timer(0.05, harness.stop)
        timer.start()
        result = harness.run()
        timer.cancel()
        # Should have stopped before sending all 500
        assert result.total_cases_sent < 500

    def test_run_small_campaign(self):
        """Run a small campaign against localhost — just verifying no crash."""
        cfg = HarnessConfig(
            target_host="127.0.0.1",
            modules=[FuzzModule.HEADER],
            max_cases=5,
            rate_pps=0,
            probe_interval=100,  # don't probe during this tiny run
        )
        harness = CrashHarness(cfg)
        result = harness.run()
        assert result.total_cases_sent == 5
        assert result.total_bytes_sent > 0
        assert result.duration >= 0

    def test_progress_callback(self):
        progress_log = []

        def cb(current, total, desc):
            progress_log.append((current, total, desc))

        cfg = HarnessConfig(
            modules=[FuzzModule.HEADER],
            max_cases=5,
            rate_pps=0,
            probe_interval=100,
        )
        harness = CrashHarness(cfg, progress_callback=cb)
        harness.run()
        assert len(progress_log) == 5
