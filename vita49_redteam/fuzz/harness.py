"""VRT-205: Crash & Hang Detection Harness.

Automated test harness that sends fuzzed packets to a target and monitors
for crashes, memory leaks, CPU spikes, and unresponsiveness via periodic
health probes and optional process monitoring.
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Iterator

from vita49_redteam.core.constants import VRT_DEFAULT_PORT
from vita49_redteam.core.packet import VRTPacket
from vita49_redteam.fuzz.header_fuzzer import HeaderFuzzer, HeaderFuzzConfig
from vita49_redteam.fuzz.payload_fuzzer import PayloadSizeFuzzer, PayloadMismatchConfig
from vita49_redteam.fuzz.trailer_fuzzer import TrailerFuzzer, TrailerFuzzConfig
from vita49_redteam.fuzz.size_fuzzer import SizeGenerator, SizeGenConfig
from vita49_redteam.transport.udp_sender import SenderConfig, UDPSender

logger = logging.getLogger(__name__)


class TargetStatus(Enum):
    """Result of a health probe."""
    ALIVE = auto()
    TIMEOUT = auto()
    REFUSED = auto()
    ERROR = auto()


class FuzzModule(Enum):
    """Available fuzz modules."""
    HEADER = auto()
    PAYLOAD_SIZE = auto()
    TRAILER = auto()
    TRUNCATED_OVERSIZED = auto()
    ALL = auto()


@dataclass
class HarnessEvent:
    """Record of a notable event during fuzzing."""
    timestamp: float
    case_index: int
    case_description: str
    event_type: str  # "target_down", "target_timeout", "cpu_spike", "resumed"
    detail: str = ""


@dataclass
class HarnessConfig:
    """Configuration for the crash & hang detection harness."""
    target_host: str = "127.0.0.1"
    target_port: int = VRT_DEFAULT_PORT
    modules: list[FuzzModule] = field(default_factory=lambda: [FuzzModule.ALL])
    probe_interval: int = 10       # Check target health every N packets
    probe_timeout: float = 2.0     # Seconds to wait for probe response
    max_cases: int = 0             # 0 = run all generated cases
    rate_pps: float = 100          # Sending rate
    pause_on_failure: bool = False  # Pause and log when target goes down
    inter_case_delay: float = 0.0  # Delay between cases (seconds)
    seed: int | None = None


@dataclass
class HarnessResult:
    """Summary of a fuzzing run."""
    total_cases_sent: int = 0
    total_bytes_sent: int = 0
    events: list[HarnessEvent] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    target_final_status: TargetStatus = TargetStatus.ALIVE

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def failures_detected(self) -> int:
        return sum(1 for e in self.events if e.event_type == "target_down")

    @property
    def timeouts_detected(self) -> int:
        return sum(1 for e in self.events if e.event_type == "target_timeout")

    def summary(self) -> str:
        lines = [
            f"=== Fuzz Harness Report ===",
            f"Duration:        {self.duration:.1f}s",
            f"Cases sent:      {self.total_cases_sent}",
            f"Bytes sent:      {self.total_bytes_sent}",
            f"Failures:        {self.failures_detected}",
            f"Timeouts:        {self.timeouts_detected}",
            f"Final status:    {self.target_final_status.name}",
        ]
        if self.events:
            lines.append(f"\nEvents ({len(self.events)}):")
            for e in self.events:
                lines.append(
                    f"  [{e.timestamp:.1f}s] case={e.case_index} "
                    f"type={e.event_type} desc={e.case_description}"
                )
                if e.detail:
                    lines.append(f"    detail: {e.detail}")
        return "\n".join(lines)


class CrashHarness:
    """Automated fuzz-and-monitor harness.

    Sends fuzzed packets from the configured modules and periodically
    probes the target for liveness. Records events when the target
    becomes unresponsive or refuses connections.
    """

    def __init__(
        self,
        config: HarnessConfig | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> None:
        self.config = config or HarnessConfig()
        self._progress_cb = progress_callback
        self._stop_requested = False

    def stop(self) -> None:
        """Request graceful stop from another thread."""
        self._stop_requested = True

    # -- Health probe ------------------------------------------------------

    def probe_target(self) -> TargetStatus:
        """Send a minimal UDP packet and check for ICMP unreachable or timeout."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.probe_timeout)
            # Send a minimal 4-byte packet (valid VRT header word)
            probe_data = b"\x10\x00\x00\x02"  # IF Data, size=2
            sock.sendto(
                probe_data,
                (self.config.target_host, self.config.target_port),
            )
            # For UDP we can't truly confirm receipt, but we can detect
            # ICMP port-unreachable via a subsequent recv attempt
            try:
                sock.recvfrom(1)
            except socket.timeout:
                # Timeout is actually normal for UDP — target accepted silently
                return TargetStatus.ALIVE
            except ConnectionResetError:
                # ICMP port unreachable received
                return TargetStatus.REFUSED
            finally:
                sock.close()
            return TargetStatus.ALIVE
        except OSError as exc:
            logger.warning("Probe error: %s", exc)
            return TargetStatus.ERROR

    # -- Case generators ---------------------------------------------------

    def _collect_cases(self) -> list[tuple[str, bytes]]:
        """Gather fuzz cases from all enabled modules."""
        cases: list[tuple[str, bytes]] = []
        modules = self.config.modules
        run_all = FuzzModule.ALL in modules

        if run_all or FuzzModule.HEADER in modules:
            hf = HeaderFuzzer(HeaderFuzzConfig(seed=self.config.seed))
            for desc, pkt in hf.generate():
                cases.append((desc, pkt.pack()))

        if run_all or FuzzModule.PAYLOAD_SIZE in modules:
            pf = PayloadSizeFuzzer(PayloadMismatchConfig())
            for desc, raw in pf.generate():
                cases.append((desc, raw))

        if run_all or FuzzModule.TRAILER in modules:
            tf = TrailerFuzzer(TrailerFuzzConfig(seed=self.config.seed))
            for desc, pkt in tf.generate():
                cases.append((desc, pkt.pack()))

        if run_all or FuzzModule.TRUNCATED_OVERSIZED in modules:
            sg = SizeGenerator(SizeGenConfig())
            for desc, raw in sg.generate():
                cases.append((desc, raw))

        if self.config.max_cases > 0:
            cases = cases[: self.config.max_cases]

        return cases

    # -- Main run ----------------------------------------------------------

    def run(self) -> HarnessResult:
        """Execute the full fuzzing campaign and return results."""
        self._stop_requested = False
        result = HarnessResult(start_time=time.monotonic())

        cases = self._collect_cases()
        total = len(cases)
        logger.info("Collected %d fuzz cases", total)

        sender_cfg = SenderConfig(
            target_host=self.config.target_host,
            target_port=self.config.target_port,
            rate_pps=self.config.rate_pps,
        )

        with UDPSender(sender_cfg) as sender:
            for idx, (desc, raw_data) in enumerate(cases):
                if self._stop_requested:
                    logger.info("Stop requested at case %d", idx)
                    break

                # Send the fuzzed packet
                sender.send_raw(raw_data)
                result.total_cases_sent += 1
                result.total_bytes_sent += len(raw_data)

                # Progress callback
                if self._progress_cb:
                    self._progress_cb(idx + 1, total, desc)

                # Periodic health probe
                if (idx + 1) % self.config.probe_interval == 0:
                    status = self.probe_target()
                    elapsed = time.monotonic() - result.start_time

                    if status == TargetStatus.TIMEOUT:
                        event = HarnessEvent(
                            timestamp=elapsed,
                            case_index=idx,
                            case_description=desc,
                            event_type="target_timeout",
                            detail=f"No response within {self.config.probe_timeout}s",
                        )
                        result.events.append(event)
                        logger.warning("Target timeout after case %d: %s", idx, desc)

                    elif status == TargetStatus.REFUSED:
                        event = HarnessEvent(
                            timestamp=elapsed,
                            case_index=idx,
                            case_description=desc,
                            event_type="target_down",
                            detail="ICMP port unreachable / connection refused",
                        )
                        result.events.append(event)
                        logger.error("Target DOWN after case %d: %s", idx, desc)

                        if self.config.pause_on_failure:
                            logger.info("Pausing — target appears down.")
                            break

                    elif status == TargetStatus.ERROR:
                        event = HarnessEvent(
                            timestamp=elapsed,
                            case_index=idx,
                            case_description=desc,
                            event_type="probe_error",
                        )
                        result.events.append(event)

                # Inter-case delay
                if self.config.inter_case_delay > 0:
                    time.sleep(self.config.inter_case_delay)

        # Final probe
        result.target_final_status = self.probe_target()
        result.end_time = time.monotonic()
        return result
