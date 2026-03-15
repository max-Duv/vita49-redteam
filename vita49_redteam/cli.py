"""Click-based CLI harness for VITA 49 red-team packet operations.

Subcommands:
    craft   — Build VRT packets and write to PCAP or hex dump
    send    — Transmit VRT packets to a target over UDP
    replay  — Load a PCAP, optionally modify fields, and replay over UDP
    sniff   — Passively capture VRT traffic and display/save
    report  — Summarize a PCAP containing VRT traffic
"""

from __future__ import annotations

import logging
import struct
import sys
import time
from pathlib import Path

import click

from vita49_redteam.core.constants import PacketType, TSI, TSF, VRT_DEFAULT_PORT
from vita49_redteam.core.packet import VRTPacket, make_if_data, make_if_context

# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def cli(verbose: bool) -> None:
    """VITA 49 (VRT) Red-Team Toolkit — packet craft, send, replay, sniff."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# craft — Build VRT packets
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--type",
    "pkt_type",
    type=click.Choice(
        ["if_data", "if_context", "ext_data", "ext_context"],
        case_sensitive=False,
    ),
    default="if_data",
    help="Packet type to craft.",
)
@click.option("--stream-id", type=str, default="0x0001", help="Stream ID (hex).")
@click.option("--count", type=int, default=1, help="Number of packets to generate.")
@click.option(
    "--payload-size", type=int, default=0, help="Payload size in bytes (zero-filled)."
)
@click.option("--tsi", type=click.Choice(["none", "utc", "gps", "other"]), default="none")
@click.option("--tsf", type=click.Choice(["none", "sample", "realtime", "free"]), default="none")
@click.option("--integer-ts", type=int, default=0, help="Integer timestamp value.")
@click.option("--fractional-ts", type=int, default=0, help="Fractional timestamp value.")
@click.option(
    "--class-id", type=str, default=None, help="Class ID as OUI:info:pkt (hex, colon-sep)."
)
@click.option("--trailer", type=str, default=None, help="Trailer word (hex, e.g. 0xC0000000).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output PCAP file path.")
@click.option("--hex-dump", is_flag=True, help="Print hex dump to stdout.")
def craft(
    pkt_type: str,
    stream_id: str,
    count: int,
    payload_size: int,
    tsi: str,
    tsf: str,
    integer_ts: int,
    fractional_ts: int,
    class_id: str | None,
    trailer: str | None,
    output: str | None,
    hex_dump: bool,
) -> None:
    """Craft VITA 49 packets and write to PCAP or display hex."""
    _PKT_TYPE_MAP = {
        "if_data": PacketType.IF_DATA_WITH_STREAM_ID,
        "if_context": PacketType.IF_CONTEXT,
        "ext_data": PacketType.EXT_DATA_WITH_STREAM_ID,
        "ext_context": PacketType.EXT_CONTEXT,
    }
    _TSI_MAP = {"none": TSI.NONE, "utc": TSI.UTC, "gps": TSI.GPS, "other": TSI.OTHER}
    _TSF_MAP = {
        "none": TSF.NONE,
        "sample": TSF.SAMPLE_COUNT,
        "realtime": TSF.REAL_TIME,
        "free": TSF.FREE_RUNNING,
    }

    sid = int(stream_id, 0)
    pt = _PKT_TYPE_MAP[pkt_type.lower()]

    packets: list[VRTPacket] = []
    for i in range(count):
        pkt = VRTPacket(
            packet_type=pt,
            stream_id=sid,
            packet_count=i & 0xF,
            tsi=_TSI_MAP[tsi],
            tsf=_TSF_MAP[tsf],
            integer_timestamp=integer_ts,
            fractional_timestamp=fractional_ts,
            payload=b"\x00" * payload_size,
        )

        if class_id:
            parts = class_id.split(":")
            pkt.with_class_id(
                oui=int(parts[0], 16),
                info_class=int(parts[1], 16) if len(parts) > 1 else 0,
                pkt_class=int(parts[2], 16) if len(parts) > 2 else 0,
            )

        if trailer is not None:
            pkt.with_trailer(raw=int(trailer, 0))

        packets.append(pkt)

    click.echo(f"Crafted {len(packets)} packet(s), type={pkt_type}, stream_id=0x{sid:08X}")

    if hex_dump:
        for i, pkt in enumerate(packets):
            data = pkt.pack()
            click.echo(f"\n--- Packet {i} ({len(data)} bytes) ---")
            _print_hex(data)

    if output:
        _write_pcap(packets, output)
        click.echo(f"Written to {output}")

    if not output and not hex_dump:
        click.echo("Use --output or --hex-dump to see results.")


# ---------------------------------------------------------------------------
# send — Transmit packets to a target
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--target", "-t", required=True, help="Target as host:port.")
@click.option("--input", "-i", "input_file", type=click.Path(exists=True), default=None,
              help="PCAP file to send.")
@click.option("--stream-id", type=str, default="0x0001", help="Stream ID for generated packets.")
@click.option("--count", type=int, default=1, help="Number of packets to send.")
@click.option("--payload-size", type=int, default=256, help="Payload size in bytes.")
@click.option("--rate", type=float, default=0, help="Packets per second (0=unlimited).")
@click.option("--burst", type=int, default=1, help="Burst size for rate limiter.")
@click.option("--loops", type=int, default=1, help="Number of times to loop.")
@click.option("--source-ip", type=str, default=None, help="Source IP for spoofing (requires raw socket).")
def send(
    target: str,
    input_file: str | None,
    stream_id: str,
    count: int,
    payload_size: int,
    rate: float,
    burst: int,
    loops: int,
    source_ip: str | None,
) -> None:
    """Send VITA 49 packets to a target over UDP."""
    from vita49_redteam.transport.udp_sender import SenderConfig, UDPSender

    host, port = _parse_target(target)
    config = SenderConfig(
        target_host=host,
        target_port=port,
        source_ip=source_ip,
        rate_pps=rate,
        burst_size=burst,
        loop_count=loops,
    )

    if input_file:
        packets = _load_vrt_from_pcap(input_file)
        click.echo(f"Loaded {len(packets)} packets from {input_file}")
    else:
        sid = int(stream_id, 0)
        packets = [
            make_if_data(stream_id=sid, payload=b"\x00" * payload_size, packet_count=i & 0xF)
            for i in range(count)
        ]
        click.echo(f"Generated {len(packets)} IF Data packets")

    with UDPSender(config) as sender:
        sender.send_loop(packets)
        click.echo(str(sender.stats))


# ---------------------------------------------------------------------------
# replay — Replay a PCAP with optional modifications
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--input", "-i", "input_file", required=True, type=click.Path(exists=True),
              help="Input PCAP file.")
@click.option("--target", "-t", required=True, help="Target as host:port.")
@click.option("--speed", type=float, default=1.0, help="Replay speed multiplier (>1=faster).")
@click.option("--no-timing", is_flag=True, help="Ignore original packet timing.")
@click.option("--new-stream-id", type=str, default=None, help="Override Stream ID (hex).")
@click.option("--time-offset", type=int, default=0, help="Add to integer timestamps.")
@click.option("--loops", type=int, default=1, help="Number of replay loops.")
@click.option("--rate", type=float, default=0, help="Rate limit (pps, 0=use timing).")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Save modified PCAP instead of sending.")
def replay(
    input_file: str,
    target: str,
    speed: float,
    no_timing: bool,
    new_stream_id: str | None,
    time_offset: int,
    loops: int,
    rate: float,
    output: str | None,
) -> None:
    """Replay a VITA 49 PCAP capture with optional field modifications."""
    from vita49_redteam.replay.pcap_engine import (
        PcapReplayEngine,
        ReplayConfig,
        load_pcap,
        modify_stream_id,
        modify_timestamps,
        save_modified_pcap,
    )
    from vita49_redteam.transport.udp_sender import SenderConfig

    modifiers = []
    if new_stream_id:
        modifiers.append(modify_stream_id(int(new_stream_id, 0)))
    if time_offset:
        modifiers.append(modify_timestamps(time_offset=time_offset))

    if output:
        n = save_modified_pcap(input_file, output, modifiers)
        click.echo(f"Saved {n} modified packets to {output}")
        return

    host, port = _parse_target(target)
    sender_cfg = SenderConfig(target_host=host, target_port=port, rate_pps=rate)
    replay_cfg = ReplayConfig(
        preserve_timing=not no_timing,
        speed_multiplier=speed,
        modifiers=modifiers,
        loop_count=loops,
    )

    engine = PcapReplayEngine(sender_cfg, replay_cfg)
    n = engine.replay_file(input_file)
    click.echo(f"Replayed {n} packets to {target}")


# ---------------------------------------------------------------------------
# sniff — Passive VRT traffic capture
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--interface", "-I", default=None, help="Network interface to sniff on.")
@click.option("--port", type=int, default=VRT_DEFAULT_PORT, help="UDP port to filter.")
@click.option("--count", "-c", type=int, default=0, help="Number of packets (0=infinite).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save to PCAP.")
@click.option("--timeout", type=int, default=0, help="Capture timeout in seconds.")
def sniff(
    interface: str | None,
    port: int,
    count: int,
    output: str | None,
    timeout: int,
) -> None:
    """Passively sniff VITA 49 traffic and display packet summaries."""
    from scapy.all import sniff as scapy_sniff, wrpcap

    from vita49_redteam.scapy_layers.layers import VRT_Header

    bpf = f"udp port {port}"
    click.echo(f"Sniffing VRT on port {port} (BPF: {bpf})...")

    kwargs: dict = {"filter": bpf, "prn": _sniff_callback}
    if interface:
        kwargs["iface"] = interface
    if count > 0:
        kwargs["count"] = count
    if timeout > 0:
        kwargs["timeout"] = timeout

    captured = scapy_sniff(**kwargs)

    click.echo(f"\nCaptured {len(captured)} packets.")
    if output:
        wrpcap(output, captured)
        click.echo(f"Saved to {output}")


# ---------------------------------------------------------------------------
# report — Summarize VRT traffic in a PCAP
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--input", "-i", "input_file", required=True, type=click.Path(exists=True),
              help="PCAP file to analyze.")
def report(input_file: str) -> None:
    """Generate a summary report of VITA 49 traffic from a PCAP."""
    from vita49_redteam.replay.pcap_engine import load_pcap

    packets = load_pcap(input_file)
    if not packets:
        click.echo("No VRT packets found.")
        return

    stream_ids: dict[int, int] = {}
    pkt_types: dict[str, int] = {}
    total_bytes = 0
    parsed_count = 0

    for cap in packets:
        total_bytes += len(cap.raw_vrt)
        if cap.parsed:
            parsed_count += 1
            sid = cap.parsed.stream_id
            stream_ids[sid] = stream_ids.get(sid, 0) + 1
            tname = cap.parsed.packet_type.name
            pkt_types[tname] = pkt_types.get(tname, 0) + 1

    click.echo(f"\n=== VITA 49 PCAP Report: {input_file} ===")
    click.echo(f"Total UDP packets:   {len(packets)}")
    click.echo(f"Parsed as VRT:       {parsed_count}")
    click.echo(f"Total VRT bytes:     {total_bytes}")

    if packets:
        duration = packets[-1].timestamp - packets[0].timestamp
        click.echo(f"Capture duration:    {duration:.3f}s")
        if duration > 0:
            click.echo(f"Avg packet rate:     {len(packets)/duration:.1f} pps")

    click.echo(f"\nPacket Types:")
    for tname, cnt in sorted(pkt_types.items(), key=lambda x: -x[1]):
        click.echo(f"  {tname:30s} {cnt}")

    click.echo(f"\nStream IDs:")
    for sid, cnt in sorted(stream_ids.items()):
        click.echo(f"  0x{sid:08X}  {cnt} packets")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_target(target: str) -> tuple[str, int]:
    """Parse 'host:port' string."""
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        return host, int(port_str)
    return target, VRT_DEFAULT_PORT


def _print_hex(data: bytes, width: int = 16) -> None:
    """Print a hex dump of bytes."""
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        click.echo(f"  {offset:04x}  {hex_part:<{width * 3}}  {ascii_part}")


def _write_pcap(packets: list[VRTPacket], path: str) -> None:
    """Write VRTPackets to a PCAP file using Scapy."""
    from scapy.all import IP, UDP, Ether, wrpcap

    scapy_pkts = []
    for pkt in packets:
        raw_data = pkt.pack()
        scapy_pkt = (
            Ether()
            / IP(dst="127.0.0.1")
            / UDP(sport=12345, dport=VRT_DEFAULT_PORT)
            / raw_data
        )
        scapy_pkts.append(scapy_pkt)

    wrpcap(path, scapy_pkts)


def _load_vrt_from_pcap(path: str) -> list[VRTPacket]:
    """Load VRT packets from PCAP, returning parsed VRTPacket objects."""
    from vita49_redteam.replay.pcap_engine import load_pcap

    captured = load_pcap(path)
    packets = []
    for cap in captured:
        if cap.parsed:
            packets.append(cap.parsed)
        else:
            try:
                packets.append(VRTPacket.unpack(cap.raw_vrt))
            except Exception:
                pass
    return packets


def _sniff_callback(pkt) -> None:  # noqa: ANN001
    """Print a one-line summary for each sniffed VRT packet."""
    from vita49_redteam.scapy_layers.layers import VRT_Header

    if pkt.haslayer(VRT_Header):
        vrt = pkt[VRT_Header]
        click.echo(
            f"  VRT type={vrt.pkt_type:#x} count={vrt.packet_count} "
            f"size={vrt.packet_size}w stream_id={getattr(vrt, 'stream_id', 'N/A'):#010x}"
        )
    else:
        click.echo(f"  UDP packet ({len(bytes(pkt.payload))} bytes)")


# =========================================================================
# Epic E2 — Fuzz sub-commands
# =========================================================================

@cli.command("fuzz-header")
@click.option("--target", "-t", default=None, help="Target host:port (sends packets if set).")
@click.option("--count", "-c", type=int, default=0, help="Max fuzz cases (0=all).")
@click.option("--strategy", type=click.Choice(["boundary", "bitflip", "type_confusion", "random", "all"]),
              default="all", help="Fuzzing strategy.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save fuzzed packets to PCAP.")
@click.option("--seed", type=int, default=None, help="RNG seed for reproducibility.")
@click.option("--payload-size", type=int, default=64, help="Base payload size in bytes.")
def fuzz_header(target, count, strategy, output, seed, payload_size):
    """VRT-201: Fuzz all VITA 49 header fields."""
    from vita49_redteam.fuzz.header_fuzzer import HeaderFuzzer, HeaderFuzzConfig, FuzzStrategy

    strategy_map = {
        "boundary": [FuzzStrategy.BOUNDARY],
        "bitflip": [FuzzStrategy.BIT_FLIP],
        "type_confusion": [FuzzStrategy.TYPE_CONFUSION],
        "random": [FuzzStrategy.RANDOM],
        "all": list(FuzzStrategy),
    }
    cfg = HeaderFuzzConfig(
        strategies=strategy_map[strategy],
        seed=seed,
        base_payload_size=payload_size,
    )
    fuzzer = HeaderFuzzer(cfg)
    cases = fuzzer.generate_count(count) if count > 0 else list(fuzzer.generate())
    click.echo(f"Generated {len(cases)} header fuzz cases (strategy={strategy})")

    if output:
        _write_pcap([pkt for _, pkt in cases], output)
        click.echo(f"Saved to {output}")

    if target:
        _fuzz_send(target, [pkt.pack() for _, pkt in cases])

    if not target and not output:
        for desc, pkt in cases[:10]:
            click.echo(f"  {desc}")
            _print_hex(pkt.pack())
        if len(cases) > 10:
            click.echo(f"  ... and {len(cases) - 10} more cases")


@cli.command("fuzz-payload")
@click.option("--target", "-t", default=None, help="Target host:port.")
@click.option("--count", "-c", type=int, default=0, help="Max cases (0=all).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save to PCAP.")
@click.option("--payload-size", type=int, default=256, help="Base payload size.")
def fuzz_payload(target, count, output, payload_size):
    """VRT-202: Generate payload size mismatch test packets."""
    from vita49_redteam.fuzz.payload_fuzzer import PayloadSizeFuzzer, PayloadMismatchConfig

    cfg = PayloadMismatchConfig(base_payload_size=payload_size)
    fuzzer = PayloadSizeFuzzer(cfg)
    cases = fuzzer.generate_count(count) if count > 0 else list(fuzzer.generate())
    click.echo(f"Generated {len(cases)} payload mismatch cases")

    if output:
        _write_raw_pcap([raw for _, raw in cases], output)
        click.echo(f"Saved to {output}")

    if target:
        _fuzz_send(target, [raw for _, raw in cases])

    if not target and not output:
        for desc, raw in cases[:10]:
            click.echo(f"  {desc} ({len(raw)} bytes)")
        if len(cases) > 10:
            click.echo(f"  ... and {len(cases) - 10} more cases")


@cli.command("fuzz-trailer")
@click.option("--target", "-t", default=None, help="Target host:port.")
@click.option("--count", "-c", type=int, default=0, help="Max cases (0=all).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save to PCAP.")
@click.option("--seed", type=int, default=None, help="RNG seed.")
def fuzz_trailer(target, count, output, seed):
    """VRT-203: Fuzz all VITA 49 trailer fields."""
    from vita49_redteam.fuzz.trailer_fuzzer import TrailerFuzzer, TrailerFuzzConfig

    cfg = TrailerFuzzConfig(seed=seed)
    fuzzer = TrailerFuzzer(cfg)
    cases = fuzzer.generate_count(count) if count > 0 else list(fuzzer.generate())
    click.echo(f"Generated {len(cases)} trailer fuzz cases")

    if output:
        _write_pcap([pkt for _, pkt in cases], output)
        click.echo(f"Saved to {output}")

    if target:
        _fuzz_send(target, [pkt.pack() for _, pkt in cases])

    if not target and not output:
        for desc, pkt in cases[:10]:
            click.echo(f"  {desc}")
        if len(cases) > 10:
            click.echo(f"  ... and {len(cases) - 10} more cases")


@cli.command("fuzz-size")
@click.option("--target", "-t", default=None, help="Target host:port.")
@click.option("--count", "-c", type=int, default=0, help="Max cases (0=all).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save to PCAP.")
def fuzz_size(target, count, output):
    """VRT-204: Generate truncated & oversized VRT packets."""
    from vita49_redteam.fuzz.size_fuzzer import SizeGenerator, SizeGenConfig

    fuzzer = SizeGenerator(SizeGenConfig())
    cases = fuzzer.generate_count(count) if count > 0 else list(fuzzer.generate())
    click.echo(f"Generated {len(cases)} size test cases")

    if output:
        _write_raw_pcap([raw for _, raw in cases], output)
        click.echo(f"Saved to {output}")

    if target:
        _fuzz_send(target, [raw for _, raw in cases])

    if not target and not output:
        for desc, raw in cases[:10]:
            click.echo(f"  {desc} ({len(raw)} bytes)")
        if len(cases) > 10:
            click.echo(f"  ... and {len(cases) - 10} more cases")


@cli.command("fuzz-run")
@click.option("--target", "-t", required=True, help="Target host:port.")
@click.option("--module", type=click.Choice(["header", "payload", "trailer", "size", "all"]),
              default="all", help="Which fuzz module to run.")
@click.option("--max-cases", type=int, default=0, help="Max cases (0=all).")
@click.option("--rate", type=float, default=100, help="Packets per second.")
@click.option("--probe-interval", type=int, default=10, help="Health-check every N packets.")
@click.option("--probe-timeout", type=float, default=2.0, help="Probe timeout in seconds.")
@click.option("--seed", type=int, default=None, help="RNG seed.")
@click.option("--pause-on-failure", is_flag=True, help="Stop if target goes down.")
def fuzz_run(target, module, max_cases, rate, probe_interval, probe_timeout, seed, pause_on_failure):
    """VRT-205: Run full fuzz campaign with crash/hang detection."""
    from vita49_redteam.fuzz.harness import CrashHarness, HarnessConfig, FuzzModule

    module_map = {
        "header": [FuzzModule.HEADER],
        "payload": [FuzzModule.PAYLOAD_SIZE],
        "trailer": [FuzzModule.TRAILER],
        "size": [FuzzModule.TRUNCATED_OVERSIZED],
        "all": [FuzzModule.ALL],
    }
    host, port = _parse_target(target)
    cfg = HarnessConfig(
        target_host=host,
        target_port=port,
        modules=module_map[module],
        max_cases=max_cases,
        rate_pps=rate,
        probe_interval=probe_interval,
        probe_timeout=probe_timeout,
        seed=seed,
        pause_on_failure=pause_on_failure,
    )

    def progress(current, total, desc):
        if current % 50 == 0 or current == total:
            click.echo(f"  [{current}/{total}] {desc}")

    harness = CrashHarness(cfg, progress_callback=progress)
    click.echo(f"Starting fuzz campaign against {target} (module={module})...")
    result = harness.run()
    click.echo(result.summary())


# -- Fuzz helpers ---------------------------------------------------------

def _fuzz_send(target: str, raw_payloads: list[bytes]) -> None:
    """Send a list of raw byte payloads to a target."""
    from vita49_redteam.transport.udp_sender import SenderConfig, UDPSender

    host, port = _parse_target(target)
    config = SenderConfig(target_host=host, target_port=port)
    with UDPSender(config) as sender:
        for raw in raw_payloads:
            sender.send_raw(raw)
    click.echo(f"Sent {len(raw_payloads)} fuzzed packets to {target}")


def _write_raw_pcap(raw_payloads: list[bytes], path: str) -> None:
    """Write raw byte payloads to a PCAP file."""
    from scapy.all import Ether, IP, UDP, wrpcap

    scapy_pkts = []
    for raw in raw_payloads:
        scapy_pkts.append(
            Ether() / IP(dst="127.0.0.1") / UDP(sport=12345, dport=VRT_DEFAULT_PORT) / raw
        )
    wrpcap(path, scapy_pkts)


if __name__ == "__main__":
    cli()
