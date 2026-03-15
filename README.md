# VITA 49 (VRT) Red-Team Toolkit

A Python toolkit for crafting, transmitting, replaying, sniffing, and analyzing **VITA 49.0 / 49.2 (VRT)** radio-transport packets over UDP. Built for red-team assessments of systems that consume or produce VRT streams.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## Features

| Capability | Description |
|---|---|
| **Packet Crafting** | Build arbitrary VRT packets — IF Data, IF Context, Extension Data/Context — with full control over headers, Stream IDs, timestamps, Class IDs, trailers, and payloads |
| **Transmission** | Send crafted packets over UDP with configurable rate limiting, burst control, looping, and source-IP spoofing (raw sockets) |
| **PCAP Replay** | Load captured VRT traffic from PCAP files, modify fields on-the-fly (Stream ID, timestamps, payload), and replay with original timing or at custom speeds |
| **Passive Sniffing** | Capture live VRT traffic on a network interface with optional BPF filtering and PCAP export |
| **Traffic Analysis** | Analyze PCAP files for packet-type distribution, stream-ID enumeration, timing statistics, and anomaly detection |
| **Scapy Integration** | Custom Scapy dissector layers (`VRT_Header`, `VRT_Trailer`) auto-bound to UDP port 4991 |
| **GUI & CLI** | Full Tkinter GUI with 5 operational tabs, plus a Click-based CLI for scripting and automation |

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Npcap** or **WinPcap** (Windows) / **libpcap** (Linux/macOS) — required for sniffing and PCAP operations
- Administrator/root privileges — required for raw-socket transmission (source-IP spoofing) and packet capture

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USER/vita49-redteam.git
cd vita49-redteam

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

### Verify Installation

```bash
# Run the test suite
pytest tests/ -v

# Check CLI
vita49-rt --help

# Launch GUI
vita49-rt-gui
```

---

## Usage Overview

### CLI (`vita49-rt`)

```
Usage: vita49-rt [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbose  Enable verbose output
  --help         Show this message and exit

Commands:
  craft   Build VRT packets and export to hex or PCAP
  send    Transmit VRT packets to a target over UDP
  replay  Replay VRT packets from a PCAP file
  sniff   Capture live VRT traffic from a network interface
  report  Analyze a PCAP file containing VRT traffic
```

#### Craft a Packet

```bash
# Craft 5 IF Data packets with a specific Stream ID, dump hex
vita49-rt craft --type if_data --stream-id 0xABCD1234 --count 5 --payload-size 256 --hex-dump

# Craft and save to PCAP
vita49-rt craft --type if_data --stream-id 0x1234 --payload-size 512 --output crafted.pcap
```

#### Send Packets

```bash
# Send 100 packets at 1000 pps to a target
vita49-rt send --target 192.168.1.50:4991 --stream-id 0xDEAD --count 100 --rate 1000

# Send with source-IP spoofing (requires admin)
vita49-rt send --target 10.0.0.5:4991 --count 50 --source-ip 10.0.0.99
```

#### Replay a PCAP

```bash
# Replay with original timing
vita49-rt replay --input capture.pcap --target 192.168.1.50:4991

# Replay at 2x speed with a new Stream ID
vita49-rt replay --input capture.pcap --target 192.168.1.50:4991 --speed 2.0 --new-stream-id 0xBEEF
```

#### Sniff Traffic

```bash
# Capture 100 VRT packets on the default interface
vita49-rt sniff --count 100 --output captured.pcap

# Sniff on a specific interface with timeout
vita49-rt sniff --interface eth0 --port 4991 --timeout 30 --output capture.pcap
```

#### Analyze a PCAP

```bash
vita49-rt report --input capture.pcap
```

### GUI (`vita49-rt-gui`)

Launch the graphical interface:

```bash
vita49-rt-gui
```

The GUI provides five tabs:

1. **Craft** — Build packets interactively with real-time hex preview
2. **Send** — Configure target, rate, and burst parameters; transmit crafted packets
3. **Replay** — Load PCAPs, apply field modifications, replay with timing control
4. **Sniff** — Capture live traffic with start/stop controls and packet display
5. **Report** — Load and analyze PCAP files with summary statistics

> See [USER_GUIDE.md](USER_GUIDE.md) for detailed instructions on every feature.

---

## Project Structure

```
vita49-redteam/
├── pyproject.toml                  # Build config, dependencies, entry points
├── README.md
├── USER_GUIDE.md
├── vita49_redteam/
│   ├── __init__.py
│   ├── cli.py                      # Click CLI (craft, send, replay, sniff, report)
│   ├── gui.py                      # Tkinter GUI (5-tab interface)
│   ├── core/
│   │   ├── constants.py            # VRT enums, masks, shifts, protocol constants
│   │   └── packet.py               # VRTPacket dataclass, builder pattern, pack/unpack
│   ├── scapy_layers/
│   │   └── layers.py               # VRT_Header & VRT_Trailer Scapy layers
│   ├── transport/
│   │   └── udp_sender.py           # UDP sender with rate limiting & raw-socket spoofing
│   └── replay/
│       └── pcap_engine.py          # PCAP loader, field modifiers, replay engine
└── tests/
    ├── test_constants.py
    ├── test_packet.py
    ├── test_scapy_layers.py
    ├── test_udp_sender.py
    └── test_cli.py
```

---

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│   CLI / GUI  │────▶│  core/       │────▶│  transport/      │
│              │     │  packet.py   │     │  udp_sender.py   │──▶ Network
│  craft/send/ │     │  constants.py│     └──────────────────┘
│  replay/sniff│     └──────────────┘
│  report      │            │
└──────────────┘            ▼
                    ┌──────────────────┐
                    │  scapy_layers/   │
                    │  layers.py       │
                    └──────────────────┘
                            │
                            ▼
                    ┌──────────────────┐
                    │  replay/         │
                    │  pcap_engine.py  │──▶ PCAP Files
                    └──────────────────┘
```

---

## Key Classes & APIs

| Module | Class / Function | Purpose |
|---|---|---|
| `core.packet` | `VRTPacket` | Dataclass with fluent builder (`.with_stream_id()`, `.with_payload()`, etc.) and `pack()` / `unpack()` |
| `core.packet` | `make_if_data()`, `make_if_context()`, `make_ext_data()` | Factory functions for common packet types |
| `core.packet` | `ClassID`, `Trailer` | Structured sub-fields for VRT Class Identifier and Trailer words |
| `core.constants` | `PacketType`, `TSI`, `TSF`, `ContextIndicator` | Protocol enumerations |
| `scapy_layers.layers` | `VRT_Header`, `VRT_Trailer` | Scapy packet layers (auto-bound to UDP/4991) |
| `transport.udp_sender` | `UDPSender`, `SenderConfig` | Rate-limited UDP transmission with optional raw-socket spoofing |
| `transport.udp_sender` | `TokenBucket` | Token-bucket rate limiter |
| `replay.pcap_engine` | `PcapReplayEngine`, `ReplayConfig` | PCAP replay with timing preservation and field modification |
| `replay.pcap_engine` | `load_pcap()`, `save_modified_pcap()` | PCAP I/O utilities |

---

## Running Tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=vita49_redteam --cov-report=term-missing
```

---

## Security & Legal Notice

**This toolkit is intended for authorized security testing only.** Unauthorized interception, injection, or disruption of radio-frequency or network communications may violate federal and local laws. Always obtain proper authorization before conducting red-team assessments.

The raw-socket features (source-IP spoofing, packet injection) require elevated privileges and should only be used in controlled test environments with explicit permission.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
