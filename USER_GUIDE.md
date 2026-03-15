# VITA 49 Red-Team Toolkit — User Guide

This guide covers every feature of the VITA 49 (VRT) Red-Team Toolkit, including the command-line interface and the graphical application.

---

## Table of Contents

1. [Installation](#installation)
2. [CLI Reference](#cli-reference)
   - [craft](#craft)
   - [send](#send)
   - [replay](#replay)
   - [sniff](#sniff)
   - [report](#report)
3. [GUI Reference](#gui-reference)
   - [Craft Tab](#craft-tab)
   - [Send Tab](#send-tab)
   - [Replay Tab](#replay-tab)
   - [Sniff Tab](#sniff-tab)
   - [Report Tab](#report-tab)
4. [Python API](#python-api)
5. [Common Workflows](#common-workflows)
6. [Troubleshooting](#troubleshooting)

---

## Installation

### System Requirements

| Requirement | Details |
|---|---|
| Python | 3.10 or later |
| Packet capture library | Npcap (Windows) or libpcap (Linux/macOS) |
| Elevated privileges | Required for raw-socket spoofing and live capture |
| OS | Windows 10/11, Linux, macOS |

### Install from Source

```bash
git clone https://github.com/max-Duv/vita49-redteam.git
cd vita49-redteam
pip install -e ".[dev]"
```

### Verify

```bash
vita49-rt --help      # CLI
vita49-rt-gui         # GUI
pytest tests/ -v      # Tests (61 tests)
```

---

## CLI Reference

The CLI is invoked with `vita49-rt`. All subcommands support `--help` for detailed option descriptions.

```
vita49-rt [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbose   Enable verbose logging
  --help          Show help and exit
```

### craft

Build one or more VRT packets and optionally dump their hex representation or save them to a PCAP file.

```bash
vita49-rt craft [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--type` | Choice | `if_data` | Packet type: `if_data`, `if_context`, `ext_data`, `ext_context` |
| `--stream-id` | Hex int | `None` | 32-bit Stream Identifier (e.g., `0xABCD1234`) |
| `--count` | Integer | `1` | Number of packets to generate |
| `--payload-size` | Integer | `64` | Payload size in bytes (random fill) |
| `--tsi` | Choice | `none` | Integer timestamp type: `none`, `utc`, `gps`, `other` |
| `--tsf` | Choice | `none` | Fractional timestamp type: `none`, `sample_count`, `real_time`, `free_running` |
| `--integer-ts` | Integer | `None` | Integer timestamp value |
| `--fractional-ts` | Integer | `None` | Fractional timestamp value |
| `--class-id` | String | `None` | Class ID as `OUI:info_code:packet_code` (e.g., `0x0012A2:1:2`) |
| `--trailer` | Flag | `False` | Append an empty trailer word |
| `--output` | Path | `None` | Save packets to a PCAP file |
| `--hex-dump` | Flag | `False` | Print hex dump of each packet |

**Examples:**

```bash
# Simple IF Data packet with hex dump
vita49-rt craft --type if_data --stream-id 0x1234 --hex-dump

# 10 packets with timestamps, saved to file
vita49-rt craft --type if_data --stream-id 0xDEAD --count 10 \
    --tsi utc --integer-ts 1700000000 --payload-size 256 --output test.pcap

# Context packet with Class ID and trailer
vita49-rt craft --type if_context --stream-id 0xBEEF \
    --class-id 0x0012A2:1:100 --trailer --hex-dump
```

---

### send

Transmit VRT packets to a target host over UDP. Packets can be crafted inline or loaded from a PCAP file.

```bash
vita49-rt send [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--target` | String | **Required** | Target as `host:port` (e.g., `192.168.1.50:4991`) |
| `--input` | Path | `None` | Load packets from a PCAP file instead of crafting inline |
| `--stream-id` | Hex int | `None` | Stream ID for inline-crafted packets |
| `--count` | Integer | `1` | Number of inline packets to craft |
| `--payload-size` | Integer | `64` | Payload size for inline packets |
| `--rate` | Integer | `0` | Packets per second (0 = unlimited) |
| `--burst` | Integer | `10` | Maximum burst size |
| `--loops` | Integer | `1` | Number of times to loop through the packet set |
| `--source-ip` | String | `None` | Spoof source IP (requires raw sockets / admin) |

**Examples:**

```bash
# Send 100 packets at 500 pps
vita49-rt send --target 192.168.1.50:4991 --stream-id 0x1234 --count 100 --rate 500

# Replay a PCAP with source-IP spoofing
vita49-rt send --target 10.0.0.5:4991 --input crafted.pcap --source-ip 10.0.0.99

# Burst mode — 50 packets, unlimited rate, 3 loops
vita49-rt send --target 192.168.1.50:4991 --count 50 --loops 3
```

---

### replay

Load VRT traffic from a PCAP file and replay it to a target with optional field modifications.

```bash
vita49-rt replay [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--input` | Path | **Required** | Source PCAP file |
| `--target` | String | **Required** | Target as `host:port` |
| `--speed` | Float | `1.0` | Replay speed multiplier (2.0 = double speed) |
| `--no-timing` | Flag | `False` | Ignore original packet timing, send as fast as possible |
| `--new-stream-id` | Hex int | `None` | Replace Stream ID in all replayed packets |
| `--time-offset` | Integer | `None` | Add offset to integer timestamps |
| `--loops` | Integer | `1` | Number of replay loops |
| `--rate` | Integer | `0` | Rate limit in pps (overrides timing when set) |
| `--output` | Path | `None` | Save modified packets to a new PCAP before replaying |

**Examples:**

```bash
# Replay with original timing
vita49-rt replay --input capture.pcap --target 192.168.1.50:4991

# Fast replay with field modification
vita49-rt replay --input capture.pcap --target 192.168.1.50:4991 \
    --speed 5.0 --new-stream-id 0xCAFE --time-offset 1000

# Save modified PCAP without replaying (set target to localhost)
vita49-rt replay --input original.pcap --target 127.0.0.1:4991 \
    --new-stream-id 0xBEEF --output modified.pcap
```

---

### sniff

Capture live VRT traffic from a network interface.

```bash
vita49-rt sniff [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--interface` | String | `None` | Network interface name (auto-detected if omitted) |
| `--port` | Integer | `4991` | UDP port to filter on |
| `--count` | Integer | `0` | Number of packets to capture (0 = unlimited) |
| `--output` | Path | `None` | Save captured packets to PCAP |
| `--timeout` | Integer | `None` | Stop capture after N seconds |

**Examples:**

```bash
# Capture 50 packets on the default interface
vita49-rt sniff --count 50 --output captured.pcap

# Sniff on a specific interface with timeout
vita49-rt sniff --interface "Ethernet" --port 4991 --timeout 60 --output long_capture.pcap
```

---

### report

Analyze a PCAP file and print summary statistics about the VRT traffic it contains.

```bash
vita49-rt report [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--input` | Path | **Required** | PCAP file to analyze |

**Output includes:**
- Total packet count
- Packet type breakdown (IF Data, IF Context, etc.)
- Unique Stream IDs
- Capture duration
- Average packet rate
- Packet size statistics (min / max / avg)

**Example:**

```bash
vita49-rt report --input capture.pcap
```

---

## GUI Reference

Launch the GUI:

```bash
vita49-rt-gui
```

The application opens a dark-themed window with five tabs along the top. All network operations run in background threads so the interface stays responsive.

---

### Craft Tab

Use this tab to build VRT packets interactively.

**Fields:**

| Field | Description |
|---|---|
| Packet Type | Drop-down: IF Data, IF Context, Ext Data, Ext Context |
| Stream ID | 32-bit hex value (e.g., `0xABCD1234`) |
| Payload Size | Bytes of random payload to include |
| Count | Number of packets to generate |
| TSI / TSF | Timestamp type selectors |
| Integer / Fractional TS | Optional timestamp values |
| Class ID | Optional, format: `OUI:info_code:packet_code` |
| Include Trailer | Checkbox to append a trailer word |

**Actions:**

| Button | Effect |
|---|---|
| **Craft Packets** | Builds packets and stores them in memory. Displays a hex dump in the output pane. |
| **Save to PCAP** | Writes the crafted packets to a PCAP file via a file-save dialog. |
| **Clear** | Clears the output pane. |

> **Tip:** Crafted packets are automatically available in the **Send** tab for transmission.

---

### Send Tab

Transmit packets to a network target.

**Fields:**

| Field | Description |
|---|---|
| Target | `host:port` format (e.g., `192.168.1.50:4991`) |
| Rate (pps) | Packets per second; 0 for unlimited |
| Burst Size | Max packets in a single burst |
| Loops | Number of times to repeat the packet set |
| Source IP | Optional spoofed source address (requires admin) |

**Packet Source (Radio Buttons):**
- **Use crafted packets** — sends whatever was built in the Craft tab
- **Load from PCAP** — opens a file dialog to select a PCAP file

**Actions:**

| Button | Effect |
|---|---|
| **Send** | Begins transmission in a background thread. Progress and stats display in the output pane. |
| **Clear** | Clears the log. |

---

### Replay Tab

Replay captured VRT traffic with on-the-fly field modifications.

**Fields:**

| Field | Description |
|---|---|
| Input PCAP | Click **Browse** to select a source PCAP file |
| Target | `host:port` destination |
| Speed | Replay speed multiplier (1.0 = original timing) |
| Ignore Timing | Checkbox to disable inter-packet delays |
| New Stream ID | Optional replacement Stream ID |
| Time Offset | Integer to add to all timestamps |
| Loops | Replay loop count |
| Rate (pps) | Optional rate limit |
| Output PCAP | Optional path to save the modified stream |

**Actions:**

| Button | Effect |
|---|---|
| **Replay** | Starts replaying in a background thread with live status updates. |
| **Clear** | Clears the output pane. |

---

### Sniff Tab

Passively capture VRT traffic from the local network.

**Fields:**

| Field | Description |
|---|---|
| Interface | Network interface name (leave blank for auto-detect) |
| Port | UDP port to filter (default: 4991) |
| Count | Packets to capture (0 = unlimited) |
| Timeout | Seconds before auto-stop (blank = no timeout) |

**Actions:**

| Button | Effect |
|---|---|
| **Start Sniff** | Begins capture in background. Packets appear in real-time in the output pane. |
| **Stop** | Halts an active capture. |
| **Save PCAP** | Writes captured packets to a file. |
| **Clear** | Clears the display. |

---

### Report Tab

Analyze PCAP files for VRT traffic statistics.

**Fields:**

| Field | Description |
|---|---|
| Input PCAP | Click **Browse** to select a file |

**Actions:**

| Button | Effect |
|---|---|
| **Analyze** | Parses the PCAP and displays a traffic summary: packet counts by type, stream IDs seen, timing stats, packet size distribution. |
| **Clear** | Clears the report. |

---

## Python API

You can also use the toolkit as a library in your own scripts.

### Building Packets

```python
from vita49_redteam.core.packet import VRTPacket, make_if_data
from vita49_redteam.core.constants import PacketType, TSI

# Quick factory
pkt = make_if_data(stream_id=0xDEAD, payload=b"\x00" * 256)
raw_bytes = pkt.pack()

# Builder pattern
pkt = (VRTPacket()
    .with_packet_type(PacketType.IF_DATA_WITH_STREAM_ID)
    .with_stream_id(0xABCD1234)
    .with_timestamps(TSI.UTC, integer_ts=1700000000)
    .with_payload(b"\xff" * 128)
    .with_trailer())
raw_bytes = pkt.pack()
```

### Sending Packets

```python
from vita49_redteam.transport.udp_sender import UDPSender, SenderConfig

config = SenderConfig(
    target_host="192.168.1.50",
    target_port=4991,
    rate_pps=1000,
    burst_size=10,
)

with UDPSender(config) as sender:
    for pkt in packets:
        sender.send_packet(pkt.pack())
```

### Loading & Replaying PCAPs

```python
from vita49_redteam.replay.pcap_engine import (
    load_pcap, PcapReplayEngine, ReplayConfig,
    modify_stream_id, modify_timestamps,
)

packets = load_pcap("capture.pcap")

config = ReplayConfig(
    preserve_timing=True,
    speed_multiplier=2.0,
    modifiers=[
        modify_stream_id(0xBEEF),
        modify_timestamps(time_offset=500),
    ],
)

engine = PcapReplayEngine(
    target_host="192.168.1.50",
    target_port=4991,
)
engine.replay(packets, config)
```

### Using Scapy Layers

```python
from scapy.all import IP, UDP, send
from vita49_redteam.scapy_layers.layers import VRT_Header

pkt = (IP(dst="192.168.1.50") /
       UDP(dport=4991) /
       VRT_Header(
           packet_type=1,
           stream_id=0x1234,
           vrt_data=b"\x00" * 64,
       ))
send(pkt)
```

---

## Common Workflows

### Workflow 1: Craft → Send

1. Open the **Craft** tab and configure your packet parameters.
2. Click **Craft Packets** — verify the hex dump looks correct.
3. Switch to the **Send** tab.
4. Select **Use crafted packets**, fill in the target, and click **Send**.

### Workflow 2: Capture → Modify → Replay

1. Use the **Sniff** tab to capture live VRT traffic and save to PCAP.
2. Switch to the **Replay** tab, load the saved PCAP.
3. Set a new Stream ID or time offset to disguise the replayed traffic.
4. Set the target and click **Replay**.

### Workflow 3: Capture → Analyze

1. Capture traffic with `vita49-rt sniff --count 500 --output cap.pcap`.
2. Analyze with `vita49-rt report --input cap.pcap`.
3. Identify anomalous stream IDs or unexpected packet types.

### Workflow 4: Stress Test

```bash
# Send 10,000 packets at maximum rate in 5 loops
vita49-rt send --target 192.168.1.50:4991 --count 10000 --rate 0 --loops 5
```

### Workflow 5: Source-IP Spoofing (requires admin)

```bash
# Impersonate a trusted VRT source
vita49-rt send --target 10.0.0.5:4991 --count 100 --source-ip 10.0.0.1 --rate 500
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `PermissionError` on send | Run as Administrator (Windows) or with `sudo` (Linux). Raw sockets require elevated privileges. |
| Sniff captures 0 packets | Ensure Npcap/libpcap is installed. Verify the interface name and that VRT traffic exists on the specified port. |
| `ModuleNotFoundError: scapy` | Run `pip install -e ".[dev]"` to install all dependencies. |
| GUI doesn't launch | Ensure Tkinter is installed. On Linux: `sudo apt install python3-tk`. On Windows, Tkinter ships with the standard Python installer. |
| PCAP replay shows no packets | Ensure the PCAP file contains UDP packets on port 4991. Use `report` to verify the file contents first. |
| `OSError: [Errno 10013]` on Windows | Windows Firewall or antivirus may block raw sockets. Run as Administrator or add a firewall exception. |

---

## VRT Protocol Quick Reference

| Field | Bits | Description |
|---|---|---|
| Packet Type | 4 | 0x0–0x7 (IF Data, IF Context, Ext Data, etc.) |
| C (Class ID present) | 1 | Class Identifier follows header |
| T (Trailer present) | 1 | Trailer appended after payload |
| TSI | 2 | Integer Timestamp type |
| TSF | 2 | Fractional Timestamp type |
| Packet Count | 4 | Rolling 0–15 counter |
| Packet Size | 16 | Total 32-bit words in packet |
| Stream ID | 32 | Optional, depends on packet type |
| Class ID | 64 | Optional OUI + information/packet codes |
| Integer Timestamp | 32 | Optional, per TSI field |
| Fractional Timestamp | 64 | Optional, per TSF field |
| Payload | Variable | Data payload |
| Trailer | 32 | Optional status/indicator word |

Default UDP port: **4991**

---

*For questions and contributions, open an issue or pull request on the GitHub repository.*
