"""VITA 49 (VRT) Red-Team Toolkit — Tkinter GUI.

Provides a tabbed graphical interface wrapping all CLI operations:
  - Craft: build VRT packets, view hex, save PCAP
  - Send:  transmit packets to a target
  - Replay: load/modify/replay PCAPs
  - Sniff:  passive traffic capture
  - Report: analyze a PCAP file
"""

from __future__ import annotations

import logging
import os
import queue
import socket
import struct
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from pathlib import Path

from vita49_redteam.core.constants import PacketType, TSI, TSF, VRT_DEFAULT_PORT
from vita49_redteam.core.packet import VRTPacket, make_if_data, make_if_context

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Colour / style constants
# ---------------------------------------------------------------------------
_BG = "#1e1e2e"
_FG = "#cdd6f4"
_ACCENT = "#89b4fa"
_ACCENT2 = "#a6e3a1"
_FIELD_BG = "#313244"
_BTN_BG = "#45475a"
_BTN_FG = "#cdd6f4"
_ERR = "#f38ba8"
_WARN = "#fab387"
_OK = "#a6e3a1"
_MONO = ("Consolas", 10)
_LABEL = ("Segoe UI", 10)
_TITLE = ("Segoe UI", 12, "bold")
_HEADER = ("Segoe UI", 14, "bold")

# Mapping helpers (same as CLI)
_PKT_TYPE_MAP = {
    "IF Data": PacketType.IF_DATA_WITH_STREAM_ID,
    "IF Context": PacketType.IF_CONTEXT,
    "Ext Data": PacketType.EXT_DATA_WITH_STREAM_ID,
    "Ext Context": PacketType.EXT_CONTEXT,
}
_TSI_MAP = {"None": TSI.NONE, "UTC": TSI.UTC, "GPS": TSI.GPS, "Other": TSI.OTHER}
_TSF_MAP = {
    "None": TSF.NONE,
    "Sample Count": TSF.SAMPLE_COUNT,
    "Real-Time (ps)": TSF.REAL_TIME,
    "Free-Running": TSF.FREE_RUNNING,
}


# ===================================================================
# Helper: hex-dump string
# ===================================================================
def _hex_dump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def _write_pcap(packets: list[VRTPacket], path: str) -> None:
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


# ===================================================================
# Styled widget helpers
# ===================================================================
def _make_label(parent, text, **kw):
    return tk.Label(parent, text=text, bg=_BG, fg=_FG, font=_LABEL, anchor="w", **kw)


def _make_entry(parent, width=20, **kw):
    e = tk.Entry(parent, width=width, bg=_FIELD_BG, fg=_FG, insertbackground=_FG,
                 font=_MONO, relief="flat", bd=2, **kw)
    return e


def _make_combo(parent, values, width=18, **kw):
    style_name = f"Dark.TCombobox"
    c = ttk.Combobox(parent, values=values, width=width, state="readonly", **kw)
    c.current(0)
    return c


def _make_button(parent, text, command, accent=False):
    bg = _ACCENT if accent else _BTN_BG
    fg = "#1e1e2e" if accent else _BTN_FG
    b = tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                  activebackground=_ACCENT2, activeforeground="#1e1e2e",
                  font=_LABEL, relief="flat", bd=0, padx=14, pady=6, cursor="hand2")
    return b


def _make_output(parent, height=15):
    t = scrolledtext.ScrolledText(parent, height=height, bg="#11111b", fg=_ACCENT2,
                                  font=_MONO, relief="flat", bd=2, insertbackground=_FG,
                                  state="disabled", wrap="none")
    return t


def _output_write(widget, text, clear=False):
    widget.config(state="normal")
    if clear:
        widget.delete("1.0", tk.END)
    widget.insert(tk.END, text)
    widget.see(tk.END)
    widget.config(state="disabled")


def _make_section(parent, title):
    lbl = tk.Label(parent, text=title, bg=_BG, fg=_ACCENT, font=_TITLE, anchor="w")
    lbl.pack(fill="x", padx=10, pady=(10, 2))
    sep = tk.Frame(parent, bg=_ACCENT, height=1)
    sep.pack(fill="x", padx=10, pady=(0, 6))


# ===================================================================
# Main GUI Application
# ===================================================================
class VRT_RedTeamGUI:
    """Top-level Tkinter application for the VRT Red-Team Toolkit."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("VITA 49 (VRT) Red-Team Toolkit")
        self.root.geometry("960x720")
        self.root.minsize(800, 600)
        self.root.configure(bg=_BG)

        # Store crafted packets for cross-tab use
        self._crafted_packets: list[VRTPacket] = []

        self._build_ui()

    # ---------------------------------------------------------------
    # Build top-level layout
    # ---------------------------------------------------------------
    def _build_ui(self) -> None:
        # Header bar
        header = tk.Frame(self.root, bg="#181825", height=48)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="  VITA 49 Red-Team Toolkit",
                 bg="#181825", fg=_ACCENT, font=_HEADER).pack(side="left", padx=8, pady=8)
        tk.Label(header, text="v0.1.0",
                 bg="#181825", fg="#585b70", font=_LABEL).pack(side="left")

        # Configure ttk styles for dark theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.TNotebook", background=_BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab", background=_BTN_BG, foreground=_FG,
                        padding=[14, 6], font=_LABEL)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", _ACCENT)],
                  foreground=[("selected", "#1e1e2e")])
        style.configure("Dark.TCombobox", fieldbackground=_FIELD_BG, background=_BTN_BG,
                        foreground=_FG, arrowcolor=_FG)

        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.root, style="Dark.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=4, pady=4)

        # Build each tab
        self._build_craft_tab()
        self._build_send_tab()
        self._build_replay_tab()
        self._build_sniff_tab()
        self._build_report_tab()

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = tk.Label(self.root, textvariable=self.status_var, bg="#181825",
                          fg="#585b70", font=("Segoe UI", 9), anchor="w")
        status.pack(fill="x", side="bottom")

    # ---------------------------------------------------------------
    # TAB 1: Craft
    # ---------------------------------------------------------------
    def _build_craft_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=_BG)
        self.notebook.add(tab, text="  Craft  ")

        _make_section(tab, "Packet Parameters")

        # Fields frame
        fields = tk.Frame(tab, bg=_BG)
        fields.pack(fill="x", padx=10, pady=4)

        # Row 0
        _make_label(fields, "Packet Type:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.craft_pkt_type = _make_combo(fields, list(_PKT_TYPE_MAP.keys()))
        self.craft_pkt_type.grid(row=0, column=1, sticky="w", padx=4, pady=3)

        _make_label(fields, "Stream ID (hex):").grid(row=0, column=2, sticky="w", padx=4, pady=3)
        self.craft_stream_id = _make_entry(fields, width=14)
        self.craft_stream_id.insert(0, "0x0001")
        self.craft_stream_id.grid(row=0, column=3, sticky="w", padx=4, pady=3)

        _make_label(fields, "Count:").grid(row=0, column=4, sticky="w", padx=4, pady=3)
        self.craft_count = _make_entry(fields, width=6)
        self.craft_count.insert(0, "1")
        self.craft_count.grid(row=0, column=5, sticky="w", padx=4, pady=3)

        # Row 1
        _make_label(fields, "Payload Size (B):").grid(row=1, column=0, sticky="w", padx=4, pady=3)
        self.craft_payload_size = _make_entry(fields, width=14)
        self.craft_payload_size.insert(0, "0")
        self.craft_payload_size.grid(row=1, column=1, sticky="w", padx=4, pady=3)

        _make_label(fields, "TSI:").grid(row=1, column=2, sticky="w", padx=4, pady=3)
        self.craft_tsi = _make_combo(fields, list(_TSI_MAP.keys()), width=14)
        self.craft_tsi.grid(row=1, column=3, sticky="w", padx=4, pady=3)

        _make_label(fields, "TSF:").grid(row=1, column=4, sticky="w", padx=4, pady=3)
        self.craft_tsf = _make_combo(fields, list(_TSF_MAP.keys()), width=14)
        self.craft_tsf.grid(row=1, column=5, sticky="w", padx=4, pady=3)

        # Row 2
        _make_label(fields, "Integer TS:").grid(row=2, column=0, sticky="w", padx=4, pady=3)
        self.craft_int_ts = _make_entry(fields, width=14)
        self.craft_int_ts.insert(0, "0")
        self.craft_int_ts.grid(row=2, column=1, sticky="w", padx=4, pady=3)

        _make_label(fields, "Fractional TS:").grid(row=2, column=2, sticky="w", padx=4, pady=3)
        self.craft_frac_ts = _make_entry(fields, width=14)
        self.craft_frac_ts.insert(0, "0")
        self.craft_frac_ts.grid(row=2, column=3, sticky="w", padx=4, pady=3)

        # Row 3: Class ID + Trailer
        _make_label(fields, "Class ID (OUI:info:pkt):").grid(row=3, column=0, sticky="w", padx=4, pady=3)
        self.craft_class_id = _make_entry(fields, width=14)
        self.craft_class_id.grid(row=3, column=1, sticky="w", padx=4, pady=3)

        _make_label(fields, "Trailer (hex):").grid(row=3, column=2, sticky="w", padx=4, pady=3)
        self.craft_trailer = _make_entry(fields, width=14)
        self.craft_trailer.grid(row=3, column=3, sticky="w", padx=4, pady=3)

        # Buttons
        btn_frame = tk.Frame(tab, bg=_BG)
        btn_frame.pack(fill="x", padx=10, pady=6)
        _make_button(btn_frame, "  Craft & Hex Dump  ", self._on_craft, accent=True).pack(side="left", padx=4)
        _make_button(btn_frame, "  Save to PCAP  ", self._on_craft_save).pack(side="left", padx=4)

        _make_section(tab, "Output")
        self.craft_output = _make_output(tab, height=16)
        self.craft_output.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _craft_packets(self) -> list[VRTPacket]:
        pt = _PKT_TYPE_MAP[self.craft_pkt_type.get()]
        sid = int(self.craft_stream_id.get(), 0)
        count = int(self.craft_count.get())
        payload_size = int(self.craft_payload_size.get())
        tsi = _TSI_MAP[self.craft_tsi.get()]
        tsf = _TSF_MAP[self.craft_tsf.get()]
        int_ts = int(self.craft_int_ts.get())
        frac_ts = int(self.craft_frac_ts.get())

        packets = []
        for i in range(count):
            pkt = VRTPacket(
                packet_type=pt,
                stream_id=sid,
                packet_count=i & 0xF,
                tsi=tsi,
                tsf=tsf,
                integer_timestamp=int_ts,
                fractional_timestamp=frac_ts,
                payload=b"\x00" * payload_size,
            )
            cid_text = self.craft_class_id.get().strip()
            if cid_text:
                parts = cid_text.split(":")
                pkt.with_class_id(
                    oui=int(parts[0], 16),
                    info_class=int(parts[1], 16) if len(parts) > 1 else 0,
                    pkt_class=int(parts[2], 16) if len(parts) > 2 else 0,
                )
            trailer_text = self.craft_trailer.get().strip()
            if trailer_text:
                pkt.with_trailer(raw=int(trailer_text, 0))
            packets.append(pkt)
        return packets

    def _on_craft(self) -> None:
        try:
            packets = self._craft_packets()
            self._crafted_packets = packets
            lines = [f"Crafted {len(packets)} packet(s)\n"]
            for i, pkt in enumerate(packets):
                data = pkt.pack()
                lines.append(f"--- Packet {i}  ({len(data)} bytes, {pkt.compute_packet_size_words()} words) ---")
                lines.append(repr(pkt))
                lines.append(_hex_dump(data))
                lines.append("")
            _output_write(self.craft_output, "\n".join(lines), clear=True)
            self.status_var.set(f"Crafted {len(packets)} packet(s)")
        except Exception as exc:
            messagebox.showerror("Craft Error", str(exc))

    def _on_craft_save(self) -> None:
        try:
            packets = self._craft_packets()
            self._crafted_packets = packets
            path = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
                title="Save PCAP",
            )
            if not path:
                return
            _write_pcap(packets, path)
            _output_write(self.craft_output, f"Saved {len(packets)} packet(s) to {path}\n", clear=True)
            self.status_var.set(f"Saved {len(packets)} packet(s) to {path}")
        except Exception as exc:
            messagebox.showerror("Save Error", str(exc))

    # ---------------------------------------------------------------
    # TAB 2: Send
    # ---------------------------------------------------------------
    def _build_send_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=_BG)
        self.notebook.add(tab, text="  Send  ")

        _make_section(tab, "Target Configuration")
        fields = tk.Frame(tab, bg=_BG)
        fields.pack(fill="x", padx=10, pady=4)

        _make_label(fields, "Target Host:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.send_host = _make_entry(fields, width=18)
        self.send_host.insert(0, "127.0.0.1")
        self.send_host.grid(row=0, column=1, sticky="w", padx=4, pady=3)

        _make_label(fields, "Port:").grid(row=0, column=2, sticky="w", padx=4, pady=3)
        self.send_port = _make_entry(fields, width=8)
        self.send_port.insert(0, str(VRT_DEFAULT_PORT))
        self.send_port.grid(row=0, column=3, sticky="w", padx=4, pady=3)

        _make_label(fields, "Source IP (spoof):").grid(row=0, column=4, sticky="w", padx=4, pady=3)
        self.send_src_ip = _make_entry(fields, width=16)
        self.send_src_ip.grid(row=0, column=5, sticky="w", padx=4, pady=3)

        _make_section(tab, "Packet Source")
        src_frame = tk.Frame(tab, bg=_BG)
        src_frame.pack(fill="x", padx=10, pady=4)

        self.send_source_var = tk.StringVar(value="generate")
        tk.Radiobutton(src_frame, text="Generate packets", variable=self.send_source_var,
                       value="generate", bg=_BG, fg=_FG, selectcolor=_FIELD_BG,
                       activebackground=_BG, activeforeground=_FG, font=_LABEL).pack(side="left", padx=4)
        tk.Radiobutton(src_frame, text="Use crafted packets", variable=self.send_source_var,
                       value="crafted", bg=_BG, fg=_FG, selectcolor=_FIELD_BG,
                       activebackground=_BG, activeforeground=_FG, font=_LABEL).pack(side="left", padx=4)
        tk.Radiobutton(src_frame, text="Load from PCAP", variable=self.send_source_var,
                       value="pcap", bg=_BG, fg=_FG, selectcolor=_FIELD_BG,
                       activebackground=_BG, activeforeground=_FG, font=_LABEL).pack(side="left", padx=4)

        gen_frame = tk.Frame(tab, bg=_BG)
        gen_frame.pack(fill="x", padx=10, pady=4)

        _make_label(gen_frame, "Stream ID:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.send_stream_id = _make_entry(gen_frame, width=12)
        self.send_stream_id.insert(0, "0x0001")
        self.send_stream_id.grid(row=0, column=1, sticky="w", padx=4, pady=3)

        _make_label(gen_frame, "Count:").grid(row=0, column=2, sticky="w", padx=4, pady=3)
        self.send_count = _make_entry(gen_frame, width=8)
        self.send_count.insert(0, "10")
        self.send_count.grid(row=0, column=3, sticky="w", padx=4, pady=3)

        _make_label(gen_frame, "Payload Size:").grid(row=0, column=4, sticky="w", padx=4, pady=3)
        self.send_payload_size = _make_entry(gen_frame, width=8)
        self.send_payload_size.insert(0, "256")
        self.send_payload_size.grid(row=0, column=5, sticky="w", padx=4, pady=3)

        _make_section(tab, "Rate Control")
        rate_frame = tk.Frame(tab, bg=_BG)
        rate_frame.pack(fill="x", padx=10, pady=4)

        _make_label(rate_frame, "Rate (pps):").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.send_rate = _make_entry(rate_frame, width=10)
        self.send_rate.insert(0, "0")
        self.send_rate.grid(row=0, column=1, sticky="w", padx=4, pady=3)

        _make_label(rate_frame, "Burst:").grid(row=0, column=2, sticky="w", padx=4, pady=3)
        self.send_burst = _make_entry(rate_frame, width=6)
        self.send_burst.insert(0, "1")
        self.send_burst.grid(row=0, column=3, sticky="w", padx=4, pady=3)

        _make_label(rate_frame, "Loops:").grid(row=0, column=4, sticky="w", padx=4, pady=3)
        self.send_loops = _make_entry(rate_frame, width=6)
        self.send_loops.insert(0, "1")
        self.send_loops.grid(row=0, column=5, sticky="w", padx=4, pady=3)

        # PCAP file selector
        pcap_frame = tk.Frame(tab, bg=_BG)
        pcap_frame.pack(fill="x", padx=10, pady=4)
        _make_label(pcap_frame, "PCAP File:").pack(side="left", padx=4)
        self.send_pcap_path = _make_entry(pcap_frame, width=50)
        self.send_pcap_path.pack(side="left", padx=4)
        _make_button(pcap_frame, "Browse", self._on_send_browse).pack(side="left", padx=4)

        # Send button
        btn_frame = tk.Frame(tab, bg=_BG)
        btn_frame.pack(fill="x", padx=10, pady=6)
        _make_button(btn_frame, "  Send Packets  ", self._on_send, accent=True).pack(side="left", padx=4)

        _make_section(tab, "Output")
        self.send_output = _make_output(tab, height=8)
        self.send_output.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _on_send_browse(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if path:
            self.send_pcap_path.delete(0, tk.END)
            self.send_pcap_path.insert(0, path)

    def _on_send(self) -> None:
        from vita49_redteam.transport.udp_sender import SenderConfig, UDPSender

        try:
            host = self.send_host.get().strip()
            port = int(self.send_port.get())
            src_ip = self.send_src_ip.get().strip() or None
            rate = float(self.send_rate.get())
            burst = int(self.send_burst.get())
            loops = int(self.send_loops.get())

            config = SenderConfig(
                target_host=host,
                target_port=port,
                source_ip=src_ip,
                rate_pps=rate,
                burst_size=burst,
                loop_count=loops,
            )

            source = self.send_source_var.get()
            if source == "crafted":
                if not self._crafted_packets:
                    messagebox.showwarning("No Packets", "Craft packets first in the Craft tab.")
                    return
                packets = self._crafted_packets
                msg = f"Sending {len(packets)} crafted packet(s)"
            elif source == "pcap":
                pcap_path = self.send_pcap_path.get().strip()
                if not pcap_path:
                    messagebox.showwarning("No PCAP", "Select a PCAP file or choose another source.")
                    return
                packets = self._load_vrt_from_pcap(pcap_path)
                msg = f"Sending {len(packets)} packets from PCAP"
            else:
                sid = int(self.send_stream_id.get(), 0)
                count = int(self.send_count.get())
                payload_size = int(self.send_payload_size.get())
                packets = [
                    make_if_data(stream_id=sid, payload=b"\x00" * payload_size, packet_count=i & 0xF)
                    for i in range(count)
                ]
                msg = f"Sending {len(packets)} generated IF Data packet(s)"

            _output_write(self.send_output, f"{msg} → {host}:{port}...\n", clear=True)
            self.status_var.set("Sending...")
            self.root.update_idletasks()

            # Run in a thread to avoid blocking the GUI
            def _do_send():
                try:
                    with UDPSender(config) as sender:
                        sender.send_loop(packets)
                        result = str(sender.stats)
                    self.root.after(0, lambda: _output_write(self.send_output, f"\n{result}\n"))
                    self.root.after(0, lambda: self.status_var.set(result))
                except Exception as exc:
                    self.root.after(0, lambda: _output_write(self.send_output, f"\nERROR: {exc}\n"))
                    self.root.after(0, lambda: self.status_var.set(f"Send error: {exc}"))

            threading.Thread(target=_do_send, daemon=True).start()

        except Exception as exc:
            messagebox.showerror("Send Error", str(exc))

    def _load_vrt_from_pcap(self, path: str) -> list[VRTPacket]:
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

    # ---------------------------------------------------------------
    # TAB 3: Replay
    # ---------------------------------------------------------------
    def _build_replay_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=_BG)
        self.notebook.add(tab, text="  Replay  ")

        _make_section(tab, "PCAP Input")
        pcap_frame = tk.Frame(tab, bg=_BG)
        pcap_frame.pack(fill="x", padx=10, pady=4)
        _make_label(pcap_frame, "PCAP File:").pack(side="left", padx=4)
        self.replay_pcap = _make_entry(pcap_frame, width=50)
        self.replay_pcap.pack(side="left", padx=4)
        _make_button(pcap_frame, "Browse", self._on_replay_browse).pack(side="left", padx=4)

        _make_section(tab, "Target & Timing")
        fields = tk.Frame(tab, bg=_BG)
        fields.pack(fill="x", padx=10, pady=4)

        _make_label(fields, "Target Host:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.replay_host = _make_entry(fields, width=16)
        self.replay_host.insert(0, "127.0.0.1")
        self.replay_host.grid(row=0, column=1, sticky="w", padx=4, pady=3)

        _make_label(fields, "Port:").grid(row=0, column=2, sticky="w", padx=4, pady=3)
        self.replay_port = _make_entry(fields, width=8)
        self.replay_port.insert(0, str(VRT_DEFAULT_PORT))
        self.replay_port.grid(row=0, column=3, sticky="w", padx=4, pady=3)

        _make_label(fields, "Speed Multiplier:").grid(row=0, column=4, sticky="w", padx=4, pady=3)
        self.replay_speed = _make_entry(fields, width=8)
        self.replay_speed.insert(0, "1.0")
        self.replay_speed.grid(row=0, column=5, sticky="w", padx=4, pady=3)

        _make_label(fields, "Loops:").grid(row=1, column=0, sticky="w", padx=4, pady=3)
        self.replay_loops = _make_entry(fields, width=8)
        self.replay_loops.insert(0, "1")
        self.replay_loops.grid(row=1, column=1, sticky="w", padx=4, pady=3)

        self.replay_preserve_timing = tk.BooleanVar(value=True)
        tk.Checkbutton(fields, text="Preserve original timing", variable=self.replay_preserve_timing,
                       bg=_BG, fg=_FG, selectcolor=_FIELD_BG, activebackground=_BG,
                       activeforeground=_FG, font=_LABEL).grid(row=1, column=2, columnspan=2, sticky="w", padx=4, pady=3)

        _make_section(tab, "Field Modifications")
        mod_frame = tk.Frame(tab, bg=_BG)
        mod_frame.pack(fill="x", padx=10, pady=4)

        _make_label(mod_frame, "New Stream ID (hex):").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.replay_new_sid = _make_entry(mod_frame, width=14)
        self.replay_new_sid.grid(row=0, column=1, sticky="w", padx=4, pady=3)

        _make_label(mod_frame, "Time Offset (int):").grid(row=0, column=2, sticky="w", padx=4, pady=3)
        self.replay_time_offset = _make_entry(mod_frame, width=14)
        self.replay_time_offset.insert(0, "0")
        self.replay_time_offset.grid(row=0, column=3, sticky="w", padx=4, pady=3)

        # Buttons
        btn_frame = tk.Frame(tab, bg=_BG)
        btn_frame.pack(fill="x", padx=10, pady=6)
        _make_button(btn_frame, "  Replay to Target  ", self._on_replay, accent=True).pack(side="left", padx=4)
        _make_button(btn_frame, "  Save Modified PCAP  ", self._on_replay_save).pack(side="left", padx=4)

        _make_section(tab, "Output")
        self.replay_output = _make_output(tab, height=8)
        self.replay_output.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _on_replay_browse(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if path:
            self.replay_pcap.delete(0, tk.END)
            self.replay_pcap.insert(0, path)

    def _get_replay_modifiers(self):
        from vita49_redteam.replay.pcap_engine import modify_stream_id, modify_timestamps
        modifiers = []
        sid_text = self.replay_new_sid.get().strip()
        if sid_text:
            modifiers.append(modify_stream_id(int(sid_text, 0)))
        time_off = int(self.replay_time_offset.get())
        if time_off:
            modifiers.append(modify_timestamps(time_offset=time_off))
        return modifiers

    def _on_replay(self) -> None:
        from vita49_redteam.replay.pcap_engine import PcapReplayEngine, ReplayConfig, load_pcap
        from vita49_redteam.transport.udp_sender import SenderConfig

        try:
            pcap_path = self.replay_pcap.get().strip()
            if not pcap_path:
                messagebox.showwarning("No PCAP", "Select a PCAP file to replay.")
                return

            host = self.replay_host.get().strip()
            port = int(self.replay_port.get())
            speed = float(self.replay_speed.get())
            loops = int(self.replay_loops.get())

            sender_cfg = SenderConfig(target_host=host, target_port=port)
            replay_cfg = ReplayConfig(
                preserve_timing=self.replay_preserve_timing.get(),
                speed_multiplier=speed,
                modifiers=self._get_replay_modifiers(),
                loop_count=loops,
            )

            _output_write(self.replay_output, f"Replaying {pcap_path} → {host}:{port}...\n", clear=True)
            self.status_var.set("Replaying...")
            self.root.update_idletasks()

            def _do_replay():
                try:
                    engine = PcapReplayEngine(sender_cfg, replay_cfg)
                    n = engine.replay_file(pcap_path)
                    result = f"Replay complete: {n} packets sent"
                    self.root.after(0, lambda: _output_write(self.replay_output, f"\n{result}\n"))
                    self.root.after(0, lambda: self.status_var.set(result))
                except Exception as exc:
                    self.root.after(0, lambda: _output_write(self.replay_output, f"\nERROR: {exc}\n"))
                    self.root.after(0, lambda: self.status_var.set(f"Replay error: {exc}"))

            threading.Thread(target=_do_replay, daemon=True).start()
        except Exception as exc:
            messagebox.showerror("Replay Error", str(exc))

    def _on_replay_save(self) -> None:
        from vita49_redteam.replay.pcap_engine import save_modified_pcap

        try:
            pcap_path = self.replay_pcap.get().strip()
            if not pcap_path:
                messagebox.showwarning("No PCAP", "Select a PCAP file first.")
                return
            out_path = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
                title="Save Modified PCAP",
            )
            if not out_path:
                return
            modifiers = self._get_replay_modifiers()
            n = save_modified_pcap(pcap_path, out_path, modifiers)
            _output_write(self.replay_output, f"Saved {n} modified packets to {out_path}\n", clear=True)
            self.status_var.set(f"Saved modified PCAP: {out_path}")
        except Exception as exc:
            messagebox.showerror("Save Error", str(exc))

    # ---------------------------------------------------------------
    # TAB 4: Sniff
    # ---------------------------------------------------------------
    def _build_sniff_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=_BG)
        self.notebook.add(tab, text="  Sniff  ")

        _make_section(tab, "Capture Settings")
        fields = tk.Frame(tab, bg=_BG)
        fields.pack(fill="x", padx=10, pady=4)

        _make_label(fields, "Interface:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.sniff_iface = _make_entry(fields, width=16)
        self.sniff_iface.grid(row=0, column=1, sticky="w", padx=4, pady=3)

        _make_label(fields, "Port:").grid(row=0, column=2, sticky="w", padx=4, pady=3)
        self.sniff_port = _make_entry(fields, width=8)
        self.sniff_port.insert(0, str(VRT_DEFAULT_PORT))
        self.sniff_port.grid(row=0, column=3, sticky="w", padx=4, pady=3)

        _make_label(fields, "Max Packets:").grid(row=0, column=4, sticky="w", padx=4, pady=3)
        self.sniff_count = _make_entry(fields, width=8)
        self.sniff_count.insert(0, "100")
        self.sniff_count.grid(row=0, column=5, sticky="w", padx=4, pady=3)

        _make_label(fields, "Timeout (s):").grid(row=1, column=0, sticky="w", padx=4, pady=3)
        self.sniff_timeout = _make_entry(fields, width=8)
        self.sniff_timeout.insert(0, "10")
        self.sniff_timeout.grid(row=1, column=1, sticky="w", padx=4, pady=3)

        btn_frame = tk.Frame(tab, bg=_BG)
        btn_frame.pack(fill="x", padx=10, pady=6)
        self._sniff_start_btn = _make_button(btn_frame, "  Start Capture  ", self._on_sniff_start, accent=True)
        self._sniff_start_btn.pack(side="left", padx=4)
        _make_button(btn_frame, "  Save Capture to PCAP  ", self._on_sniff_save).pack(side="left", padx=4)

        _make_section(tab, "Captured Packets")
        self.sniff_output = _make_output(tab, height=16)
        self.sniff_output.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._sniff_captured = []

    def _on_sniff_start(self) -> None:
        try:
            port = int(self.sniff_port.get())
            count = int(self.sniff_count.get())
            timeout = int(self.sniff_timeout.get())
            iface = self.sniff_iface.get().strip() or None

            _output_write(self.sniff_output, f"Starting capture on port {port}...\n", clear=True)
            self.status_var.set("Sniffing...")
            self._sniff_start_btn.config(state="disabled")
            self.root.update_idletasks()

            def _do_sniff():
                try:
                    from scapy.all import sniff as scapy_sniff
                    from vita49_redteam.scapy_layers.layers import VRT_Header

                    kwargs = {"filter": f"udp port {port}"}
                    if iface:
                        kwargs["iface"] = iface
                    if count > 0:
                        kwargs["count"] = count
                    if timeout > 0:
                        kwargs["timeout"] = timeout

                    captured = scapy_sniff(**kwargs)
                    self._sniff_captured = captured

                    lines = [f"Captured {len(captured)} packet(s)\n"]
                    for i, pkt in enumerate(captured):
                        if pkt.haslayer(VRT_Header):
                            vrt = pkt[VRT_Header]
                            sid = getattr(vrt, "stream_id", "N/A")
                            sid_str = f"0x{sid:08X}" if isinstance(sid, int) else str(sid)
                            lines.append(
                                f"  [{i:4d}] VRT type={vrt.pkt_type:#x} count={vrt.packet_count} "
                                f"size={vrt.packet_size}w stream_id={sid_str}"
                            )
                        else:
                            lines.append(f"  [{i:4d}] UDP packet ({len(bytes(pkt))} bytes)")

                    result = "\n".join(lines)
                    self.root.after(0, lambda: _output_write(self.sniff_output, result))
                    self.root.after(0, lambda: self.status_var.set(f"Captured {len(captured)} packet(s)"))
                except Exception as exc:
                    self.root.after(0, lambda: _output_write(self.sniff_output, f"\nERROR: {exc}\n"))
                    self.root.after(0, lambda: self.status_var.set(f"Sniff error: {exc}"))
                finally:
                    self.root.after(0, lambda: self._sniff_start_btn.config(state="normal"))

            threading.Thread(target=_do_sniff, daemon=True).start()
        except Exception as exc:
            messagebox.showerror("Sniff Error", str(exc))
            self._sniff_start_btn.config(state="normal")

    def _on_sniff_save(self) -> None:
        if not self._sniff_captured:
            messagebox.showwarning("No Capture", "Run a capture first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Save Capture",
        )
        if not path:
            return
        from scapy.all import wrpcap
        wrpcap(path, self._sniff_captured)
        _output_write(self.sniff_output, f"\nSaved {len(self._sniff_captured)} packets to {path}\n")
        self.status_var.set(f"Saved capture to {path}")

    # ---------------------------------------------------------------
    # TAB 5: Report
    # ---------------------------------------------------------------
    def _build_report_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=_BG)
        self.notebook.add(tab, text="  Report  ")

        _make_section(tab, "PCAP Analysis")
        pcap_frame = tk.Frame(tab, bg=_BG)
        pcap_frame.pack(fill="x", padx=10, pady=4)
        _make_label(pcap_frame, "PCAP File:").pack(side="left", padx=4)
        self.report_pcap = _make_entry(pcap_frame, width=50)
        self.report_pcap.pack(side="left", padx=4)
        _make_button(pcap_frame, "Browse", self._on_report_browse).pack(side="left", padx=4)

        btn_frame = tk.Frame(tab, bg=_BG)
        btn_frame.pack(fill="x", padx=10, pady=6)
        _make_button(btn_frame, "  Generate Report  ", self._on_report, accent=True).pack(side="left", padx=4)

        _make_section(tab, "Report Output")
        self.report_output = _make_output(tab, height=20)
        self.report_output.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _on_report_browse(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if path:
            self.report_pcap.delete(0, tk.END)
            self.report_pcap.insert(0, path)

    def _on_report(self) -> None:
        from vita49_redteam.replay.pcap_engine import load_pcap

        try:
            pcap_path = self.report_pcap.get().strip()
            if not pcap_path:
                messagebox.showwarning("No PCAP", "Select a PCAP file to analyze.")
                return

            packets = load_pcap(pcap_path)
            if not packets:
                _output_write(self.report_output, "No VRT packets found in the PCAP.\n", clear=True)
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

            lines = [
                f"{'=' * 55}",
                f"  VITA 49 PCAP Report: {pcap_path}",
                f"{'=' * 55}",
                f"",
                f"  Total UDP packets:   {len(packets)}",
                f"  Parsed as VRT:       {parsed_count}",
                f"  Total VRT bytes:     {total_bytes}",
            ]

            if packets:
                duration = packets[-1].timestamp - packets[0].timestamp
                lines.append(f"  Capture duration:    {duration:.3f}s")
                if duration > 0:
                    lines.append(f"  Avg packet rate:     {len(packets) / duration:.1f} pps")

            lines.append(f"\n  Packet Types:")
            for tname, cnt in sorted(pkt_types.items(), key=lambda x: -x[1]):
                lines.append(f"    {tname:30s} {cnt}")

            lines.append(f"\n  Stream IDs:")
            for sid, cnt in sorted(stream_ids.items()):
                lines.append(f"    0x{sid:08X}  {cnt} packets")

            _output_write(self.report_output, "\n".join(lines) + "\n", clear=True)
            self.status_var.set(f"Report: {len(packets)} packets, {parsed_count} parsed")
        except Exception as exc:
            messagebox.showerror("Report Error", str(exc))

    # ---------------------------------------------------------------
    # Run
    # ---------------------------------------------------------------
    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    """Entry point for the GUI."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app = VRT_RedTeamGUI()
    app.run()


if __name__ == "__main__":
    main()
