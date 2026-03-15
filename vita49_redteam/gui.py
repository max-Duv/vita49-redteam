"""Modern Tkinter GUI for the VITA 49 (VRT) toolkit."""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from vita49_redteam.core.constants import PacketType, TSI, TSF, VRT_DEFAULT_PORT
from vita49_redteam.core.packet import VRTPacket, make_if_data

logger = logging.getLogger(__name__)

APP_BG = "#0c1224"
SHELL_BG = "#111a31"
CARD_BG = "#17233d"
CARD_ALT = "#0f1830"
BORDER = "#273a61"
TEXT = "#eef4ff"
MUTED = "#93a6cd"
ACCENT = "#69d5ff"
ACCENT_ALT = "#7cf0c4"
WARN = "#ffc27c"
OUTPUT_BG = "#09101f"

FONT_UI = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI Semibold", 24)
FONT_SUB = ("Segoe UI", 10)
FONT_SECTION = ("Segoe UI Semibold", 12)
FONT_LABEL = ("Segoe UI", 9)
FONT_MONO = ("Cascadia Code", 10)

PKT_TYPE_MAP = {
    "IF Data": PacketType.IF_DATA_WITH_STREAM_ID,
    "IF Context": PacketType.IF_CONTEXT,
    "Ext Data": PacketType.EXT_DATA_WITH_STREAM_ID,
    "Ext Context": PacketType.EXT_CONTEXT,
}
TSI_MAP = {"None": TSI.NONE, "UTC": TSI.UTC, "GPS": TSI.GPS, "Other": TSI.OTHER}
TSF_MAP = {
    "None": TSF.NONE,
    "Sample Count": TSF.SAMPLE_COUNT,
    "Real-Time (ps)": TSF.REAL_TIME,
    "Free-Running": TSF.FREE_RUNNING,
}


def _hex_dump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def _write_pcap(packets: list[VRTPacket], path: str) -> None:
    from scapy.all import Ether, IP, UDP, wrpcap

    scapy_packets = []
    for packet in packets:
        scapy_packets.append(
            Ether() / IP(dst="127.0.0.1") / UDP(sport=12345, dport=VRT_DEFAULT_PORT) / packet.pack()
        )
    wrpcap(path, scapy_packets)


def _output_write(widget: scrolledtext.ScrolledText, text: str, clear: bool = False) -> None:
    widget.config(state="normal")
    if clear:
        widget.delete("1.0", tk.END)
    widget.insert(tk.END, text)
    widget.see(tk.END)
    widget.config(state="disabled")


class VRT_RedTeamGUI:
    """Top-level Tkinter application for the VRT toolkit."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("VITA 49 (VRT) Toolkit")
        self.root.geometry("1280x860")
        self.root.minsize(1080, 760)
        self.root.configure(bg=APP_BG)

        self._crafted_packets: list[VRTPacket] = []
        self._sniff_captured = []
        self.status_var = tk.StringVar(value="Ready")
        self.status_detail_var = tk.StringVar(value="No active background tasks.")
        self.metric_crafted = tk.StringVar(value="0")
        self.metric_captured = tk.StringVar(value="0")
        self.metric_reports = tk.StringVar(value="0")

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=APP_BG, foreground=TEXT, font=FONT_UI)
        style.configure("App.TFrame", background=APP_BG)
        style.configure("Hero.TFrame", background=SHELL_BG)
        style.configure("Card.TFrame", background=CARD_BG)
        style.configure("Alt.TFrame", background=CARD_ALT)
        style.configure("Title.TLabel", background=SHELL_BG, foreground=TEXT, font=FONT_TITLE)
        style.configure("Subtitle.TLabel", background=SHELL_BG, foreground=MUTED, font=FONT_SUB)
        style.configure("Section.TLabel", background=CARD_BG, foreground=TEXT, font=FONT_SECTION)
        style.configure("Muted.TLabel", background=CARD_BG, foreground=MUTED, font=FONT_LABEL)
        style.configure("Field.TLabel", background=CARD_BG, foreground=MUTED, font=FONT_LABEL)
        style.configure("MetricValue.TLabel", background=CARD_ALT, foreground=TEXT, font=("Segoe UI Semibold", 18))
        style.configure("MetricName.TLabel", background=CARD_ALT, foreground=MUTED, font=FONT_LABEL)
        style.configure("StatusValue.TLabel", background=CARD_BG, foreground=TEXT, font=("Segoe UI Semibold", 11))
        style.configure("StatusName.TLabel", background=CARD_BG, foreground=MUTED, font=FONT_LABEL)
        style.configure("Field.TEntry", fieldbackground="#0d1730", foreground=TEXT, bordercolor=BORDER, lightcolor=BORDER)
        style.configure(
            "Field.TCombobox",
            fieldbackground="#0d1730",
            background="#0d1730",
            foreground=TEXT,
            arrowcolor=ACCENT,
            bordercolor=BORDER,
            lightcolor=BORDER,
            darkcolor=BORDER,
        )
        style.map(
            "Field.TCombobox",
            fieldbackground=[("readonly", "#0d1730")],
            foreground=[("readonly", TEXT)],
            selectbackground=[("readonly", "#0d1730")],
            selectforeground=[("readonly", TEXT)],
        )
        style.configure("Accent.TButton", background=ACCENT, foreground="#05111c", borderwidth=0, padding=(16, 10), font=("Segoe UI Semibold", 10))
        style.map("Accent.TButton", background=[("active", ACCENT_ALT), ("pressed", ACCENT_ALT)])
        style.configure("Soft.TButton", background="#22365d", foreground=TEXT, borderwidth=0, padding=(16, 10), font=("Segoe UI Semibold", 10))
        style.map("Soft.TButton", background=[("active", "#31497b"), ("pressed", "#31497b")])
        style.configure("Shell.TNotebook", background=APP_BG, borderwidth=0, tabmargins=(0, 6, 0, 0))
        style.configure("Shell.TNotebook.Tab", background=SHELL_BG, foreground=MUTED, borderwidth=0, padding=(18, 10), font=("Segoe UI Semibold", 10))
        style.map("Shell.TNotebook.Tab", background=[("selected", CARD_BG), ("active", SHELL_BG)], foreground=[("selected", TEXT), ("active", TEXT)])

    def _build_ui(self) -> None:
        shell = ttk.Frame(self.root, style="App.TFrame", padding=18)
        shell.pack(fill="both", expand=True)
        self._build_header(shell)
        self.notebook = ttk.Notebook(shell, style="Shell.TNotebook")
        self.notebook.pack(fill="both", expand=True, pady=(18, 0))
        self._build_craft_tab()
        self._build_send_tab()
        self._build_replay_tab()
        self._build_sniff_tab()
        self._build_report_tab()
        self._build_footer(shell)

    def _build_header(self, parent) -> None:
        hero = ttk.Frame(parent, style="Hero.TFrame", padding=20)
        hero.pack(fill="x")
        left = ttk.Frame(hero, style="Hero.TFrame")
        left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="VITA 49 Toolkit Console", style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text="A cleaner desktop shell for packet crafting, replay, live capture, and PCAP analysis.", style="Subtitle.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=(6, 0))
        chip_row = ttk.Frame(left, style="Hero.TFrame")
        chip_row.pack(anchor="w", pady=(14, 0))
        for text, color in (("Desktop GUI", ACCENT), ("VRT 49.0 / 49.2", ACCENT_ALT), ("Tabbed workflows", WARN)):
            tk.Label(chip_row, text=text, bg=color, fg="#05111c", padx=10, pady=4, bd=0).pack(side="left", padx=(0, 10))
        metrics = ttk.Frame(hero, style="Hero.TFrame")
        metrics.pack(side="right", anchor="n")
        self._metric_card(metrics, self.metric_crafted, "Crafted Packets").pack(side="left", padx=(0, 10))
        self._metric_card(metrics, self.metric_captured, "Captured Frames").pack(side="left", padx=(0, 10))
        self._metric_card(metrics, self.metric_reports, "Reports Run").pack(side="left")

    def _metric_card(self, parent, value_var: tk.StringVar, label: str) -> ttk.Frame:
        card = ttk.Frame(parent, style="Alt.TFrame", padding=(18, 14))
        ttk.Label(card, textvariable=value_var, style="MetricValue.TLabel").pack(anchor="w")
        ttk.Label(card, text=label, style="MetricName.TLabel").pack(anchor="w", pady=(2, 0))
        return card

    def _build_footer(self, parent) -> None:
        footer = ttk.Frame(parent, style="Card.TFrame", padding=(18, 12))
        footer.pack(fill="x", pady=(16, 0))
        left = ttk.Frame(footer, style="Card.TFrame")
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="Status", style="StatusName.TLabel").pack(anchor="w")
        ttk.Label(left, textvariable=self.status_var, style="StatusValue.TLabel").pack(anchor="w", pady=(2, 0))
        ttk.Label(left, textvariable=self.status_detail_var, style="StatusName.TLabel", wraplength=840).pack(anchor="w", pady=(4, 0))

    def _set_status(self, title: str, detail: str) -> None:
        self.status_var.set(title)
        self.status_detail_var.set(detail)

    def _new_tab(self, name: str, subtitle: str) -> ttk.Frame:
        tab = ttk.Frame(self.notebook, style="App.TFrame", padding=12)
        self.notebook.add(tab, text=f"  {name}  ")
        card = ttk.Frame(tab, style="Card.TFrame", padding=(18, 14))
        card.pack(fill="x", pady=(0, 12))
        ttk.Label(card, text=name, style="Section.TLabel").pack(anchor="w")
        ttk.Label(card, text=subtitle, style="Muted.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(4, 0))
        body = ttk.Frame(tab, style="App.TFrame")
        body.pack(fill="both", expand=True)
        return body

    def _make_output(self, parent, height: int) -> scrolledtext.ScrolledText:
        widget = scrolledtext.ScrolledText(parent, height=height, bg=OUTPUT_BG, fg=TEXT, insertbackground=TEXT, relief="flat", bd=0, padx=14, pady=14, font=FONT_MONO, wrap="none")
        widget.configure(highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT)
        widget.config(state="disabled")
        return widget

    def _form_card(self, parent, title: str, body: str) -> tuple[ttk.Frame, ttk.Frame]:
        card = ttk.Frame(parent, style="Card.TFrame", padding=18)
        card.pack(fill="x", pady=(0, 12))
        ttk.Label(card, text=title, style="Section.TLabel").pack(anchor="w")
        ttk.Label(card, text=body, style="Muted.TLabel", wraplength=560, justify="left").pack(anchor="w", pady=(4, 12))
        grid = ttk.Frame(card, style="Card.TFrame")
        grid.pack(fill="x")
        return card, grid

    def _field(self, parent, row: int, col: int, label: str, widget) -> None:
        parent.columnconfigure(col * 2 + 1, weight=1)
        ttk.Label(parent, text=label, style="Field.TLabel").grid(row=row, column=col * 2, sticky="w", padx=(0, 10), pady=(0, 6))
        widget.grid(row=row, column=col * 2 + 1, sticky="ew", padx=(0, 18), pady=(0, 12))

    def _entry(self, parent, width: int = 18) -> ttk.Entry:
        return ttk.Entry(parent, width=width, style="Field.TEntry")

    def _combo(self, parent, values: list[str], width: int = 18) -> ttk.Combobox:
        combo = ttk.Combobox(parent, values=values, width=width, state="readonly", style="Field.TCombobox")
        combo.current(0)
        return combo

    def _button(self, parent, text: str, command, accent: bool = False) -> ttk.Button:
        return ttk.Button(parent, text=text, command=command, style="Accent.TButton" if accent else "Soft.TButton")

    def _build_craft_tab(self) -> None:
        body = self._new_tab("Craft", "Build packets, inspect the result, and export to PCAP.")
        form_card, fields = self._form_card(body, "Packet Definition", "Set packet family, timing fields, and optional metadata.")
        self.craft_pkt_type = self._combo(fields, list(PKT_TYPE_MAP.keys()))
        self.craft_stream_id = self._entry(fields)
        self.craft_stream_id.insert(0, "0x0001")
        self.craft_count = self._entry(fields, 10)
        self.craft_count.insert(0, "1")
        self.craft_payload_size = self._entry(fields, 12)
        self.craft_payload_size.insert(0, "0")
        self.craft_tsi = self._combo(fields, list(TSI_MAP.keys()), 14)
        self.craft_tsf = self._combo(fields, list(TSF_MAP.keys()), 18)
        self.craft_int_ts = self._entry(fields, 14)
        self.craft_int_ts.insert(0, "0")
        self.craft_frac_ts = self._entry(fields, 16)
        self.craft_frac_ts.insert(0, "0")
        self.craft_class_id = self._entry(fields, 22)
        self.craft_trailer = self._entry(fields, 16)
        self._field(fields, 0, 0, "Packet Type", self.craft_pkt_type)
        self._field(fields, 0, 1, "Stream ID (hex)", self.craft_stream_id)
        self._field(fields, 0, 2, "Count", self.craft_count)
        self._field(fields, 1, 0, "Payload Size (bytes)", self.craft_payload_size)
        self._field(fields, 1, 1, "TSI", self.craft_tsi)
        self._field(fields, 1, 2, "TSF", self.craft_tsf)
        self._field(fields, 2, 0, "Integer Timestamp", self.craft_int_ts)
        self._field(fields, 2, 1, "Fractional Timestamp", self.craft_frac_ts)
        self._field(fields, 3, 0, "Class ID (OUI:info:pkt)", self.craft_class_id)
        self._field(fields, 3, 1, "Trailer (hex)", self.craft_trailer)
        actions = ttk.Frame(form_card, style="Card.TFrame")
        actions.pack(fill="x")
        self._button(actions, "Craft and Preview", self._on_craft, accent=True).pack(side="left")
        self._button(actions, "Save to PCAP", self._on_craft_save).pack(side="left", padx=(10, 0))
        out = ttk.Frame(body, style="Card.TFrame", padding=18)
        out.pack(fill="both", expand=True)
        ttk.Label(out, text="Hex Preview", style="Section.TLabel").pack(anchor="w")
        ttk.Label(out, text="Generated packets are rendered as a structured hex dump.", style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
        self.craft_output = self._make_output(out, 20)
        self.craft_output.pack(fill="both", expand=True)

    def _craft_packets(self) -> list[VRTPacket]:
        packet_type = PKT_TYPE_MAP[self.craft_pkt_type.get()]
        stream_id = int(self.craft_stream_id.get(), 0)
        count = int(self.craft_count.get())
        payload_size = int(self.craft_payload_size.get())
        tsi = TSI_MAP[self.craft_tsi.get()]
        tsf = TSF_MAP[self.craft_tsf.get()]
        integer_timestamp = int(self.craft_int_ts.get())
        fractional_timestamp = int(self.craft_frac_ts.get())
        packets = []
        for index in range(count):
            packet = VRTPacket(
                packet_type=packet_type,
                stream_id=stream_id,
                packet_count=index & 0xF,
                tsi=tsi,
                tsf=tsf,
                integer_timestamp=integer_timestamp,
                fractional_timestamp=fractional_timestamp,
                payload=b"\x00" * payload_size,
            )
            class_id = self.craft_class_id.get().strip()
            if class_id:
                parts = class_id.split(":")
                packet.with_class_id(
                    oui=int(parts[0], 16),
                    info_class=int(parts[1], 16) if len(parts) > 1 else 0,
                    pkt_class=int(parts[2], 16) if len(parts) > 2 else 0,
                )
            trailer = self.craft_trailer.get().strip()
            if trailer:
                packet.with_trailer(raw=int(trailer, 0))
            packets.append(packet)
        return packets

    def _on_craft(self) -> None:
        try:
            packets = self._craft_packets()
            self._crafted_packets = packets
            self.metric_crafted.set(str(len(packets)))
            lines = [f"Crafted {len(packets)} packet(s)\n"]
            for index, packet in enumerate(packets):
                raw_data = packet.pack()
                lines.append(f"Packet {index} | {len(raw_data)} bytes | {packet.compute_packet_size_words()} words")
                lines.append(repr(packet))
                lines.append(_hex_dump(raw_data))
                lines.append("")
            _output_write(self.craft_output, "\n".join(lines), clear=True)
            self._set_status("Craft complete", f"Prepared {len(packets)} packet(s) for later send or export.")
        except Exception as exc:
            messagebox.showerror("Craft Error", str(exc))
            self._set_status("Craft failed", str(exc))

    def _on_craft_save(self) -> None:
        try:
            packets = self._craft_packets()
            path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")], title="Save PCAP")
            if not path:
                return
            self._crafted_packets = packets
            _write_pcap(packets, path)
            _output_write(self.craft_output, f"Saved {len(packets)} packet(s) to {path}\n", clear=True)
            self.metric_crafted.set(str(len(packets)))
            self._set_status("PCAP saved", f"Crafted packet set written to {path}.")
        except Exception as exc:
            messagebox.showerror("Save Error", str(exc))
            self._set_status("Save failed", str(exc))

    def _build_send_tab(self) -> None:
        body = self._new_tab("Send", "Push generated, crafted, or PCAP-derived packets to a configured destination.")
        top = ttk.Frame(body, style="App.TFrame")
        top.pack(fill="both", expand=True)
        left = ttk.Frame(top, style="App.TFrame")
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(top, style="App.TFrame")
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))
        card, fields = self._form_card(left, "Target and Source", "Configure the destination endpoint and optional spoof source.")
        self.send_host = self._entry(fields)
        self.send_host.insert(0, "127.0.0.1")
        self.send_port = self._entry(fields, 10)
        self.send_port.insert(0, str(VRT_DEFAULT_PORT))
        self.send_src_ip = self._entry(fields)
        self._field(fields, 0, 0, "Target Host", self.send_host)
        self._field(fields, 0, 1, "Port", self.send_port)
        self._field(fields, 1, 0, "Source IP (optional)", self.send_src_ip)

        source_card = ttk.Frame(left, style="Card.TFrame", padding=18)
        source_card.pack(fill="x")
        ttk.Label(source_card, text="Packet Source", style="Section.TLabel").pack(anchor="w")
        ttk.Label(source_card, text="Choose generated packets, crafted packets, or a PCAP file.", style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
        self.send_source_var = tk.StringVar(value="generate")
        for label, value in (("Generate packets", "generate"), ("Use crafted packets", "crafted"), ("Load from PCAP", "pcap")):
            ttk.Radiobutton(source_card, text=label, variable=self.send_source_var, value=value).pack(anchor="w", pady=2)

        gen = ttk.Frame(source_card, style="Card.TFrame")
        gen.pack(fill="x", pady=(12, 0))
        self.send_stream_id = self._entry(gen, 14)
        self.send_stream_id.insert(0, "0x0001")
        self.send_count = self._entry(gen, 10)
        self.send_count.insert(0, "10")
        self.send_payload_size = self._entry(gen, 10)
        self.send_payload_size.insert(0, "256")
        self._field(gen, 0, 0, "Stream ID", self.send_stream_id)
        self._field(gen, 0, 1, "Count", self.send_count)
        self._field(gen, 0, 2, "Payload Size", self.send_payload_size)

        selector = ttk.Frame(source_card, style="Card.TFrame")
        selector.pack(fill="x", pady=(4, 0))
        ttk.Label(selector, text="PCAP File", style="Field.TLabel").pack(anchor="w")
        row = ttk.Frame(selector, style="Card.TFrame")
        row.pack(fill="x", pady=(6, 0))
        self.send_pcap_path = self._entry(row, 52)
        self.send_pcap_path.pack(side="left", fill="x", expand=True)
        self._button(row, "Browse", self._on_send_browse).pack(side="left", padx=(10, 0))

        rate_card, rate = self._form_card(right, "Rate Control", "Shape the send rate, burst size, and loop count.")
        self.send_rate = self._entry(rate, 10)
        self.send_rate.insert(0, "0")
        self.send_burst = self._entry(rate, 10)
        self.send_burst.insert(0, "1")
        self.send_loops = self._entry(rate, 10)
        self.send_loops.insert(0, "1")
        self._field(rate, 0, 0, "Rate (pps)", self.send_rate)
        self._field(rate, 0, 1, "Burst", self.send_burst)
        self._field(rate, 0, 2, "Loops", self.send_loops)
        self._button(rate_card, "Send Packets", self._on_send, accent=True).pack(anchor="w")

        out = ttk.Frame(right, style="Card.TFrame", padding=18)
        out.pack(fill="both", expand=True)
        ttk.Label(out, text="Send Console", style="Section.TLabel").pack(anchor="w")
        ttk.Label(out, text="Transmission progress and sender statistics are logged here.", style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
        self.send_output = self._make_output(out, 18)
        self.send_output.pack(fill="both", expand=True)

    def _on_send_browse(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if path:
            self.send_pcap_path.delete(0, tk.END)
            self.send_pcap_path.insert(0, path)

    def _load_vrt_from_pcap(self, path: str) -> list[VRTPacket]:
        from vita49_redteam.replay.pcap_engine import load_pcap

        captured = load_pcap(path)
        packets = []
        for item in captured:
            if item.parsed:
                packets.append(item.parsed)
            else:
                try:
                    packets.append(VRTPacket.unpack(item.raw_vrt))
                except Exception:
                    pass
        return packets

    def _on_send(self) -> None:
        from vita49_redteam.transport.udp_sender import SenderConfig, UDPSender

        try:
            config = SenderConfig(
                target_host=self.send_host.get().strip(),
                target_port=int(self.send_port.get()),
                source_ip=self.send_src_ip.get().strip() or None,
                rate_pps=float(self.send_rate.get()),
                burst_size=int(self.send_burst.get()),
                loop_count=int(self.send_loops.get()),
            )
            source = self.send_source_var.get()
            if source == "crafted":
                if not self._crafted_packets:
                    messagebox.showwarning("No Packets", "Craft packets first in the Craft tab.")
                    return
                packets = self._crafted_packets
                label = f"Sending {len(packets)} crafted packet(s)"
            elif source == "pcap":
                pcap_path = self.send_pcap_path.get().strip()
                if not pcap_path:
                    messagebox.showwarning("No PCAP", "Select a PCAP file or choose another source.")
                    return
                packets = self._load_vrt_from_pcap(pcap_path)
                label = f"Sending {len(packets)} packet(s) from PCAP"
            else:
                stream_id = int(self.send_stream_id.get(), 0)
                count = int(self.send_count.get())
                payload_size = int(self.send_payload_size.get())
                packets = [make_if_data(stream_id=stream_id, payload=b"\x00" * payload_size, packet_count=i & 0xF) for i in range(count)]
                label = f"Sending {len(packets)} generated IF Data packet(s)"
            _output_write(self.send_output, f"{label} -> {config.target_host}:{config.target_port}\n", clear=True)
            self._set_status("Sending", f"Dispatching {len(packets)} packet(s) to {config.target_host}:{config.target_port}.")

            def _do_send() -> None:
                try:
                    with UDPSender(config) as sender:
                        sender.send_loop(packets)
                        result = str(sender.stats)
                    self.root.after(0, lambda: _output_write(self.send_output, f"\n{result}\n"))
                    self.root.after(0, lambda: self._set_status("Send complete", result))
                except Exception as exc:
                    self.root.after(0, lambda: _output_write(self.send_output, f"\nERROR: {exc}\n"))
                    self.root.after(0, lambda: self._set_status("Send failed", str(exc)))

            threading.Thread(target=_do_send, daemon=True).start()
        except Exception as exc:
            messagebox.showerror("Send Error", str(exc))
            self._set_status("Send failed", str(exc))

    def _build_replay_tab(self) -> None:
        body = self._new_tab("Replay", "Load PCAP data, apply simple field changes, and replay to a selected target.")
        top = ttk.Frame(body, style="App.TFrame")
        top.pack(fill="both", expand=True)
        left = ttk.Frame(top, style="App.TFrame")
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(top, style="App.TFrame")
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))

        source_card = ttk.Frame(left, style="Card.TFrame", padding=18)
        source_card.pack(fill="x")
        ttk.Label(source_card, text="PCAP Source", style="Section.TLabel").pack(anchor="w")
        ttk.Label(source_card, text="Select the PCAP capture to replay or transform.", style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
        row = ttk.Frame(source_card, style="Card.TFrame")
        row.pack(fill="x")
        self.replay_pcap = self._entry(row, 56)
        self.replay_pcap.pack(side="left", fill="x", expand=True)
        self._button(row, "Browse", self._on_replay_browse).pack(side="left", padx=(10, 0))

        timing_card, timing = self._form_card(left, "Target and Timing", "Control destination, speed multiplier, and loop behavior.")
        self.replay_host = self._entry(timing)
        self.replay_host.insert(0, "127.0.0.1")
        self.replay_port = self._entry(timing, 10)
        self.replay_port.insert(0, str(VRT_DEFAULT_PORT))
        self.replay_speed = self._entry(timing, 10)
        self.replay_speed.insert(0, "1.0")
        self.replay_loops = self._entry(timing, 10)
        self.replay_loops.insert(0, "1")
        self._field(timing, 0, 0, "Target Host", self.replay_host)
        self._field(timing, 0, 1, "Port", self.replay_port)
        self._field(timing, 0, 2, "Speed Multiplier", self.replay_speed)
        self._field(timing, 1, 0, "Loops", self.replay_loops)
        self.replay_preserve_timing = tk.BooleanVar(value=True)
        ttk.Checkbutton(timing, text="Preserve original timing", variable=self.replay_preserve_timing).grid(row=1, column=2, columnspan=4, sticky="w", pady=(0, 12))

        modify_card, modify = self._form_card(right, "Field Modifications", "Apply simple stream-id or timestamp adjustments before replay.")
        self.replay_new_sid = self._entry(modify, 18)
        self.replay_time_offset = self._entry(modify, 18)
        self.replay_time_offset.insert(0, "0")
        self._field(modify, 0, 0, "New Stream ID (hex)", self.replay_new_sid)
        self._field(modify, 0, 1, "Time Offset", self.replay_time_offset)
        actions = ttk.Frame(modify_card, style="Card.TFrame")
        actions.pack(fill="x")
        self._button(actions, "Replay to Target", self._on_replay, accent=True).pack(side="left")
        self._button(actions, "Save Modified PCAP", self._on_replay_save).pack(side="left", padx=(10, 0))

        out = ttk.Frame(right, style="Card.TFrame", padding=18)
        out.pack(fill="both", expand=True)
        ttk.Label(out, text="Replay Console", style="Section.TLabel").pack(anchor="w")
        ttk.Label(out, text="Replay progress and completion messages are shown here.", style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
        self.replay_output = self._make_output(out, 18)
        self.replay_output.pack(fill="both", expand=True)

    def _on_replay_browse(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if path:
            self.replay_pcap.delete(0, tk.END)
            self.replay_pcap.insert(0, path)

    def _get_replay_modifiers(self):
        from vita49_redteam.replay.pcap_engine import modify_stream_id, modify_timestamps

        modifiers = []
        stream_id = self.replay_new_sid.get().strip()
        if stream_id:
            modifiers.append(modify_stream_id(int(stream_id, 0)))
        time_offset = int(self.replay_time_offset.get())
        if time_offset:
            modifiers.append(modify_timestamps(time_offset=time_offset))
        return modifiers

    def _on_replay(self) -> None:
        from vita49_redteam.replay.pcap_engine import PcapReplayEngine, ReplayConfig
        from vita49_redteam.transport.udp_sender import SenderConfig

        try:
            pcap_path = self.replay_pcap.get().strip()
            if not pcap_path:
                messagebox.showwarning("No PCAP", "Select a PCAP file to replay.")
                return
            sender_config = SenderConfig(target_host=self.replay_host.get().strip(), target_port=int(self.replay_port.get()))
            replay_config = ReplayConfig(
                preserve_timing=self.replay_preserve_timing.get(),
                speed_multiplier=float(self.replay_speed.get()),
                modifiers=self._get_replay_modifiers(),
                loop_count=int(self.replay_loops.get()),
            )
            _output_write(self.replay_output, f"Replaying {pcap_path} -> {sender_config.target_host}:{sender_config.target_port}\n", clear=True)
            self._set_status("Replay running", f"Streaming packets from {pcap_path}.")

            def _do_replay() -> None:
                try:
                    engine = PcapReplayEngine(sender_config, replay_config)
                    packet_count = engine.replay_file(pcap_path)
                    message = f"Replay complete: {packet_count} packet(s) sent"
                    self.root.after(0, lambda: _output_write(self.replay_output, f"\n{message}\n"))
                    self.root.after(0, lambda: self._set_status("Replay complete", message))
                except Exception as exc:
                    self.root.after(0, lambda: _output_write(self.replay_output, f"\nERROR: {exc}\n"))
                    self.root.after(0, lambda: self._set_status("Replay failed", str(exc)))

            threading.Thread(target=_do_replay, daemon=True).start()
        except Exception as exc:
            messagebox.showerror("Replay Error", str(exc))
            self._set_status("Replay failed", str(exc))

    def _on_replay_save(self) -> None:
        from vita49_redteam.replay.pcap_engine import save_modified_pcap

        try:
            pcap_path = self.replay_pcap.get().strip()
            if not pcap_path:
                messagebox.showwarning("No PCAP", "Select a PCAP file first.")
                return
            output_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")], title="Save Modified PCAP")
            if not output_path:
                return
            packet_count = save_modified_pcap(pcap_path, output_path, self._get_replay_modifiers())
            _output_write(self.replay_output, f"Saved {packet_count} modified packet(s) to {output_path}\n", clear=True)
            self._set_status("Replay export saved", f"Modified PCAP written to {output_path}.")
        except Exception as exc:
            messagebox.showerror("Save Error", str(exc))
            self._set_status("Replay export failed", str(exc))

    def _build_sniff_tab(self) -> None:
        body = self._new_tab("Sniff", "Capture VRT traffic from a network interface and review the live summary.")
        card, fields = self._form_card(body, "Capture Settings", "Choose interface, VRT port, limits, and timeout.")
        self.sniff_iface = self._entry(fields)
        self.sniff_port = self._entry(fields, 10)
        self.sniff_port.insert(0, str(VRT_DEFAULT_PORT))
        self.sniff_count = self._entry(fields, 10)
        self.sniff_count.insert(0, "100")
        self.sniff_timeout = self._entry(fields, 10)
        self.sniff_timeout.insert(0, "10")
        self._field(fields, 0, 0, "Interface", self.sniff_iface)
        self._field(fields, 0, 1, "Port", self.sniff_port)
        self._field(fields, 0, 2, "Max Packets", self.sniff_count)
        self._field(fields, 1, 0, "Timeout (s)", self.sniff_timeout)
        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(fill="x")
        self._sniff_start_btn = self._button(actions, "Start Capture", self._on_sniff_start, accent=True)
        self._sniff_start_btn.pack(side="left")
        self._button(actions, "Save Capture to PCAP", self._on_sniff_save).pack(side="left", padx=(10, 0))

        out = ttk.Frame(body, style="Card.TFrame", padding=18)
        out.pack(fill="both", expand=True)
        ttk.Label(out, text="Capture Output", style="Section.TLabel").pack(anchor="w")
        ttk.Label(out, text="Live capture summaries and packet identities appear here.", style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
        self.sniff_output = self._make_output(out, 20)
        self.sniff_output.pack(fill="both", expand=True)

    def _on_sniff_start(self) -> None:
        try:
            port = int(self.sniff_port.get())
            count = int(self.sniff_count.get())
            timeout = int(self.sniff_timeout.get())
            interface = self.sniff_iface.get().strip() or None
            _output_write(self.sniff_output, f"Starting capture on UDP port {port}\n", clear=True)
            self._set_status("Sniffing", f"Listening for VRT traffic on UDP port {port}.")
            self._sniff_start_btn.config(state="disabled")

            def _do_sniff() -> None:
                try:
                    from scapy.all import sniff as scapy_sniff
                    from vita49_redteam.scapy_layers.layers import VRT_Header

                    sniff_kwargs = {"filter": f"udp port {port}"}
                    if interface:
                        sniff_kwargs["iface"] = interface
                    if count > 0:
                        sniff_kwargs["count"] = count
                    if timeout > 0:
                        sniff_kwargs["timeout"] = timeout
                    captured = scapy_sniff(**sniff_kwargs)
                    self._sniff_captured = captured
                    self.root.after(0, lambda: self.metric_captured.set(str(len(captured))))
                    lines = [f"Captured {len(captured)} packet(s)\n"]
                    for index, packet in enumerate(captured):
                        if packet.haslayer(VRT_Header):
                            vrt = packet[VRT_Header]
                            stream_id = getattr(vrt, "stream_id", "N/A")
                            stream_value = f"0x{stream_id:08X}" if isinstance(stream_id, int) else str(stream_id)
                            lines.append(f"[{index:04d}] VRT type={vrt.pkt_type:#x} count={vrt.packet_count} size={vrt.packet_size}w stream_id={stream_value}")
                        else:
                            lines.append(f"[{index:04d}] UDP frame ({len(bytes(packet))} bytes)")
                    self.root.after(0, lambda: _output_write(self.sniff_output, "\n".join(lines)))
                    self.root.after(0, lambda: self._set_status("Capture complete", f"Captured {len(captured)} frame(s)."))
                except Exception as exc:
                    self.root.after(0, lambda: _output_write(self.sniff_output, f"\nERROR: {exc}\n"))
                    self.root.after(0, lambda: self._set_status("Capture failed", str(exc)))
                finally:
                    self.root.after(0, lambda: self._sniff_start_btn.config(state="normal"))

            threading.Thread(target=_do_sniff, daemon=True).start()
        except Exception as exc:
            messagebox.showerror("Sniff Error", str(exc))
            self._sniff_start_btn.config(state="normal")
            self._set_status("Capture failed", str(exc))

    def _on_sniff_save(self) -> None:
        if not self._sniff_captured:
            messagebox.showwarning("No Capture", "Run a capture first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")], title="Save Capture")
        if not path:
            return
        from scapy.all import wrpcap

        wrpcap(path, self._sniff_captured)
        _output_write(self.sniff_output, f"\nSaved {len(self._sniff_captured)} packet(s) to {path}\n")
        self._set_status("Capture saved", f"Saved {len(self._sniff_captured)} frame(s) to {path}.")

    def _build_report_tab(self) -> None:
        body = self._new_tab("Report", "Analyze a PCAP file and summarize streams, packet types, byte volume, and timing.")
        card = ttk.Frame(body, style="Card.TFrame", padding=18)
        card.pack(fill="x", pady=(0, 12))
        ttk.Label(card, text="PCAP Analysis", style="Section.TLabel").pack(anchor="w")
        ttk.Label(card, text="Select a PCAP and generate a compact textual report.", style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        self.report_pcap = self._entry(row, 56)
        self.report_pcap.pack(side="left", fill="x", expand=True)
        self._button(row, "Browse", self._on_report_browse).pack(side="left", padx=(10, 0))
        self._button(card, "Generate Report", self._on_report, accent=True).pack(anchor="w", pady=(12, 0))

        out = ttk.Frame(body, style="Card.TFrame", padding=18)
        out.pack(fill="both", expand=True)
        ttk.Label(out, text="Report Output", style="Section.TLabel").pack(anchor="w")
        ttk.Label(out, text="The report includes counts, duration, type distribution, and stream IDs.", style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
        self.report_output = self._make_output(out, 22)
        self.report_output.pack(fill="both", expand=True)

    def _on_report_browse(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
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
                _output_write(self.report_output, "No VRT packets found in the selected PCAP.\n", clear=True)
                self._set_status("Report complete", "The selected PCAP did not contain any VRT packets.")
                return

            stream_counts: dict[int, int] = {}
            type_counts: dict[str, int] = {}
            total_bytes = 0
            parsed_count = 0
            for packet in packets:
                total_bytes += len(packet.raw_vrt)
                if packet.parsed:
                    parsed_count += 1
                    stream_counts[packet.parsed.stream_id] = stream_counts.get(packet.parsed.stream_id, 0) + 1
                    type_counts[packet.parsed.packet_type.name] = type_counts.get(packet.parsed.packet_type.name, 0) + 1

            lines = [
                "=" * 64,
                f"VITA 49 PCAP Report: {pcap_path}",
                "=" * 64,
                "",
                f"Total UDP packets:   {len(packets)}",
                f"Parsed as VRT:       {parsed_count}",
                f"Total VRT bytes:     {total_bytes}",
            ]
            duration = packets[-1].timestamp - packets[0].timestamp
            lines.append(f"Capture duration:    {duration:.3f}s")
            if duration > 0:
                lines.append(f"Average packet rate: {len(packets) / duration:.1f} pps")

            lines.append("\nPacket Types:")
            for name, count in sorted(type_counts.items(), key=lambda item: (-item[1], item[0])):
                lines.append(f"  {name:28s} {count}")
            lines.append("\nStream IDs:")
            for stream_id, count in sorted(stream_counts.items()):
                lines.append(f"  0x{stream_id:08X}  {count} packet(s)")

            _output_write(self.report_output, "\n".join(lines) + "\n", clear=True)
            self.metric_reports.set(str(int(self.metric_reports.get()) + 1))
            self._set_status("Report ready", f"Analyzed {len(packets)} packet(s) from {Path(pcap_path).name}.")
        except Exception as exc:
            messagebox.showerror("Report Error", str(exc))
            self._set_status("Report failed", str(exc))

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    app = VRT_RedTeamGUI()
    app.run()


if __name__ == "__main__":
    main()
