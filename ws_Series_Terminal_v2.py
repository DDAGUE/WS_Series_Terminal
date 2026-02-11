import threading
import time
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import serial
from serial.tools import list_ports
import struct
import os
import json
from pathlib import Path


# -----------------------------
# UMB minimal builder
# -----------------------------
SOH, STX, ETX, EOT = 0x01, 0x02, 0x03, 0x04
UMB_VER_1_0 = 0x10
CMD_2F = 0x2F
VERC_1_0 = 0x10



# WS series 'fast' channels
CH_WIND_SPEED_FAST = 0x0191  # 401
CH_WIND_DIR_FAST   = 0x01F5  # 501
def crc16_mcrf4xx(data: bytes, init: int = 0xFFFF) -> int:
    crc = init & 0xFFFF
    for b in data:
        byte = b
        for _ in range(8):
            crc ^= (byte & 0x01)
            crc = ((crc >> 1) ^ 0x8408) if (crc & 0x01) else (crc >> 1)
            byte >>= 1
        crc &= 0xFFFF
    return crc


def pack_u16_le(x: int) -> bytes:
    return struct.pack("<H", x & 0xFFFF)


def umb_addr(class_id: int, device_id: int) -> int:
    return ((class_id & 0x0F) << 12) | (device_id & 0xFF)


def build_umb_frame(to_addr: int, from_addr: int, cmd: int, verc: int, payload: bytes) -> bytes:
    data_between = bytes([cmd, verc]) + payload
    length = len(data_between)
    header = bytes([SOH, UMB_VER_1_0]) + pack_u16_le(to_addr) + pack_u16_le(from_addr) + bytes([length]) + bytes([STX])
    pre_crc = header + data_between + bytes([ETX])
    crc = crc16_mcrf4xx(pre_crc)
    return pre_crc + pack_u16_le(crc) + bytes([EOT])


def parse_hex_string_to_bytes(s: str) -> bytes:
    cleaned = []
    for ch in s:
        if ch.lower() in "0123456789abcdef":
            cleaned.append(ch)
    if len(cleaned) % 2 == 1:
        cleaned = cleaned[:-1]
    hexstr = "".join(cleaned)
    if not hexstr:
        return b""
    return bytes.fromhex(hexstr)


def format_bytes(data: bytes, mode: str) -> str:
    if mode == "DEC":
        return " ".join(str(b) for b in data)
    return " ".join(f"{b:02X}" for b in data)


# -----------------------------
# Settings dialog
# -----------------------------
class SettingsDialog(tk.Toplevel):
    def __init__(self, master, settings: dict):
        super().__init__(master)
        self.title("Settings")
        self.resizable(False, False)
        self.result = None

        self.port_var = tk.StringVar(value=settings.get("port", ""))
        self.baud_var = tk.IntVar(value=settings.get("baud", 19200))
        self.databits_var = tk.IntVar(value=settings.get("databits", 8))
        self.parity_var = tk.StringVar(value=settings.get("parity", "N"))
        self.stopbits_var = tk.DoubleVar(value=settings.get("stopbits", 1))
        self.xonxoff_var = tk.BooleanVar(value=settings.get("xonxoff", False))
        self.rtscts_var = tk.BooleanVar(value=settings.get("rtscts", False))
        self.dsrdtr_var = tk.BooleanVar(value=settings.get("dsrdtr", False))

        self.tx_interval_var = tk.DoubleVar(value=settings.get("tx_interval", 1.0))
        self.tx_repeat_var = tk.IntVar(value=settings.get("tx_repeat", 1))

        self.view_mode_var = tk.StringVar(value=settings.get("view_mode", "HEX"))

        self._build()

    def _ports(self):
        return [p.device for p in list_ports.comports()]

    def _build(self):
        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="COM Port").grid(row=0, column=0, sticky="w")
        self.port_combo = ttk.Combobox(frm, textvariable=self.port_var, width=18, values=self._ports())
        self.port_combo.grid(row=0, column=1, padx=6)
        ttk.Button(frm, text="Refresh", command=lambda: self.port_combo.configure(values=self._ports())).grid(row=0, column=2)

        ttk.Label(frm, text="Baud").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.baud_var, width=12).grid(row=1, column=1, sticky="w", padx=6)

        ttk.Label(frm, text="Data bits").grid(row=2, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=self.databits_var, width=10, values=[5, 6, 7, 8]).grid(row=2, column=1, sticky="w", padx=6)

        ttk.Label(frm, text="Parity").grid(row=3, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=self.parity_var, width=10, values=["N", "E", "O", "M", "S"]).grid(row=3, column=1, sticky="w", padx=6)

        ttk.Label(frm, text="Stop bits").grid(row=4, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=self.stopbits_var, width=10, values=[1, 1.5, 2]).grid(row=4, column=1, sticky="w", padx=6)

        flow = ttk.LabelFrame(frm, text="Flow control", padding=8)
        flow.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Checkbutton(flow, text="XON/XOFF", variable=self.xonxoff_var).grid(row=0, column=0, sticky="w", padx=6)
        ttk.Checkbutton(flow, text="RTS/CTS", variable=self.rtscts_var).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Checkbutton(flow, text="DSR/DTR", variable=self.dsrdtr_var).grid(row=0, column=2, sticky="w", padx=6)

        tx = ttk.LabelFrame(frm, text="Auto TX", padding=8)
        tx.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Label(tx, text="Interval (sec)").grid(row=0, column=0, sticky="w")
        ttk.Entry(tx, textvariable=self.tx_interval_var, width=10).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(tx, text="Repeat / interval").grid(row=0, column=2, sticky="w")
        ttk.Entry(tx, textvariable=self.tx_repeat_var, width=10).grid(row=0, column=3, sticky="w", padx=6)

        view = ttk.LabelFrame(frm, text="Display", padding=8)
        view.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Radiobutton(view, text="HEX", value="HEX", variable=self.view_mode_var).grid(row=0, column=0, padx=6, sticky="w")
        ttk.Radiobutton(view, text="DEC", value="DEC", variable=self.view_mode_var).grid(row=0, column=1, padx=6, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=8, column=0, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="OK", command=self._ok).grid(row=0, column=1)

    def _ok(self):
        try:
            if not self.port_var.get().strip():
                messagebox.showwarning("Settings", "COM 포트를 선택해 주세요.")
                return
            if float(self.tx_interval_var.get()) <= 0:
                messagebox.showwarning("Settings", "TX interval은 0보다 커야 합니다.")
                return
            if int(self.tx_repeat_var.get()) <= 0:
                messagebox.showwarning("Settings", "TX repeat은 1 이상이어야 합니다.")
                return
        except Exception:
            messagebox.showerror("Settings", "설정 값 형식이 올바르지 않습니다.")
            return

        self.result = {
            "port": self.port_var.get().strip(),
            "baud": int(self.baud_var.get()),
            "databits": int(self.databits_var.get()),
            "parity": self.parity_var.get().strip().upper(),
            "stopbits": float(self.stopbits_var.get()),
            "xonxoff": bool(self.xonxoff_var.get()),
            "rtscts": bool(self.rtscts_var.get()),
            "dsrdtr": bool(self.dsrdtr_var.get()),
            "tx_interval": float(self.tx_interval_var.get()),
            "tx_repeat": int(self.tx_repeat_var.get()),
            "view_mode": self.view_mode_var.get(),
        }
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


# -----------------------------


# -----------------------------
# Serial worker (RX frame buffering + TX queue)
# -----------------------------
class SerialWorker(threading.Thread):
    def __init__(self, settings_getter, auto_tx_getter, tx_queue: queue.Queue, ui_queue: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.settings_getter = settings_getter
        self.auto_tx_getter = auto_tx_getter
        self.tx_queue = tx_queue      # manual TX bytes
        self.ui_queue = ui_queue      # events for UI
        self.stop_event = stop_event
        self.ser = None

    def _open(self, s: dict):
        parity_map = {
            "N": serial.PARITY_NONE,
            "E": serial.PARITY_EVEN,
            "O": serial.PARITY_ODD,
            "M": serial.PARITY_MARK,
            "S": serial.PARITY_SPACE,
        }
        bytesize_map = {
            5: serial.FIVEBITS,
            6: serial.SIXBITS,
            7: serial.SEVENBITS,
            8: serial.EIGHTBITS,
        }
        stopbits_map = {
            1: serial.STOPBITS_ONE,
            1.5: serial.STOPBITS_ONE_POINT_FIVE,
            2: serial.STOPBITS_TWO,
        }

        self.ser = serial.Serial(
            port=s["port"],
            baudrate=s["baud"],
            bytesize=bytesize_map.get(s["databits"], serial.EIGHTBITS),
            parity=parity_map.get(s["parity"], serial.PARITY_NONE),
            stopbits=stopbits_map.get(s["stopbits"], serial.STOPBITS_ONE),
            timeout=0.05,
            xonxoff=s["xonxoff"],
            rtscts=s["rtscts"],
            dsrdtr=s["dsrdtr"],
        )

    def _close(self):
        try:
            if self.ser and self.ser.is_open:
                self.ser.close()
        except Exception:
            pass
        self.ser = None

    def run(self):
        s = self.settings_getter()
        try:
            self._open(s)
            self.ui_queue.put(("info", f"CONNECTED {s['port']} @ {s['baud']}"))
        except Exception as e:
            self.ui_queue.put(("error", f"Serial open failed: {e}"))
            return

        rx_buf = bytearray()
        last_auto_tx = 0.0

        try:
            while not self.stop_event.is_set():
                # 1) RX: assemble UMB telegrams using LEN field (byte 6)
                # NOTE: Do NOT split on 0x04 blindly; 0x04 can appear in payload (e.g., channel count).
                try:
                    chunk = self.ser.read(512)
                    if chunk:
                        rx_buf.extend(chunk)

                        while True:
                            # resync to SOH
                            try:
                                soh_idx = rx_buf.index(SOH)
                            except ValueError:
                                rx_buf.clear()
                                break
                            if soh_idx > 0:
                                del rx_buf[:soh_idx]

                            # Need at least header+CRC+EOT
                            if len(rx_buf) < 12:
                                break

                            payload_len = rx_buf[6]  # bytes between STX and ETX (exclusive)
                            total_len = 12 + payload_len  # 7 hdr + STX + payload + ETX + CRC16(2) + EOT
                            if len(rx_buf) < total_len:
                                break

                            frame = bytes(rx_buf[:total_len])
                            del rx_buf[:total_len]

                            # Basic validation; if invalid, push back tail and keep scanning
                            etx_idx = 8 + payload_len
                            if not (frame[0] == SOH and frame[7] == STX and etx_idx < len(frame) and frame[etx_idx] == ETX and frame[-1] == EOT):
                                # Put back everything except the first byte to find next SOH
                                rx_buf[:0] = frame[1:]
                                continue

                            self.ui_queue.put(("rx_frame", frame))
                except Exception as e:
                    self.ui_queue.put(("error", f"RX error: {e}"))
                    break

                # 2) Manual TX: immediate send
                try:
                    while True:
                        b = self.tx_queue.get_nowait()
                        if b:
                            self.ser.write(b)
                            self.ser.flush()
                            self.ui_queue.put(("tx", b))
                except queue.Empty:
                    pass
                except Exception as e:
                    self.ui_queue.put(("error", f"TX error: {e}"))
                    break

                # 3) Auto TX: interval + repeat
                s = self.settings_getter()
                now = time.time()
                if (now - last_auto_tx) >= float(s["tx_interval"]):
                    last_auto_tx = now
                    b = self.auto_tx_getter()
                    if b:
                        rep = max(1, int(s["tx_repeat"]))
                        for _ in range(rep):
                            try:
                                self.ser.write(b)
                                self.ser.flush()
                                self.ui_queue.put(("tx", b))
                            except Exception as e:
                                self.ui_queue.put(("error", f"Auto TX error: {e}"))
                                break

                time.sleep(0.01)

        finally:
            self._close()
            self.ui_queue.put(("info", "DISCONNECTED"))


# -----------------------------
# App
# -----------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WS200/WS500 UMB RS485 Terminal")
        self.geometry("980x720")

        self.ui_q = queue.Queue()
        self.tx_q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None

        # -----------------------------
        # Config persistence (per-user)
        #  - stored at %LOCALAPPDATA%\WS_Series_Terminal\config.json (Windows)
        # -----------------------------
        self._save_job = None

        # Defaults
        default_settings = {
            "port": "",
            "baud": 19200,
            "databits": 8,
            "parity": "N",
            "stopbits": 1,
            "xonxoff": False,
            "rtscts": False,
            "dsrdtr": False,
            "tx_interval": 1.0,
            "tx_repeat": 1,
            "view_mode": "HEX",
        }
        default_preset = {
            "class_id": 7,
            "device_id": 1,
            "controller_addr": 0xF001,
            "channels": "100,200,300,401,501",
        }
        default_tx = {
            "tx_mode": "UMB_2F",  # UMB_2F or CUSTOM
            "custom_tx_hex": "01 10 01 70 01 F0 11 02 2F 10 07 64 00 C8 00 2C 01 91 01 F5 01 71 02 C0 03 03 8A AC 04",
        }

        cfg = self._load_config()
        self.settings = {**default_settings, **(cfg.get("settings") or {})}
        preset = {**default_preset, **(cfg.get("preset") or {})}
        txcfg = {**default_tx, **(cfg.get("tx") or {})}

        # Save TXT
        self.save_enabled = tk.BooleanVar(value=False)
        self.save_path = None
        self.save_fp = None

        # UMB preset config
        self.class_id = tk.IntVar(value=int(preset.get("class_id", 7)))
        self.device_id = tk.IntVar(value=int(preset.get("device_id", 1)))
        self.controller_addr = tk.IntVar(value=int(preset.get("controller_addr", 0xF001)))
        self.channels_var = tk.StringVar(value=str(preset.get("channels", "100,200,300,401,501")))

        # TX mode
        self.tx_mode = tk.StringVar(value=str(txcfg.get("tx_mode", "UMB_2F")))
        self.custom_tx_hex = tk.StringVar(value=str(txcfg.get("custom_tx_hex", default_tx["custom_tx_hex"])))

        # Auto-save on changes (debounced)
        for v in (
            self.class_id, self.device_id, self.controller_addr,
            self.channels_var, self.tx_mode, self.custom_tx_hex
        ):
            v.trace_add("write", lambda *args: self._schedule_save_config())

        self._build_ui()
        self.after(60, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # -----------------------------
    # Config persistence helpers
    # -----------------------------
    def _config_path(self) -> Path:
        base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
        if base:
            root = Path(base)
        else:
            root = Path.home() / ".config"
        cfg_dir = root / "WS_Series_Terminal"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        return cfg_dir / "config.json"

    def _load_config(self) -> dict:
        p = self._config_path()
        try:
            if p.exists():
                with p.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}

    def _gather_config(self) -> dict:
        return {
            "settings": dict(self.settings),
            "preset": {
                "class_id": int(self.class_id.get()),
                "device_id": int(self.device_id.get()),
                "controller_addr": int(self.controller_addr.get()),
                "channels": str(self.channels_var.get()),
            },
            "tx": {
                "tx_mode": str(self.tx_mode.get()),
                "custom_tx_hex": str(self.custom_tx_hex.get()),
            },
        }

    def _save_config(self):
        p = self._config_path()
        data = self._gather_config()
        tmp = p.with_suffix(".json.tmp")
        try:
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            tmp.replace(p)
        except Exception as e:
            # 저장 실패는 동작을 막지 않도록 로그만 남깁니다.
            self._log_line(f"Config save failed: {e}")

    def _schedule_save_config(self):
        # Debounce to avoid excessive disk writes while typing.
        try:
            if self._save_job is not None:
                self.after_cancel(self._save_job)
        except Exception:
            pass
        self._save_job = self.after(400, self._save_config)

    def _build_ui(self):
        # Toolbar
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")

        ttk.Button(bar, text="Settings", command=self.open_settings).pack(side="left")
        self.btn_connect = ttk.Button(bar, text="Connect", command=self.connect)
        self.btn_connect.pack(side="left", padx=(8, 0))
        self.btn_disconnect = ttk.Button(bar, text="Disconnect", command=self.disconnect, state="disabled")
        self.btn_disconnect.pack(side="left", padx=(8, 0))

        self.lbl_status = ttk.Label(bar, text="(not connected)")
        self.lbl_status.pack(side="left", padx=12)

        ttk.Label(bar, text="View").pack(side="right")
        self.view_combo = ttk.Combobox(bar, width=6, values=["HEX", "DEC"])
        self.view_combo.set(self.settings["view_mode"])
        self.view_combo.bind("<<ComboboxSelected>>", lambda e: self._set_view_mode(self.view_combo.get()))
        self.view_combo.pack(side="right", padx=6)

        # Save bar
        savebar = ttk.Frame(self, padding=6)
        savebar.pack(fill="x")
        ttk.Checkbutton(savebar, text="Save TXT", variable=self.save_enabled, command=self._toggle_save).pack(side="left")
        ttk.Button(savebar, text="Select TXT...", command=self._select_txt).pack(side="left", padx=8)
        self.lbl_save = ttk.Label(savebar, text="(no file)")
        self.lbl_save.pack(side="left", padx=8)

                # Terminal (split view: RAW on top, Human-readable on bottom)
        term_frame = ttk.Frame(self, padding=6)
        term_frame.pack(fill="both", expand=True)

        paned = ttk.PanedWindow(term_frame, orient="vertical")
        paned.pack(fill="both", expand=True)

        # --- RAW (top) ---
        raw_frame = ttk.Frame(paned)
        self.term_raw = tk.Text(raw_frame, wrap="none")
        self.term_raw.pack(side="left", fill="both", expand=True)

        raw_ys = ttk.Scrollbar(raw_frame, orient="vertical", command=self.term_raw.yview)
        raw_ys.pack(side="right", fill="y")
        self.term_raw.configure(yscrollcommand=raw_ys.set)

        # --- Human-readable (bottom) ---
        human_frame = ttk.Frame(paned)
        self.term_human = tk.Text(human_frame, wrap="none", height=6)
        self.term_human.pack(side="left", fill="both", expand=True)

        human_ys = ttk.Scrollbar(human_frame, orient="vertical", command=self.term_human.yview)
        human_ys.pack(side="right", fill="y")
        self.term_human.configure(yscrollcommand=human_ys.set)

        paned.add(raw_frame, weight=1)
        paned.add(human_frame, weight=1)

        # Bottom TX controls
        bottom = ttk.Frame(self, padding=6)
        bottom.pack(fill="x")

        ttk.Label(bottom, text="TX Mode").grid(row=0, column=0, sticky="w")
        ttk.Combobox(bottom, textvariable=self.tx_mode, width=10, values=["UMB_2F", "CUSTOM"]).grid(row=0, column=1, padx=6, sticky="w")

        ttk.Label(bottom, text="WS class").grid(row=0, column=2, sticky="w")
        ttk.Entry(bottom, textvariable=self.class_id, width=6).grid(row=0, column=3, padx=6, sticky="w")

        ttk.Label(bottom, text="device_id").grid(row=0, column=4, sticky="w")
        ttk.Entry(bottom, textvariable=self.device_id, width=6).grid(row=0, column=5, padx=6, sticky="w")

        ttk.Label(bottom, text="channels").grid(row=0, column=6, sticky="w")
        ttk.Entry(bottom, textvariable=self.channels_var, width=40).grid(row=0, column=7, padx=6, sticky="w")

        ttk.Button(bottom, text="Send Once", command=self.send_once).grid(row=0, column=8, padx=8)
        btn_clear = ttk.Button(bottom, text="Clear", command=self._clear_terminal_views)
        btn_clear.grid(row=0, column=9, padx=8)

        ttk.Label(bottom, text="Custom TX (hex)").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(bottom, textvariable=self.custom_tx_hex, width=110).grid(row=1, column=1, columnspan=9, padx=6, sticky="w", pady=(6, 0))

    # ---- Save TXT ----
    def _select_txt(self):
        path = filedialog.asksaveasfilename(
            title="Select log txt",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.save_path = path
            self.lbl_save.config(text=path)

    def _toggle_save(self):
        if self.save_enabled.get():
            if not self.save_path:
                messagebox.showwarning("Save", "TXT 파일을 먼저 선택해 주세요.")
                self.save_enabled.set(False)
                return
            try:
                self.save_fp = open(self.save_path, "a", encoding="utf-8")
                self._log_line(f"SAVE ON: {self.save_path}")
            except Exception as e:
                messagebox.showerror("Save", f"파일 열기 실패: {e}")
                self.save_enabled.set(False)
        else:
            try:
                if self.save_fp:
                    self.save_fp.flush()
                    self.save_fp.close()
            except Exception:
                pass
            self.save_fp = None
            self._log_line("SAVE OFF")

    # ---- UI helpers ----
    def _set_view_mode(self, mode: str):
        if mode in ("HEX", "DEC"):
            self.settings["view_mode"] = mode
            self._schedule_save_config()

    def _clear_terminal_views(self):
        if hasattr(self, "term_raw"):
            self.term_raw.delete("1.0", "end")
        if hasattr(self, "term_human"):
            self.term_human.delete("1.0", "end")

    def _log_line(self, line: str):
        # General info/status messages (kept in RAW view with timestamp)
        ts = time.strftime("%H:%M:%S")
        out = f"[{ts}] {line}"
        self.term_raw.insert("end", out + "\n")
        self.term_raw.see("end")

    def _append_raw_frame(self, direction: str, data: bytes):
        # RAW UMB bytes (timestamped in UI only)
        s = format_bytes(data, self.settings["view_mode"])
        tokens = s.split()
        ts = time.strftime("%H:%M:%S")

        def emit(line_tokens):
            ui_line = f"[{ts}] {direction}: " + " ".join(line_tokens)
            self.term_raw.insert("end", ui_line + "\n")
            self.term_raw.see("end")

        if len(tokens) <= 40:
            emit(tokens)
        else:
            mid = (len(tokens) + 1) // 2
            emit(tokens[:mid])
            emit(tokens[mid:])

    def _extract_umb_values(self, frame: bytes) -> dict:
        # Extract float32(0x16) values from CMD_2F responses.
        # Returns {channel:int -> value:float}
        if not frame or len(frame) < 10:
            return {}
        if frame[0] != SOH or frame[-1] != EOT:
            return {}

        try:
            stx_idx = frame.index(STX)
        except ValueError:
            return {}

        # UMB frames: ... STX <payload> ETX <CRC16LE(2)> EOT
        etx_idx = len(frame) - 4
        if etx_idx <= stx_idx or frame[etx_idx] != ETX:
            return {}

        data_between = frame[stx_idx + 1: etx_idx]
        if len(data_between) < 1:
            return {}
        # Note: Some devices/requests may return value records under different command codes.
        # We therefore scan the entire payload for value records instead of enforcing CMD_2F.

        out = {}

        # Robust scan: value record format (WS series)
        # [0x08][rec_type=0x00][chLo][chHi][dtype=0x16][f32LE(4)]
        # We do NOT rely on the "num" field because some stations include extra
        # non-value records that can shift counts.
        n = len(data_between)
        for j in range(0, n - 8):
            if data_between[j] != 0x08:
                continue
            if data_between[j + 1] != 0x00:
                continue
            if data_between[j + 4] != 0x16:
                continue
            ch = int.from_bytes(data_between[j + 2:j + 4], "little")
            fb = data_between[j + 5:j + 9]
            try:
                out[ch] = struct.unpack("<f", fb)[0]
            except Exception:
                pass

        return out
    def _append_human_from_frame(self, frame: bytes):
        vals = self._extract_umb_values(frame)
        if not vals:
            return

        channels = self._parse_channels()
        if not channels:
            return

        def fmt(v: float) -> str:
            s = f"{v:.3f}"
            s = s.rstrip("0").rstrip(".")
            return s

        parts = []
        for ch in channels:
            if ch in vals:
                parts.append(fmt(vals[ch]))
            else:
                parts.append("NA")

        line = " ; ".join(parts)

        # UI 출력
        self.term_human.insert("end", line + "\n")
        self.term_human.see("end")

        # TXT 저장: 하단(Human) 출력값만 저장 + 타임스탬프
        if self.save_enabled.get() and self.save_fp:
            ts = time.strftime("%H:%M:%S")
            self.save_fp.write(f"[{ts}] {line}\n")
            self.save_fp.flush()

    def open_settings(self):
        dlg = SettingsDialog(self, dict(self.settings))
        self.wait_window(dlg)
        if dlg.result:
            self.settings.update(dlg.result)
            self.view_combo.set(self.settings["view_mode"])
            self._log_line("Settings updated.")
            self._save_config()

    # ---- Connect/Disconnect ----
    def connect(self):
        if self.worker and self.worker.is_alive():
            return
        if not self.settings.get("port"):
            self.open_settings()
            if not self.settings.get("port"):
                return

        self.stop_event.clear()
        self.worker = SerialWorker(
            settings_getter=self._get_settings,
            auto_tx_getter=self._get_auto_tx_bytes,
            tx_queue=self.tx_q,
            ui_queue=self.ui_q,
            stop_event=self.stop_event
        )
        self.worker.start()
        self.btn_connect.configure(state="disabled")
        self.btn_disconnect.configure(state="normal")

    def disconnect(self):
        self.stop_event.set()
        self.btn_connect.configure(state="normal")
        self.btn_disconnect.configure(state="disabled")

    def on_close(self):
        self._save_config()
        self.disconnect()
        try:
            if self.save_fp:
                self.save_fp.close()
        except Exception:
            pass
        self.destroy()

    def _get_settings(self):
        return dict(self.settings)

    # ---- TX bytes builders ----
    def _parse_channels(self):
        s = self.channels_var.get().strip()
        if not s:
            return []
        out = []
        for p in s.split(","):
            p = p.strip()
            if p:
                out.append(int(p))
        return out

    def _build_umb_2f(self) -> bytes:
        to_addr = umb_addr(int(self.class_id.get()), int(self.device_id.get()))
        from_addr = int(self.controller_addr.get())
        channels = self._parse_channels()
        payload = bytes([len(channels)]) + b"".join(pack_u16_le(ch) for ch in channels)
        return build_umb_frame(to_addr, from_addr, CMD_2F, VERC_1_0, payload)

    def _get_auto_tx_bytes(self) -> bytes | None:
        mode = self.tx_mode.get()
        if mode == "CUSTOM":
            b = parse_hex_string_to_bytes(self.custom_tx_hex.get())
            return b if b else None
        return self._build_umb_2f()

    def send_once(self):
        if not (self.worker and self.worker.is_alive()):
            messagebox.showwarning("Send", "먼저 Connect 해 주세요.")
            return
        b = self._get_auto_tx_bytes()
        if not b:
            messagebox.showwarning("Send", "TX 바이트가 비어 있습니다.")
            return
        self.tx_q.put(b)


    def _drain_ui_queue(self):
        try:
            while True:
                kind, payload = self.ui_q.get_nowait()

                if kind == "info":
                    self.lbl_status.configure(text=str(payload))
                    self._log_line(str(payload))

                elif kind == "error":
                    self.lbl_status.configure(text="(error)")
                    self._log_line(str(payload))
                    messagebox.showerror("Error", str(payload))
                    self.disconnect()

                elif kind == "tx":
                    # RAW bytes on top
                    self._append_raw_frame("TX", payload)

                elif kind == "rx_frame":
                    # Apply offsets (dev) then show RAW + Human-readable
                    self._append_raw_frame("RX", payload)
                    self._append_human_from_frame(payload)

        except queue.Empty:
            pass

        self.after(60, self._drain_ui_queue)


if __name__ == "__main__":
    app = App()
    app.mainloop()
