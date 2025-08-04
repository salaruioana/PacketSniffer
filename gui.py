# gui.py
import tkinter as tk
import tkinter.font as tkFont
from tkinter import scrolledtext, filedialog
import threading
from utils import is_mostly_printable
from sniffer import PacketSniffer

# Dark Hacker Theme Colors
COLORS = {
        "bg": "#1e0033",
        "fg": "#39ff14",  # neon green
        "label_fg": "#00ffff",  # cyan
        "entry_bg": "#2e004d",
        "entry_fg": "#ffffff",
        "button_bg": "#290066",
        "button_fg": "#ffffff",
        "highlight": "#8a2be2",  # purple border highlight
        "payload_bg": "#1a0029",
        "payload_fg": "#ffffff"
    }
class PacketSnifferGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.configure(bg=COLORS["bg"])

        # Set global default font
        default_font = tkFont.Font(family="Consolas", size=10)
        self.root.option_add("*Font", default_font)

        # Label
        tk.Label(
            root,
            text=" Packet Sniffer ",
            font=("Consolas", 14, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["fg"],
            pady=10
        ).pack()

        # --- Filters ---
        # Add protocol filter field
        tk.Label(root, text="Protocol (TCP/UDP/ALL):", bg=COLORS["bg"], fg=COLORS["label_fg"]).pack()
        self.protocol_entry = tk.Entry(root, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"],
                                       insertbackground=COLORS["entry_fg"])
        # by default, capture everything
        self.protocol_entry.insert(0, "ALL")
        self.protocol_entry.pack(padx=10, pady=2)

        # Add port filter field
        tk.Label(root, text="Port (optional):", bg=COLORS["bg"], fg=COLORS["label_fg"]).pack()
        self.port_entry = tk.Entry(root, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"],
                                       insertbackground=COLORS["entry_fg"])
        # empty means no filtering
        self.port_entry.insert(0, "")
        self.port_entry.pack(padx=10, pady=2)

        # --- Output Areas ---
        # insert a text box for the sniffed packets
        self.text_area = scrolledtext.ScrolledText(
            root,
            width=80, height=20,
            bg=COLORS["payload_bg"],
            fg=COLORS["fg"],
            insertbackground=COLORS["fg"]
        )
        self.text_area.pack(padx=10, pady=10)

        # insert a text box for decoded payload that makes sense
        self.payload_area = scrolledtext.ScrolledText(
            root,
            width=80, height=20,
            bg=COLORS["payload_bg"],
            fg=COLORS["fg"],
            insertbackground=COLORS["fg"]
        )
        tk.Label(root, text="Decoded Payloads:",bg=COLORS["bg"], fg=COLORS["label_fg"]).pack()
        self.payload_area.pack(padx=10, pady=5)

        # --- Buttons ---
        self.start_button = tk.Button(
            root,
            text="Start Sniffing",
            bg=COLORS["button_bg"],
            fg=COLORS["button_fg"],
            activebackground=COLORS["highlight"],
            activeforeground=COLORS["fg"],
            relief="flat",
            cursor="hand2",
            command=self.start_sniffing,
            state = tk.NORMAL
        )
        self.start_button.pack(padx=10, pady=5)

        self.stop_button = tk.Button(
            root,
            text="Stop Sniffing",
            bg=COLORS["button_bg"],
            fg=COLORS["button_fg"],
            activebackground=COLORS["highlight"],
            activeforeground=COLORS["fg"],
            relief="flat",
            cursor="hand2",
            command=self.stop_sniffing,
            state = tk.DISABLED
        )
        self.stop_button.pack(padx=10, pady=5)

        # --- Options ---
        #option show payload
        self.show_payload = tk.BooleanVar(value=True)
        tk.Checkbutton(
            root,
            text="Show Payload",
            variable=self.show_payload,
            bg=COLORS["bg"],
            fg=COLORS["fg"],
            activebackground=COLORS["bg"],
            activeforeground=COLORS["fg"],
            selectcolor=COLORS["entry_bg"],  # this is the checkbox fill color
        ).pack()

        #option save payload to file
        self.save_payloads = tk.BooleanVar(value=False)
        tk.Checkbutton(
            root,
            text="Save Readable Payloads to File",
            variable=self.save_payloads,
            bg=COLORS["bg"],
            fg=COLORS["fg"],
            activebackground=COLORS["bg"],
            activeforeground=COLORS["fg"],
            selectcolor=COLORS["entry_bg"],
        ).pack()
        #option to browse the location where we want to store the payload
        self.browse_button = tk.Button(root,
                                       text='Browse...',
                                       bg=COLORS["button_bg"],
                                       fg=COLORS["button_fg"],
                                       activebackground=COLORS["highlight"],
                                       activeforeground=COLORS["fg"],
                                       relief="flat",
                                       cursor="hand2",
                                       command=self.browse_file)
        self.browse_button.pack(padx=10, pady=2)

        # here will be the actual path for that file
        self.file_path = tk.StringVar(value="output.txt")
        tk.Label(root, text="File Path:", bg=COLORS["bg"], fg=COLORS["label_fg"]).pack()
        self.file_path_entry = tk.Entry(
            root,
            textvariable=self.file_path,
            width=60,
            bg=COLORS["entry_bg"],
            fg=COLORS["entry_fg"],
            insertbackground=COLORS["entry_fg"],
            state="readonly",
            readonlybackground=COLORS["entry_bg"],
            highlightbackground=COLORS["highlight"],
            highlightthickness=1
        )
        self.file_path_entry.pack(padx=10, pady=2)

        # --- Internal state ---
        self.sniffer = None
        self.sniffing = False
        self.sniff_thread = None

    def browse_file(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if path:
            self.file_path.set(path)

    def start_sniffing(self):
        if not self.sniffer or not self.sniffer.sniffing:

            protocol = self.protocol_entry.get().strip().upper()
            port = self.port_entry.get().strip()

            self.sniffer = PacketSniffer(protocol, port, packet_callback=self.packet_callback)
            self.sniff_thread = threading.Thread(target=self.sniffer.start, daemon=True)
            self.sniffer.start()

            self.sniffing = True
            self.text_area.delete(1.0, tk.END)
            self.payload_area.delete(1.0, tk.END)
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, "Sniffing started...\n")

    def stop_sniffing(self):
        if self.sniffing and self.sniffer.sniffing:
            self.sniffer.stop()
            self.sniffing = False

            if self.sniff_thread and self.sniff_thread.is_alive():
                self.sniff_thread.join(timeout=2)
                self.sniff_thread = None  # <-- add this

            self.stop_button.config(state=tk.DISABLED)
            self.start_button.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, "Sniffing stopped.\n")
            self.text_area.see(tk.END)

    def packet_callback(self, src_ip, dst_ip, proto, sport=None, dport=None, payload=None):
        line = f"[{proto}] {src_ip}"
        if sport:
            line += f":{sport}"
        line += f" → {dst_ip}"
        if dport:
            line += f":{dport}"
        line += "\n"

        self.text_area.insert(tk.END, line)
        self.text_area.see(tk.END)

        if payload and self.show_payload.get():
            try:
                text = payload.decode("utf-8", errors="replace").strip()
                if is_mostly_printable(text):
                    if self.save_payloads.get():
                        with open(self.file_path.get(), "a", encoding="utf-8") as f:
                            f.write(f"{line}{text}\n{'-' * 40}\n")
                    self.payload_area.insert(tk.END, f"{line}{text}\n{'-' * 40}\n")
            except Exception:
                self.payload_area.insert(tk.END, "[Could not decode payload]\n" + "-" * 40 + "\n")

            self.payload_area.see(tk.END)
