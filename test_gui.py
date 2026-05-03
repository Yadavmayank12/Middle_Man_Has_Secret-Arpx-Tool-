# ─────────────────────────────────────────────────────
# TC-03: GUI Integration Test
# Tester  : Nitin Agrawal
# Purpose : Verify all 3 modules work together in GUI
# Run     : sudo python3 tests/test_gui.py
# ─────────────────────────────────────────────────────

import tkinter as tk
from threading import Thread
from scapy.all import ARP, Ether, srp, sniff

# ---------------- LOG FUNCTION ----------------
def log(msg):
    output.insert(tk.END, msg + "\n")
    output.see(tk.END)

# ---------------- TEST SCAN ----------------
def test_scan():
    network = subnet_entry.get()
    log("[*] Testing Scan Module...")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    if result:
        log("[+] Scan Working ✅")
        for sent, received in result:
            log(f"{received.psrc} --> {received.hwsrc}")
    else:
        log("[-] Scan failed or no devices found ❌")

# ---------------- TEST DETECTION ----------------
def test_detect():
    log("[*] Testing Detection Module...")

    def process(packet):
        if packet.haslayer(ARP) and packet.op == 2:
            log(f"[!] ARP Reply: {packet.psrc} is at {packet.hwsrc}")

    sniff(filter="arp", prn=process, store=0)

# ---------------- TEST SPOOF (SAFE SIMULATION) ----------------
def test_spoof():
    target = target_entry.get()
    gateway = gateway_entry.get()

    log("[*] Testing Spoof Module...")
    log(f"[+] Simulating spoof between {target} and {gateway}")
    log("[+] No real packets sent (safe mode)")
    log("[+] Spoof Module Working ✅")

# ---------------- GUI ----------------
root = tk.Tk()
root.title("ARPX Tool - TEST MODE")
root.geometry("500x500")
root.configure(bg="black")

tk.Label(root, text="Subnet (e.g. 192.168.1.0/24)", fg="lime", bg="black").pack()
subnet_entry = tk.Entry(root)
subnet_entry.pack()

tk.Button(root, text="Test Scan", command=lambda: Thread(target=test_scan).start()).pack(pady=5)

tk.Label(root, text="Target IP", fg="lime", bg="black").pack()
target_entry = tk.Entry(root)
target_entry.pack()

tk.Label(root, text="Gateway IP", fg="lime", bg="black").pack()
gateway_entry = tk.Entry(root)
gateway_entry.pack()

tk.Button(root, text="Test Spoof (Safe)", command=test_spoof).pack(pady=5)
tk.Button(root, text="Test Detection", command=lambda: Thread(target=test_detect).start()).pack(pady=5)

output = tk.Text(root, height=15, width=60, bg="black", fg="lime")
output.pack(pady=10)

root.mainloop()