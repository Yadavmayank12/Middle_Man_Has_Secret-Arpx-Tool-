# ─────────────────────────────────────────────────────
# TC-02: ARP Detection Test
# Tester  : Mayank Sharma
# Purpose : Verify detection module captures ARP replies
# Run     : sudo python3 tests/test_detect.py
# ─────────────────────────────────────────────────────

# test_detect.py
from scapy.all import sniff, ARP

print(" Testing Detection Module...")

def detect(packet):
    if packet.haslayer(ARP) and packet.op == 2:
        print(f"[!] ARP Reply: {packet.psrc} is at {packet.hwsrc}")

sniff(filter="arp", prn=detect, store=0)