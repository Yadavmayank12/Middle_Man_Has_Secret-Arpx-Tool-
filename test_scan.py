# ─────────────────────────────────────────────────────
# TC-01: Network Scan Test
# Tester  : Shashank Saini
# Purpose : Verify ARP scanner discovers all active hosts
# Run     : sudo python3 tests/test_scan.py
# ─────────────────────────────────────────────────────

# test_scan.py
from scapy.all import ARP, Ether, srp

def test_scan(network):
    print("[*] Testing Scan Module...")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    if result:
        print(" Scan Working ")
        for sent, received in result:
            print(f"{received.psrc} --> {received.hwsrc}")
    else:
        print(" No devices found or scan failed ")

# Run test
test_scan("192.168.1.0/24")