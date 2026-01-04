#!/usr/bin/env python3
"""
network_watchdog.py - Alert on new devices joining your network

Run with: sudo python3 network_watchdog.py
"""

import json
import time
from datetime import datetime
from pathlib import Path

from network_os_utils import get_interface, get_local_network

KNOWN_DEVICES_FILE = Path.home() / ".known_devices.json"
CHECK_INTERVAL = 60  # seconds


def get_current_devices():
    """Get all devices currently on the network via ARP."""
    devices = {}
    try:
        from scapy.all import ARP, Ether, conf, srp

        conf.verb = 0

        # Get network range and interface
        network = get_local_network()
        interface = get_interface()

        if network and interface:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            answered, _ = srp(packet, iface=interface, timeout=3, verbose=False)

            for sent, received in answered:
                devices[received.hwsrc] = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "last_seen": datetime.now().isoformat(),
                }
    except Exception as e:
        print(f"Scan error: {e}")

    return devices


def load_known_devices():
    """Load known devices from file."""
    if KNOWN_DEVICES_FILE.exists():
        return json.loads(KNOWN_DEVICES_FILE.read_text())
    return {}


def save_known_devices(devices):
    """Save known devices to file."""
    KNOWN_DEVICES_FILE.write_text(json.dumps(devices, indent=2))


def main():
    print("🔍 Network Watchdog Starting...")
    print(f"   Checking every {CHECK_INTERVAL} seconds")
    print(f"   Known devices file: {KNOWN_DEVICES_FILE}")
    print("-" * 50)

    known = load_known_devices()

    if not known:
        print("\n📝 First run - learning your network...")
        known = get_current_devices()
        save_known_devices(known)
        print(f"   Learned {len(known)} devices:")
        for mac, info in known.items():
            print(f"   • {info['ip']:<16} {mac}")
        print("\n   Run again to start monitoring.\n")
        return

    print(f"   Monitoring... ({len(known)} known devices)")

    try:
        while True:
            current = get_current_devices()

            # Check for new devices
            for mac, info in current.items():
                if mac not in known:
                    print("\n🚨 NEW DEVICE DETECTED!")
                    print(f"   IP:  {info['ip']}")
                    print(f"   MAC: {mac}")
                    print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"\n   To add to known devices, edit: {KNOWN_DEVICES_FILE}")

                    # Optional: add to known automatically
                    # known[mac] = info
                    # save_known_devices(known)

            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n\nWatchdog stopped.")


if __name__ == "__main__":
    import os

    if os.geteuid() != 0:
        print("Run with: sudo python3 network_watchdog.py")
    else:
        main()
