#!/usr/bin/env python3
"""
02_arp_discovery.py - Discover Devices on Your Network

This script uses ARP (Address Resolution Protocol) to find all devices
on your local network. Requires root/sudo to send ARP packets.

LEARNING OBJECTIVE:
Understand how devices are discovered on a network, and why this
information is visible to everyone on the same network.

Run with: sudo python3 02_arp_discovery.py
"""

import platform
import subprocess
import sys


def check_root():
    """Check if running as root."""
    import os

    if os.geteuid() != 0:
        print("❌ This script requires root privileges.")
        print("   Run with: sudo python3 02_arp_discovery.py")
        sys.exit(1)


def get_local_network():
    """Determine the local network range to scan."""
    try:
        system = platform.system()

        if system == "Linux":
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "src" in line and "default" not in line:
                    parts = line.split()
                    return parts[0]  # Returns something like 192.168.1.0/24

        elif system == "Darwin":  # macOS
            # Get IP and netmask from ifconfig
            result = subprocess.run(["ifconfig"], capture_output=True, text=True)
            lines = result.stdout.split("\n")

            for i, line in enumerate(lines):
                if "inet " in line and "127.0.0.1" not in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1]
                        netmask = parts[3]

                        # Convert netmask to CIDR
                        if netmask.startswith("0x"):
                            netmask_int = int(netmask, 16)
                            cidr = bin(netmask_int).count('1')

                            # Calculate network address
                            ip_parts = ip.split('.')
                            network_parts = []
                            netmask_parts = [
                                (netmask_int >> 24) & 0xFF,
                                (netmask_int >> 16) & 0xFF,
                                (netmask_int >> 8) & 0xFF,
                                netmask_int & 0xFF
                            ]

                            for j in range(4):
                                network_parts.append(str(int(ip_parts[j]) & netmask_parts[j]))

                            network = '.'.join(network_parts) + f"/{cidr}"
                            return network
    except Exception:
        pass
    return None


def get_interface():
    """Get the primary network interface."""
    try:
        system = platform.system()

        if system == "Linux":
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    dev_idx = parts.index("dev") + 1
                    return parts[dev_idx]

        elif system == "Darwin":  # macOS
            result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "default" in line and ("UG" in line or "UGSc" in line):
                    parts = line.split()
                    # Interface is typically the last column
                    if len(parts) >= 4:
                        interface = parts[-1]
                        # Skip loopback and utun interfaces
                        if not interface.startswith(("lo", "utun")):
                            return interface
    except Exception:
        pass
    return None


def lookup_vendor(mac: str) -> str:
    """
    Look up the vendor from MAC address OUI (first 3 bytes).

    WHY THIS MATTERS:
    The first 3 bytes of a MAC address identify the manufacturer.
    This can reveal what kind of device is on your network.
    """
    # Common OUI prefixes (Organizationally Unique Identifier)
    oui_database = {
        "ac:de:48": "Apple",
        "f0:18:98": "Apple",
        "00:1a:2b": "Cisco",
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "ec:fa:bc": "Amazon (Echo/Fire)",
        "44:65:0d": "Amazon",
        "18:b4:30": "Nest",
        "64:16:66": "Nest",
        "f4:f5:d8": "Google",
        "94:eb:2c": "Google",
        "b0:be:76": "TP-Link",
        "50:c7:bf": "TP-Link",
        "00:11:32": "Synology",
        "74:da:38": "Edimax",
        "a4:77:33": "Google (Chromecast)",
        "00:1e:c9": "Dell",
        "00:25:64": "Dell",
        "d4:be:d9": "Dell",
        "3c:52:82": "HP",
        "94:57:a5": "HP",
        "f8:bc:12": "Dell",
        "00:15:5d": "Microsoft (Hyper-V)",
        "00:0c:29": "VMware",
        "00:0d:3a": "Microsoft Azure",
        "00:23:ae": "Dell",
        "b4:2e:99": "NETGEAR",
        "a0:04:60": "NETGEAR",
        "28:80:23": "NETGEAR",
        "00:14:bf": "ASUS",
        "2c:fd:a1": "ASUS",
        "00:1f:3c": "Intel",
        "3c:97:0e": "Intel",
        "68:05:ca": "Intel",
        "88:78:73": "Intel",
        "00:16:ea": "Intel",
        "00:1b:21": "Intel",
        "4c:eb:42": "Intel",
        "34:02:86": "Intel",
    }

    prefix = mac.lower()[:8]
    return oui_database.get(prefix, "Unknown Vendor")


def arp_scan(network: str, interface: str):
    """
    Perform an ARP scan of the network.

    HOW THIS WORKS:
    1. We send ARP "who-has" requests to every IP in the range
    2. Devices respond with their MAC address
    3. We collect all the responses

    WHY THIS IS SIGNIFICANT:
    - ARP has no authentication - anyone can ask
    - Anyone on the network can do this scan
    - This reveals all active devices
    """
    print(f"\n🔍 Scanning network: {network}")
    print(f"   Using interface: {interface}")
    print("-" * 60)

    try:
        from scapy.all import ARP, Ether, conf, srp

        conf.verb = 0  # Suppress scapy output

        # Create ARP request packet
        # Ether: broadcast to all devices (ff:ff:ff:ff:ff:ff)
        # ARP: asking "who has <ip>? tell me"
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        print("\n📤 Sending ARP requests (this broadcasts to the whole network)...")
        print("   Everyone on the network can see these requests.\n")

        # Send packets and collect responses
        answered, unanswered = srp(packet, iface=interface, timeout=3, verbose=False)

        devices = []
        for sent, received in answered:
            devices.append(
                {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "vendor": lookup_vendor(received.hwsrc),
                }
            )

        return devices

    except ImportError:
        print("❌ Scapy not installed. Run: pip install scapy")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return []


def main():
    print("=" * 60)
    print("📡 ARP NETWORK DISCOVERY")
    print("=" * 60)
    print(
        """
This script discovers all devices on your local network using ARP.

🔑 KEY CONCEPT: ARP (Address Resolution Protocol)
   
   ARP maps IP addresses to MAC (hardware) addresses.
   When your computer wants to talk to 192.168.1.5, it needs
   to know the physical address (MAC) to send the packet to.
   
   ARP asks: "Who has 192.168.1.5? Tell me your MAC address!"
   And the device responds with its MAC.

⚠️  SECURITY INSIGHT:
   
   ARP has NO authentication. Anyone can:
   - Scan the network to find all devices
   - Claim to be any IP address (ARP spoofing)
   - Intercept traffic by pretending to be the router
   
   This is why being on an untrusted network is dangerous.
"""
    )

    check_root()

    network = get_local_network()
    interface = get_interface()

    if not network or not interface:
        print("❌ Could not determine network configuration.")
        sys.exit(1)

    devices = arp_scan(network, interface)

    if devices:
        print(f"\n✅ Found {len(devices)} device(s):\n")
        print(f"{'IP Address':<16} {'MAC Address':<20} {'Vendor'}")
        print("-" * 60)

        for device in sorted(
            devices, key=lambda x: [int(p) for p in x["ip"].split(".")]
        ):
            print(f"{device['ip']:<16} {device['mac']:<20} {device['vendor']}")

        print("\n" + "=" * 60)
        print("🔐 WHAT THIS REVEALS")
        print("=" * 60)
        print(
            """
From this scan, an attacker on your network could learn:

1. How many devices are connected
2. What types of devices (from MAC vendor lookup)
3. Potential targets (IoT devices often have weak security)
4. The router's IP (usually the gateway)

DEFENSE TIPS:

• Enable AP Isolation on your router (prevents device-to-device scanning)
• Use a separate network/VLAN for IoT devices
• Monitor your network for unknown devices
• Some routers can alert you when new devices connect
"""
        )
    else:
        print("\n❌ No devices found. Check your network connection.")


if __name__ == "__main__":
    main()
