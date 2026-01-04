#!/usr/bin/env python3
"""
network_os_utils.py - Cross-platform network utility functions

Provides OS-agnostic functions for network operations that work on both
Linux and macOS (Darwin). Each script can import and use these functions
instead of implementing platform-specific code.
"""

import platform
import subprocess
from typing import Optional


def get_platform() -> str:
    """Get the current platform (Linux, Darwin, etc.)."""
    return platform.system()


def get_local_network() -> Optional[str]:
    """
    Determine the local network range to scan.
    Returns something like "192.168.1.0/24"
    """
    try:
        system = get_platform()

        if system == "Linux":
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "src" in line and "default" not in line:
                    parts = line.split()
                    return parts[0]

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


def get_interface() -> Optional[str]:
    """
    Get the primary network interface.
    Returns something like "eth0" on Linux or "en0" on macOS.
    """
    try:
        system = get_platform()

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
                    if len(parts) >= 4:
                        interface = parts[-1]
                        # Skip loopback and utun interfaces
                        if not interface.startswith(("lo", "utun")):
                            return interface
    except Exception:
        pass
    return "eth0" if system == "Linux" else "en0"


def get_default_gateway() -> Optional[str]:
    """
    Get the default gateway (router's IP).
    Returns something like "192.168.1.1"
    """
    try:
        system = get_platform()

        if system == "Linux":
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    gateway_idx = parts.index("via") + 1
                    return parts[gateway_idx]

        elif system == "Darwin":  # macOS
            result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    # Gateway is typically the second column
                    if len(parts) >= 2:
                        gateway = parts[1]
                        # Make sure it's an IP address, not an interface name
                        if gateway and gateway[0].isdigit():
                            return gateway
    except Exception:
        pass
    return None


def get_network_interfaces() -> dict:
    """
    Get all network interfaces and their details.
    Returns dict of {interface_name: {mac, ip, state}}
    """
    interfaces = {}
    try:
        system = get_platform()

        if system == "Linux":
            import re
            result = subprocess.run(["ip", "addr"], capture_output=True, text=True)
            current_iface = None

            for line in result.stdout.split("\n"):
                # New interface
                if re.match(r"^\d+:", line):
                    parts = line.split(":")
                    current_iface = parts[1].strip()
                    interfaces[current_iface] = {
                        "mac": None,
                        "ip": None,
                        "state": "unknown",
                    }
                    if "UP" in line:
                        interfaces[current_iface]["state"] = "UP"
                    elif "DOWN" in line:
                        interfaces[current_iface]["state"] = "DOWN"

                # MAC address line
                elif "link/ether" in line and current_iface:
                    mac = line.split()[1]
                    interfaces[current_iface]["mac"] = mac

                # IP address line
                elif "inet " in line and current_iface:
                    ip = line.split()[1]
                    interfaces[current_iface]["ip"] = ip

        elif system == "Darwin":  # macOS
            result = subprocess.run(["ifconfig"], capture_output=True, text=True)
            current_iface = None

            for line in result.stdout.split("\n"):
                # New interface (starts at beginning of line, no leading space)
                if line and not line[0].isspace() and ":" in line:
                    current_iface = line.split(":")[0]
                    interfaces[current_iface] = {
                        "mac": None,
                        "ip": None,
                        "state": "unknown",
                    }
                    # Check flags for UP/DOWN
                    if "UP" in line:
                        interfaces[current_iface]["state"] = "UP"
                    elif "DOWN" in line:
                        interfaces[current_iface]["state"] = "DOWN"

                # MAC address (ether)
                elif current_iface and "ether " in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        interfaces[current_iface]["mac"] = parts[1]

                # IP address (inet)
                elif current_iface and "inet " in line and "inet6" not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        # Include netmask if available
                        if len(parts) >= 4 and parts[2] == "netmask":
                            netmask = parts[3]
                            if netmask.startswith("0x"):
                                # Convert hex netmask to CIDR
                                netmask_int = int(netmask, 16)
                                cidr = bin(netmask_int).count('1')
                                ip = f"{ip}/{cidr}"
                        interfaces[current_iface]["ip"] = ip

    except Exception as e:
        print(f"Error getting interfaces: {e}")

    return interfaces


def check_command_exists(command: str) -> bool:
    """Check if a command exists on the system."""
    try:
        result = subprocess.run(
            ["which", command],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


# Platform-specific command mappings
def get_arp_command() -> list:
    """Get the appropriate ARP command for the platform."""
    system = get_platform()
    # Both Linux and macOS use 'arp -a'
    return ["arp", "-a"]


def get_firewall_check_command() -> Optional[list]:
    """Get the appropriate firewall check command for the platform."""
    system = get_platform()

    if system == "Linux":
        if check_command_exists("ufw"):
            return ["ufw", "status"]
        elif check_command_exists("firewall-cmd"):
            return ["firewall-cmd", "--state"]
    elif system == "Darwin":
        # macOS uses pf (packet filter)
        return ["pfctl", "-s", "info"]

    return None
