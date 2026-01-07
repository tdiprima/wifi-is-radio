#!/usr/bin/env python3
"""
01_network_info.py - Understand Your Network Configuration

This script shows you what YOUR device knows about the network it's connected to.
No root required - this is all public information your computer already has.

LEARNING OBJECTIVE:
Understand what information is available just by being connected to a network.
"""

import socket
import subprocess
import re
from typing import Optional

def get_hostname() -> str:
    """Get this machine's hostname - how it identifies itself on the network."""
    return socket.gethostname()

def get_local_ip() -> Optional[str]:
    """
    Get your local IP address.
    
    This is your PRIVATE IP - only meaningful within your local network.
    It's typically something like 192.168.x.x or 10.x.x.x
    
    WHY THIS MATTERS:
    - This IP is assigned by your router via DHCP
    - Everyone on your network can see traffic to/from this IP
    - It changes if you reconnect (usually)
    """
    try:
        # This trick creates a socket but doesn't send anything
        # It just figures out which interface would be used
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def get_default_gateway() -> Optional[str]:
    """
    Get the default gateway (your router's IP).
    
    WHY THIS MATTERS:
    - All your internet traffic goes through this device
    - The gateway can see ALL your unencrypted traffic
    - Whoever controls the gateway controls your network access
    """
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'default' in line:
                parts = line.split()
                gateway_idx = parts.index('via') + 1
                return parts[gateway_idx]
    except Exception:
        pass
    return None

def get_dns_servers() -> list:
    """
    Get configured DNS servers.
    
    WHY THIS MATTERS:
    - DNS translates domain names to IP addresses
    - Your DNS server sees EVERY website you visit (by name)
    - This is a major privacy concern on untrusted networks
    - Using encrypted DNS (DoH/DoT) hides this from the network
    """
    dns_servers = []
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns_servers.append(line.split()[1])
    except Exception:
        pass
    return dns_servers

def get_network_interfaces() -> dict:
    """
    Get all network interfaces and their details.
    
    WHY THIS MATTERS:
    - Each interface has a MAC address (hardware identifier)
    - MAC addresses can be used to track your device
    - Stores and airports use MAC tracking for analytics
    """
    interfaces = {}
    try:
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        current_iface = None
        
        for line in result.stdout.split('\n'):
            # New interface
            if re.match(r'^\d+:', line):
                parts = line.split(':')
                current_iface = parts[1].strip()
                interfaces[current_iface] = {'mac': None, 'ip': None, 'state': 'unknown'}
                if 'UP' in line:
                    interfaces[current_iface]['state'] = 'UP'
                elif 'DOWN' in line:
                    interfaces[current_iface]['state'] = 'DOWN'
            
            # MAC address line
            elif 'link/ether' in line and current_iface:
                mac = line.split()[1]
                interfaces[current_iface]['mac'] = mac
            
            # IP address line
            elif 'inet ' in line and current_iface:
                ip = line.split()[1]
                interfaces[current_iface]['ip'] = ip
                
    except Exception as e:
        print(f"Error getting interfaces: {e}")
    
    return interfaces

def explain_ip_range(ip: str) -> str:
    """Explain what type of IP address this is."""
    if ip.startswith('192.168.'):
        return "Private IP (Class C) - Common home network range"
    elif ip.startswith('10.'):
        return "Private IP (Class A) - Common corporate network range"
    elif ip.startswith('172.'):
        octets = ip.split('.')
        if 16 <= int(octets[1]) <= 31:
            return "Private IP (Class B) - Sometimes used in larger networks"
    elif ip.startswith('169.254.'):
        return "Link-local IP - No DHCP server found, self-assigned"
    elif ip.startswith('127.'):
        return "Loopback - This machine talking to itself"
    return "Public or other IP range"

def main():
    print("=" * 60)
    print("🖥️  YOUR NETWORK CONFIGURATION")
    print("=" * 60)
    print("\nThis is what your device knows about its network connection.\n")
    
    # Hostname
    hostname = get_hostname()
    print(f"📛 Hostname: {hostname}")
    print("   └─ This is how your device identifies itself on the network")
    print("   └─ Other devices can see this name\n")
    
    # Local IP
    local_ip = get_local_ip()
    if local_ip:
        print(f"🔢 Local IP Address: {local_ip}")
        print(f"   └─ {explain_ip_range(local_ip)}")
        print("   └─ This IP is visible to everyone on your local network\n")
    
    # Gateway
    gateway = get_default_gateway()
    if gateway:
        print(f"🚪 Default Gateway: {gateway}")
        print("   └─ This is your router - ALL internet traffic goes through it")
        print("   └─ The gateway can see all unencrypted traffic\n")
    
    # DNS
    dns_servers = get_dns_servers()
    if dns_servers:
        print(f"🔍 DNS Servers: {', '.join(dns_servers)}")
        print("   └─ These servers see every domain name you look up")
        print("   └─ Consider using encrypted DNS (DoH/DoT) for privacy\n")
    
    # Interfaces
    print("=" * 60)
    print("📡 NETWORK INTERFACES")
    print("=" * 60)
    
    interfaces = get_network_interfaces()
    for name, info in interfaces.items():
        if name == 'lo':  # Skip loopback
            continue
        print(f"\n🔌 {name} [{info['state']}]")
        if info['mac']:
            print(f"   MAC Address: {info['mac']}")
            print("   └─ Unique hardware identifier (can be spoofed)")
            print("   └─ Used for device tracking in public spaces")
        if info['ip']:
            print(f"   IP Address: {info['ip']}")
    
    # Security insights
    print("\n" + "=" * 60)
    print("🔐 SECURITY INSIGHTS")
    print("=" * 60)
    print("""
What this information reveals:
    
1. ANYONE on your local network can see your MAC and IP
2. Your router sees ALL your traffic destinations
3. Your DNS server knows every website you visit
4. Your hostname might reveal your name or device type

What you can do:
    
• Use a VPN to encrypt all traffic (even from your router)
• Use encrypted DNS (1.1.1.1 or 8.8.8.8 with DoH)
• Randomize your MAC address on public networks
• Use HTTPS
""")

if __name__ == "__main__":
    main()
