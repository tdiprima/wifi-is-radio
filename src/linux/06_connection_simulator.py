#!/usr/bin/env python3
"""
06_connection_simulator.py - WiFi Connection Process Explained

This is a SIMULATION/EDUCATIONAL script that walks you through
what happens when you connect to a WiFi network. No actual
network operations are performed.

LEARNING OBJECTIVE:
Understand the complete WiFi connection process, from finding
networks to establishing encrypted communication.

No root required - this is purely educational.
"""

import time
import random
import string

def print_slow(text, delay=0.02):
    """Print text with a slight delay for effect."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def print_packet(direction, packet_type, details):
    """Print a formatted packet representation."""
    arrow = "→" if direction == "out" else "←"
    color = "\033[94m" if direction == "out" else "\033[92m"
    reset = "\033[0m"
    print(f"  {color}{arrow} [{packet_type}]{reset} {details}")
    time.sleep(0.3)

def generate_mac():
    """Generate a random MAC address for demonstration."""
    return ':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])

def generate_nonce():
    """Generate a random nonce for demonstration."""
    return ''.join(random.choices(string.hexdigits[:16], k=32))

def simulate_scanning():
    """Simulate the network scanning phase."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 1: SCANNING FOR NETWORKS                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    print_slow("""
When you turn on WiFi, your device does two things:

1. PASSIVE SCANNING: Listens for beacon frames
   Routers broadcast their presence every ~100ms
   
2. ACTIVE SCANNING: Sends probe requests
   Your device asks "Is [network name] here?"
""")
    
    input("\nPress Enter to see this in action...\n")
    
    # Simulate beacons
    print("📡 Your device is listening for beacon frames...")
    time.sleep(1)
    
    networks = [
        ("HomeNetwork_5G", "WPA2", -45, generate_mac()),
        ("NETGEAR-Guest", "Open", -60, generate_mac()),
        ("Apartment_204", "WPA2", -72, generate_mac()),
        ("CoffeeShop_Free", "Open", -80, generate_mac()),
    ]
    
    for ssid, security, signal, bssid in networks:
        print_packet("in", "BEACON", f"SSID: {ssid}, Security: {security}, Signal: {signal}dBm")
    
    print("""
💡 INSIGHT: Beacon frames are NEVER encrypted.
   Anyone nearby can see:
   • What networks exist
   • Their security settings  
   • Approximate router locations (via signal strength)
""")
    
    input("\nPress Enter to see probe requests...\n")
    
    # Simulate probes
    print("📱 Your device sends probe requests for saved networks...")
    time.sleep(0.5)
    
    saved_networks = ["HomeNetwork_5G", "Work-Corporate", "Airport_WiFi"]
    for ssid in saved_networks:
        print_packet("out", "PROBE REQUEST", f"Looking for: {ssid}")
    
    print("""
⚠️ PRIVACY CONCERN: Your device just announced where you've been!

   By probing for "Work-Corporate" and "Airport_WiFi", you revealed:
   • You work at a company using that network name
   • You recently traveled through that airport
   
   Attackers use this for:
   • Tracking individuals
   • Setting up "evil twin" networks with names you trust
   
   🛡️ DEFENSE: Disable "auto-join" for sensitive networks
""")

def simulate_authentication():
    """Simulate the authentication phase."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 2: AUTHENTICATION                                         ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    print_slow("""
You select "HomeNetwork_5G" and enter the password.
Now the authentication process begins...
""")
    
    input("\nPress Enter to start authentication...\n")
    
    client_mac = generate_mac()
    ap_mac = generate_mac()
    
    print(f"Your device MAC: {client_mac}")
    print(f"Access Point MAC: {ap_mac}")
    print()
    
    # Authentication request
    print("Step 1: Open System Authentication")
    print("-" * 50)
    print_packet("out", "AUTH REQUEST", "Algorithm: Open System, Seq: 1")
    print_packet("in", "AUTH RESPONSE", "Algorithm: Open System, Seq: 2, Status: Successful")
    
    print("""
💡 NOTE: This "authentication" is just a formality in WPA2.
   The REAL authentication happens in the 4-way handshake.
   This step exists for backward compatibility.
""")
    
    input("\nPress Enter for association...\n")
    
    # Association
    print("Step 2: Association")
    print("-" * 50)
    print_packet("out", "ASSOC REQUEST", 
                 "SSID: HomeNetwork_5G, Capabilities: 802.11n, 802.11ac")
    print_packet("in", "ASSOC RESPONSE", 
                 f"Status: Successful, Association ID: {random.randint(1, 100)}")
    
    print("""
💡 Association tells the AP:
   • Which network you want to join
   • What capabilities your device has
   • Establishes your "slot" on the network
   
   But you still can't send real data yet...
""")

def simulate_4way_handshake():
    """Simulate the WPA2 4-way handshake."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 3: THE 4-WAY HANDSHAKE (Where the magic happens)         ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    print_slow("""
This is where WPA2 security actually happens.
The goal: Prove you know the password WITHOUT sending it.
""")
    
    input("\nPress Enter to begin the handshake...\n")
    
    # Generate demonstration values
    anonce = generate_nonce()
    snonce = generate_nonce()
    ptk_demo = generate_nonce()
    
    print("=" * 60)
    print("MESSAGE 1 of 4: AP sends ANonce")
    print("=" * 60)
    print_packet("in", "EAPOL Key", f"ANonce: {anonce[:16]}...")
    print("""
   The AP generates a random number (ANonce) and sends it.
   This will be used to derive the encryption keys.
""")
    
    input("\nPress Enter for Message 2...\n")
    
    print("=" * 60)
    print("MESSAGE 2 of 4: Client sends SNonce + MIC")
    print("=" * 60)
    print("""
   Your device now has everything needed to calculate the PTK:
   
   PTK = PRF(PMK + ANonce + SNonce + AP_MAC + Client_MAC)
   
   Where PMK is derived from the WiFi password.
""")
    print(f"\n   📝 Calculating PTK...")
    time.sleep(1)
    print(f"   ✓ PTK generated: {ptk_demo[:16]}...")
    print()
    print_packet("out", "EAPOL Key", f"SNonce: {snonce[:16]}..., MIC: [proof of PTK]")
    print("""
   The MIC (Message Integrity Code) proves you calculated
   the correct PTK - which means you know the password.
   
   🔑 THE PASSWORD IS NEVER TRANSMITTED!
   Only proof that you could calculate the same result.
""")
    
    input("\nPress Enter for Message 3...\n")
    
    print("=" * 60)
    print("MESSAGE 3 of 4: AP sends GTK + confirmation")
    print("=" * 60)
    print_packet("in", "EAPOL Key", "GTK: [encrypted group key], MIC: [verified]")
    print("""
   The AP verified your MIC - you proved you know the password!
   
   Now it sends the Group Temporal Key (GTK), encrypted with
   the PTK you both derived. The GTK is used for broadcast
   traffic that goes to all devices.
""")
    
    input("\nPress Enter for Message 4...\n")
    
    print("=" * 60)
    print("MESSAGE 4 of 4: Client confirms")
    print("=" * 60)
    print_packet("out", "EAPOL Key", "ACK: Installation confirmed")
    print("""
   ✅ HANDSHAKE COMPLETE!
   
   Both sides now have:
   • PTK - For encrypted unicast (device-to-AP) traffic
   • GTK - For encrypted broadcast traffic
   
   All future communication will be encrypted.
""")

def simulate_dhcp():
    """Simulate DHCP address assignment."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 4: GETTING AN IP ADDRESS (DHCP)                          ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    print_slow("""
You're authenticated and encrypted, but you still need an IP
address to actually communicate on the network.
""")
    
    input("\nPress Enter to start DHCP...\n")
    
    offered_ip = f"192.168.1.{random.randint(100, 200)}"
    gateway = "192.168.1.1"
    dns = "192.168.1.1"
    
    print("DHCP Process:")
    print("-" * 50)
    print_packet("out", "DHCP DISCOVER", "Broadcast: I need an IP address!")
    print_packet("in", "DHCP OFFER", f"How about {offered_ip}? Gateway: {gateway}")
    print_packet("out", "DHCP REQUEST", f"Yes, I'll take {offered_ip} please")
    print_packet("in", "DHCP ACK", f"Confirmed. Lease time: 24 hours")
    
    print(f"""
   ✅ You now have:
   • IP Address: {offered_ip}
   • Gateway: {gateway}
   • DNS Server: {dns}
   • Lease Time: 24 hours
   
   💡 INSIGHT: DHCP traffic is encrypted by WPA2, but...
      Your hostname is often sent in the DHCP request.
      Everyone on the network could see "John's-MacBook" joined.
""")

def simulate_connection_complete():
    """Show the completed connection state."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  CONNECTION COMPLETE - WHAT'S HAPPENING NOW                     ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    print_slow("""
You're fully connected! Here's what's protecting your traffic:
""")
    
    print("""
   ┌─────────────────────────────────────────────────────────────┐
   │                    PROTECTION LAYERS                        │
   ├─────────────────────────────────────────────────────────────┤
   │                                                             │
   │   Your Data  ────┐                                          │
   │                  │                                          │
   │            ┌─────▼─────┐                                    │
   │            │  HTTPS    │  Protects web content              │
   │            │  (TLS)    │  from everyone including router    │
   │            └─────┬─────┘                                    │
   │                  │                                          │
   │            ┌─────▼─────┐                                    │
   │            │   WPA2    │  Protects from people NOT         │
   │            │ Encryption│  on your network                   │
   │            └─────┬─────┘                                    │
   │                  │                                          │
   │                  ▼                                          │
   │              [Router] ───► Internet                         │
   │                                                             │
   └─────────────────────────────────────────────────────────────┘
   
   ⚠️ IMPORTANT: WPA2 only protects the wireless hop!
   
   • Your router can still see unencrypted traffic
   • Other devices on the network can see broadcast traffic  
   • DNS queries reveal what sites you visit
   
   HTTPS provides end-to-end protection that WPA2 cannot.
""")

def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🔐 WIFI CONNECTION SIMULATOR                                    ║
║     Understanding What Happens When You Connect                  ║
╚══════════════════════════════════════════════════════════════════╝

This educational tool walks you through every step of connecting
to a WPA2-protected WiFi network.

You'll learn:
• How your device finds networks
• What information is exposed during connection
• How the 4-way handshake proves you know the password
• What protections you actually have (and don't have)

Press Enter to begin, or Ctrl+C to exit at any time.
""")
    
    input()
    
    try:
        simulate_scanning()
        input("\n" + "=" * 60 + "\nPress Enter for Phase 2: Authentication...\n")
        
        simulate_authentication()
        input("\n" + "=" * 60 + "\nPress Enter for Phase 3: 4-Way Handshake...\n")
        
        simulate_4way_handshake()
        input("\n" + "=" * 60 + "\nPress Enter for Phase 4: Getting an IP...\n")
        
        simulate_dhcp()
        input("\n" + "=" * 60 + "\nPress Enter to see the final summary...\n")
        
        simulate_connection_complete()
        
        print("""
╔══════════════════════════════════════════════════════════════════╗
║  📚 KEY TAKEAWAYS                                                ║
╚══════════════════════════════════════════════════════════════════╝

1. PROBE REQUESTS LEAK INFORMATION
   Your device announces what networks it knows. 
   Attackers can use this to track you or set up fake networks.

2. THE PASSWORD IS NEVER SENT OVER THE AIR
   The 4-way handshake uses cryptographic proofs.
   But capturing the handshake allows offline password cracking.

3. WPA2 ONLY PROTECTS THE WIRELESS HOP
   Once traffic reaches your router, WPA2 encryption is removed.
   Use HTTPS and VPNs for end-to-end protection.

4. EVERYONE ON THE NETWORK IS "INSIDE THE FIREWALL"
   Other devices on the same network can potentially:
   • See your MAC address and hostname
   • Monitor broadcast traffic
   • Attempt ARP spoofing attacks
   
5. ENCRYPT EVERYTHING YOU CAN
   • Use HTTPS
   • Use encrypted DNS (DoH/DoT)
   • Consider a VPN on untrusted networks
""")
        
    except KeyboardInterrupt:
        print("\n\nSimulation ended. Thanks for learning!")

if __name__ == "__main__":
    main()
