#!/usr/bin/env python3
"""
03_packet_types.py - Understanding WiFi Packet Types

This is an EDUCATIONAL script - it explains the different types of packets
you'd see on a WiFi network. No special privileges required.

LEARNING OBJECTIVE:
Understand the different types of traffic on a network and what
each type reveals about network activity.
"""

def explain_management_frames():
    """Explain WiFi management frames."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  802.11 MANAGEMENT FRAMES - The Invisible Chatter                ║
╚══════════════════════════════════════════════════════════════════╝

Management frames are how WiFi devices find, join, and leave networks.
These frames are NEVER ENCRYPTED (even on WPA2/WPA3 networks).

┌─────────────────────────────────────────────────────────────────┐
│  BEACON FRAMES                                                   │
│  Sent by: Access Points (your router)                           │
│  Frequency: Every ~100ms                                         │
│                                                                  │
│  Contains:                                                       │
│    • Network name (SSID) - unless hidden                        │
│    • Supported speeds and channels                               │
│    • Security type (WPA2, WPA3, etc.)                           │
│    • Router's MAC address (BSSID)                               │
│                                                                  │
│  🔍 What this reveals:                                          │
│     Anyone nearby can see what networks exist, their security,  │
│     and where the router physically is (signal strength).       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  PROBE REQUESTS                                                  │
│  Sent by: Your devices (phones, laptops, etc.)                  │
│  When: Device is looking for known networks                      │
│                                                                  │
│  Contains:                                                       │
│    • Your device's MAC address                                  │
│    • Networks your device is looking for (sometimes)            │
│    • Device capabilities                                         │
│                                                                  │
│  🔍 What this reveals:                                          │
│     YOUR PHONE BROADCASTS where you've been!                    │
│     If your phone is looking for "HomeWiFi" and "WorkWiFi",    │
│     anyone listening knows you have those networks saved.       │
│                                                                  │
│  😱 Real attack: Create a fake "HomeWiFi", your phone connects │
│     automatically. Called an "Evil Twin" attack.                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  PROBE RESPONSES                                                 │
│  Sent by: Access Points responding to requests                  │
│                                                                  │
│  Contains:                                                       │
│    • Network information (like a beacon)                        │
│    • Sent directly to requesting device                         │
│                                                                  │
│  🔍 What this reveals:                                          │
│     Shows active engagement between device and AP.              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  AUTHENTICATION FRAMES                                           │
│  Part of: Connection handshake                                  │
│                                                                  │
│  Contains:                                                       │
│    • Authentication type                                         │
│    • Success/failure status                                      │
│                                                                  │
│  🔍 What this reveals:                                          │
│     Who is connecting/disconnecting from the network.           │
│     Failed auths might indicate password guessing attempts.     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  DEAUTHENTICATION FRAMES                                        │
│  Sent by: AP or client to disconnect                            │
│                                                                  │
│  Contains:                                                       │
│    • Reason code for disconnect                                 │
│    • Source and destination                                      │
│                                                                  │
│  😱 ATTACK VECTOR:                                              │
│     These frames have NO authentication!                        │
│     Anyone can send fake deauth frames to kick you offline.     │
│     This is called a "deauthentication attack".                │
│                                                                  │
│  Defense: WPA3's Protected Management Frames (PMF)              │
└─────────────────────────────────────────────────────────────────┘
""")

def explain_data_frames():
    """Explain data frame types."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  DATA FRAMES - Your Actual Traffic                               ║
╚══════════════════════════════════════════════════════════════════╝

Data frames carry your actual internet traffic. These ARE encrypted
on WPA2/WPA3 networks, but some information is still visible.

┌─────────────────────────────────────────────────────────────────┐
│  WHAT'S ENCRYPTED (Protected):                                   │
│    • Payload content (your actual data)                         │
│    • Application-layer information                               │
│                                                                  │
│  WHAT'S NOT ENCRYPTED (Visible to everyone):                    │
│    • Source/destination MAC addresses                           │
│    • Frame size                                                  │
│    • Timing information                                          │
│    • QoS (Quality of Service) tags                              │
└─────────────────────────────────────────────────────────────────┘

Even with encryption, observers can learn:

  📊 TRAFFIC ANALYSIS
     • How much data you're transferring
     • When you're active online
     • Patterns that might indicate video streaming, gaming, etc.
     
  🔍 SIZE-BASED INFERENCE
     • Different activities have different packet size patterns
     • Video calls, file downloads, web browsing all look different
     
  ⏱️ TIMING ANALYSIS
     • Keystroke timing can sometimes be inferred
     • Request-response patterns reveal application behavior
""")

def explain_common_protocols():
    """Explain common network protocols."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  COMMON PROTOCOLS YOU'LL SEE                                     ║
╚══════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────┐
│  ARP - Address Resolution Protocol                               │
│  Purpose: Maps IP addresses to MAC addresses                    │
│  Encryption: NONE                                               │
│                                                                  │
│  Example:                                                        │
│    "Who has 192.168.1.1? Tell 192.168.1.100"                   │
│    "192.168.1.1 is at aa:bb:cc:dd:ee:ff"                       │
│                                                                  │
│  🔍 Reveals: All active IPs on the network                     │
│  😱 Attack: ARP spoofing - claim to be the router              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  DNS - Domain Name System                                        │
│  Purpose: Translates domain names to IP addresses               │
│  Encryption: Usually NONE (unless using DoH/DoT)               │
│                                                                  │
│  Example:                                                        │
│    "What's the IP for google.com?"                             │
│    "google.com is at 142.250.80.46"                            │
│                                                                  │
│  🔍 Reveals: EVERY WEBSITE you visit (by name)                 │
│  😱 Attack: DNS spoofing - return fake IP for a domain         │
│                                                                  │
│  ✅ Defense: Use encrypted DNS                                  │
│     • DNS over HTTPS (DoH): Cloudflare 1.1.1.1, Google 8.8.8.8│
│     • DNS over TLS (DoT): Supported by many providers          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  DHCP - Dynamic Host Configuration Protocol                     │
│  Purpose: Assigns IP addresses to devices                       │
│  Encryption: NONE                                               │
│                                                                  │
│  Process:                                                        │
│    1. DISCOVER: Device broadcasts "I need an IP!"              │
│    2. OFFER: Server offers an available IP                      │
│    3. REQUEST: Device accepts the offer                         │
│    4. ACK: Server confirms the lease                            │
│                                                                  │
│  🔍 Reveals: When devices connect, their hostnames             │
│  😱 Attack: Rogue DHCP - give devices wrong gateway/DNS        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  HTTP - Hypertext Transfer Protocol                              │
│  Purpose: Web traffic                                            │
│  Encryption: NONE (use HTTPS instead!)                          │
│                                                                  │
│  🔍 Reveals: EVERYTHING - URLs, content, cookies, passwords    │
│  😱 Attack: Read and modify any traffic                        │
│                                                                  │
│  ✅ Defense: ALWAYS use HTTPS. Use browser extensions like     │
│     HTTPS Everywhere. Never enter passwords on HTTP sites.      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  HTTPS/TLS - Encrypted Web Traffic                               │
│  Purpose: Secure web traffic                                    │
│  Encryption: YES                                                │
│                                                                  │
│  Still visible:                                                  │
│    • Server Name Indication (SNI) - what site you're visiting  │
│    • Traffic volume and patterns                                │
│    • Timing information                                          │
│                                                                  │
│  Protected:                                                       │
│    • Page content                                                │
│    • Cookies and credentials                                    │
│    • Specific URLs (just the domain is visible)                │
│                                                                  │
│  Note: Encrypted SNI (ECH) is rolling out to hide even this    │
└─────────────────────────────────────────────────────────────────┘
""")

def explain_the_4way_handshake():
    """Explain the WPA2 4-way handshake."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  THE WPA2 4-WAY HANDSHAKE - How WiFi Encryption Works           ║
╚══════════════════════════════════════════════════════════════════╝

When you connect to a WPA2 network, this happens:

        Your Device                          Access Point
             │                                     │
             │  ← ─ ─ 1. ANonce ─ ─ ─ ─ ─ ─ ─ ─ ─│
             │     (Random number from AP)         │
             │                                     │
    ┌────────┴────────┐                           │
    │ Calculate PTK:  │                           │
    │ PTK = f(PMK,    │                           │
    │   ANonce,       │                           │
    │   SNonce,       │                           │
    │   MAC addrs)    │                           │
    └────────┬────────┘                           │
             │                                     │
             │─ ─ ─ 2. SNonce + MIC ─ ─ ─ ─ ─ ─ →│
             │     (My random number + proof)      │
             │                                    │
             │                          ┌─────────┴─────────┐
             │                          │ Calculate PTK     │
             │                          │ Verify MIC        │
             │                          │ (Proves client    │
             │                          │  knows password)  │
             │                          └─────────┬─────────┘
             │                                    │
             │  ← ─ ─ 3. GTK + MIC ─ ─ ─ ─ ─ ─ ─│
             │     (Group key for broadcasts)     │
             │                                    │
             │─ ─ ─ 4. ACK ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ →│
             │     (Confirmation)                 │
             │                                    │
      ══════════════════════════════════════════════
                  ENCRYPTED COMMUNICATION
      ══════════════════════════════════════════════

KEY TERMS:
    
  • PMK (Pairwise Master Key): Derived from your WiFi password
  • PTK (Pairwise Transient Key): Session key for your connection
  • GTK (Group Temporal Key): Shared key for broadcast traffic
  • ANonce/SNonce: Random numbers to ensure unique keys
  • MIC (Message Integrity Code): Proof that you know the password

🔍 CRITICAL INSIGHT:
   
   The password is NEVER sent over the air!
   
   Both sides independently calculate the same keys using:
   - The password (you both know it)
   - Random numbers (exchanged in the handshake)
   - MAC addresses (visible to both)
   
   The MIC proves you calculated the same result without
   revealing the password.

😱 ATTACK VECTOR:
   
   If an attacker captures this handshake, they can:
   1. Take it offline
   2. Try millions of passwords
   3. See if any produces a matching MIC
   
   This is why strong, unique passwords matter!
   A 12+ character random password would take centuries to crack.
""")

def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  📚 WIFI PACKET TYPES - EDUCATIONAL REFERENCE                    ║
╚══════════════════════════════════════════════════════════════════╝

This guide explains what types of packets flow over WiFi networks
and what information each type reveals. Understanding this helps
you make informed decisions about your network security.

Press Enter to continue through each section, or Ctrl+C to exit.
""")
    
    sections = [
        ("Management Frames", explain_management_frames),
        ("Data Frames", explain_data_frames),
        ("Common Protocols", explain_common_protocols),
        ("The 4-Way Handshake", explain_the_4way_handshake),
    ]
    
    for i, (name, func) in enumerate(sections, 1):
        input(f"\n[{i}/{len(sections)}] Press Enter to learn about {name}...")
        func()
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  📋 SUMMARY: WHAT'S VISIBLE ON YOUR NETWORK                      ║
╚══════════════════════════════════════════════════════════════════╝

Even with WPA2/WPA3 encryption:

  ALWAYS VISIBLE (to anyone nearby):
    ✗ Network names and locations
    ✗ Device MAC addresses
    ✗ When devices connect/disconnect
    ✗ Broadcast traffic patterns
    
  VISIBLE TO NETWORK USERS:
    ✗ ARP traffic (all device IPs)
    ✗ DNS queries (if not encrypted)
    ✗ DHCP hostnames
    ✗ Traffic patterns and volumes
    
  PROTECTED:
    ✓ Packet contents (if encrypted at WiFi layer)
    ✓ HTTPS content (double encrypted)
    ✓ VPN traffic (triple encrypted)

BEST PRACTICES:
    
  1. Use WPA3 where possible (has Protected Management Frames)
  2. Enable encrypted DNS (DoH or DoT)
  3. Use HTTPS everywhere
  4. Consider a VPN on untrusted networks
  5. Randomize MAC addresses on mobile devices
  6. Don't save sensitive network names (they're broadcast!)
""")

if __name__ == "__main__":
    main()
