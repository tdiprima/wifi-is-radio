#!/usr/bin/env python3
"""
04_dns_observer.py - Watch DNS Queries on Your Network

This script monitors DNS queries on YOUR network, showing you what
domain names devices are looking up. Requires root privileges.

LEARNING OBJECTIVE:
Understand how DNS queries reveal browsing activity, and why
encrypted DNS (DoH/DoT) is important for privacy.

Run with: sudo python3 04_dns_observer.py

ONLY USE ON YOUR OWN NETWORK.
"""

import sys
import os
from datetime import datetime
from collections import defaultdict

def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        print("❌ This script requires root privileges.")
        print("   Run with: sudo python3 04_dns_observer.py")
        sys.exit(1)

def get_interface():
    """Get the primary network interface."""
    import subprocess
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'default' in line:
                parts = line.split()
                dev_idx = parts.index('dev') + 1
                return parts[dev_idx]
    except Exception:
        pass
    return 'eth0'

def analyze_dns_packet(packet):
    """
    Analyze a DNS packet and extract query information.
    
    DNS packets contain:
    - Transaction ID
    - Flags (query vs response, recursion, etc.)
    - Questions (what's being asked)
    - Answers (IP addresses, etc.)
    """
    from scapy.all import DNS, DNSQR, DNSRR, IP
    
    if not packet.haslayer(DNS):
        return None
    
    dns = packet[DNS]
    
    result = {
        'time': datetime.now().strftime('%H:%M:%S'),
        'src_ip': packet[IP].src if packet.haslayer(IP) else 'unknown',
        'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'unknown',
        'is_response': dns.qr == 1,
        'queries': [],
        'answers': []
    }
    
    # Extract query names
    if dns.qdcount > 0 and dns.qd:
        for i in range(dns.qdcount):
            try:
                qname = dns.qd[i].qname.decode() if isinstance(dns.qd[i].qname, bytes) else str(dns.qd[i].qname)
                qtype = dns.qd[i].qtype
                type_names = {1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS'}
                result['queries'].append({
                    'name': qname.rstrip('.'),
                    'type': type_names.get(qtype, str(qtype))
                })
            except:
                pass
    
    # Extract answers (if response)
    if dns.ancount > 0 and dns.an:
        for i in range(dns.ancount):
            try:
                answer = dns.an[i]
                if hasattr(answer, 'rdata'):
                    rdata = answer.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode()
                    result['answers'].append(str(rdata))
            except:
                pass
    
    return result

def categorize_domain(domain: str) -> str:
    """
    Categorize a domain into a broad category.
    This helps understand what types of activity are happening.
    """
    domain = domain.lower()
    
    categories = {
        'Advertising/Tracking': [
            'doubleclick', 'googlesyndication', 'googleadservices',
            'facebook.com/tr', 'analytics', 'tracking', 'adservice',
            'scorecardresearch', 'quantserve', 'adsserver'
        ],
        'Social Media': [
            'facebook', 'twitter', 'instagram', 'tiktok', 'linkedin',
            'snapchat', 'reddit', 'pinterest'
        ],
        'Streaming': [
            'netflix', 'youtube', 'twitch', 'spotify', 'hulu',
            'disney', 'hbo', 'amazonvideo', 'primevideo'
        ],
        'Cloud Services': [
            'amazonaws', 'azure', 'cloudfront', 'akamai', 
            'cloudflare', 'fastly', 'googleusercontent'
        ],
        'Apple Services': [
            'apple.com', 'icloud', 'itunes', 'mzstatic'
        ],
        'Microsoft Services': [
            'microsoft', 'windows', 'office', 'outlook', 'live.com',
            'msn.com', 'bing.com'
        ],
        'Google Services': [
            'google', 'googleapis', 'gstatic', 'youtube', 'gmail'
        ],
        'IoT/Smart Home': [
            'nest', 'ring.com', 'smartthings', 'tuya', 'wemo',
            'myq', 'ecobee', 'arlo.com'
        ],
    }
    
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword in domain:
                return category
    
    return 'Other'

def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🔍 DNS OBSERVER - See What Your Network Is Looking Up          ║
╚══════════════════════════════════════════════════════════════════╝

This tool monitors DNS queries on YOUR network. It shows what 
domain names are being resolved to IP addresses.

🔑 WHY THIS MATTERS:

   Traditional DNS is UNENCRYPTED. Anyone on your network can see
   every website every device visits - just by watching DNS.
   
   This is why:
   • ISPs can (and do) log your browsing history
   • Public WiFi is dangerous without a VPN
   • Encrypted DNS (DoH/DoT) is important

Press Ctrl+C to stop monitoring.
""")

    check_root()
    
    interface = get_interface()
    print(f"📡 Monitoring DNS on interface: {interface}")
    print("=" * 70)
    print(f"{'Time':<10} {'Source IP':<16} {'Domain':<35} {'Category'}")
    print("=" * 70)
    
    # Statistics
    stats = defaultdict(int)
    domains_seen = set()
    
    try:
        from scapy.all import sniff, DNS, conf
        conf.verb = 0
        
        def packet_callback(packet):
            result = analyze_dns_packet(packet)
            if result and result['queries'] and not result['is_response']:
                for query in result['queries']:
                    domain = query['name']
                    if domain and domain not in domains_seen:
                        domains_seen.add(domain)
                        category = categorize_domain(domain)
                        stats[category] += 1
                        
                        # Truncate long domains
                        display_domain = domain[:33] + '..' if len(domain) > 35 else domain
                        
                        print(f"{result['time']:<10} {result['src_ip']:<16} {display_domain:<35} {category}")
        
        # Capture DNS packets (port 53)
        sniff(
            iface=interface,
            filter="udp port 53",
            prn=packet_callback,
            store=False
        )
        
    except KeyboardInterrupt:
        print("\n\n" + "=" * 70)
        print("📊 SESSION STATISTICS")
        print("=" * 70)
        print(f"\nUnique domains observed: {len(domains_seen)}")
        print("\nBy category:")
        for category, count in sorted(stats.items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 40)
            print(f"  {category:<20} {count:>4} {bar}")
        
        print("""
🔐 PRIVACY RECOMMENDATIONS:

1. Use encrypted DNS to hide these queries:
   • Cloudflare: 1.1.1.1 (supports DoH and DoT)
   • Google: 8.8.8.8 (supports DoH and DoT)
   • Quad9: 9.9.9.9 (privacy-focused)

2. Configure DNS encryption:
   • macOS/iOS: Settings → WiFi → DNS → Manual → Add DoH server
   • Android: Settings → Network → Private DNS
   • Browser: Firefox/Chrome have DoH built-in

3. Use a VPN for complete privacy on untrusted networks

4. Consider Pi-hole or AdGuard Home to block trackers at DNS level
""")
        
    except ImportError:
        print("❌ Scapy not installed. Run: pip install scapy")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
