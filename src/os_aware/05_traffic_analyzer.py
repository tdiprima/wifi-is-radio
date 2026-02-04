#!/usr/bin/env python3
"""
05_traffic_analyzer.py - Analyze Traffic Patterns on Your Network

This script captures and analyzes traffic patterns on YOUR network,
showing you what kinds of communication are happening.

LEARNING OBJECTIVE:
Understand how traffic analysis works - even without reading content,
patterns themselves reveal information.

Run with: sudo python3 05_traffic_analyzer.py

ONLY USE ON YOUR OWN NETWORK.
"""

import os
import sys
import time
from collections import defaultdict

from network_os_utils import get_interface


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        print("❌ This script requires root privileges.")
        print("   Run with: sudo python3 05_traffic_analyzer.py")
        sys.exit(1)


# get_interface is imported from network_os_utils


class TrafficAnalyzer:
    """Analyzes network traffic patterns."""

    def __init__(self):
        self.packet_count = 0
        self.bytes_total = 0
        self.protocols = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {"sent": 0, "received": 0, "packets": 0})
        self.start_time = time.time()
        self.packet_sizes = []

        # Well-known ports
        self.port_names = {
            20: "FTP-Data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP-Server",
            68: "DHCP-Client",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            587: "SMTP-Submit",
            993: "IMAPS",
            995: "POP3S",
            1194: "OpenVPN",
            1883: "MQTT",
            3306: "MySQL",
            3389: "RDP",
            5060: "SIP",
            5061: "SIPS",
            5353: "mDNS",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8883: "MQTT-TLS",
            # Streaming and common services
            554: "RTSP",
            1935: "RTMP",
            5228: "Google-Play",
            19302: "Google-STUN",
            3478: "STUN",
            3479: "STUN-Alt",
        }

    def analyze_packet(self, packet):
        """Analyze a single packet."""
        from scapy.all import ICMP, IP, TCP, UDP

        self.packet_count += 1

        if packet.haslayer(IP):
            ip = packet[IP]
            size = len(packet)
            self.bytes_total += size
            self.packet_sizes.append(size)

            # Track by IP
            self.ip_stats[ip.src]["sent"] += size
            self.ip_stats[ip.src]["packets"] += 1
            self.ip_stats[ip.dst]["received"] += size

            # Protocol detection
            if packet.haslayer(TCP):
                self.protocols["TCP"] += 1
                tcp = packet[TCP]
                self.port_stats[tcp.dport] += 1
                self.port_stats[tcp.sport] += 1
            elif packet.haslayer(UDP):
                self.protocols["UDP"] += 1
                udp = packet[UDP]
                self.port_stats[udp.dport] += 1
                self.port_stats[udp.sport] += 1
            elif packet.haslayer(ICMP):
                self.protocols["ICMP"] += 1
            else:
                self.protocols["Other IP"] += 1
        else:
            self.protocols["Non-IP"] += 1

    def get_port_name(self, port: int) -> str:
        """Get human-readable name for a port."""
        return self.port_names.get(port, f"Port-{port}")

    def print_live_stats(self):
        """Print current statistics."""
        elapsed = time.time() - self.start_time
        rate = self.bytes_total / elapsed if elapsed > 0 else 0

        print("\033[2J\033[H")  # Clear screen
        print("=" * 70)
        print("📊 LIVE TRAFFIC ANALYSIS")
        print("=" * 70)
        print(f"\n⏱️  Running for: {elapsed:.1f}s")
        print(f"📦 Packets captured: {self.packet_count:,}")
        print(f"💾 Total data: {self.format_bytes(self.bytes_total)}")
        print(f"📈 Average rate: {self.format_bytes(rate)}/s")

        # Protocol breakdown
        print("\n" + "-" * 70)
        print("🔌 PROTOCOL BREAKDOWN")
        print("-" * 70)
        for proto, count in sorted(self.protocols.items(), key=lambda x: -x[1])[:5]:
            pct = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            bar = "█" * int(pct / 2)
            print(f"  {proto:<12} {count:>8,} packets ({pct:>5.1f}%) {bar}")

        # Top ports
        print("\n" + "-" * 70)
        print("🚪 TOP PORTS (reveals what services are in use)")
        print("-" * 70)
        top_ports = sorted(self.port_stats.items(), key=lambda x: -x[1])[:10]
        for port, count in top_ports:
            name = self.get_port_name(port)
            bar = "█" * min(count // 10, 30)
            print(f"  {port:>5} ({name:<14}) {count:>6} {bar}")

        # Top talkers
        print("\n" + "-" * 70)
        print("🗣️  TOP TALKERS (most active IPs)")
        print("-" * 70)
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]["sent"] + x[1]["received"],
            reverse=True,
        )[:8]
        for ip, stats in sorted_ips:
            total = stats["sent"] + stats["received"]
            print(
                f"  {ip:<16} Total: {self.format_bytes(total):>10}  "
                f"TX: {self.format_bytes(stats['sent']):>10}  "
                f"RX: {self.format_bytes(stats['received']):>10}  "
                f"Pkts: {stats['packets']:>6}"
            )

        print("\n" + "=" * 70)
        print("Press Ctrl+C to stop and see final analysis")

    def format_bytes(self, bytes_val: float) -> str:
        """Format bytes into human-readable string."""
        for unit in ("B", "KB", "MB", "GB"):
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"

    def print_final_analysis(self):
        """Print final analysis with insights."""
        print("\n\n" + "=" * 70)
        print("🔬 FINAL TRAFFIC ANALYSIS")
        print("=" * 70)

        elapsed = time.time() - self.start_time
        print(f"\n⏱️  Total capture duration: {elapsed:.1f} seconds")
        print(f"📦 Total packets analyzed: {self.packet_count:,}")
        print(f"💾 Total data captured: {self.format_bytes(self.bytes_total)}")

        # Packet size analysis
        if self.packet_sizes:
            avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
            min_size = min(self.packet_sizes)
            max_size = max(self.packet_sizes)

            print(
                f"""
📊 PACKET SIZE STATISTICS:
   Average: {avg_size:.0f} bytes
   Minimum: {min_size} bytes
   Maximum: {max_size} bytes
   
   💡 WHAT THIS REVEALS:
      • Small packets (~64-200 bytes): Interactive traffic (SSH, gaming, chat)
      • Medium packets (~500-1000 bytes): Web browsing, API calls
      • Large packets (~1400+ bytes): Downloads, streaming, file transfers
"""
            )

        # Protocol insights
        print("-" * 70)
        print("🔍 TRAFFIC INSIGHTS")
        print("-" * 70)

        https_count = self.port_stats.get(443, 0)
        http_count = self.port_stats.get(80, 0)
        dns_count = self.port_stats.get(53, 0)

        if http_count > 0 and https_count > 0:
            https_pct = https_count / (http_count + https_count) * 100
            print(
                f"""
   🔒 Encryption ratio: {https_pct:.1f}% of web traffic is HTTPS
      {"✅ Good! Most traffic is encrypted." if https_pct > 90 else "⚠️ Some unencrypted HTTP traffic detected!"}
"""
            )

        if dns_count > 0:
            print(
                f"""
   📡 DNS queries: {dns_count} observed
      Unless using DoH/DoT, these reveal every site visited.
"""
            )

        # Suspicious port check
        suspicious_ports = [
            (port, self.get_port_name(port))
            for port in (23, 21, 445, 3389)  # Telnet, FTP, SMB, RDP
            if self.port_stats.get(port, 0) > 0
        ]

        if suspicious_ports:
            print("   ⚠️ POTENTIALLY INSECURE SERVICES DETECTED:")
            for port, name in suspicious_ports:
                print(f"      • {name} (port {port}) - Consider if this is needed")

        print(
            """
🔐 WHAT TRAFFIC ANALYSIS REVEALS (even without decryption):

   1. TIMING PATTERNS
      • When you're online
      • Burst patterns suggest video calls, streaming
      
   2. SIZE PATTERNS  
      • Large downloads/uploads are visible
      • Interactive vs. bulk transfer is distinguishable
      
   3. COMMUNICATION PATTERNS
      • Who you communicate with (by IP)
      • How frequently
      • For how long

   This is why a VPN matters - it hides all of this from local observers
   by encrypting everything and routing it through a single tunnel.
"""
        )


def main():
    print(
        """
╔══════════════════════════════════════════════════════════════════╗
║  📊 TRAFFIC PATTERN ANALYZER                                     ║
╚══════════════════════════════════════════════════════════════════╝

This tool analyzes traffic patterns on YOUR network, showing what
types of communication are happening without reading content.

🔑 KEY CONCEPT: Traffic Analysis

   Even fully encrypted traffic reveals patterns:
   • What ports are being used (what applications)
   • How much data is being transferred
   • Who is talking to whom
   • When activity occurs

   This is called "metadata" - and it's often as revealing
   as the content itself.

Press Ctrl+C to stop and see detailed analysis.
"""
    )

    check_root()

    interface = get_interface()
    print(f"📡 Capturing on interface: {interface}")
    print("   Starting capture... (traffic will appear shortly)")

    analyzer = TrafficAnalyzer()
    last_update = time.time()

    try:
        from scapy.all import conf, sniff

        conf.verb = 0

        def packet_callback(packet):
            nonlocal last_update
            analyzer.analyze_packet(packet)

            # Update display every 2 seconds
            if time.time() - last_update > 2:
                analyzer.print_live_stats()
                last_update = time.time()

        sniff(iface=interface, prn=packet_callback, store=False)

    except KeyboardInterrupt:
        analyzer.print_final_analysis()

    except ImportError:
        print("❌ Scapy not installed. Run: pip install scapy")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
