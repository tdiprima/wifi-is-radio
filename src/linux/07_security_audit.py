#!/usr/bin/env python3
"""
07_security_audit.py - Basic Security Audit of Your Network

This script performs a basic security assessment of YOUR network,
checking for common misconfigurations and vulnerabilities.

LEARNING OBJECTIVE:
Learn what to check when evaluating network security, and understand
common weaknesses in home/small office networks.

Run with: sudo python3 07_security_audit.py

ONLY USE ON YOUR OWN NETWORK.
"""

import sys
import os
import subprocess
import socket
from datetime import datetime

def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        print("❌ This script requires root privileges for full analysis.")
        print("   Run with: sudo python3 07_security_audit.py")
        sys.exit(1)

def print_finding(severity, title, description, recommendation):
    """Print a security finding."""
    icons = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}
    icon = icons.get(severity, '•')
    
    print(f"\n{icon} [{severity}] {title}")
    print(f"   {description}")
    if recommendation:
        print(f"   ✅ Recommendation: {recommendation}")

def get_gateway():
    """Get the default gateway IP."""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'default' in line:
                return line.split()[2]
    except:
        pass
    return None

def get_local_ip():
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None

def check_router_ports(gateway):
    """Check for open ports on the router."""
    findings = []
    
    dangerous_ports = {
        21: ('FTP', 'File transfer, often unencrypted'),
        22: ('SSH', 'Remote access - secure if properly configured'),
        23: ('Telnet', 'Remote access, completely unencrypted'),
        80: ('HTTP', 'Web interface, check if it requires HTTPS'),
        443: ('HTTPS', 'Secure web interface'),
        445: ('SMB', 'File sharing, common attack target'),
        3389: ('RDP', 'Remote desktop, common attack target'),
        8080: ('HTTP-Alt', 'Alternative web interface'),
        8443: ('HTTPS-Alt', 'Alternative secure web interface'),
    }
    
    print("\n📡 Checking router ports...")
    
    open_ports = []
    for port, (name, desc) in dangerous_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((gateway, port))
            sock.close()
            
            if result == 0:
                open_ports.append((port, name, desc))
                print(f"   ✓ Port {port} ({name}): OPEN")
            else:
                print(f"   ✗ Port {port} ({name}): Closed")
        except:
            pass
    
    # Generate findings
    for port, name, desc in open_ports:
        if port == 23:
            findings.append(('HIGH', 'Telnet (port 23) open on router',
                           'Telnet sends credentials in plain text',
                           'Disable Telnet and use SSH instead'))
        elif port == 21:
            findings.append(('MEDIUM', 'FTP (port 21) open on router',
                           'FTP credentials and data are unencrypted',
                           'Disable FTP or switch to SFTP'))
        elif port == 80:
            findings.append(('LOW', 'HTTP (port 80) open on router',
                           'Web admin interface may accept unencrypted logins',
                           'Ensure admin panel redirects to HTTPS'))
        elif port in [445, 3389]:
            findings.append(('MEDIUM', f'{name} (port {port}) open on router',
                           desc,
                           'Disable if not needed, or restrict access'))
    
    return findings

def check_dns_configuration():
    """Check DNS configuration for potential issues."""
    findings = []
    
    print("\n🔍 Checking DNS configuration...")
    
    try:
        with open('/etc/resolv.conf', 'r') as f:
            content = f.read()
        
        dns_servers = []
        for line in content.split('\n'):
            if line.startswith('nameserver'):
                dns_servers.append(line.split()[1])
        
        for dns in dns_servers:
            print(f"   DNS Server: {dns}")
            
            # Check if it's the gateway (potentially logging)
            gateway = get_gateway()
            if dns == gateway:
                findings.append(('INFO', 'Using router as DNS server',
                               'Your router handles DNS - it can log all domains you visit',
                               'Consider using encrypted DNS (1.1.1.1 DoH or 8.8.8.8 DoH)'))
    except:
        pass
    
    return findings

def check_arp_table():
    """Check ARP table for anomalies."""
    findings = []
    
    print("\n📋 Checking ARP table...")
    
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        
        ip_to_mac = {}
        mac_to_ips = {}
        
        for line in lines:
            if '(' in line and ')' in line:
                parts = line.split()
                ip = parts[1].strip('()')
                mac = parts[3] if len(parts) > 3 else 'unknown'
                
                if mac != 'unknown' and mac != '(incomplete)':
                    ip_to_mac[ip] = mac
                    if mac not in mac_to_ips:
                        mac_to_ips[mac] = []
                    mac_to_ips[mac].append(ip)
                    print(f"   {ip:<16} → {mac}")
        
        # Check for duplicate MACs (potential ARP spoofing)
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                findings.append(('HIGH', 'Multiple IPs sharing same MAC address',
                               f'MAC {mac} is associated with: {", ".join(ips)}',
                               'This could indicate ARP spoofing attack'))
        
        # Check for gateway MAC
        gateway = get_gateway()
        if gateway and gateway in ip_to_mac:
            print(f"\n   Gateway {gateway} has MAC: {ip_to_mac[gateway]}")
    
    except Exception as e:
        print(f"   Error checking ARP: {e}")
    
    return findings

def check_open_services():
    """Check for potentially insecure services on the network."""
    findings = []
    
    print("\n🔌 Checking for common insecure services...")
    
    local_ip = get_local_ip()
    if not local_ip:
        return findings
    
    network_prefix = '.'.join(local_ip.split('.')[:3])
    
    # Check for common insecure services (quick scan of common IPs)
    insecure_services = []
    test_ips = [f"{network_prefix}.{i}" for i in [1, 2, 100, 101, 102, 254]]
    
    for ip in test_ips:
        # Quick check for Telnet
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, 23)) == 0:
                insecure_services.append((ip, 23, 'Telnet'))
            sock.close()
        except:
            pass
        
        # Quick check for unencrypted HTTP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, 80)) == 0:
                insecure_services.append((ip, 80, 'HTTP'))
            sock.close()
        except:
            pass
    
    for ip, port, service in insecure_services:
        print(f"   Found {service} on {ip}:{port}")
    
    if any(s[2] == 'Telnet' for s in insecure_services):
        findings.append(('HIGH', 'Telnet services found on network',
                        'Telnet transmits credentials in plain text',
                        'Disable Telnet on all devices, use SSH instead'))
    
    return findings

def check_local_security():
    """Check local machine security settings."""
    findings = []
    
    print("\n🖥️ Checking local security settings...")
    
    # Check if firewall is enabled
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
        if 'inactive' in result.stdout.lower():
            findings.append(('MEDIUM', 'Local firewall (ufw) is disabled',
                           'Your machine accepts all incoming connections',
                           'Enable with: sudo ufw enable'))
            print("   Firewall: DISABLED")
        else:
            print("   Firewall: Enabled")
    except:
        print("   Firewall: Unable to check (ufw not installed)")
    
    # Check listening services
    try:
        result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
        listening = result.stdout.count('LISTEN')
        print(f"   Listening services: {listening}")
    except:
        pass
    
    return findings

def generate_report(all_findings):
    """Generate a summary report."""
    print("\n" + "=" * 70)
    print("📊 SECURITY AUDIT REPORT")
    print("=" * 70)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Scope: Local network assessment")
    
    # Count by severity
    by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []}
    for finding in all_findings:
        by_severity[finding[0]].append(finding)
    
    print("\n📈 SUMMARY:")
    print(f"   🔴 High severity:   {len(by_severity['HIGH'])}")
    print(f"   🟡 Medium severity: {len(by_severity['MEDIUM'])}")
    print(f"   🟢 Low severity:    {len(by_severity['LOW'])}")
    print(f"   ℹ️  Informational:  {len(by_severity['INFO'])}")
    
    # Print findings by severity
    print("\n" + "-" * 70)
    print("DETAILED FINDINGS")
    print("-" * 70)
    
    for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
        for finding in by_severity[severity]:
            print_finding(*finding)
    
    if not all_findings:
        print("\n✅ No significant security issues found in this basic scan.")
    
    # General recommendations
    print("\n" + "=" * 70)
    print("📝 GENERAL SECURITY RECOMMENDATIONS")
    print("=" * 70)
    print("""
1. ROUTER SECURITY
   • Change default admin password
   • Disable WPS (WiFi Protected Setup)
   • Enable WPA3 if available, otherwise WPA2
   • Disable remote management
   • Keep firmware updated

2. NETWORK SEGMENTATION
   • Put IoT devices on a separate network/VLAN
   • Use guest network for visitors
   • Enable AP isolation if available

3. DNS SECURITY
   • Use encrypted DNS (DoH or DoT)
   • Consider: Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9)

4. ENDPOINT SECURITY
   • Enable local firewalls on all devices
   • Keep operating systems and software updated
   • Use HTTPS
   • Consider a VPN for sensitive activities

5. MONITORING
   • Review connected devices regularly
   • Check router logs periodically
   • Consider network monitoring tools
""")

def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🔐 NETWORK SECURITY AUDIT                                       ║
║     Basic Assessment of Your Network Security                    ║
╚══════════════════════════════════════════════════════════════════╝

This tool performs a basic security assessment of YOUR network.
It checks for common misconfigurations and potential vulnerabilities.

⚠️ IMPORTANT: Only run this on networks you own or have permission to test.

This is NOT a comprehensive penetration test. It's an educational tool
to help you understand what to look for in network security.
""")

    check_root()
    
    all_findings = []
    
    gateway = get_gateway()
    local_ip = get_local_ip()
    
    print("\n📍 Network Information:")
    print(f"   Your IP: {local_ip}")
    print(f"   Gateway: {gateway}")
    
    if gateway:
        all_findings.extend(check_router_ports(gateway))
    
    all_findings.extend(check_dns_configuration())
    all_findings.extend(check_arp_table())
    all_findings.extend(check_open_services())
    all_findings.extend(check_local_security())
    
    generate_report(all_findings)
    
    print("\n" + "=" * 70)
    print("💡 REMEMBER: Security is a process, not a product.")
    print("=" * 70)
    print("""
This basic audit only scratches the surface. For thorough security:

• Perform regular audits
• Stay informed about new vulnerabilities
• Test your defenses periodically
• Keep everything updated
• Practice good security hygiene

Knowledge is your best defense. Keep learning!
""")

if __name__ == "__main__":
    main()
