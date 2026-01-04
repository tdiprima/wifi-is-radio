# WiFi Security Learning Kit 🛜

A small set of Python scripts for understanding what's observable on **your own WiFi network**.

This is about visibility, not breaking in.

## ⚠️ Ethics (Read This)

Use these tools **only** on networks you own or have explicit permission to test.
Learning how networks leak info ≠ permission to spy.

## What This Covers (High Level)

* How devices appear and announce themselves on WiFi
* What metadata is visible even with WPA2/WPA3
* What encryption does *and doesn't* hide
* Why HTTPS, VPNs, and segmentation actually matter

No exploits, no gimmicks — just how the air actually behaves.

## Scripts

| Script                       | Purpose                       | Root |
| ---------------------------- | ----------------------------- | ---- |
| `01_network_info.py`         | Local network details         | No   |
| `02_arp_discovery.py`        | Discover devices on LAN       | Yes  |
| `03_packet_types.py`         | Common WiFi / network packets | No   |
| `04_dns_observer.py`         | Observe DNS traffic           | Yes  |
| `05_traffic_analyzer.py`     | Traffic patterns & volume     | Yes  |
| `06_connection_simulator.py` | WiFi connection flow          | No   |
| `07_security_audit.py`       | Basic network sanity checks   | Yes  |

## Running

```bash
python3 01_network_info.py
python3 03_packet_types.py
python3 06_connection_simulator.py

sudo python3 02_arp_discovery.py
sudo python3 04_dns_observer.py
sudo python3 05_traffic_analyzer.py
sudo python3 07_security_audit.py
```

Root is required only when capturing packets.

## Things This Will Make Obvious

* WiFi encryption protects **payloads**, not **presence**
* Devices leak identity and behavior through metadata
* Anyone on the same network can see more than you think
* "Hidden" networks and MAC filtering are weak defenses
* HTTPS and VPNs are not optional on shared networks

## If You Want to Go Deeper

* WPA3 vs WPA2
* Encrypted DNS (DoH / DoT)
* Router-level VPNs
* VLANs for IoT devices
* Wireshark for real packet inspection

## Final Note

This kit is for defense and understanding:

* Secure your own network
* Make smarter choices on public WiFi
* Cut through security hype with reality

Know the system. Don't be weird with it.

<br>
