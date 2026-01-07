# 🔐 WIFI CONNECTION SIMULATOR                                    
Understanding What Happens When You Connect

This educational tool walks you through every step of connecting
to a WPA2-protected WiFi network.

You'll learn:  

- How your device finds networks  
- What information is exposed during connection  
- How the 4-way handshake proves you know the password  
- What protections you actually have (and don't have)

## PHASE 1: SCANNING FOR NETWORKS

When you turn on WiFi, your device does two things:

1. PASSIVE SCANNING: Listens for beacon frames  
   Routers broadcast their presence every ~100ms
   
2. ACTIVE SCANNING: Sends probe requests  
   Your device asks "Is [network name] here?"


📡 Your device is listening for beacon frames...  
  <span style="color:#0f0;">← [BEACON]</span> SSID: HomeNetwork\_5G, Security: WPA2, Signal: -45dBm  
  <span style="color:#0f0;">← [BEACON]</span> SSID: NETGEAR-Guest, Security: Open, Signal: -60dBm  
  <span style="color:#0f0;">← [BEACON]</span> SSID: Apartment\_204, Security: WPA2, Signal: -72dBm  
  <span style="color:#0f0;">← [BEACON]</span> SSID: CoffeeShop\_Free, Security: Open, Signal: -80dBm  

💡 INSIGHT: Beacon frames are NEVER encrypted.  
   Anyone nearby can see:  
   
   - What networks exist  
   - Their security settings  
   - Approximate router locations (via signal strength)


📱 Your device sends probe requests for saved networks...  
  <span style="color:#0ff;">→ [PROBE REQUEST]</span> Looking for: HomeNetwork\_5G  
  <span style="color:#0ff;">→ [PROBE REQUEST]</span> Looking for: Work-Corporate  
  <span style="color:#0ff;">→ [PROBE REQUEST]</span> Looking for: Airport\_WiFi  

⚠️ PRIVACY CONCERN: Your device just announced where you've been!

   By probing for "Work-Corporate" and "Airport\_WiFi", you revealed:
  
   - You work at a company using that network name  
   - You recently traveled through that airport  
   
   Attackers use this for:

   - Tracking individuals  
   - Setting up "evil twin" networks with names you trust  
   
   🛡️ DEFENSE: Disable "auto-join" for sensitive networks


## PHASE 2: AUTHENTICATION

You select "HomeNetwork\_5G" and enter the password.  
Now the authentication process begins...


Your device MAC: xx:xx:xx:xx:xx:xx  
Access Point MAC: xx:xx:xx:xx:xx:xy

### Step 1: Open System Authentication

  <span style="color:#0ff;">→ [AUTH REQUEST]</span> Algorithm: Open System, Seq: 1  
  <span style="color:#0f0;">← [AUTH RESPONSE]</span> Algorithm: Open System, Seq: 2, Status: Successful

💡 NOTE: This "authentication" is just a formality in WPA2.  
   The REAL authentication happens in the 4-way handshake.  
   This step exists for backward compatibility.


### Step 2: Association

  <span style="color:#0ff;">→ [ASSOC REQUEST]</span> SSID: HomeNetwork\_5G, Capabilities: 802.11n, 802.11ac  
  <span style="color:#0f0;">← [ASSOC RESPONSE]</span> Status: Successful, Association ID: 57  

💡 Association tells the AP:
  
   - Which network you want to join  
   - What capabilities your device has  
   - Establishes your "slot" on the network
   
   But you still can't send real data yet...


### PHASE 3: THE 4-WAY HANDSHAKE (Where the magic happens)

This is where WPA2 security actually happens.  
The goal: Prove you know the password WITHOUT sending it.


#### MESSAGE 1 of 4: AP sends ANonce

  <span style="color:#0f0;">← [EAPOL Key]</span> ANonce: 4c23aab97e5052d6...

   The AP generates a random number (ANonce) and sends it.  
   This will be used to derive the encryption keys.


#### MESSAGE 2 of 4: Client sends SNonce + MIC

   Your device now has everything needed to calculate the PTK:
   
   PTK = PRF(PMK + ANonce + SNonce + AP\_MAC + Client\_MAC)
   
   Where PMK is derived from the WiFi password.


   📝 Calculating PTK...  
   ✓ PTK generated: 497d48d49a12294d...

  <span style="color:#0ff;">→ [EAPOL Key]</span> SNonce: ea74432a6efe105b..., MIC: [proof of PTK]

   The MIC (Message Integrity Code) proves you calculated  
   the correct PTK - which means you know the password.
   
   🔑 THE PASSWORD IS NEVER TRANSMITTED!  
   Only proof that you could calculate the same result.


#### MESSAGE 3 of 4: AP sends GTK + confirmation
  <span style="color:#0f0;">← [EAPOL Key]</span> GTK: [encrypted group key], MIC: [verified]

   The AP verified your MIC - you proved you know the password!
   
   Now it sends the Group Temporal Key (GTK), encrypted with  
   the PTK you both derived. The GTK is used for broadcast  
   traffic that goes to all devices.


#### MESSAGE 4 of 4: Client confirms

  <span style="color:#0ff;">→ [EAPOL Key]</span> ACK: Installation confirmed

   ✅ HANDSHAKE COMPLETE!
   
   Both sides now have:

   - PTK - For encrypted unicast (device-to-AP) traffic  
   - GTK - For encrypted broadcast traffic
   
   All future communication will be encrypted.

## PHASE 4: GETTING AN IP ADDRESS (DHCP)

You're authenticated and encrypted, but you still need an IP  
address to actually communicate on the network.


### DHCP Process:

  <span style="color:#0ff;">→ [DHCP DISCOVER]</span> Broadcast: I need an IP address!  
  <span style="color:#0f0;">← [DHCP OFFER]</span> How about 192.168.1.10? Gateway: 192.168.1.11  
  <span style="color:#0ff;">→ [DHCP REQUEST]</span> Yes, I'll take 192.168.1.10 please  
  <span style="color:#0ff;">← [DHCP ACK]</span> Confirmed. Lease time: 24 hours

   ✅ You now have:
   
   - IP Address: 192.168.1.10  
   - Gateway: 192.168.1.11  
   - DNS Server: 192.168.1.12  
   - Lease Time: 24 hours
   
   💡 INSIGHT: DHCP traffic is encrypted by WPA2, but...  
      Your hostname is often sent in the DHCP request.  
      Everyone on the network could see "Bear's-MacBook" joined.


## CONNECTION COMPLETE - WHAT'S HAPPENING NOW

You're fully connected! Here's what's protecting your traffic:

```
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
   │            │   WPA2    │  Protects from people NOT          │
   │            │ Encryption│  on your network                   │
   │            └─────┬─────┘                                    │
   │                  │                                          │
   │                  ▼                                          │
   │              [Router] ───► Internet                         │
   │                                                             │
   └─────────────────────────────────────────────────────────────┘
```
   
   ⚠️ IMPORTANT: WPA2 only protects the wireless hop!
   
   - Your router can still see unencrypted traffic  
   - Other devices on the network can see broadcast traffic  
   - DNS queries reveal what sites you visit
   
   HTTPS provides end-to-end protection that WPA2 cannot.


## 📚 KEY TAKEAWAYS

1. **Probe requests leak information**  
   Your device announces what networks it knows.  
   Attackers can use this to track you or set up fake networks.

2. **The password is never sent over the air**  
   The 4-way handshake uses cryptographic proofs.  
   But capturing the handshake allows offline password cracking.

3. **WPA2 only protects the wireless hop**  
   Once traffic reaches your router, WPA2 encryption is removed.  
   Use HTTPS and VPNs for end-to-end protection.

4. **Everyone on the network is "inside the firewall"**  
   Other devices on the same network can potentially:  
   - See your MAC address and hostname  
   - Monitor broadcast traffic  
   - Attempt ARP spoofing attacks  
   
5. **Encrypt everything you can**  
   - Use HTTPS everywhere  
   - Use encrypted DNS (DoH/DoT)  
   - Consider a VPN on untrusted networks

<br>
