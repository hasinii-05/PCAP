# Network Forensics Analyzer

A packet-level threat hunting tool that reconstructs network traffic from `.pcap` captures and detects attacks only visible at the wire — reconnaissance sweeps, C2 beacon timing, DNS tunneling, ARP spoofing, cleartext credential exposure, and weak TLS negotiation.



## What Makes This Packet-Level, Not Log-Level

| This tool detects... | ...because it inspects |
|---|---|
| C2 beacon timing | Raw packet timestamps — statistical interval analysis impossible from a single log line |
| ARP spoofing | Layer-2 frames — invisible to any application or auth log |
| Cleartext credentials | Actual TCP payload bytes — a log file never contains the wire-level plaintext |
| Weak/legacy TLS | TLS ClientHello handshake bytes — not logged by any standard system log |
| DNS tunneling | Per-query subdomain entropy and volume — requires seeing every DNS packet, not just summarized logs |

Deliberately **not** included here (these live in the Security Log Analysis platform instead, where they're a better fit): SSH/RDP brute-force counting, static "known-bad-port" signature matching.

---

## Usage

```bash
# CLI
python3 src/analyzer.py capture.pcap
python3 src/analyzer.py capture.pcap --verbose

# Web dashboard
python3 web/app.py
open http://localhost:8080
```

---

## What It Detects

| Detection | MITRE | How |
|---|---|---|
| Network Reconnaissance (SYN Sweep) | T1046 | SYN packets to 15+ distinct ports from one IP |
| C2 Beaconing | T1071 | Connection timing with statistically low variance (regular intervals) |
| DNS Tunneling | T1071.004 | High DNS volume or abnormally long subdomain labels |
| ARP Spoofing / MITM | T1557.002 | Multiple MAC addresses claiming the same IP |
| Data Exfiltration | T1048 | Large outbound byte volume to external IPs |
| ICMP Tunneling | T1095 | ICMP payloads exceeding normal ping size (64 bytes) |
| Cleartext Credentials | T1040 | Plaintext `password=`, HTTP Basic Auth, or FTP USER/PASS in payload bytes |
| Weak TLS Version | T1573 | SSLv3/TLS 1.0/TLS 1.1 negotiated in handshake bytes |

---

## Sample Output

```
==========================================================
  PCAP NETWORK FORENSICS ANALYZER
  File : cleartext_creds.pcap
==========================================================

[*] Running network forensics detection rules...
    ✓ 3 alerts generated

  > [CRITICAL] Cleartext Credentials (HTTP Form)
     MITRE  : T1040 — Credential Access
     Src    : 192.168.1.100
     Dst    : 192.168.1.50:80
     Detail : Unencrypted credential material observed in HTTP Form
              traffic — full plaintext capture possible by any
              network observer
     Evidence: Captured fragment: SuperSecret123

  > [CRITICAL] Cleartext Credentials (FTP)
     MITRE  : T1040 — Credential Access
     Detail : Unencrypted credential material observed in FTP traffic
     Evidence: Captured fragment: ftpadmin

  > [HIGH] C2 Beacon (Timing Analysis)
     MITRE  : T1071 — Command and Control
     Detail : 10 connections every 5.0s ± 0.00s — statistically
              regular interval indicates automated beaconing
```

---

## Quick Start (Mac M4)

```bash
brew install wireshark
pip3 install scapy flask

git clone https://github.com/YOUR_USERNAME/network-forensics-analyzer
cd network-forensics-analyzer
python3 src/generate_samples.py
python3 src/analyzer.py samples/cleartext_creds.pcap --verbose
```

### Analyze a real capture
```bash
sudo tcpdump -i en0 -w capture.pcap -G 60 -W 1
python3 src/analyzer.py capture.pcap --verbose
```

### Public PCAP datasets for testing
- https://www.malware-traffic-analysis.net/
- https://wiki.wireshark.org/SampleCaptures

---

## Project Structure

```
pcap-analyzer/
├── README.md
├── web/
│   ├── app.py                    ← Flask dashboard
│   └── templates/index.html
├── src/
│   ├── analyzer.py               ← CLI entrypoint, Scapy/tshark parser
│   ├── detections.py             ← 8 packet-level detection rules
│   ├── report.py                 ← markdown report generator
│   └── generate_samples.py       ← creates test PCAPs
├── samples/
│   ├── recon.pcap
│   ├── c2_beacon.pcap
│   ├── dns_tunnel.pcap
│   ├── cleartext_creds.pcap
│   └── mixed_attacks.pcap
└── results/
```

---

## Skills Demonstrated

- Raw packet parsing and payload reconstruction with Scapy
- Protocol analysis across TCP, UDP, ICMP, ARP, DNS, and TLS handshake bytes
- Statistical timing analysis for behavioral C2 detection
- Cleartext credential extraction from HTTP/FTP payloads
- MITRE ATT&CK mapping for network-layer techniques
- Flask web application with drag-and-drop file analysis

---

