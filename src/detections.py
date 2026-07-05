#!/usr/bin/env python3
"""
detections.py — Network Forensics Detection Rules
─────────────────────────────────────────────────
Protocol-level and flow-level detections that only a packet capture
can reveal — not duplicated from the Security Log Analysis platform.

  1. Network Reconnaissance (SYN sweep)   MITRE T1046
  2. C2 Beaconing                         MITRE T1071
  3. DNS Tunneling                        MITRE T1071.004
  4. ARP Spoofing / MITM                  MITRE T1557.002
  5. Data Exfiltration                    MITRE T1048
  6. ICMP Tunneling                       MITRE T1095
  7. Cleartext Credential Exposure        MITRE T1040 / CWE-319
  8. Weak / Self-Signed TLS               MITRE T1573 (related)

Deliberately NOT included (lives in the Security Log Analysis platform instead):
  - SSH/RDP brute force counting        → that's an auth-log detection
  - Static "bad port" signature list    → that's a firewall-log detection
"""

from collections import defaultdict
import math, re

MITRE = {
    "recon":          {"id": "T1046",     "tactic": "Discovery"},
    "c2_beacon":      {"id": "T1071",     "tactic": "Command and Control"},
    "dns_tunnel":     {"id": "T1071.004", "tactic": "Command and Control"},
    "arp_spoof":      {"id": "T1557.002", "tactic": "Collection"},
    "exfiltration":   {"id": "T1048",     "tactic": "Exfiltration"},
    "icmp_tunnel":    {"id": "T1095",     "tactic": "Command and Control"},
    "cleartext_cred": {"id": "T1040",     "tactic": "Credential Access"},
    "weak_tls":       {"id": "T1573",     "tactic": "Command and Control"},
}

KNOWN_C2_PORTS = {
    4444: "Metasploit default", 1234: "Common backdoor",
    8888: "Common C2",          9001: "Tor / C2",
    31337: "Elite backdoor",
}

RECON_PORT_THRESHOLD    = 15
BEACON_MIN_CONNECTIONS  = 5
BEACON_MAX_STDDEV       = 2.0
DNS_QUERY_THRESHOLD     = 50
DNS_LABEL_LENGTH        = 40
EXFIL_BYTES_THRESHOLD   = 500_000
ICMP_PAYLOAD_THRESHOLD  = 64

CRED_PATTERNS = [
    re.compile(rb'password=([^&\s]{2,60})', re.I),
    re.compile(rb'passwd=([^&\s]{2,60})', re.I),
    re.compile(rb'pwd=([^&\s]{2,60})', re.I),
    re.compile(rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.I),
    re.compile(rb'USER\s+(\S+)', re.I),   # FTP
    re.compile(rb'PASS\s+(\S+)', re.I),   # FTP
]

def mk_alert(severity, type_, mitre_key, src, dst, detail, evidence=""):
    return {"severity": severity, "type": type_, "mitre": MITRE[mitre_key],
            "src": src, "dst": dst, "detail": detail, "evidence": evidence}

def is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4: return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a==10 or (a==172 and 16<=b<=31) or (a==192 and b==168) or a==127)
    except: return False

# ── 1. Network Reconnaissance (SYN sweep) ─────────────────────────────────────
def detect_network_recon(packets):
    """
    Many distinct destination ports probed by one source via SYN packets.
    Framed as packet-level reconnaissance, not 'port scan' (avoids overlap
    with the firewall-log DROP-counting detection in the other project).
    """
    alerts = []
    syn_map = defaultdict(set)
    for p in packets:
        if p.get("proto") != "TCP": continue
        flags = p.get("flags", "")
        if "S" in flags and "A" not in flags:
            src, dst, dp = p.get("src_ip",""), p.get("dst_ip",""), p.get("dst_port",0)
            if src and dp: syn_map[src].add((dst, dp))
    for src, targets in syn_map.items():
        ports = set(p for _,p in targets)
        if len(ports) >= RECON_PORT_THRESHOLD:
            dst_ips = set(d for d,_ in targets)
            alerts.append(mk_alert(
                "CRITICAL" if len(ports)>100 else "HIGH",
                "Network Reconnaissance (SYN Sweep)", "recon", src=src,
                dst=", ".join(list(dst_ips)[:3]),
                detail=f"SYN packets probed {len(ports)} distinct ports across {len(dst_ips)} host(s) — packet-level evidence of pre-attack scanning",
                evidence=f"Ports: {sorted(list(ports))[:10]}{'...' if len(ports)>10 else ''}"
            ))
    return alerts

# ── 2. C2 Beaconing ───────────────────────────────────────────────────────────
def detect_c2_beacon(packets):
    """
    Regular outbound connections at consistent intervals = C2 beacon.
    Statistical timing analysis only possible from raw packet timestamps.
    """
    alerts = []
    conn_times = defaultdict(list)
    for p in packets:
        if p.get("proto") not in ("TCP","UDP"): continue
        flags = p.get("flags","")
        if p.get("proto")=="TCP" and ("S" not in flags or "A" in flags): continue
        src,dst,dp,ts = p.get("src_ip",""),p.get("dst_ip",""),p.get("dst_port",0),p.get("timestamp",0)
        if src and dst and dp and ts: conn_times[(src,dst,dp)].append(ts)
    for (src,dst,dp),times in conn_times.items():
        if len(times) < BEACON_MIN_CONNECTIONS: continue
        times.sort()
        intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
        if not intervals: continue
        mean = sum(intervals)/len(intervals)
        std  = math.sqrt(sum((x-mean)**2 for x in intervals)/len(intervals))
        if mean>0 and std<BEACON_MAX_STDDEV and mean<300:
            note = KNOWN_C2_PORTS.get(dp, "")
            alerts.append(mk_alert(
                "CRITICAL" if dp in KNOWN_C2_PORTS else "HIGH",
                "C2 Beacon (Timing Analysis)", "c2_beacon", src=src, dst=f"{dst}:{dp}",
                detail=f"{len(times)} connections every {mean:.1f}s ± {std:.2f}s — statistically regular interval indicates automated beaconing, not human activity",
                evidence=f"Port {dp} {note}, StdDev={std:.3f}s (low variance = scripted)"
            ))
    return alerts

# ── 3. DNS Tunneling ──────────────────────────────────────────────────────────
def detect_dns_tunneling(packets):
    """
    DNS queries with unusually long subdomains or high query volume —
    classic data exfiltration channel hidden inside DNS.
    """
    alerts = []
    dns_queries = defaultdict(list)
    long_labels = []
    for p in packets:
        if p.get("proto") != "DNS": continue
        src, qname = p.get("src_ip",""), p.get("dns_query","")
        if not qname: continue
        dns_queries[src].append(qname)
        for label in qname.split("."):
            if len(label) > DNS_LABEL_LENGTH:
                long_labels.append((src, qname, label))
    for src, queries in dns_queries.items():
        if len(queries) >= DNS_QUERY_THRESHOLD:
            alerts.append(mk_alert("HIGH","DNS Tunneling (High Volume)","dns_tunnel",
                src=src, dst="DNS",
                detail=f"{len(queries)} DNS queries from single host — volume far exceeds normal browsing",
                evidence=f"Sample: {queries[:2]}"))
    seen = set()
    for src, qname, label in long_labels:
        if src not in seen:
            seen.add(src)
            alerts.append(mk_alert("HIGH","DNS Tunneling (Encoded Label)","dns_tunnel",
                src=src, dst="DNS",
                detail=f"DNS label {len(label)} chars — consistent with base64/hex encoded data exfiltration",
                evidence=f"Query: {qname[:80]}"))
    return alerts

# ── 4. ARP Spoofing ───────────────────────────────────────────────────────────
def detect_arp_spoofing(packets):
    """
    Multiple MACs claiming the same IP = ARP cache poisoning / MITM.
    Pure layer-2 attack — completely invisible to any log source.
    """
    alerts = []
    ip_macs = defaultdict(set)
    for p in packets:
        if p.get("proto") != "ARP": continue
        ip, mac = p.get("src_ip",""), p.get("src_mac","")
        if ip and mac: ip_macs[ip].add(mac)
    for ip, macs in ip_macs.items():
        if len(macs) > 1:
            alerts.append(mk_alert("CRITICAL","ARP Spoofing / MITM","arp_spoof",
                src=", ".join(macs), dst=ip,
                detail=f"IP {ip} claimed by {len(macs)} different MAC addresses — classic ARP poisoning for man-in-the-middle interception",
                evidence=f"MACs: {list(macs)}"))
    return alerts

# ── 5. Data Exfiltration ──────────────────────────────────────────────────────
def detect_exfiltration(packets):
    """
    Large outbound payload volume to external IPs, measured directly
    from packet sizes — independent of any application log.
    """
    alerts = []
    outbound = defaultdict(int)
    for p in packets:
        src,dst,size = p.get("src_ip",""),p.get("dst_ip",""),p.get("size",0)
        if src and dst and is_private(src) and not is_private(dst):
            outbound[(src,dst)] += size
    for (src,dst),total in outbound.items():
        if total >= EXFIL_BYTES_THRESHOLD:
            mb = total/1_000_000
            alerts.append(mk_alert(
                "CRITICAL" if mb>10 else "HIGH",
                "Data Exfiltration (Volume Analysis)","exfiltration", src=src, dst=dst,
                detail=f"{mb:.2f} MB transferred outbound to external IP — measured directly from wire traffic",
                evidence=f"{total:,} bytes from {src} → {dst}"))
    return alerts

# ── 6. ICMP Tunneling ─────────────────────────────────────────────────────────
def detect_icmp_tunneling(packets):
    """
    ICMP packets with oversized payloads = data smuggled inside ping packets.
    Normal ICMP echo = 32-64 bytes. Tunnels carry hundreds of bytes.
    """
    alerts = []
    suspicious = defaultdict(list)
    for p in packets:
        if p.get("proto") != "ICMP": continue
        size,src,dst = p.get("size",0),p.get("src_ip",""),p.get("dst_ip","")
        if size > ICMP_PAYLOAD_THRESHOLD and src:
            suspicious[(src,dst)].append(size)
    for (src,dst),sizes in suspicious.items():
        if len(sizes) >= 3:
            avg = sum(sizes)/len(sizes)
            alerts.append(mk_alert("HIGH","ICMP Tunneling","icmp_tunnel",
                src=src, dst=dst,
                detail=f"{len(sizes)} oversized ICMP packets (avg {avg:.0f} bytes, normal ping ≈64 bytes)",
                evidence=f"Sizes: {sizes[:5]}"))
    return alerts

# ── 7. Cleartext Credential Exposure ──────────────────────────────────────────
def detect_cleartext_credentials(packets):
    """
    Scans raw packet payloads for unencrypted credentials in HTTP form
    submissions, Basic Auth headers, and FTP USER/PASS commands.
    This is only possible by inspecting actual packet bytes — a log
    file would never contain the raw wire payload.
    """
    alerts = []
    seen = set()
    for p in packets:
        payload = p.get("payload", b"")
        if not payload: continue
        src, dst = p.get("src_ip",""), p.get("dst_ip","")
        dport = p.get("dst_port", 0)

        for pattern in CRED_PATTERNS:
            m = pattern.search(payload)
            if not m: continue
            key = (src, dst, dport)
            if key in seen: continue
            seen.add(key)

            proto_label = "FTP" if dport == 21 else ("HTTP Basic Auth" if b"Authorization" in payload else "HTTP Form")
            captured = m.group(1)[:40]
            try:
                captured_str = captured.decode(errors='replace')
            except Exception:
                captured_str = str(captured)

            alerts.append(mk_alert(
                "CRITICAL", f"Cleartext Credentials ({proto_label})", "cleartext_cred",
                src=src, dst=f"{dst}:{dport}",
                detail=f"Unencrypted credential material observed in {proto_label} traffic — full plaintext capture possible by any network observer",
                evidence=f"Captured fragment: {captured_str}"
            ))
    return alerts

# ── 8. Weak / Self-Signed TLS ─────────────────────────────────────────────────
def detect_weak_tls(packets):
    """
    Flags TLS handshakes using legacy versions (SSLv3/TLS1.0/1.1) —
    detectable only from the raw ClientHello/ServerHello bytes.
    """
    alerts = []
    seen = set()
    WEAK_VERSIONS = {b"\x03\x00": "SSLv3", b"\x03\x01": "TLS 1.0", b"\x03\x02": "TLS 1.1"}
    for p in packets:
        payload = p.get("payload", b"")
        if not payload or p.get("dst_port") != 443: continue
        # TLS record header: type(1) + version(2) + length(2)
        if len(payload) < 3 or payload[0] != 0x16:  # 0x16 = Handshake
            continue
        version_bytes = payload[1:3]
        if version_bytes in WEAK_VERSIONS:
            src, dst = p.get("src_ip",""), p.get("dst_ip","")
            key = (src, dst)
            if key in seen: continue
            seen.add(key)
            alerts.append(mk_alert(
                "MEDIUM", "Weak TLS Version Negotiated", "weak_tls",
                src=src, dst=dst,
                detail=f"TLS handshake offered/used {WEAK_VERSIONS[version_bytes]} — deprecated and vulnerable to downgrade attacks",
                evidence=f"Record header version bytes: {version_bytes.hex()}"
            ))
    return alerts

# ── Run all ────────────────────────────────────────────────────────────────────
def run_all(packets):
    alerts  = []
    alerts += detect_network_recon(packets)
    alerts += detect_c2_beacon(packets)
    alerts += detect_dns_tunneling(packets)
    alerts += detect_arp_spoofing(packets)
    alerts += detect_exfiltration(packets)
    alerts += detect_icmp_tunneling(packets)
    alerts += detect_cleartext_credentials(packets)
    alerts += detect_weak_tls(packets)
    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    alerts.sort(key=lambda a: order.get(a["severity"],9))
    return alerts
