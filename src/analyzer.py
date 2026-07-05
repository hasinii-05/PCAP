#!/usr/bin/env python3
"""
analyzer.py — Network Forensics Analyzer
──────────────────────────────────────────
Usage:
    python3 src/analyzer.py sample.pcap
    python3 src/analyzer.py sample.pcap --verbose
    python3 src/analyzer.py sample.pcap --out results/

Parses a PCAP file using Scapy, reconstructs packet + payload metadata,
runs all network forensics detection rules, and generates a report.

This tool operates purely at the packet/wire level — it does not
duplicate authentication or firewall-log detections, which belong
to the separate Security Log Analysis & Threat Detection platform.
"""

import os, sys, json, argparse, subprocess

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether, Raw
    SCAPY = True
except ImportError:
    SCAPY = False

sys.path.insert(0, os.path.dirname(__file__))
import detections
from report import generate_report

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# ── Scapy parser ──────────────────────────────────────────────────────────────
def parse_with_scapy(path, verbose=False):
    print(f"    Using: Scapy")
    packets = []
    try:
        raw = rdpcap(path)
    except Exception as e:
        print(f"[!] Scapy failed to read {path}: {e}")
        return []

    for pkt in raw:
        p = {"size": len(pkt), "timestamp": float(pkt.time), "proto": "OTHER",
             "src_ip": "", "dst_ip": "", "src_port": 0, "dst_port": 0,
             "flags": "", "src_mac": "", "dst_mac": "", "dns_query": "",
             "payload": b""}
        try:
            if Ether in pkt:
                p["src_mac"] = pkt[Ether].src
                p["dst_mac"] = pkt[Ether].dst
            if ARP in pkt:
                p["proto"]   = "ARP"
                p["src_ip"]  = pkt[ARP].psrc
                p["dst_ip"]  = pkt[ARP].pdst
                p["src_mac"] = pkt[ARP].hwsrc
            elif IP in pkt:
                p["src_ip"] = pkt[IP].src
                p["dst_ip"] = pkt[IP].dst
                if Raw in pkt:
                    p["payload"] = bytes(pkt[Raw].load)
                if TCP in pkt:
                    p["proto"]    = "TCP"
                    p["src_port"] = pkt[TCP].sport
                    p["dst_port"] = pkt[TCP].dport
                    flags = pkt[TCP].flags
                    p["flags"] = "".join([
                        "S" if flags.S else "", "A" if flags.A else "",
                        "F" if flags.F else "", "R" if flags.R else "",
                        "P" if flags.P else "",
                    ])
                    if DNS in pkt and pkt[TCP].dport == 53:
                        p["proto"] = "DNS"
                        if DNSQR in pkt:
                            p["dns_query"] = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
                elif UDP in pkt:
                    p["proto"]    = "UDP"
                    p["src_port"] = pkt[UDP].sport
                    p["dst_port"] = pkt[UDP].dport
                    if DNS in pkt:
                        p["proto"] = "DNS"
                        if DNSQR in pkt:
                            p["dns_query"] = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
                elif ICMP in pkt:
                    p["proto"] = "ICMP"
        except Exception:
            pass
        packets.append(p)

    if verbose:
        protos = {}
        for p in packets:
            protos[p["proto"]] = protos.get(p["proto"],0)+1
        print(f"    Protocol breakdown: {protos}")
    return packets

# ── tshark fallback parser ────────────────────────────────────────────────────
def parse_with_tshark(path, verbose=False):
    """Fallback parser — does not extract payload bytes (Scapy required for
    cleartext credential / TLS version detection)."""
    print(f"    Using: tshark (payload-based detections will be skipped)")
    fields = [
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "tcp.flags.syn", "-e", "tcp.flags.ack",
        "-e", "tcp.flags.fin", "-e", "tcp.flags.reset",
        "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4",
        "-e", "eth.src", "-e", "eth.dst",
        "-e", "dns.qry.name",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
    ]
    cmd = ["tshark", "-r", path, "-T", "fields",
           "-E", "separator=|", "-E", "occurrence=f"] + fields
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        print("[!] tshark not found. Install with: brew install wireshark")
        return []
    except subprocess.TimeoutExpired:
        print("[!] tshark timed out on large file")
        return []

    packets = []
    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 18: continue
        try:
            ts       = float(parts[0]) if parts[0] else 0
            src_ip, dst_ip = parts[1], parts[2]
            tcp_sp   = int(parts[3]) if parts[3] else 0
            tcp_dp   = int(parts[4]) if parts[4] else 0
            udp_sp   = int(parts[5]) if parts[5] else 0
            udp_dp   = int(parts[6]) if parts[6] else 0
            syn, ack, fin, rst = parts[7]=="1", parts[8]=="1", parts[9]=="1", parts[10]=="1"
            arp_src, arp_dst = parts[11], parts[12]
            eth_src, eth_dst = parts[13], parts[14]
            dns_q    = parts[15]
            flen     = int(parts[16]) if parts[16] else 0
            proto_col= parts[17].strip().upper() if len(parts)>17 else ""

            flags = ("S" if syn else "")+("A" if ack else "")+("F" if fin else "")+("R" if rst else "")

            if arp_src:
                proto = "ARP"
                src_ip, dst_ip = arp_src, arp_dst
            elif dns_q:
                proto = "DNS"
            elif tcp_dp or tcp_sp:
                proto = "TCP"
            elif udp_dp or udp_sp:
                proto = "UDP"
            elif "ICMP" in proto_col:
                proto = "ICMP"
            else:
                proto = proto_col or "OTHER"

            packets.append({
                "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": tcp_sp or udp_sp, "dst_port": tcp_dp or udp_dp,
                "flags": flags, "proto": proto,
                "src_mac": eth_src, "dst_mac": eth_dst,
                "dns_query": dns_q, "size": flen, "payload": b"",
            })
        except (ValueError, IndexError):
            continue
    return packets

# ── Main analyzer ─────────────────────────────────────────────────────────────
def analyze(path, verbose=False, out_dir=None):
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)

    size_mb = os.path.getsize(path) / 1_000_000
    print(f"\n{'='*58}")
    print(f"  PCAP NETWORK FORENSICS ANALYZER")
    print(f"  File : {os.path.basename(path)}")
    print(f"  Size : {size_mb:.2f} MB")
    print(f"{'='*58}\n")

    print("[*] Parsing packets...")
    packets = parse_with_scapy(path, verbose) if SCAPY else parse_with_tshark(path, verbose)

    if not packets:
        print("[!] No packets parsed. Check the file is a valid PCAP.")
        sys.exit(1)

    print(f"    ✓ {len(packets):,} packets parsed\n")

    protos = {}
    for p in packets:
        protos[p["proto"]] = protos.get(p["proto"],0)+1
    print("[*] Traffic breakdown:")
    for proto, count in sorted(protos.items(), key=lambda x: -x[1])[:8]:
        bar = "█" * min(30, int(count/max(protos.values())*30))
        print(f"    {proto:8s} {bar} {count:,}")
    print()

    print("[*] Running network forensics detection rules...")
    alerts = detections.run_all(packets)
    print(f"    ✓ {len(alerts)} alerts generated\n")

    icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    print(f"{'='*58}")
    print(f"  THREAT DETECTION RESULTS  —  {len(alerts)} alerts")
    print(f"{'='*58}")
    if not alerts:
        print("\n  ✅  No threats detected in this capture.\n")
    for a in alerts:
        icon = icons.get(a["severity"],"⚪")
        print(f"\n  {icon} [{a['severity']}] {a['type']}")
        print(f"     MITRE  : {a['mitre']['id']} — {a['mitre']['tactic']}")
        print(f"     Src    : {a['src']}")
        print(f"     Dst    : {a['dst']}")
        print(f"     Detail : {a['detail']}")
        if verbose and a.get("evidence"):
            print(f"     Evidence: {a['evidence']}")

    out = out_dir or RESULTS_DIR
    rpt = generate_report(alerts, packets, path, out)
    print(f"\n[+] Report : {rpt}")
    jsn = rpt.replace(".md",".json")
    with open(jsn,"w") as f: json.dump(alerts, f, indent=2)
    print(f"[+] JSON   : {jsn}\n")
    return alerts

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Network Forensics Analyzer — detect network-layer attacks in packet captures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 src/analyzer.py sample.pcap
  python3 src/analyzer.py samples/recon.pcap --verbose
  python3 src/analyzer.py capture.pcap --out results/
        """
    )
    parser.add_argument("pcap", help="Path to .pcap or .pcapng file")
    parser.add_argument("-v","--verbose", action="store_true", help="Show evidence for each alert")
    parser.add_argument("--out", help="Output directory for reports (default: results/)")
    args = parser.parse_args()
    analyze(args.pcap, verbose=args.verbose, out_dir=args.out)

if __name__ == "__main__":
    main()
