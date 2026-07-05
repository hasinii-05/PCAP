#!/usr/bin/env python3
"""
report.py — Network Forensics Report Generator
"""

import os
from datetime import datetime
from collections import defaultdict

def generate_report(alerts, packets, pcap_path, out_dir):
    now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.basename(pcap_path)
    counts   = {s: sum(1 for a in alerts if a["severity"]==s)
                for s in ["CRITICAL","HIGH","MEDIUM","LOW"]}

    total_bytes = sum(p.get("size",0) for p in packets)
    protos = defaultdict(int)
    unique_ips = set()
    for p in packets:
        protos[p.get("proto","?")] += 1
        if p.get("src_ip"): unique_ips.add(p["src_ip"])
        if p.get("dst_ip"): unique_ips.add(p["dst_ip"])

    top_protos = sorted(protos.items(), key=lambda x: -x[1])[:6]
    attacker_ips = list(set(a["src"] for a in alerts if "." in a.get("src","")))

    md = [
        f"# Network Forensics Report",
        f"**File:** `{filename}`  |  **Analyzed:** {now}\n",
        f"---\n",
        f"## Executive Summary\n",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Total Packets | {len(packets):,} |",
        f"| Total Traffic | {total_bytes/1_000_000:.2f} MB |",
        f"| Unique IPs | {len(unique_ips)} |",
        f"| Total Alerts | {len(alerts)} |",
        f"| 🔴 Critical | {counts.get('CRITICAL',0)} |",
        f"| 🟠 High | {counts.get('HIGH',0)} |",
        f"| 🟡 Medium | {counts.get('MEDIUM',0)} |",
        f"| Hosts of Interest | {', '.join(attacker_ips[:5]) if attacker_ips else 'None'} |\n",
        f"---\n",
        f"## Traffic Breakdown\n",
        f"| Protocol | Packets |",
        f"|---|---|",
    ]
    for proto, count in top_protos:
        md.append(f"| {proto} | {count:,} |")

    md += [f"\n---\n", f"## Alerts\n"]

    icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    for a in alerts:
        icon = icons.get(a["severity"],"⚪")
        md += [
            f"### {icon} [{a['severity']}] {a['type']}",
            f"| Field | Value |",
            f"|---|---|",
            f"| MITRE ATT&CK | [{a['mitre']['id']}](https://attack.mitre.org/techniques/{a['mitre']['id'].replace('.','/')}) — {a['mitre']['tactic']} |",
            f"| Source | `{a['src']}` |",
            f"| Destination | `{a['dst']}` |",
            f"| Detail | {a['detail']} |",
            f"| Evidence | {a.get('evidence','—')} |\n",
        ]

    md += ["---\n", "## MITRE ATT&CK Coverage\n", "| Technique | Tactic | Detections |", "|---|---|---|"]
    mitre_counts = defaultdict(int)
    for a in alerts:
        key = f"{a['mitre']['id']} — {a['mitre']['tactic']}"
        mitre_counts[key] += 1
    for key, cnt in sorted(mitre_counts.items()):
        md.append(f"| {key} | {cnt} |")

    md += [
        f"\n---\n", f"## Recommendations\n",
        f"1. Block hosts of interest at perimeter firewall pending investigation",
        f"2. Rotate any credentials observed in cleartext immediately",
        f"3. Enforce TLS 1.2+ only — disable legacy SSL/TLS negotiation",
        f"4. Investigate hosts with regular C2-style beaconing patterns",
        f"5. Deploy network segmentation to limit ARP spoofing blast radius",
        f"6. Monitor DNS traffic for tunneling / high-entropy subdomains",
    ]

    out_path = os.path.join(out_dir, f"pcap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w") as f:
        f.write("\n".join(md))
    return out_path
