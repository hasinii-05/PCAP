#!/usr/bin/env python3
"""
app.py — Network Forensics Analyzer Web Interface
"""

import os, sys, tempfile
from flask import Flask, render_template, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import detections
from analyzer import parse_with_scapy, parse_with_tshark, SCAPY

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '..', 'results', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

def build_response(filename, file_size_mb, packets, alerts):
    protos, unique_src, unique_dst = {}, set(), set()
    total_bytes, src_counts, port_counts = 0, {}, {}
    for p in packets:
        proto = p.get("proto","OTHER")
        protos[proto] = protos.get(proto,0)+1
        if p.get("src_ip"):
            unique_src.add(p["src_ip"])
            src_counts[p["src_ip"]] = src_counts.get(p["src_ip"],0)+1
        if p.get("dst_ip"): unique_dst.add(p["dst_ip"])
        total_bytes += p.get("size",0)
        dp = p.get("dst_port",0)
        if dp and dp < 10000:
            port_counts[dp] = port_counts.get(dp,0)+1

    timeline = [{
        "index": i+1, "severity": a["severity"], "type": a["type"],
        "src": a["src"], "dst": a["dst"], "mitre_id": a["mitre"]["id"],
        "mitre_tactic": a["mitre"]["tactic"], "detail": a["detail"],
        "evidence": a.get("evidence",""),
    } for i,a in enumerate(alerts)]

    return {
        "filename": filename, "file_size_mb": file_size_mb,
        "total_packets": len(packets), "total_bytes": total_bytes,
        "unique_src_ips": len(unique_src), "unique_dst_ips": len(unique_dst),
        "protocol_dist": protos,
        "top_talkers": sorted(src_counts.items(), key=lambda x:-x[1])[:8],
        "top_ports": sorted(port_counts.items(), key=lambda x:-x[1])[:10],
        "alerts": timeline,
        "severity_counts": {
            "CRITICAL": sum(1 for a in alerts if a["severity"]=="CRITICAL"),
            "HIGH":     sum(1 for a in alerts if a["severity"]=="HIGH"),
            "MEDIUM":   sum(1 for a in alerts if a["severity"]=="MEDIUM"),
        },
        "total_alerts": len(alerts),
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'pcap' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['pcap']
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ('.pcap', '.pcapng', '.cap'):
        return jsonify({"error": "File must be .pcap, .pcapng, or .cap"}), 400

    tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False, dir=UPLOAD_DIR)
    file.save(tmp.name)
    tmp.close()

    try:
        file_size = os.path.getsize(tmp.name)
        packets = parse_with_scapy(tmp.name) if SCAPY else parse_with_tshark(tmp.name)
        if not packets:
            return jsonify({"error": "Could not parse PCAP file"}), 400
        alerts = detections.run_all(packets)
        return jsonify(build_response(file.filename, round(file_size/1_000_000,2), packets, alerts))
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
    finally:
        try: os.unlink(tmp.name)
        except: pass

@app.route('/sample/<name>')
def use_sample(name):
    safe = {"recon":"recon.pcap", "c2":"c2_beacon.pcap",
            "dns":"dns_tunnel.pcap", "creds":"cleartext_creds.pcap",
            "mixed":"mixed_attacks.pcap"}
    if name not in safe:
        return jsonify({"error":"Unknown sample"}), 404
    path = os.path.join(os.path.dirname(__file__),'..','samples', safe[name])
    if not os.path.exists(path):
        return jsonify({"error":"Sample not found — run generate_samples.py first"}), 404

    packets = parse_with_scapy(path) if SCAPY else parse_with_tshark(path)
    alerts = detections.run_all(packets)
    return jsonify(build_response(safe[name], round(os.path.getsize(path)/1_000_000,2), packets, alerts))

if __name__ == '__main__':
    print("\n" + "="*50)
    print("  Network Forensics Analyzer — Web Interface")
    print("  Open: http://localhost:8080")
    print("="*50 + "\n")
    app.run(debug=False, host="0.0.0.0", port=8080)
