#!/bin/bash
# ═══════════════════════════════════════════════════
#  Network Forensics Analyzer — Mac M4 Apple Silicon
#
#  Usage:
#    ./run.sh                        — generate samples + analyze all
#    ./run.sh samples/recon.pcap     — analyze specific file
#    ./run.sh samples/ --verbose     — analyze folder verbosely
# ═══════════════════════════════════════════════════

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║   Network Forensics Analyzer              ║"
echo "║   Packet-Level Threat Hunting (DFIR)      ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

if [ -n "$1" ]; then
  python3 src/analyzer.py "$@"
  exit 0
fi

echo "[ 1/2 ] Generating sample PCAP files..."
python3 src/generate_samples.py
echo ""

echo "[ 2/2 ] Analyzing all samples..."
echo ""
for pcap in samples/*.pcap; do
  echo "── $pcap ──────────────────────────────────"
  python3 src/analyzer.py "$pcap"
  echo ""
done

echo "══════════════════════════════════════════════"
echo "  Reports saved to: results/"
echo ""
echo "  Analyze your own PCAP:"
echo "    python3 src/analyzer.py your_capture.pcap"
echo ""
echo "  Or launch the web dashboard:"
echo "    python3 web/app.py"
echo "══════════════════════════════════════════════"
