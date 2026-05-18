#!/usr/bin/env python3
"""Extract wire-level throughput from pcapng files using capinfos.

Wire throughput = total data bytes / capture duration (includes all
headers, ACKs, retransmissions, control frames).

Usage:
    python3 extract_throughput.py <pcap_dir> [output.json]

Requires: capinfos (part of Wireshark/tshark package)
"""
import subprocess
import sys
import os
import json
import re

CAPINFOS = os.environ.get("CAPINFOS", "capinfos")


def get_throughput(pcap_path):
    """Get wire throughput from capinfos."""
    out = subprocess.run(
        [CAPINFOS, "-M", pcap_path],
        capture_output=True, text=True, timeout=30
    )

    data_bytes = None
    duration = None
    bit_rate = None

    for line in out.stdout.split("\n"):
        if line.startswith("Data size:"):
            m = re.search(r"(\d+)", line)
            if m:
                data_bytes = int(m.group(1))
        elif line.startswith("Capture duration:"):
            m = re.search(r"([\d.]+)", line)
            if m:
                duration = float(m.group(1))
        elif line.startswith("Data bit rate:"):
            m = re.search(r"([\d.]+)", line)
            if m:
                bit_rate = float(m.group(1))

    if bit_rate:
        throughput_mbps = bit_rate / 1_000_000
    elif data_bytes and duration and duration > 0:
        throughput_mbps = (data_bytes * 8) / (duration * 1_000_000)
    else:
        throughput_mbps = 0

    return {
        "throughput_mbps": round(throughput_mbps, 2),
        "data_bytes": data_bytes,
        "duration_s": round(duration, 3) if duration else 0,
    }


def main():
    pcap_dir = sys.argv[1] if len(sys.argv) > 1 else "pcaps"
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    files = sorted(f for f in os.listdir(pcap_dir) if f.endswith(".pcapng"))
    if not files:
        print(f"No pcapng files found in {pcap_dir}", file=sys.stderr)
        sys.exit(1)

    results = {}
    for i, f in enumerate(files):
        path = os.path.join(pcap_dir, f)
        try:
            stats = get_throughput(path)
            results[f] = stats
            print(f"  [{i+1}/{len(files)}] {f}: {stats['throughput_mbps']:.2f} Mbps", file=sys.stderr)
        except Exception as e:
            results[f] = {"throughput_mbps": 0, "error": str(e)}
            print(f"  [{i+1}/{len(files)}] {f}: ERROR {e}", file=sys.stderr)

    if output_file:
        with open(output_file, "w") as fout:
            json.dump(results, fout, indent=2)
        print(f"\nSaved to {output_file}", file=sys.stderr)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
