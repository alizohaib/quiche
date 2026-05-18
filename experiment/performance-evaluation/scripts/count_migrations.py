#!/usr/bin/env python3
"""Count actual IPv6 address migrations from pcapng files.

Uses tshark's endpoint statistics to count unique addresses per hopping
prefix. Each unique address in the hopping prefix = one migration.

This is the correct approach because during QUIC path validation, packets
interleave between old and new addresses. Counting consecutive address
changes (uniq) overcounts due to this interleaving. The endpoint/conversation
view correctly counts distinct addresses actually used.

Usage:
    python3 count_migrations.py <pcap_dir> [output.json]

Requires: tshark (Wireshark CLI)
"""
import subprocess
import sys
import os
import json

SERVER_HOP_PREFIX = "2600:1f18:6da3:7600:8bc4"
CLIENT_HOP_PREFIX = "2600:1f1c:2d:e700:12f2"

TSHARK = os.environ.get("TSHARK", "tshark")


def count_migrations_endpoints(pcap_path):
    """Count migrations = unique hopping-prefix addresses from endpoint stats."""
    out = subprocess.run(
        [TSHARK, "-r", pcap_path, "-q", "-z", "endpoints,ipv6"],
        capture_output=True, text=True, timeout=120
    )

    server_hops = 0
    client_hops = 0

    for line in out.stdout.split("\n"):
        if SERVER_HOP_PREFIX in line:
            server_hops += 1
        if CLIENT_HOP_PREFIX in line:
            client_hops += 1

    return client_hops, server_hops


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
            cm, sm = count_migrations_endpoints(path)
            results[f] = {"client_migrations": cm, "server_migrations": sm}
            print(f"  [{i+1}/{len(files)}] {f}: client={cm}, server={sm}", file=sys.stderr)
        except Exception as e:
            results[f] = {"client_migrations": 0, "server_migrations": 0, "error": str(e)}
            print(f"  [{i+1}/{len(files)}] {f}: ERROR {e}", file=sys.stderr)

    if output_file:
        with open(output_file, "w") as fout:
            json.dump(results, fout, indent=2)
        print(f"\nSaved to {output_file}", file=sys.stderr)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
