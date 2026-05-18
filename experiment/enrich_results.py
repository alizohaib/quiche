#!/usr/bin/env python3
"""Post-process AWS ablation results: parse logs and pcaps to produce enriched JSON
with pcap_stats and path_validation fields matching the Docker experiment format."""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
CLIENT_PREFIX = "2600:1f1c:2d:e700:12f2"
PROXY_PREFIX = "2600:1f18:6da3:7600:8bc4"
PROXY_ORIG = "2600:1f18:6da3:7600:a6dc:abdb:b83a:625c"


def parse_timestamp(line):
    """Extract timestamp from glog format: I0517 07:09:21.838400"""
    m = re.match(r'[IWE](\d{4})\s+(\d{2}):(\d{2}):(\d{2})\.(\d+)', line)
    if not m:
        return None
    month_day = m.group(1)
    h, mi, s, us = int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
    return h * 3600 + mi * 60 + s + us / 1e6


def parse_client_log(log_path):
    """Parse client log for migration events and path validation timing.
    Handles both server-initiated (SPA) and client-initiated migrations."""
    migrations = []
    spa_received = []
    client_validations = []
    peer_addresses = set()
    self_addresses = set()

    if not os.path.exists(log_path):
        return None

    with open(log_path, 'r', errors='replace') as f:
        for line in f:
            # Server-mode SPA: "Server preferred address: [addr]:port validated. Migrating path, ..."
            m = re.search(
                r'Server preferred address: \[([^\]]+)\]:(\d+) validated\. Migrating path, '
                r'self_address: \[([^\]]+)\]:(\d+), peer_address: \[([^\]]+)\]:(\d+)',
                line
            )
            if m:
                ts = parse_timestamp(line)
                peer_addr = m.group(1)
                self_addr = m.group(3)
                peer_addresses.add(peer_addr)
                self_addresses.add(f"{self_addr}:{m.group(4)}")
                migrations.append({
                    'timestamp': ts,
                    'peer_address': f"[{peer_addr}]:{m.group(2)}",
                    'self_address': f"[{self_addr}]:{m.group(4)}",
                    'type': 'server_spa',
                })
                continue

            # Client-mode: "Successfully validated path from  from [addr]:port to [addr]:port. Migrate to it now."
            m2 = re.search(
                r'Successfully validated path from\s+from \[([^\]]+)\]:(\d+) to \[([^\]]+)\]:(\d+)',
                line
            )
            if m2:
                ts = parse_timestamp(line)
                self_addr = m2.group(1)
                peer_addr = m2.group(3)
                self_addresses.add(f"{self_addr}:{m2.group(2)}")
                peer_addresses.add(peer_addr)
                client_validations.append({
                    'timestamp': ts,
                    'self_address': f"[{self_addr}]:{m2.group(2)}",
                    'peer_address': f"[{peer_addr}]:{m2.group(4)}",
                    'type': 'client_validated',
                })
                continue

            # Fallback: any other validation success pattern
            m3 = re.search(r'Successfully validated path', line)
            if m3:
                ts = parse_timestamp(line)
                client_validations.append({
                    'timestamp': ts,
                    'type': 'client_validated',
                })
                continue

            # "Received server preferred address: [addr]:port"
            m4 = re.search(r'Received server preferred address: \[([^\]]+)\]:(\d+)', line)
            if m4:
                ts = parse_timestamp(line)
                spa_received.append({'timestamp': ts, 'address': m4.group(1)})

    # Combine server SPA migrations and client validations
    all_migrations = migrations + client_validations
    all_migrations.sort(key=lambda x: x.get('timestamp') or 0)

    if not all_migrations:
        return {
            'migration_count': 0,
            'server_ips': list(peer_addresses),
            'client_endpoints': [],
            'subconnection_durations_ms': [],
            'spa_frames_received': len(spa_received),
            'migration_type': 'none',
        }

    # Compute subconnection durations (time between consecutive migrations)
    subconn_durations = []
    for i in range(1, len(all_migrations)):
        if all_migrations[i].get('timestamp') and all_migrations[i-1].get('timestamp'):
            dur_ms = (all_migrations[i]['timestamp'] - all_migrations[i-1]['timestamp']) * 1000
            if dur_ms > 0:
                subconn_durations.append(round(dur_ms, 2))

    # Determine migration type
    if migrations and not client_validations:
        mig_type = 'server_spa'
    elif client_validations and not migrations:
        mig_type = 'client_initiated'
    elif migrations and client_validations:
        mig_type = 'both'
    else:
        mig_type = 'none'

    # Compute path validation RTTs
    validation_rtts = []
    if spa_received and migrations:
        first_spa_ts = spa_received[0]['timestamp']
        first_validated_ts = migrations[0]['timestamp']
        if first_spa_ts and first_validated_ts:
            initial_rtt = (first_validated_ts - first_spa_ts) * 1000
            validation_rtts.append(round(initial_rtt, 2))

    return {
        'migration_count': len(all_migrations),
        'server_ips': sorted(peer_addresses),
        'client_endpoints': sorted(self_addresses)[:20],
        'subconnection_durations_ms': subconn_durations,
        'spa_frames_received': len(spa_received) + len(migrations),
        'client_validations': len(client_validations),
        'first_migration_ts': all_migrations[0].get('timestamp'),
        'last_migration_ts': all_migrations[-1].get('timestamp'),
        'migration_type': mig_type,
    }


def parse_proxy_log(log_path):
    """Parse proxy log for peer migration events (port/address changes)."""
    port_migrations = 0
    full_address_migrations = 0
    peer_ports = set()
    peer_addresses = set()
    blackholes = 0
    migration_timestamps = []

    if not os.path.exists(log_path):
        return None

    with open(log_path, 'r', errors='replace') as f:
        for line in f:
            if "address change type is PORT_CHANGE, migrating" in line:
                port_migrations += 1
                ts = parse_timestamp(line)
                if ts:
                    migration_timestamps.append(ts)
                m = re.search(r'to \[([^\]]+)\]:(\d+)', line)
                if m:
                    peer_ports.add(int(m.group(2)))
                    peer_addresses.add(m.group(1))
            elif "address change type is" in line and "migrating" in line and "PORT_CHANGE" not in line:
                full_address_migrations += 1
                ts = parse_timestamp(line)
                if ts:
                    migration_timestamps.append(ts)
                m = re.search(r'to \[([^\]]+)\]:(\d+)', line)
                if m:
                    peer_addresses.add(m.group(1))
                    peer_ports.add(int(m.group(2)))
            elif "Network blackhole detected" in line:
                blackholes += 1

    # Compute inter-migration intervals from proxy perspective
    migration_timestamps.sort()
    proxy_subconn_durations = []
    for i in range(1, len(migration_timestamps)):
        dur_ms = (migration_timestamps[i] - migration_timestamps[i-1]) * 1000
        if dur_ms > 0:
            proxy_subconn_durations.append(round(dur_ms, 2))

    return {
        'port_change_migrations': port_migrations,
        'full_address_migrations': full_address_migrations,
        'total_migrations_observed': port_migrations + full_address_migrations,
        'unique_peer_ports': len(peer_ports),
        'unique_peer_addresses': len(peer_addresses),
        'network_blackholes': blackholes,
        'proxy_subconn_durations_ms': proxy_subconn_durations,
    }


def parse_pcap_stats(pcap_path):
    """Parse pcapng/pcap for basic stats using tshark."""
    if not os.path.exists(pcap_path) or not os.path.exists(TSHARK):
        return None

    try:
        result = subprocess.run(
            [TSHARK, '-r', pcap_path, '-q', '-z', 'io,stat,0'],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout

        total_packets = 0
        total_bytes = 0
        duration_s = 0.0

        m = re.search(r'Duration:\s+([\d.]+)\s+secs', output)
        if m:
            duration_s = float(m.group(1))

        m = re.search(r'\|\s+(\d+)\s+\|\s+(\d+)\s+\|', output)
        if m:
            total_packets = int(m.group(1))
            total_bytes = int(m.group(2))

        # Get unique IPv6 source addresses
        result2 = subprocess.run(
            [TSHARK, '-r', pcap_path, '-T', 'fields', '-e', 'ipv6.src'],
            capture_output=True, text=True, timeout=120
        )
        all_srcs = set(line.strip() for line in result2.stdout.splitlines() if line.strip())

        client_ips = sorted(ip for ip in all_srcs if ip.startswith(CLIENT_PREFIX))
        server_ips = sorted(ip for ip in all_srcs
                           if ip.startswith(PROXY_PREFIX) or ip == PROXY_ORIG)

        return {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'duration_s': duration_s,
            'client_ips': client_ips[:20],
            'server_ips': server_ips[:20],
        }
    except (subprocess.TimeoutExpired, Exception) as e:
        return {'error': str(e)}


def enrich_json(json_path, output_dir):
    """Enrich a single JSON result file with log and pcap analysis."""
    if not os.path.exists(json_path):
        return None

    with open(json_path, 'r') as f:
        content = f.read().strip()
        if not content:
            return None
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None

    base = json_path.rsplit('.json', 1)[0]

    # Parse logs
    client_log = f"{base}_client.log"
    proxy_log = f"{base}_proxy.log"
    pcap_file = f"{base}.pcapng"
    if not os.path.exists(pcap_file):
        pcap_file = f"{base}.pcap"

    client_stats = parse_client_log(client_log)
    proxy_stats = parse_proxy_log(proxy_log)
    pcap_stats = parse_pcap_stats(pcap_file) if os.path.exists(pcap_file) else None

    # Build enriched output
    enriched = dict(data)

    # pcap_stats section
    ps = {}
    if pcap_stats:
        ps['total_packets'] = pcap_stats['total_packets']
        ps['total_bytes'] = pcap_stats['total_bytes']
        ps['capture_duration_s'] = pcap_stats['duration_s']
        ps['client_ips'] = pcap_stats['client_ips']
        ps['server_ips'] = pcap_stats['server_ips']

    if client_stats:
        ps['client_migrations'] = client_stats['migration_count']
        ps['server_ips_from_log'] = client_stats['server_ips']
        ps['subconnection_durations_ms'] = client_stats['subconnection_durations_ms']
        ps['spa_frames_total'] = client_stats.get('spa_frames_received', 0)

    if proxy_stats:
        ps['server_observed_port_migrations'] = proxy_stats['port_change_migrations']
        ps['server_observed_address_migrations'] = proxy_stats['full_address_migrations']
        ps['unique_client_ports'] = proxy_stats['unique_peer_ports']
        ps['unique_client_addresses'] = proxy_stats['unique_peer_addresses']
        ps['network_blackholes'] = proxy_stats['network_blackholes']

    if client_stats:
        ps['migration_type'] = client_stats.get('migration_type', 'unknown')

    enriched['pcap_stats'] = ps

    # path_validation section
    pv = {}
    if client_stats and client_stats['migration_count'] > 0:
        pv['migrations_completed'] = client_stats['migration_count']
        pv['migration_type'] = client_stats.get('migration_type', 'unknown')
        durations = client_stats['subconnection_durations_ms']
        if durations:
            pv['avg_subconnection_duration_ms'] = round(sum(durations) / len(durations), 2)
            pv['min_subconnection_duration_ms'] = round(min(durations), 2)
            pv['max_subconnection_duration_ms'] = round(max(durations), 2)
            pv['median_subconnection_duration_ms'] = round(sorted(durations)[len(durations)//2], 2)

        freq = data.get('freq', 0)
        if freq > 0 and durations:
            validation_overheads = [max(0, d - freq) for d in durations]
            valid_overheads = [v for v in validation_overheads if v > 0]
            if valid_overheads:
                pv['estimated_avg_validation_rtt_ms'] = round(
                    sum(valid_overheads) / len(valid_overheads), 2)

        pv['unique_server_addresses_used'] = len(client_stats['server_ips'])
        if client_stats.get('client_validations', 0) > 0:
            pv['client_path_validations'] = client_stats['client_validations']
    else:
        pv['migrations_completed'] = 0

    if proxy_stats:
        pv['proxy_port_change_count'] = proxy_stats['port_change_migrations']
        pv['proxy_address_change_count'] = proxy_stats['full_address_migrations']
        if proxy_stats['proxy_subconn_durations_ms']:
            proxy_durs = proxy_stats['proxy_subconn_durations_ms']
            pv['proxy_avg_subconn_duration_ms'] = round(sum(proxy_durs) / len(proxy_durs), 2)

    enriched['path_validation'] = pv

    return enriched


def process_directory(base_dir):
    """Process all JSON result files in the ablation output directory."""
    base_path = Path(base_dir)

    # Find all ablation mode directories
    results = {}
    for mode_dir in sorted(base_path.glob('rtt58/validate/ablation_*')):
        mode = mode_dir.name.replace('ablation_', '')
        results[mode] = []

        json_files = sorted(f for f in mode_dir.glob('validate_freq_*_run*.json')
                            if '_enriched' not in f.name)
        print(f"\n  Processing mode={mode}: {len(json_files)} result files")

        for jf in json_files:
            enriched = enrich_json(str(jf), str(mode_dir))
            if enriched:
                results[mode].append(enriched)
                # Write enriched version back
                enriched_path = str(jf).replace('.json', '_enriched.json')
                with open(enriched_path, 'w') as f:
                    json.dump(enriched, f, indent=2)
                print(f"    {jf.name} -> {enriched.get('pcap_stats', {}).get('client_migrations', 'N/A')} migrations")

    # Write combined results
    combined_path = base_path / 'enriched_results.json'
    with open(combined_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n  Combined results written to: {combined_path}")

    # Print summary
    print("\n  === SUMMARY ===")
    for mode, runs in results.items():
        print(f"\n  Mode: {mode}")
        freqs = {}
        for r in runs:
            freq = r.get('freq', 0)
            if freq not in freqs:
                freqs[freq] = []
            freqs[freq].append(r)

        for freq in sorted(freqs.keys()):
            freq_runs = freqs[freq]
            durations = [r['duration_ms'] for r in freq_runs if r.get('duration_ms', 0) > 0]
            migrations = [r.get('pcap_stats', {}).get('client_migrations', 0) for r in freq_runs]
            if durations:
                avg_dur = sum(durations) / len(durations)
                avg_mig = sum(migrations) / len(migrations)
                print(f"    freq={freq:>4}ms: avg_duration={avg_dur:.0f}ms, "
                      f"avg_migrations={avg_mig:.0f}, n={len(durations)}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output-aws')
    else:
        base_dir = sys.argv[1]

    print(f"[*] Enriching results in: {base_dir}")
    process_directory(base_dir)
    print("\n[*] Done.")
