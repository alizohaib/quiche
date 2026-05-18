#!/usr/bin/env python3
"""Analyze a pcap/pcapng file and enrich the corresponding JSON with stats."""

import json
import struct
import subprocess
import sys
import os


def parse_pcap_legacy(f):
    magic = f.read(4)
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        return
    f.read(20)
    while True:
        pkt_header = f.read(16)
        if len(pkt_header) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_header)
        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len:
            break
        yield ts_sec + ts_usec / 1_000_000.0, orig_len, pkt_data


def parse_pcapng(f):
    interfaces = []

    def read_exact(n):
        data = f.read(n)
        return data if len(data) == n else None

    shb_type = read_exact(4)
    if shb_type is None:
        return
    shb_len = read_exact(4)
    if shb_len is None:
        return
    bom_bytes = read_exact(4)
    if bom_bytes is None:
        return
    if bom_bytes == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    elif bom_bytes == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    else:
        return
    block_total_len = struct.unpack(endian + "I", shb_len)[0]
    remaining = block_total_len - 12
    if remaining > 0:
        f.read(remaining)

    while True:
        block_header = read_exact(8)
        if block_header is None:
            break
        block_type, block_total_len = struct.unpack(endian + "II", block_header)
        body_len = block_total_len - 12
        if body_len < 0:
            break
        body = read_exact(body_len)
        if body is None:
            break
        read_exact(4)

        if block_type == 1:  # IDB
            tsresol = 1e-6
            if len(body) >= 8:
                opts = body[8:]
                i = 0
                while i + 4 <= len(opts):
                    opt_code, opt_len = struct.unpack(endian + "HH", opts[i:i+4])
                    if opt_code == 0:
                        break
                    if opt_code == 9 and opt_len == 1:
                        val = opts[i+4]
                        if val & 0x80:
                            tsresol = 1.0 / (2 ** (val & 0x7f))
                        else:
                            tsresol = 1.0 / (10 ** val)
                    i += 4 + ((opt_len + 3) & ~3)
            interfaces.append(tsresol)

        elif block_type == 6:  # EPB
            if len(body) < 20:
                continue
            iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                endian + "IIIII", body[:20]
            )
            pkt_data = body[20:20+cap_len]
            tsresol = interfaces[iface_id] if iface_id < len(interfaces) else 1e-6
            ts_raw = (ts_hi << 32) | ts_lo
            timestamp = ts_raw * tsresol
            yield timestamp, orig_len, pkt_data


def analyze(pcap_path):
    """Analyze pcap and return stats dict."""
    first_ts = None
    last_ts = None
    total_bytes = 0
    pkt_count = 0
    client_ips = set()
    server_ips = set()

    prev_client_src = None
    prev_server_src = None
    client_migrations = 0
    server_migrations = 0

    # Track sub-connections (unique src→dst address pairs)
    subconn_pairs = set()
    # Track duration of each sub-connection segment
    subconn_start_times = {}  # (src, dst) → first_ts for current segment
    subconn_durations = []

    with open(pcap_path, "rb") as f:
        magic = f.read(4)
        if len(magic) < 4:
            return None
        f.seek(0)

        if magic == b"\x0a\x0d\x0d\x0a":
            packets = parse_pcapng(f)
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            packets = parse_pcap_legacy(f)
        else:
            return None

        current_client_src = None
        current_server_src = None
        current_pair = None
        pair_start_ts = None

        for timestamp, orig_len, pkt_data in packets:
            if first_ts is None:
                first_ts = timestamp
            last_ts = timestamp
            total_bytes += orig_len
            pkt_count += 1

            if len(pkt_data) >= 14 + 40:
                ethertype = struct.unpack("!H", pkt_data[12:14])[0]
                if ethertype == 0x86DD:
                    src_ip = pkt_data[22:38]
                    dst_ip = pkt_data[38:54]
                    src_group = struct.unpack("!H", src_ip[12:14])[0]

                    if src_group == 3:
                        client_ips.add(src_ip)
                        if prev_client_src is not None and src_ip != prev_client_src:
                            client_migrations += 1
                        prev_client_src = src_ip
                        current_client_src = src_ip
                    elif src_group == 2:
                        server_ips.add(src_ip)
                        if prev_server_src is not None and src_ip != prev_server_src:
                            server_migrations += 1
                        prev_server_src = src_ip
                        current_server_src = src_ip

                    # Track sub-connection changes
                    if current_client_src and current_server_src:
                        new_pair = (current_client_src, current_server_src)
                        subconn_pairs.add(new_pair)
                        if new_pair != current_pair:
                            # End previous sub-connection
                            if current_pair is not None and pair_start_ts is not None:
                                subconn_durations.append(timestamp - pair_start_ts)
                            current_pair = new_pair
                            pair_start_ts = timestamp

        # Close final sub-connection
        if current_pair is not None and pair_start_ts is not None and last_ts is not None:
            subconn_durations.append(last_ts - pair_start_ts)

    if first_ts is None or last_ts is None:
        return None

    duration = last_ts - first_ts
    avg_subconn_duration_ms = 0.0
    if subconn_durations:
        avg_subconn_duration_ms = (sum(subconn_durations) / len(subconn_durations)) * 1000.0

    def format_ip(raw):
        groups = struct.unpack("!8H", raw)
        return ":".join(f"{g:x}" for g in groups)

    return {
        "pcap_stats": {
            "total_bytes": total_bytes,
            "total_packets": pkt_count,
            "duration_s": round(duration, 3),
            "client_migrations": client_migrations,
            "server_migrations": server_migrations,
            "total_migrations": client_migrations + server_migrations,
            "client_ip_count": len(client_ips),
            "server_ip_count": len(server_ips),
            "client_ips": sorted(format_ip(ip) for ip in client_ips),
            "server_ips": sorted(format_ip(ip) for ip in server_ips),
            "total_subconnections": len(subconn_pairs),
            "avg_subconnection_duration_ms": round(avg_subconn_duration_ms, 1),
            "subconnection_durations_ms": [round(d * 1000.0, 1) for d in subconn_durations],
        }
    }


def analyze_path_validation(pcap_path):
    """Use tshark to extract PATH_CHALLENGE/RESPONSE stats from decrypted pcap."""
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    # Extract all PATH_CHALLENGE (0x1a) and PATH_RESPONSE (0x1b) frames
    result = subprocess.run(
        ["tshark", "-r", pcap_path,
         "-Y", "quic.frame_type == 0x1a || quic.frame_type == 0x1b",
         "-T", "fields",
         "-e", "frame.time_relative",
         "-e", "quic.frame_type",
         "-e", "ipv6.src",
         "-e", "ipv6.dst",
         "-e", "quic.path_challenge.data",
         "-e", "quic.path_response.data"],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        return None

    lines = result.stdout.strip().split("\n")
    if not lines or lines == [""]:
        return {"path_challenges_sent": 0, "path_responses_sent": 0,
                "path_validations": 0,
                "client_initiated_challenges": 0, "server_initiated_challenges": 0,
                "avg_validation_rtt_ms": 0.0, "validation_rtts_ms": []}

    challenges = {}  # data -> (timestamp, src, dst)
    client_challenges = 0
    server_challenges = 0
    total_challenges = 0
    total_responses = 0
    validation_rtts = []

    for line in lines:
        fields = line.split("\t")
        if len(fields) < 4:
            continue
        timestamp = float(fields[0])
        frame_types = fields[1].split(",")
        src = fields[2]
        dst = fields[3]
        challenge_data = fields[4] if len(fields) > 4 else ""
        response_data = fields[5] if len(fields) > 5 else ""

        # Determine direction based on IPv6 address group
        src_is_client = ":3:" in src or src.endswith(":3:1")
        src_is_server = ":2:" in src or ":2:0" in src

        for ft in frame_types:
            ft = ft.strip()
            if ft == "0x000000000000001a":  # PATH_CHALLENGE
                total_challenges += 1
                if src_is_client:
                    client_challenges += 1
                elif src_is_server:
                    server_challenges += 1
                # Store challenge for RTT matching
                if challenge_data:
                    for cd in challenge_data.split(","):
                        cd = cd.strip()
                        if cd:
                            challenges[cd] = (timestamp, src, dst)
            elif ft == "0x000000000000001b":  # PATH_RESPONSE
                total_responses += 1
                # Match response to challenge for RTT
                if response_data:
                    for rd in response_data.split(","):
                        rd = rd.strip()
                        if rd and rd in challenges:
                            challenge_ts = challenges[rd][0]
                            rtt_ms = (timestamp - challenge_ts) * 1000.0
                            if rtt_ms > 0:
                                validation_rtts.append(round(rtt_ms, 2))
                            del challenges[rd]

    avg_rtt = 0.0
    if validation_rtts:
        avg_rtt = round(sum(validation_rtts) / len(validation_rtts), 2)

    return {
        "path_challenges_sent": total_challenges,
        "path_responses_sent": total_responses,
        "path_validations_completed": len(validation_rtts),
        "path_validations_pending": len(challenges),
        "client_initiated_challenges": client_challenges,
        "server_initiated_challenges": server_challenges,
        "avg_validation_rtt_ms": avg_rtt,
        "min_validation_rtt_ms": round(min(validation_rtts), 2) if validation_rtts else 0.0,
        "max_validation_rtt_ms": round(max(validation_rtts), 2) if validation_rtts else 0.0,
        "validation_rtts_ms": validation_rtts,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_pcap.py <pcap_or_pcapng> [json_file]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    json_path = sys.argv[2] if len(sys.argv) > 2 else None

    # Auto-detect json path from pcap path
    if json_path is None:
        base = pcap_path.replace(".pcapng", "").replace(".pcap", "")
        json_path = base + ".json"

    stats = analyze(pcap_path)
    if stats is None:
        print(f"ERROR: Could not parse {pcap_path}", file=sys.stderr)
        sys.exit(1)

    # Get path validation stats via tshark (if available)
    pathval_stats = analyze_path_validation(pcap_path)
    if pathval_stats is not None:
        stats["path_validation"] = pathval_stats

    # Merge with existing JSON if it exists
    if os.path.exists(json_path):
        with open(json_path) as f:
            data = json.load(f)
        data.update(stats)
    else:
        data = stats

    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    main()
