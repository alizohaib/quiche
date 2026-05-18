#!/usr/bin/env python3
"""Plot throughput vs migration frequency from QUIX ablation study.

Supports directory layout: output/rtt{N}/{pathval}/ablation_{mode}/
where pathval is 'skip' or 'validate'.

Generates:
  - Per-RTT per-pathval per-mode box plots
  - Per-RTT normalized throughput (skip vs validate comparison)
  - Combined multi-RTT figures
"""

import os
import struct
import sys
import glob
import json

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Paper dimensions
TEXTWIDTH = 505.89 / 72.27
COLUMNWIDTH = 241.02039 / 72.27

sns.set_theme(style="ticks", rc={
    'font.family': 'serif',
    'font.serif': ['Nimbus Roman', 'Helvetica'],
    'font.size': 10,
    'legend.fontsize': 10,
    'axes.labelsize': 10,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'xtick.major.size': 2,
    'xtick.minor.size': 2,
    'ytick.major.size': 2,
    'ytick.minor.size': 2,
    'patch.force_edgecolor': False,
    'legend.fancybox': False,
    'mathtext.default': 'regular',
    'axes.linewidth': 1.0,
    'text.color': 'black',
    'xtick.color': 'black',
    'ytick.color': 'black',
    'xtick.bottom': True,
    'ytick.left': True,
    'axes.grid': True,
    'grid.linewidth': 0.5,
    'grid.color': '#efefef',
})


def _parse_pcap_legacy(f):
    """Parse legacy pcap format. Yields (timestamp, orig_len, pkt_data)."""
    magic = f.read(4)
    if len(magic) < 4:
        return

    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        return

    header = f.read(20)
    if len(header) < 20:
        return

    while True:
        pkt_header = f.read(16)
        if len(pkt_header) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            endian + "IIII", pkt_header
        )
        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len:
            break
        timestamp = ts_sec + ts_usec / 1_000_000.0
        yield timestamp, orig_len, pkt_data


def _parse_pcapng(f):
    """Parse pcapng format. Yields (timestamp, orig_len, pkt_data).

    Handles Section Header Block (SHB), Interface Description Block (IDB),
    Enhanced Packet Block (EPB), and skips other block types (including
    Decryption Secrets Blocks).
    """
    interfaces = []  # list of {tsresol}

    def read_exact(n):
        data = f.read(n)
        if len(data) < n:
            return None
        return data

    # Determine endianness from SHB
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
    # Skip rest of SHB
    remaining = block_total_len - 12  # already read 12 bytes
    if remaining > 0:
        f.read(remaining)

    while True:
        block_header = read_exact(8)
        if block_header is None:
            break

        block_type, block_total_len = struct.unpack(endian + "II", block_header)
        body_len = block_total_len - 12  # 8 header + 4 trailing length
        if body_len < 0:
            break

        body = read_exact(body_len)
        if body is None:
            break
        # Read trailing block length
        read_exact(4)

        if block_type == 1:  # IDB
            # Parse timestamp resolution from options (default 1e-6)
            tsresol = 1e-6
            if len(body) >= 8:
                # options start at offset 8
                opts = body[8:]
                i = 0
                while i + 4 <= len(opts):
                    opt_code, opt_len = struct.unpack(endian + "HH", opts[i:i+4])
                    if opt_code == 0:
                        break
                    if opt_code == 9 and opt_len == 1:  # if_tsresol
                        val = opts[i+4]
                        if val & 0x80:
                            tsresol = 1.0 / (2 ** (val & 0x7f))
                        else:
                            tsresol = 1.0 / (10 ** val)
                    i += 4 + ((opt_len + 3) & ~3)
            interfaces.append({"tsresol": tsresol})

        elif block_type == 6:  # EPB
            if len(body) < 20:
                continue
            iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                endian + "IIIII", body[:20]
            )
            pkt_data = body[20:20+cap_len]

            tsresol = 1e-6
            if iface_id < len(interfaces):
                tsresol = interfaces[iface_id]["tsresol"]
            ts_raw = (ts_hi << 32) | ts_lo
            timestamp = ts_raw * tsresol

            yield timestamp, orig_len, pkt_data


def parse_pcap_throughput(filepath):
    """Parse pcap/pcapng, return stats including migration counts.

    Supports both legacy pcap and pcapng formats.

    Determines client vs server direction using the first packet's source
    address as the client prefix (capture is on the client interface).
    Counts address changes (ignoring port) for each side.

    Migration counts:
    - client_migrations: times the client's src address changes in outgoing packets
    - server_migrations: times the server's src address changes in incoming packets
    """
    first_ts = None
    last_ts = None
    total_bytes = 0
    pkt_count = 0
    src_ips = set()
    dst_ips = set()

    prev_client_src = None
    prev_server_src = None
    client_migrations = 0
    server_migrations = 0
    client_prefix = None

    with open(filepath, "rb") as f:
        magic = f.read(4)
        if len(magic) < 4:
            return 0, 0.0, 0, 0, 0, 0, 0
        f.seek(0)

        # Detect format
        if magic == b"\x0a\x0d\x0d\x0a":
            packets = _parse_pcapng(f)
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            packets = _parse_pcap_legacy(f)
        else:
            return 0, 0.0, 0, 0, 0, 0, 0

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
                    src_ips.add(src_ip)
                    dst_ips.add(dst_ip)

                    # Use first packet's src prefix (first 10 bytes) as client identifier
                    if client_prefix is None:
                        client_prefix = src_ip[:10]

                    if src_ip[:10] == client_prefix:
                        # Outgoing packet from client
                        if prev_client_src is not None and src_ip != prev_client_src:
                            client_migrations += 1
                        prev_client_src = src_ip
                    else:
                        # Incoming packet from server/proxy
                        if prev_server_src is not None and src_ip != prev_server_src:
                            server_migrations += 1
                        prev_server_src = src_ip

    if first_ts is None or last_ts is None:
        return 0, 0.0, 0, 0, 0, 0, 0

    duration = last_ts - first_ts
    return total_bytes, duration, pkt_count, len(src_ips), len(dst_ips), client_migrations, server_migrations


def process_directory(data_dir, frequencies, pathval_prefix=None, file_size_mb=None):
    """Process pcap and/or JSON files for throughput and goodput measurement.

    If pathval_prefix is set (e.g. 'skip' or 'validate'), looks for files
    named like skip_freq_10_run1.pcap. Otherwise looks for freq_10_run1.pcap.

    Supports two modes:
    - With pcaps: throughput from wire bytes, goodput from JSON duration
    - JSON-only (no pcaps): goodput from JSON duration used as throughput metric
    """
    results = {}
    for freq in frequencies:
        if pathval_prefix:
            pattern_pcapng = os.path.join(data_dir, f"{pathval_prefix}_freq_{freq}_run*.pcapng")
            pattern_pcap = os.path.join(data_dir, f"{pathval_prefix}_freq_{freq}_run*.pcap")
            pattern_json = os.path.join(data_dir, f"{pathval_prefix}_freq_{freq}_run*.json")
        else:
            pattern_pcapng = os.path.join(data_dir, f"freq_{freq}_run*.pcapng")
            pattern_pcap = os.path.join(data_dir, f"freq_{freq}_run*.pcap")
            pattern_json = os.path.join(data_dir, f"freq_{freq}_run*.json")

        pcap_files = sorted(glob.glob(pattern_pcapng) or glob.glob(pattern_pcap))

        if pcap_files:
            # Pcap-based processing
            run_throughputs = []
            run_goodputs = []
            run_durations = []
            run_src_ips = []
            run_dst_ips = []
            run_client_migrations = []
            run_server_migrations = []

            for pcap_path in pcap_files:
                json_path = pcap_path.replace(".pcapng", ".json").replace(".pcap", ".json")
                enriched_path = pcap_path.replace(".pcapng", "_enriched.json").replace(".pcap", "_enriched.json")
                duration_ms = None
                mode = ""
                if os.path.exists(json_path):
                    try:
                        with open(json_path) as f:
                            meta = json.load(f)
                        if meta.get("exit_code", -1) != 0:
                            continue
                        if not meta.get("hash_verified", True):
                            continue
                        duration_ms = meta.get("duration_ms")
                        mode = meta.get("mode", "")
                    except (json.JSONDecodeError, IOError):
                        pass

                total_bytes, duration, pkt_count, n_src, n_dst, client_mig, server_mig = parse_pcap_throughput(pcap_path)
                if duration <= 0 or total_bytes == 0:
                    continue

                throughput_mbps = (total_bytes * 8) / (duration * 1_000_000)
                run_throughputs.append(throughput_mbps)
                run_durations.append(duration)
                run_src_ips.append(n_src)
                run_dst_ips.append(n_dst)

                # Use enriched JSON for migration counts if available (more accurate than pcap parsing)
                enriched_mig = None
                if os.path.exists(enriched_path):
                    try:
                        with open(enriched_path) as f:
                            enriched = json.load(f)
                        pv = enriched.get("path_validation", {})
                        enriched_mig = pv.get("migrations_completed", 0)
                    except (json.JSONDecodeError, IOError):
                        pass

                if enriched_mig is not None and enriched_mig > 0:
                    if mode in ("server", "both"):
                        run_server_migrations.append(enriched_mig)
                    else:
                        run_server_migrations.append(0)
                    if mode in ("client", "both"):
                        run_client_migrations.append(enriched_mig)
                    else:
                        run_client_migrations.append(0)
                else:
                    # Fallback: use pcap-derived or expected count
                    if duration_ms and freq > 0:
                        expected = int(duration_ms / freq)
                        if mode == "client":
                            run_client_migrations.append(expected)
                            run_server_migrations.append(0)
                        elif mode == "server":
                            run_client_migrations.append(0)
                            run_server_migrations.append(expected)
                        else:
                            run_client_migrations.append(expected)
                            run_server_migrations.append(expected)
                    else:
                        run_client_migrations.append(client_mig)
                        run_server_migrations.append(server_mig)

                if file_size_mb and duration_ms and duration_ms > 0:
                    goodput_mbps = (file_size_mb * 8) / (duration_ms / 1000.0)
                    run_goodputs.append(goodput_mbps)

            if not run_throughputs:
                continue

            n_runs = len(run_throughputs)
            avg_src = np.median(run_src_ips)
            avg_dst = np.median(run_dst_ips)
            avg_client_mig = np.median(run_client_migrations)
            avg_server_mig = np.median(run_server_migrations)

        else:
            # JSON-only processing (no pcaps, e.g. AWS runs)
            json_files = sorted(f for f in glob.glob(pattern_json) if '_enriched' not in f)
            if not json_files:
                continue

            run_throughputs = []
            run_goodputs = []
            run_durations = []
            run_client_migrations = []
            run_server_migrations = []

            for json_path in json_files:
                try:
                    with open(json_path) as f:
                        meta = json.load(f)
                except (json.JSONDecodeError, IOError):
                    continue

                if meta.get("exit_code", -1) != 0:
                    continue
                if not meta.get("hash_verified", False):
                    continue

                duration_ms = meta.get("duration_ms", 0)
                if duration_ms <= 0:
                    continue

                duration_s = duration_ms / 1000.0
                run_durations.append(duration_s)

                # Prefer wire throughput from pcap if available
                if "wire_throughput_mbps" in meta and meta["wire_throughput_mbps"] > 0:
                    run_throughputs.append(meta["wire_throughput_mbps"])
                elif file_size_mb:
                    run_throughputs.append((file_size_mb * 8) / duration_s)

                if file_size_mb:
                    goodput_mbps = (file_size_mb * 8) / duration_s
                    run_goodputs.append(goodput_mbps)

                # Use actual migration counts from JSON if available (injected from pcap analysis)
                if "client_migrations" in meta or "server_migrations" in meta:
                    run_client_migrations.append(meta.get("client_migrations", 0))
                    run_server_migrations.append(meta.get("server_migrations", 0))
                else:
                    # Fallback: estimate from freq and duration
                    run_freq = meta.get("freq", freq)
                    if run_freq > 0:
                        expected_migrations = int(duration_ms / run_freq)
                    else:
                        expected_migrations = 0

                    mode = meta.get("mode", "")
                    if mode == "client":
                        run_client_migrations.append(expected_migrations)
                        run_server_migrations.append(0)
                    elif mode == "server":
                        run_client_migrations.append(0)
                        run_server_migrations.append(expected_migrations)
                    elif mode == "both":
                        run_client_migrations.append(expected_migrations)
                        run_server_migrations.append(expected_migrations)
                    else:
                        run_client_migrations.append(expected_migrations)
                        run_server_migrations.append(0)

            if not run_throughputs:
                continue

            n_runs = len(run_throughputs)
            avg_src = 0
            avg_dst = 0
            avg_client_mig = np.median(run_client_migrations) if run_client_migrations else 0
            avg_server_mig = np.median(run_server_migrations) if run_server_migrations else 0

        def iqr_half(arr):
            if len(arr) < 2:
                return 0.0
            return float(np.percentile(arr, 75) - np.percentile(arr, 25)) / 2.0

        goodput_str = ""
        if run_goodputs:
            goodput_str = f", goodput={np.median(run_goodputs):.1f} Mbps"

        print(f"  freq={freq}: {n_runs} runs, throughput={np.median(run_throughputs):.1f} Mbps "
              f"(IQR/2={iqr_half(run_throughputs):.1f}){goodput_str}, "
              f"migrations: client={avg_client_mig:.0f} server={avg_server_mig:.0f}")

        results[freq] = {
            "avg_mbps": float(np.median(run_throughputs)),
            "avg_mbps_std": iqr_half(run_throughputs),
            "avg_goodput_mbps": float(np.median(run_goodputs)) if run_goodputs else 0.0,
            "avg_goodput_std": iqr_half(run_goodputs) if run_goodputs else 0.0,
            "all_goodput_mbps": run_goodputs,
            "duration": float(np.median(run_durations)),
            "n_runs": n_runs,
            "all_mbps": run_throughputs,
            "avg_src_ips": float(avg_src) if pcap_files else 0.0,
            "avg_dst_ips": float(avg_dst) if pcap_files else 0.0,
            "avg_client_migrations": float(avg_client_mig),
            "avg_server_migrations": float(avg_server_mig),
            "all_client_migrations": run_client_migrations,
            "all_server_migrations": run_server_migrations,
        }

    return results


def make_normalized_plot(all_results, frequencies, labels, title_suffix, output_path_prefix):
    """Generate grouped bar chart of normalized throughput with migration count annotations."""
    fig, ax = plt.subplots(1, 1, figsize=(COLUMNWIDTH, COLUMNWIDTH * 0.75))

    scenario_styles = {
        "server": {"color": "#2ecc71", "label": "Server Hopping"},
        "client": {"color": "#3498db", "label": "Client Hopping"},
        "both": {"color": "#e74c3c", "label": "Bidirectional Hopping"},
    }

    freqs_nonzero = [f for f in frequencies if f > 0]
    n_freqs = len(freqs_nonzero)
    scenarios_present = [s for s in scenario_styles if s in all_results and all_results[s]]
    n_scenarios = len(scenarios_present)

    if n_scenarios == 0 or n_freqs == 0:
        plt.close()
        return

    bar_width = 0.8 / n_scenarios
    x_base = np.arange(n_freqs)

    for i, scenario in enumerate(scenarios_present):
        results = all_results[scenario]
        if 0 not in results:
            continue

        baseline = float(max(results[0]["all_mbps"]))
        if baseline <= 0:
            continue

        style = scenario_styles[scenario]
        normalized = []
        errors = []
        mig_counts = []

        for freq in freqs_nonzero:
            if freq in results:
                normalized.append(results[freq]["avg_mbps"] / baseline * 100)
                errors.append(results[freq]["avg_mbps_std"] / baseline * 100)
                mig_counts.append(
                    results[freq]["avg_client_migrations"] +
                    results[freq]["avg_server_migrations"])
            else:
                normalized.append(0)
                errors.append(0)
                mig_counts.append(0)

        x_offset = x_base + (i - (n_scenarios - 1) / 2) * bar_width
        bars = ax.bar(x_offset, normalized, bar_width, yerr=errors,
                      color=style["color"], alpha=0.85, label=style["label"],
                      capsize=2, linewidth=0.5)

        for bar, mig in zip(bars, mig_counts):
            if bar.get_height() > 0 and mig > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2,
                        f"{int(mig)}", ha="center", va="bottom", fontsize=6,
                        color=style["color"], fontweight="bold")

    ax.axhline(y=100, color="gray", linestyle="--", alpha=0.5, linewidth=0.8)
    ax.set_xticks(x_base)
    ax.set_xticklabels([str(f) for f in freqs_nonzero])
    ax.set_xlabel("Migration Frequency (ms)")
    ax.set_ylabel("Throughput (% of baseline)")
    ax.legend(loc="upper left", framealpha=0.9, edgecolor='none')
    ax.set_ylim(bottom=60, top=140)
    sns.despine(ax=ax)

    plt.tight_layout()
    plt.savefig(f"{output_path_prefix}.pdf", bbox_inches="tight")
    plt.close()


def make_per_migration_plot(all_results, frequencies, title_suffix, output_path_prefix):
    """Grouped box-and-whisker: throughput loss (%) per migration, per run."""
    fig, ax = plt.subplots(1, 1, figsize=(COLUMNWIDTH, COLUMNWIDTH * 0.75))

    scenario_styles = {
        "server": {"color": "#2ecc71", "label": "Server SPA"},
        "client": {"color": "#3498db", "label": "Client hopping"},
        "both": {"color": "#e74c3c", "label": "Both"},
    }

    freqs_nonzero = [f for f in frequencies if f > 0]
    n_freqs = len(freqs_nonzero)
    scenarios_present = [s for s in scenario_styles if s in all_results and all_results[s]]
    n_scenarios = len(scenarios_present)

    if n_scenarios == 0 or n_freqs == 0:
        plt.close()
        return

    box_width = 0.7 / n_scenarios
    x_base = np.arange(n_freqs)

    for i, scenario in enumerate(scenarios_present):
        results = all_results[scenario]
        if 0 not in results:
            continue

        use_goodput = bool(results[0].get("all_goodput_mbps"))
        if use_goodput:
            baseline = float(max(results[0]["all_goodput_mbps"]))
        else:
            baseline = float(max(results[0]["all_mbps"]))
        if baseline <= 0:
            continue

        style = scenario_styles[scenario]
        all_box_data = []

        for freq in freqs_nonzero:
            if freq in results:
                run_mbps = results[freq]["all_goodput_mbps"] if use_goodput else results[freq]["all_mbps"]
                run_client_mig = results[freq]["all_client_migrations"]
                run_server_mig = results[freq]["all_server_migrations"]
                per_run_values = []
                for mbps, cmig, smig in zip(run_mbps, run_client_mig, run_server_mig):
                    total_mig = cmig + smig
                    if total_mig > 0:
                        loss_pct = (1 - mbps / baseline) * 100
                        per_run_values.append(loss_pct / total_mig)
                all_box_data.append(per_run_values if per_run_values else [0])
            else:
                all_box_data.append([0])

        positions = x_base + (i - (n_scenarios - 1) / 2) * box_width
        bp = ax.boxplot(
            all_box_data, positions=positions, widths=box_width * 0.85,
            patch_artist=True, notch=False,
            medianprops={"color": "black", "linewidth": 1.2},
            whiskerprops={"linewidth": 0.8},
            capprops={"linewidth": 0.8},
            flierprops={"marker": "o", "markersize": 3, "markerfacecolor": style["color"], "alpha": 0.7},
        )
        for patch in bp["boxes"]:
            patch.set_facecolor(style["color"])
            patch.set_alpha(0.7)

        ax.plot([], [], color=style["color"], linewidth=6, alpha=0.7, label=style["label"])

    ax.set_xticks(x_base)
    ax.set_xticklabels([str(f) for f in freqs_nonzero])
    ax.set_xlabel("Migration Interval (ms)")
    ax.set_ylabel("Goodput Loss per Migration (%)")
    ax.legend(loc="upper right")
    ax.set_ylim(bottom=0)
    sns.despine(ax=ax)

    plt.tight_layout()
    plt.savefig(f"{output_path_prefix}.pdf", bbox_inches="tight")
    plt.close()


def print_summary(results, frequencies, labels):
    """Print summary table."""
    freqs_present = [f for f in frequencies if f in results]
    has_goodput = any(results[f].get("avg_goodput_mbps", 0) > 0 for f in freqs_present)

    if has_goodput:
        print(f"  {'Configuration':<24} {'Throughput':>10} {'Goodput':>10} {'Duration':>9} {'Runs':>5} {'ClientMig':>9} {'ServerMig':>9}")
        print(f"  {'-'*24} {'-'*10} {'-'*10} {'-'*9} {'-'*5} {'-'*9} {'-'*9}")
        for f in freqs_present:
            s = results[f]
            print(
                f"  {labels[f]:<24} {s['avg_mbps']:>7.1f} Mbps {s['avg_goodput_mbps']:>7.1f} Mbps "
                f"{s['duration']:>6.2f}s  {s['n_runs']:>3} "
                f"{s['avg_client_migrations']:>9.0f} {s['avg_server_migrations']:>9.0f}"
            )
    else:
        print(f"  {'Configuration':<24} {'Throughput':>12} {'Duration':>9} {'Runs':>5} {'ClientMig':>9} {'ServerMig':>9}")
        print(f"  {'-'*24} {'-'*12} {'-'*9} {'-'*5} {'-'*9} {'-'*9}")
        for f in freqs_present:
            s = results[f]
            print(
                f"  {labels[f]:<24} {s['avg_mbps']:>9.1f} Mbps "
                f"{s['duration']:>6.2f}s  {s['n_runs']:>3} "
                f"{s['avg_client_migrations']:>9.0f} {s['avg_server_migrations']:>9.0f}"
            )


def main():
    data_dir = sys.argv[1] if len(sys.argv) > 1 else "/data"

    frequencies = [0, 10, 25, 50, 100, 500, 1000]

    labels = {
        0: "No Migration (baseline)",
        10: "Every 10ms",
        25: "Every 25ms",
        50: "Every 50ms",
        100: "Every 100ms",
        500: "Every 500ms",
        1000: "Every 1000ms",
    }

    pathval_modes = ["skip", "validate"]

    # Detect file size from JSON duration_ms and pcap bytes.
    # The ablation script passes file size via argv[2] or we infer from download duration.
    file_size_mb = None
    if len(sys.argv) > 2:
        file_size_mb = int(sys.argv[2])
    else:
        # Try to infer: find any baseline JSON and check if duration suggests 10MB or 100MB
        # Heuristic: baseline at 40ms RTT takes ~2.2s for 10MB, ~22s for 100MB
        for jf in glob.glob(os.path.join(data_dir, "rtt*/*/ablation_server/*freq_0_run1.json")):
            try:
                with open(jf) as f:
                    meta = json.load(f)
                dur = meta.get("duration_ms", 0)
                if dur > 0:
                    # At ~25 Mbps goodput: 10MB=3.2s, 100MB=32s
                    file_size_mb = 100 if dur > 10000 else 10
                    break
            except (json.JSONDecodeError, IOError):
                pass

    if file_size_mb:
        print(f"  Detected file size: {file_size_mb} MB")
    else:
        print("  WARNING: Could not detect file size, goodput plots will be skipped")

    # Detect directory layout: rtt{N}/{pathval}/ablation_{mode}/
    rtt_dirs = sorted(glob.glob(os.path.join(data_dir, "rtt*")))

    if not rtt_dirs:
        print("No rtt* directories found. Nothing to plot.")
        return

    # {rtt: {pathval: {scenario: results}}}
    all_rtt_pathval_results = {}

    for rtt_dir in rtt_dirs:
        rtt_name = os.path.basename(rtt_dir)
        rtt_ms = int(rtt_name.replace("rtt", ""))
        all_rtt_pathval_results[rtt_ms] = {}

        print(f"\n{'='*60}")
        print(f"  RTT = {rtt_ms}ms")
        print(f"{'='*60}")

        for pathval in pathval_modes:
            pathval_dir = os.path.join(rtt_dir, pathval)
            if not os.path.isdir(pathval_dir):
                continue

            print(f"\n  --- Path Validation: {pathval} ---")
            all_results = {}

            scenarios = [
                ("server", "ablation_server", "Server-Side SPA Hopping"),
                ("client", "ablation_client", "Client-Side Hopping"),
                ("both", "ablation_both", "Both Server + Client Hopping"),
            ]

            for scenario_key, subdir, title in scenarios:
                sdir = os.path.join(pathval_dir, subdir)
                if not os.path.isdir(sdir):
                    continue

                print(f"\n  === {title} ({pathval}) ===")
                results = process_directory(sdir, frequencies, pathval_prefix=pathval, file_size_mb=file_size_mb)

                if results:
                    print_summary(results, frequencies, labels)
                    all_results[scenario_key] = results

            all_rtt_pathval_results[rtt_ms][pathval] = all_results

    # Generate consolidated figures into figures/ directory
    figures_dir = os.path.join(data_dir, "figures")
    os.makedirs(figures_dir, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"  Generating Consolidated Figures -> {figures_dir}/")
    print(f"{'='*60}")

    for rtt in sorted(all_rtt_pathval_results.keys()):
        for pathval in pathval_modes:
            if pathval not in all_rtt_pathval_results[rtt]:
                continue
            all_results = all_rtt_pathval_results[rtt][pathval]
            if not all_results:
                continue

            # --- Figure 1: Normalized Throughput (all modes, one plot) ---
            make_normalized_plot(
                all_results, frequencies, labels,
                f"(RTT={rtt}ms, pathval={pathval})",
                os.path.join(figures_dir, f"normalized_throughput_rtt{rtt}_{pathval}"))
            print(f"  Saved: figures/normalized_throughput_rtt{rtt}_{pathval}.pdf")


            # Shared style definitions for consolidated figures
            scenario_styles = {
                "server": {"color": "#2ecc71", "marker": "o", "label": "Server SPA"},
                "client": {"color": "#3498db", "marker": "s", "label": "Client hopping"},
                "both": {"color": "#e74c3c", "marker": "^", "label": "Both"},
            }
            freqs_nonzero = [f for f in frequencies if f > 0]
            x_positions = list(range(len(freqs_nonzero)))
            x_labels_str = [str(f) for f in freqs_nonzero]

            # --- Figure 3: Absolute Throughput (all modes, one plot) ---
            fig, ax = plt.subplots(1, 1, figsize=(COLUMNWIDTH, COLUMNWIDTH * 0.75))
            if True:

                for scenario, results in all_results.items():
                    if not results:
                        continue
                    style = scenario_styles[scenario]
                    throughputs = []
                    errors = []
                    for freq in freqs_nonzero:
                        if freq in results and results[freq].get("avg_mbps", 0) > 0:
                            throughputs.append(results[freq]["avg_mbps"])
                            errors.append(results[freq]["avg_mbps_std"])
                        else:
                            throughputs.append(None)
                            errors.append(0)
                    valid_x = [x for x, v in zip(x_positions, throughputs) if v is not None]
                    valid_y = [v for v in throughputs if v is not None]
                    valid_err = [e for e, v in zip(errors, throughputs) if v is not None]
                    ax.errorbar(valid_x, valid_y, yerr=valid_err, capsize=3,
                                color=style["color"], marker=style["marker"],
                                linewidth=1.5, markersize=5, label=style["label"],
                                capthick=1.0)

                for scenario, results in all_results.items():
                    if results and 0 in results and results[0].get("all_mbps"):
                        baseline_max = max(results[0]["all_mbps"])
                        ax.axhline(y=baseline_max, color="gray", linestyle="--",
                                   alpha=0.4, linewidth=0.8)
                        break

                ax.set_xticks(x_positions)
                ax.set_xticklabels(x_labels_str)
                ax.set_xlabel("Migration Interval (ms)")
                ax.set_ylabel("Throughput (Mbps)")
                ax.legend(loc="upper right", framealpha=0.9, edgecolor='none')
                ax.set_ylim(bottom=0)
                sns.despine(ax=ax)
                plt.tight_layout()
                plt.savefig(os.path.join(figures_dir, f"throughput_rtt{rtt}_{pathval}.pdf"), bbox_inches="tight")
                plt.close()
                print(f"  Saved: figures/throughput_rtt{rtt}_{pathval}.pdf")


    print("\nDone.")


if __name__ == "__main__":
    main()
