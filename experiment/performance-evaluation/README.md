# QUIX Performance Evaluation

Self-contained artifact for the throughput ablation experiment in the QUIX paper.

## Directory Structure

```
performance-evaluation/
├── README.md                       # This file
├── paper_section_evaluation.tex    # LaTeX section ready to include
├── scripts/
│   ├── run-ablation-aws-final.sh   # Experiment runner (3 modes × 7 freqs × 5 runs)
│   ├── plot_ablation.py            # Plot generation (USENIX-style figures)
│   ├── count_migrations.py        # Count migrations from pcapng (tshark endpoints)
│   └── extract_throughput.py      # Extract wire throughput from pcapng (capinfos)
├── data/
│   └── rtt58/validate/
│       ├── ablation_server/       # JSON results: server-side SPA hopping
│       ├── ablation_client/       # JSON results: client-side hopping
│       └── ablation_both/         # JSON results: bidirectional hopping
├── figures/
│   ├── normalized_throughput_rtt58_validate.pdf
│   └── throughput_rtt58_validate.pdf
└── pcaps/                         # Packet captures (not in git, see below)
```

## Experiment Summary

| Parameter | Value |
|-----------|-------|
| Client | AWS t3.medium, us-west-1 (California) |
| Proxy | AWS t3.medium, us-east-1 (Virginia) |
| Origin | AWS t3.micro, us-east-1 (Virginia) |
| RTT | ~58ms (cross-region) |
| File size | 100 MB |
| Modes | server, client, both |
| Frequencies | 0, 10, 25, 50, 100, 500, 1000 ms |
| Runs per config | 5 |
| Total runs | 105 |
| IPv6 prefix size | /80 (2^48 addresses per endpoint) |

## Reproducing

### Prerequisites

- 3 AWS EC2 instances (Ubuntu 22.04) with IPv6 enabled
- Source/destination checking disabled on client and proxy instances
- SSH key access to all instances
- `tshark`, `capinfos` (Wireshark CLI tools)
- Python 3.10+ with `numpy`, `matplotlib`, `seaborn`

### Step 1: Build and deploy QUIX binaries

Build `masque_client` and `masque_server` from the quiche source tree:

```bash
CC=clang bazel build //quiche/masque:masque_client //quiche/masque:masque_server
```

Deploy to the respective instances.

### Step 2: Run the experiment

Edit `scripts/run-ablation-aws-final.sh` with your instance IPs and SSH key path, then:

```bash
chmod +x scripts/run-ablation-aws-final.sh
./scripts/run-ablation-aws-final.sh
```

This runs all 105 configurations, captures pcapng with embedded TLS keys on the client VPS, and saves JSON results locally.

### Step 3: Extract metrics from pcaps

```bash
# Count actual migrations (unique addresses from endpoint stats)
python3 scripts/count_migrations.py /path/to/pcaps migrations.json

# Extract wire throughput
python3 scripts/extract_throughput.py /path/to/pcaps throughput.json
```

### Step 4: Inject metrics into JSON results

```python
import json, glob
migrations = json.load(open("migrations.json"))
throughput = json.load(open("throughput.json"))

for jf in glob.glob("data/rtt58/validate/ablation_*/validate_freq_*.json"):
    data = json.load(open(jf))
    key = f"{data['mode']}_freq_{data['freq']}_run{data['run']}.pcapng"
    if key in migrations:
        data["client_migrations"] = migrations[key]["client_migrations"]
        data["server_migrations"] = migrations[key]["server_migrations"]
    if key in throughput:
        data["wire_throughput_mbps"] = throughput[key]["throughput_mbps"]
    json.dump(data, open(jf, "w"))
```

### Step 5: Generate figures

```bash
python3 scripts/plot_ablation.py data 100
# Output: data/figures/normalized_throughput_rtt58_validate.pdf
#         data/figures/throughput_rtt58_validate.pdf
```

## Packet Captures

The 105 pcapng files (13 GB total, ~125 MB each) contain:
- Full packet capture on the client interface (UDP port 4433)
- Embedded TLS session keys (Decryption Secrets Block)

Open in Wireshark to decrypt QUIC and inspect frame types (SPA, PATH_CHALLENGE, etc.).

The pcaps are not committed to git due to size. They are archived at:
- Client VPS: `/home/ubuntu/pcaps/`
- Local: `experiment/pcaps/`

### Verifying migration counts from pcap

```bash
# Using Wireshark GUI: Statistics → Endpoints → IPv6 tab
# Count unique addresses in hopping prefix = migrations

# Command line:
tshark -r server_freq_10_run1.pcapng -q -z endpoints,ipv6 | grep "8bc4" | wc -l
# → 286 = server migrations for this run
```

## Key Results

- At 10ms interval: 286 server hops or 272 client hops per 100 MB transfer
- Throughput remains within 70-95% of baseline across all configurations
- Client hopping has ~2x less per-hop overhead than server SPA hopping
- Bidirectional hopping does not compound overhead
- Path validation bounds effective hop rate to ~15 hops/sec per endpoint at 58ms RTT

## JSON Schema

Each result file (`validate_freq_{freq}_run{run}.json`) contains:

```json
{
  "freq": 10,
  "run": 1,
  "mode": "server",
  "duration_ms": 18106,
  "exit_code": 0,
  "hash_verified": true,
  "hash": "5b31448712872eb4d26d275f20c66e10",
  "client_migrations": 0,
  "server_migrations": 286,
  "wire_throughput_mbps": 50.5,
  "wire_data_bytes": 125184664,
  "wire_duration_s": 19.832
}
```

| Field | Source | Description |
|-------|--------|-------------|
| `duration_ms` | curl timing | Application-layer download time |
| `hash_verified` | md5sum | Integrity check (100 MB file) |
| `client_migrations` | tshark endpoints | Unique client hopping-prefix addresses |
| `server_migrations` | tshark endpoints | Unique server hopping-prefix addresses |
| `wire_throughput_mbps` | capinfos | Total wire bytes / capture duration |
| `wire_data_bytes` | capinfos | Total bytes on wire |
| `wire_duration_s` | capinfos | First-to-last packet time |
