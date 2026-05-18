# QUIX AWS Cloud Experiment

End-to-end ablation study of QUIX IPv6 address hopping over real AWS infrastructure
with cross-region RTT and uncapped bandwidth.

## Architecture

```
 us-west-1                          us-east-1
┌──────────────┐    ~58ms RTT     ┌──────────────────┐      same AZ     ┌──────────────┐
│  Client      │    IPv6 QUIC     │  Proxy           │      HTTP/1.1    │  Origin      │
│  13.56.226.30│─────────────────▶│  3.88.159.86     │─────────────────▶│  54.226.82.155│
│              │                  │                  │                  │              │
│  masque_     │  Outer: UDP/4433 │  masque_server   │  TUN → curl →   │  python3 -m  │
│  client      │  IPv6 QUIC      │  CONNECT-IP      │  IPv4 to origin  │  http.server │
│              │                  │                  │                  │  :8080       │
│  TUN iface   │  Inner: IPv4    │  NAT/MASQUERADE  │                  │  100MB file  │
│  routes to   │  HTTP traffic   │  forwards inner  │                  │              │
│  origin via  │                  │  packets         │                  │              │
│  tunnel      │                  │                  │                  │              │
└──────────────┘                  └──────────────────┘                  └──────────────┘
     │                                   │
     │ Hops within:                      │ Hops within:
     │ dc32:d8f8:b90f:c0XX/120           │ 8bc4::0 - 8bc4::ff (/80 prefix)
     │ (last 8 bits of primary addr)     │ (delegated prefix, 256 or 2^48 addrs)
     │                                   │
```

## Instance Details

| Role | Region | Instance ID | Public IPv4 | Primary IPv6 | Delegated Prefix |
|------|--------|-------------|-------------|--------------|------------------|
| Client | us-west-1 | i-020499021d7c02081 | 13.56.226.30 | 2600:1f1c:2d:e700:dc32:d8f8:b90f:c0c8 | 2600:1f1c:2d:e700:12f2::/80 |
| Proxy | us-east-1 | i-08c26e60d5a6b80c5 | 3.88.159.86 | 2600:1f18:6da3:7600:a6dc:abdb:b83a:625c | 2600:1f18:6da3:7600:8bc4::/80 |
| Origin | us-east-1 | i-0b2be50ffbba3bf87 | 54.226.82.155 | 2600:1f18:6da3:7600::6703 | 2600:1f18:6da3:7600:b666::/80 |

## How It Works

### Data Path

1. Client establishes a QUIC connection to the proxy over IPv6 (outer tunnel)
2. Inside the QUIC connection, an H3 CONNECT-IP stream creates a virtual IP tunnel
3. The proxy assigns the client a TUN interface with IP 10.1.1.2
4. The client routes traffic to the origin (54.226.82.155) through the TUN
5. The proxy decapsulates inner IPv4 packets and forwards them to the origin via NAT
6. The origin serves a 100MB file over HTTP on port 8080

### Server-Side Address Hopping (SPA)

1. Proxy advertises initial preferred address (`8bc4::0`) in TLS transport parameters
2. Client validates path to preferred address and migrates
3. Every N milliseconds, proxy generates a random address in `8bc4::/80`
4. Proxy sends a custom SPA frame (type 0x33) containing the new address
5. Client validates path to the new address using PATH_CHALLENGE/RESPONSE
6. On successful validation, client migrates to the new server address
7. Proxy updates its `send_from_address` to use IPV6_PKTINFO in sendmsg()

### Client-Side Address Hopping

1. Every N milliseconds, client randomizes the last 8 bits of its current self_address
2. Client creates a new UDP socket bound to the new address
3. Path validation occurs (PATH_CHALLENGE from new address, PATH_RESPONSE back)
4. On success, client migrates to the new source address
5. Server accepts the migration (sees port/address change, validates)

### Both Mode

Both server and client hop simultaneously at the same frequency.

## Prerequisites

### AWS Configuration

- 3 EC2 instances (t3.medium or larger) with IPv6 enabled
- IPv6 prefix delegation (/80) on each instance's ENI
- **Source/destination check DISABLED on the proxy instance** (required for address hopping)
  - EC2 Console → Instance → Actions → Networking → Change source/destination check → Disable
- Security groups allowing UDP port 4433 (IPv6) and TCP port 8080 (IPv4) between instances
- SSH key at `~/.ssh/aws-quix`

### Why Disable Source/Destination Check

AWS VPC normally validates that outgoing packets have a source address explicitly assigned
to the ENI. When the proxy hops to addresses in the delegated prefix that aren't individually
assigned (e.g., using AnyIP), AWS drops them silently. Disabling source/dest check removes
this filtering.

With source/dest check disabled, two address assignment methods work:

| Method | Command | Address Space |
|--------|---------|---------------|
| Individual /128 | `ip -6 addr add <prefix>::N/128 dev ens5 nodad` × 256 | 256 addresses |
| AnyIP | `ip -6 route add local <prefix>::/80 dev lo` + `sysctl net.ipv6.ip_nonlocal_bind=1` | 2^48 addresses |

See [ANYIP-SETUP.md](ANYIP-SETUP.md) for detailed AnyIP documentation.

### Software on Instances

The `deploy-aws.sh` script handles full setup:
- Installs Bazel, Clang, and build dependencies on the proxy
- Builds `masque_server` and `masque_client` natively on x86_64
- Distributes binaries to all instances
- Generates TLS certificates
- Creates origin test file (100MB random data)

## Deployment

```bash
# One-time setup: build and deploy everything
./deploy-aws.sh

# This will:
# 1. Upload source to proxy
# 2. Build masque_server + masque_client via Bazel (~10 min first time)
# 3. Copy binaries to client and server instances
# 4. Generate TLS certs on proxy
# 5. Create 100MB test file on origin
# 6. Install dependencies (curl, tcpdump, iproute2)
```

## Running the Experiment

```bash
# Full ablation study (21 configurations × NUM_RUNS each)
./run-ablation-aws.sh

# Only regenerate plots from existing data
./run-ablation-aws.sh --plot-only
```

### What the Ablation Script Does

For each combination of (mode, frequency):
1. Kills any previous proxy process
2. Starts `masque_server` with appropriate SPA flags
3. Assigns 256 addresses from the hopping prefix to `ens5`
4. On the client: starts tcpdump, launches `masque_client`, waits for TUN
5. Downloads 100MB file via the tunnel, measures duration
6. Verifies file integrity via MD5 hash
7. Collects pcap, client log, proxy log, and TLS keylog
8. Embeds TLS keys into pcapng for Wireshark analysis (if editcap available)

### Configuration Matrix

| Parameter | Values |
|-----------|--------|
| Mode | `server`, `client`, `both` |
| Frequency (ms) | 0 (baseline), 10, 25, 50, 100, 500, 1000 |
| Runs per config | 1 (configurable via NUM_RUNS) |
| Total configs | 21 (3 modes × 7 frequencies) |

### Proxy Setup Per Run

```bash
# IP forwarding + NAT (for CONNECT-IP inner packets)
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE

# Address assignment for server-side hopping (one of):
# Option A: Individual addresses (works without disabling source/dest check)
for i in $(seq 0 255); do
  ip -6 addr add 2600:1f18:6da3:7600:8bc4::$(printf '%x' $i)/128 dev ens5 nodad
done

# Option B: AnyIP (requires source/dest check disabled)
ip -6 route add local 2600:1f18:6da3:7600:8bc4::/80 dev lo
sysctl -w net.ipv6.ip_nonlocal_bind=1
```

### Server Flags

| Flag | Description |
|------|-------------|
| `--certificate_file` | TLS certificate path |
| `--key_file` | TLS private key path |
| `--port` | UDP listen port (4433) |
| `--preferred_addr` | Initial preferred IPv6 address advertised in transport params |
| `--preferred_addr_prefix` | Prefix length for random address generation (80) |
| `--server_ipv6_hopping` | Enable server-side SPA frame hopping |
| `--send_spa_frames_every_n_ms` | Migration interval in milliseconds |

### Client Flags

| Flag | Description |
|------|-------------|
| `--disable_certificate_verification` | Skip TLS cert verification |
| `--masque_mode=connect-ip` | Use CONNECT-IP tunneling (vs CONNECT-UDP) |
| `--bring_up_tun=true` | Create TUN interface for inner traffic |
| `--server_hopping` | Migrate to server's new preferred addresses |
| `--client_hopping` | Proactively hop client source address |
| `--migrate_every_n_ms` | Migration interval in milliseconds |

## Output

### Directory Structure

```
output-aws/
├── rtt58/validate/
│   ├── ablation_server/          # Server-only hopping results
│   │   ├── validate_freq_0_run1.json
│   │   ├── validate_freq_0_run1.pcapng
│   │   ├── validate_freq_0_run1_client.log
│   │   ├── validate_freq_0_run1_proxy.log
│   │   ├── validate_freq_100_run1.json
│   │   └── ...
│   ├── ablation_client/          # Client-only hopping results
│   └── ablation_both/            # Bidirectional hopping results
└── figures/
    ├── normalized_throughput_rtt58_validate.pdf
    ├── throughput_per_migration_rtt58_validate.pdf
    ├── goodput_rtt58_validate.pdf
    └── migrations_rtt58_validate.pdf
```

### JSON Result Format

```json
{
  "freq": 100,
  "run": 1,
  "mode": "server",
  "duration_ms": 19511,
  "exit_code": 0,
  "hash_verified": true,
  "hash": "5b31448712872eb4d26d275f20c66e10"
}
```

### Pcapng Files

Each run produces a pcapng with embedded TLS keys for full decryption in Wireshark.
Captured on the client's `ens5` interface, filtered to UDP port 4433, truncated to 128 bytes
per packet (headers only — sufficient for address analysis).

## Plotting

Plots are generated automatically via Docker:

```bash
docker run --rm \
  -v ./output-aws:/data \
  -v ./plot_ablation.py:/plot_ablation.py:ro \
  python:3.10-slim \
  bash -c 'pip install matplotlib numpy && python3 /plot_ablation.py /data'
```

Generated figures:
- **Normalized throughput**: throughput relative to baseline (no migration)
- **Throughput per migration**: efficiency cost of each migration event
- **Goodput**: actual useful data transfer rate
- **Migration count**: number of successful migrations per configuration

## Results Summary (RTT=58ms, 100MB file)

### Server-Side Hopping

| Frequency | Throughput | Goodput | Migrations |
|-----------|-----------|---------|------------|
| Baseline (no hop) | 58.6 Mbps | 50.4 Mbps | 3 |
| Every 10ms | 44.3 Mbps | 44.1 Mbps | 1815 |
| Every 25ms | 46.2 Mbps | 44.2 Mbps | 724 |
| Every 50ms | 47.6 Mbps | 47.9 Mbps | 333 |
| Every 100ms | 43.3 Mbps | 41.0 Mbps | 195 |
| Every 500ms | 67.5 Mbps | 59.1 Mbps | 27 |
| Every 1000ms | 74.4 Mbps | 66.5 Mbps | 12 |

### Client-Side Hopping

| Frequency | Throughput | Goodput | Migrations |
|-----------|-----------|---------|------------|
| Baseline (no hop) | 58.5 Mbps | 50.7 Mbps | 3 |
| Every 10ms | 45.3 Mbps | 43.8 Mbps | 1824 |
| Every 100ms | 50.3 Mbps | 50.8 Mbps | 157 |
| Every 1000ms | 71.8 Mbps | 63.2 Mbps | 12 |

### Key Findings

- Hopping at ≥500ms intervals has minimal throughput overhead (<5% vs baseline)
- Sub-RTT hopping (10-25ms with 58ms RTT) causes throughput degradation due to
  path validation competing with data transfer
- Bidirectional hopping at 25ms (both mode) can cause connection failure due to
  competing PATH_CHALLENGE/RESPONSE exchanges
- All successful runs verify file integrity (MD5 hash match)

## SSH Access

```bash
ssh -i ~/.ssh/aws-quix ubuntu@13.56.226.30   # Client (us-west-1)
ssh -i ~/.ssh/aws-quix ubuntu@3.88.159.86    # Proxy (us-east-1)
ssh -i ~/.ssh/aws-quix ubuntu@54.226.82.155  # Origin (us-east-1)
```

## Troubleshooting

**Proxy fails to start (ss shows no listener on 4433)**
- Check `/home/ubuntu/server.log` on the proxy for errors
- Verify certificates exist at `/home/ubuntu/certs/`

**TUN doesn't come up on client**
- Check client log: if `QUIC_DECRYPTION_FAILURE` appears, likely stale state from a previous run
- Kill all processes on both hosts and retry
- If client connects but CONNECT-IP response never arrives: check source address selection
  (`ip -6 route get <proxy_ipv6>` should show the primary address, not a delegated prefix address)

**Hash verification fails**
- Origin file may have been regenerated (reboot loses `/home/ubuntu/largefile`)
- Recreate: `dd if=/dev/urandom of=/home/ubuntu/largefile bs=1M count=100`
- Update EXPECTED_HASH in the script

**Client uses wrong source address**
- If delegated prefix addresses are on `ens5`, the kernel may prefer them
- Fix: remove delegated prefix addresses from client, or add a source route:
  `ip -6 route add <proxy_ipv6>/128 via <gateway> dev ens5 src <primary_addr>`

**Packets leave proxy but never arrive at client**
- Source/destination check is likely still enabled on the proxy instance
- Verify: send test UDP from proxy and tcpdump on client
- Fix: Disable source/dest check in EC2 console

**Both mode at sub-RTT frequency times out**
- Expected behavior: when both sides hop faster than the RTT, PATH_CHALLENGE/RESPONSE
  for one side arrives at an address the other side has already abandoned
- Use frequencies ≥ 2×RTT for bidirectional hopping (≥120ms for 58ms RTT)
