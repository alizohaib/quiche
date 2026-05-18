# QUIX Address Hopping Experiment

End-to-end test of the QUIX IPv6 address hopping system using a Dockerized IPv6
network. The MASQUE proxy tunnels traffic to external servers while client and
server hop between IPv6 addresses for anti-fingerprinting.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Docker Network: fd00:abcd::/64                         │
│                                                         │
│  ┌───────────────────┐      ┌───────────────────────┐  │
│  │  masque-client     │      │  masque-server         │  │
│  │  fd00:abcd::3      │─────▶│  fd00:abcd::2          │  │
│  │                    │ QUIC │  Listens on :4433      │  │
│  │  Client hops to    │◀─────│                        │  │
│  │  random addresses  │ SPA  │  Server hops within    │──┼──▶ example.org
│  │  in fd00:abcd::/124│frames│  fd00:abcd::/64        │  │    (tunneled)
│  └───────────────────┘      └───────────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## What it tests

| Test | Feature | Description |
|------|---------|-------------|
| 1 | Server IPv6 hopping | Server sends SPA frames every 10 packets with a new random address in fd00:abcd::/64. Client migrates to new server address. |
| 2 | Client IPv6 hopping | Client proactively migrates to a random source address in fd00:abcd::/124 every 10 packets. |
| 3 | FRONT WF defense | Padded probe packets sent on a Rayleigh-distributed schedule to mask traffic fingerprints. |

## Prerequisites

- Docker with Docker Compose v2
- Docker IPv6 networking enabled (see below)
- ~3 GB disk space for the build image
- ~10 minutes for first build (Bazel compiles ~2200 targets)

### Enabling Docker IPv6

**Docker Desktop (Mac/Windows):**
Settings → Docker Engine → add to the JSON config:
```json
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80"
}
```
Then click "Apply & Restart".

**Linux:**
Add to `/etc/docker/daemon.json`:
```json
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80"
}
```
Then: `sudo systemctl restart docker`

## Quick Start

```bash
cd experiment/
./run-experiment.sh
```

This will:
1. Check Docker IPv6 support
2. Build the Docker image (compiles masque_server + masque_client)
3. Create a `fd00:abcd::/64` Docker network
4. Start the MASQUE server with server-side IPv6 hopping
5. Run 3 automated tests exercising server hopping, client hopping, and FRONT
6. Print a summary with captured packet counts and migration events

## Usage Options

```bash
# Full automated run (build + test)
./run-experiment.sh

# Skip rebuild (use cached image)
./run-experiment.sh --no-build

# Interactive shell mode (for manual testing)
./run-experiment.sh --shell
```

### Manual Testing (Shell Mode)

```bash
./run-experiment.sh --shell
```

Inside the client container:

```bash
# Basic connection through MASQUE proxy
/src/quiche/bazel-bin/quiche/masque_client \
  --disable_certificate_verification \
  --server_hopping=true \
  '[fd00:abcd::2]:4433' https://example.org/

# With client-side hopping
/src/quiche/bazel-bin/quiche/masque_client \
  --disable_certificate_verification \
  --client_hopping=true \
  --migrate_every_n_packets=5 \
  '[fd00:abcd::2]:4433' https://example.org/

# With FRONT defense
/src/quiche/bazel-bin/quiche/masque_client \
  --disable_certificate_verification \
  --server_hopping=true \
  --client_hopping=true \
  --enable_wf_defense=true \
  '[fd00:abcd::2]:4433' https://example.org/

# Capture packets while testing
tcpdump -i any -w /tmp/capture.pcap udp port 4433 &
# ... run client ...
kill %1
tcpdump -nn -r /tmp/capture.pcap | grep fd00
```

## Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--preferred_addr` | `2600:3c01:e000:8e0::0` | Initial preferred IPv6 address (transport parameter) |
| `--server_ipv6_hopping` | `true` | Enable server-side SPA frame hopping |
| `--send_spa_frames_every_n_packets` | `50` | Send SPA frame every N packets |
| `--preferred_addr_prefix` | `124` | Prefix length for random address generation |
| `--enable_wf_defense` | `false` | Enable FRONT WF defense probes |
| `--port` | `9661` | UDP port to listen on |

## Client Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server_hopping` | `false` | Migrate to server's new preferred addresses |
| `--client_hopping` | `false` | Proactively hop client source address |
| `--migrate_every_n_packets` | `100` | Trigger migration every N packets |
| `--enable_wf_defense` | `false` | Enable FRONT WF defense probes |
| `--disable_certificate_verification` | `false` | Skip TLS cert verification |

## How Address Hopping Works

### Server-Side Hopping (SPA Frames)
1. Server advertises initial preferred address in TLS transport parameters
2. Every N packets, server generates a random IPv6 in `prefix::/prefix_len`
3. Server sends a custom SPA frame (IETF type 0x33) with the new address
4. Client receives SPA frame, validates path to new address, migrates

### Client-Side Hopping
1. Client receives server's preferred address prefix from transport parameters
2. Every N packets, client generates a random IPv6 in its local /124 prefix
3. Client calls `ValidateAndMigrateSocket()` to bind a new source address
4. Server accepts packets from new source (subnet-aware matching in /64)

### FRONT Defense
1. At connection start, Rayleigh-distributed schedule is generated
2. Padded PING frames are sent according to the schedule
3. Adds noise to traffic patterns to defeat website fingerprinting

## Interpreting Results

A successful run shows:
- "MASQUE proxy connected: YES" — TLS handshake + H3 SETTINGS exchange succeeded
- "Preferred address received: YES" — Server's initial preferred address was in transport params
- Multiple unique `fd00:abcd::*` addresses in packet captures — address hopping is working

The "Failed to connect" error for the **encapsulated** connection to `example.org` means the
MASQUE tunnel tried to reach the external target. Whether it succeeds depends on the Docker
container's outbound internet access. The proxy-layer QUIC connection (with all QUIX features)
works regardless.

## Troubleshooting

**"Docker IPv6 networking is not available"**
- Enable IPv6 in Docker settings (see Prerequisites above)

**Build fails with Rosetta error**
- On Apple Silicon: the Dockerfile detects architecture automatically
- If using Docker Desktop, ensure "Use Rosetta" is disabled for Linux containers

**"Write probing packet failed with error = 101"**
- ENETUNREACH: The preferred address isn't routable. In this experiment, all
  addresses are in fd00:abcd::/64 which Docker routes within the compose network.

**Server exits immediately**
- Check `--certificate_file` and `--key_file` flags point to valid PEM files
- The experiment Dockerfile generates certs at build time in `/certs/`

## File Structure

```
experiment/
├── README.md                 # This file
├── docker-compose.yml        # Network and service definitions
├── Dockerfile.experiment     # Build image with masque binaries + tools
├── run-experiment.sh         # Main launcher script
└── run-client.sh            # Client-side test orchestration
```
