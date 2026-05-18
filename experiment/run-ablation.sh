#!/bin/bash
set -e

# QUIX Ablation Study: Throughput vs Migration Frequency (CONNECT-IP TUN + curl)
#
# Architecture (3-node CONNECT-IP with TUN):
#   Client ──[IPv6 outer, RTT=80ms]──> Proxy ──[IPv4 inner, RTT=2ms]──> Origin
#   fd00::3:1                           fd00::2 / 10.0.0.3              10.0.0.2
#
# Dimensions:
#   - Mode: server | client | both
#   - Frequency: 0 (baseline) | 10 | 50 | 100 packets between hops
#   - Path validation: skip (lightweight) | validate (standard QUIC with CIDs)
#
# Prerequisites: quix-experiment Docker image (run run-experiment.sh first)
#
# Usage:
#   ./run-ablation.sh              # Run full ablation study
#   ./run-ablation.sh --plot-only  # Re-plot from existing data
#   ./run-ablation.sh --quick      # Quick run (same as default currently)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PLOT_ONLY=false
FILE_SIZE_MB=100
NUM_RUNS=3
for arg in "$@"; do
  case $arg in
    --plot-only) PLOT_ONLY=true ;;
    --quick) FILE_SIZE_MB=100; NUM_RUNS=3 ;;
    --help|-h)
      echo "Usage: $0 [--plot-only] [--quick] [--help]"
      echo ""
      echo "  --plot-only  Skip experiments, re-plot from existing data"
      echo "  --quick      Use 100MB file (5 runs)"
      exit 0
      ;;
  esac
done

# Migration intervals to test (milliseconds between hops)
# 0 = baseline (no migration)
FREQUENCIES=(0 100 250 500 1000 2000 5000)

# Outer RTTs to test (ms)
OUTER_RTTS=(80)

# Inner RTT (ms) - proxy to origin, typically same region/datacenter
INNER_RTT=2

# Bandwidth cap on outer link (bits/sec)
OUTER_BW="50mbit"

# Path validation modes
PATH_VALIDATION_MODES=(validate)

# Verbosity for masque binaries
# NOTE: -v=2 on the server causes severe throughput degradation (6x slower)
# due to per-packet logging overhead. Use -v=0 for the server in performance runs.
SERVER_VERBOSITY=0
CLIENT_VERBOSITY=0

cleanup() {
  docker rm -f quix-origin quix-proxy quix-client 2>/dev/null || true
  docker network rm quix-outer quix-inner 2>/dev/null || true
}

create_networks() {
  docker network create --ipv6 --subnet fd00::/64 quix-outer >/dev/null
  docker network create --subnet 10.0.0.0/24 quix-inner >/dev/null
}

start_origin() {
  local inner_delay=$(( INNER_RTT / 2 ))

  docker run -d --rm \
    --name quix-origin \
    --network quix-inner \
    --ip 10.0.0.2 \
    --privileged \
    quix-experiment \
    bash -c "
tc qdisc add dev eth0 root handle 1: netem delay ${inner_delay}ms

mkdir -p /srv
dd if=/dev/urandom of=/srv/largefile bs=1M count=${FILE_SIZE_MB} 2>/dev/null
md5sum /srv/largefile | cut -d' ' -f1 > /srv/largefile.md5
cd /srv && python3 -m http.server 8080
" >/dev/null
}

get_origin_hash() {
  docker exec quix-origin cat /srv/largefile.md5
}

start_proxy() {
  local freq=$1
  local mode=$2
  local outer_rtt=$3
  local spa_flag=""

  local outer_delay=$(( outer_rtt / 2 ))
  local inner_delay=$(( INNER_RTT / 2 ))

  if ([ "$mode" = "server" ] || [ "$mode" = "both" ]) && [ "$freq" -gt 0 ]; then
    spa_flag="--server_ipv6_hopping=true --send_spa_frames_every_n_ms=$freq"
  else
    spa_flag="--server_ipv6_hopping=false"
  fi

  docker run -d --rm \
    --name quix-proxy \
    --network quix-outer \
    --ip6 fd00::2 \
    --privileged \
    quix-experiment \
    bash -c "
while ! ip addr show eth1 2>/dev/null | grep -q 'inet '; do sleep 0.1; done

tc qdisc add dev eth0 root handle 1: tbf rate ${OUTER_BW} burst 64kb latency 50ms
tc qdisc add dev eth0 parent 1:1 handle 10: netem delay ${outer_delay}ms
tc qdisc add dev eth1 root handle 1: netem delay ${inner_delay}ms

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

for i in \$(seq 0 255); do
  ip -6 addr add fd00::2:\$(printf '%x' \$i)/128 dev eth0 nodad 2>/dev/null
done

cd /tmp
masque_server \
  --certificate_file=/certs/cert.pem \
  --key_file=/certs/key.pem \
  --port=4433 \
  --preferred_addr=fd00::2:0 \
  --preferred_addr_prefix=120 \
  $spa_flag \
  -v=${SERVER_VERBOSITY} 2>/tmp/server.log
" >/dev/null

  docker network connect --ip 10.0.0.3 quix-inner quix-proxy
}

wait_for_proxy() {
  for i in $(seq 1 30); do
    if docker exec quix-proxy ss -uln 2>/dev/null | grep -q 4433; then
      sleep 2
      return 0
    fi
    sleep 1
  done
  echo "ERROR: Proxy failed to start"
  return 1
}

run_download() {
  local freq=$1
  local run=$2
  local output_dir=$3
  local outer_rtt=$4
  local mode=$5
  local expected_hash=$6
  local pathval_mode=$7

  local outer_delay=$(( outer_rtt / 2 ))

  local server_hop_flag="--server_hopping=false"
  local client_hop_flag="--client_hopping=false"
  local skip_cwnd_flag=""
  local migrate_flag=""

  if ([ "$mode" = "server" ] || [ "$mode" = "both" ]) && [ "$freq" -gt 0 ]; then
    server_hop_flag="--server_hopping=true"
    migrate_flag="--migrate_every_n_ms=$freq"
    if [ "$pathval_mode" = "skip" ]; then
      skip_cwnd_flag="--skip_cwnd_reset=true --skip_path_validation=true"
    fi
  fi
  if ([ "$mode" = "client" ] || [ "$mode" = "both" ]) && [ "$freq" -gt 0 ]; then
    client_hop_flag="--client_hopping=true"
    migrate_flag="--migrate_every_n_ms=$freq"
    if [ "$pathval_mode" = "skip" ]; then
      skip_cwnd_flag="--skip_cwnd_reset=true --skip_path_validation=true"
    fi
  fi

  local tag="${pathval_mode}_freq_${freq}_run${run}"

  docker run --rm \
    --name quix-client \
    --network quix-outer \
    --ip6 fd00::3:1 \
    --privileged \
    -v "$output_dir:/output" \
    quix-experiment \
    bash -c "
tc qdisc add dev eth0 root handle 1: tbf rate ${OUTER_BW} burst 64kb latency 50ms
tc qdisc add dev eth0 parent 1:1 handle 10: netem delay ${outer_delay}ms

# Add client hop addresses if needed
if [ '$client_hop_flag' = '--client_hopping=true' ]; then
  for i in \$(seq 0 255); do
    ip -6 addr add fd00::3:\$(printf '%x' \$i)/128 dev eth0 nodad 2>/dev/null
  done
fi

# Start tcpdump
tcpdump -i eth0 -w /output/${tag}.pcap 'udp and port 4433' 2>/dev/null &
TCPDUMP_PID=\$!
sleep 1

# Start masque_client in TUN mode (background)
masque_client --disable_certificate_verification \
  --masque_mode=connect-ip \
  --bring_up_tun=true \
  $server_hop_flag \
  $client_hop_flag \
  $skip_cwnd_flag \
  $migrate_flag \
  -v=${CLIENT_VERBOSITY} \
  '[fd00::2]:4433' 2>/output/${tag}.log &
MASQUE_PID=\$!

# Wait for TUN to come up
for i in \$(seq 1 30); do
  if ip link show tun0 2>/dev/null | grep -q UP; then break; fi
  sleep 0.5
done
sleep 1

# Add route for origin through TUN
ip route add 10.0.0.0/24 dev tun0

# Download via curl through TUN
START_NS=\$(date +%s%N)
curl -s -o /tmp/download --max-time 600 http://10.0.0.2:8080/largefile
CURL_EC=\$?
END_NS=\$(date +%s%N)

DURATION_MS=\$(( (END_NS - START_NS) / 1000000 ))

# Verify hash
HASH=\$(md5sum /tmp/download 2>/dev/null | cut -d' ' -f1)
if [ \"\$HASH\" = \"$expected_hash\" ] && [ \"\$CURL_EC\" = \"0\" ]; then
  EC=0
  VERIFIED=\"true\"
else
  EC=1
  VERIFIED=\"false\"
fi

echo \"{\\\"freq\\\": $freq, \\\"run\\\": $run, \\\"pathval\\\": \\\"$pathval_mode\\\", \\\"duration_ms\\\": \$DURATION_MS, \\\"exit_code\\\": \$EC, \\\"hash_verified\\\": \$VERIFIED, \\\"curl_exit\\\": \$CURL_EC, \\\"hash\\\": \\\"\$HASH\\\"}\" > /output/${tag}.json

kill \$TCPDUMP_PID 2>/dev/null
kill \$MASQUE_PID 2>/dev/null
wait \$TCPDUMP_PID 2>/dev/null || true
wait \$MASQUE_PID 2>/dev/null || true
sleep 1
" 2>&1

  # Grab SSLKEYLOG and server log from proxy
  docker cp quix-proxy:/tmp/sslkeylogfile.txt "$output_dir/${tag}.keys" 2>/dev/null || true
  docker cp quix-proxy:/tmp/server.log "$output_dir/${tag}.server.log" 2>/dev/null || true
  # Reset for next run
  docker exec quix-proxy bash -c "rm -f /tmp/sslkeylogfile.txt /tmp/server.log" 2>/dev/null || true

  # Embed SSL keys into pcapng and remove raw pcap
  if [ -f "$output_dir/${tag}.pcap" ]; then
    if [ -f "$output_dir/${tag}.keys" ] && command -v editcap >/dev/null 2>&1; then
      editcap --inject-secrets "tls,$output_dir/${tag}.keys" \
        "$output_dir/${tag}.pcap" "$output_dir/${tag}.pcapng" 2>/dev/null && \
        rm -f "$output_dir/${tag}.pcap" "$output_dir/${tag}.keys" && \
        echo "    → ${tag}.pcapng (with embedded TLS keys)"
    else
      # No keys or no editcap — just convert to pcapng without keys
      if command -v editcap >/dev/null 2>&1; then
        editcap "$output_dir/${tag}.pcap" "$output_dir/${tag}.pcapng" 2>/dev/null && \
          rm -f "$output_dir/${tag}.pcap"
      fi
    fi
  fi

  # Enrich JSON with pcap analysis (migrations, sub-connections, IPs)
  local pcap_file="$output_dir/${tag}.pcapng"
  [ ! -f "$pcap_file" ] && pcap_file="$output_dir/${tag}.pcap"
  if [ -f "$pcap_file" ]; then
    python3 "$SCRIPT_DIR/analyze_pcap.py" "$pcap_file" "$output_dir/${tag}.json" 2>/dev/null
  fi

  # Print result
  local json_file="$output_dir/${tag}.json"
  if [ -f "$json_file" ]; then
    echo "    $(cat "$json_file")"
  fi
}

run_experiment_pass() {
  local mode=$1
  local label=$2
  local outer_rtt=$3
  local output_dir=$4
  local pathval_mode=$5

  echo "╔════════════════════════════════════════════╗"
  echo "║  $label"
  echo "╚════════════════════════════════════════════╝"
  echo ""

  cleanup 2>/dev/null

  echo "[*] Creating networks (outer: fd00::/64, inner: 10.0.0.0/24)..."
  create_networks
  echo ""

  echo "[*] Starting origin server (10.0.0.2:8080, ${FILE_SIZE_MB}MB file, Python HTTP)..."
  start_origin
  sleep 3
  local expected_hash=$(get_origin_hash)
  echo "    Origin ready. MD5: $expected_hash"
  echo ""

  for freq in "${FREQUENCIES[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "$freq" -eq 0 ]; then
      echo "  [$mode|$pathval_mode] NO MIGRATION (baseline) × ${NUM_RUNS} runs"
    else
      echo "  [$mode|$pathval_mode] Every ${freq}ms × ${NUM_RUNS} runs"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    for run in $(seq 1 $NUM_RUNS); do
      echo "  Run $run/$NUM_RUNS:"
      echo "    Starting proxy (interval=${freq}ms, mode=$mode, pathval=$pathval_mode, rtt=${outer_rtt}ms)..."
      start_proxy "$freq" "$mode" "$outer_rtt"
      wait_for_proxy
      echo "    Downloading ${FILE_SIZE_MB}MB via TUN+curl..."
      run_download "$freq" "$run" "$output_dir" "$outer_rtt" "$mode" "$expected_hash" "$pathval_mode"
      docker rm -f quix-proxy 2>/dev/null || true
      sleep 2
    done
    echo ""
  done

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $label complete"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""

  cleanup 2>/dev/null
  sleep 2
}

if [ "$PLOT_ONLY" = false ]; then
  echo "============================================"
  echo "  QUIX Ablation Study (TUN + curl)"
  echo "  File size: ${FILE_SIZE_MB}MB"
  echo "  Frequencies: ${FREQUENCIES[*]}"
  echo "  Runs per config: ${NUM_RUNS}"
  echo "  Outer RTTs: ${OUTER_RTTS[*]} ms"
  echo "  Inner RTT: ${INNER_RTT}ms"
  echo "  Outer BW cap: ${OUTER_BW}"
  echo "  Path validation: ${PATH_VALIDATION_MODES[*]}"
  echo "  Verbosity: server=v${SERVER_VERBOSITY}, client=v${CLIENT_VERBOSITY}"
  echo ""
  echo "  Architecture:"
  echo "    Client ──[TUN]──[IPv6]──> Proxy ──[IPv4]──> Origin"
  echo "    curl→tun0  fd00::3:1      fd00::2/10.0.0.3   10.0.0.2:8080"
  echo ""
  echo "  File integrity verified via MD5 hash"
  echo "  SSL keys captured (.keys) for pcap decryption"
  echo "============================================"
  echo ""

  for rtt in "${OUTER_RTTS[@]}"; do
    echo ""
    echo "████████████████████████████████████████████████████████████████"
    echo "██  OUTER RTT = ${rtt}ms  (inner RTT = ${INNER_RTT}ms)"
    echo "████████████████████████████████████████████████████████████████"
    echo ""

    for pathval in "${PATH_VALIDATION_MODES[@]}"; do
      echo ""
      echo "┌────────────────────────────────────────────────────────────┐"
      echo "│  Path Validation: $pathval"
      echo "└────────────────────────────────────────────────────────────┘"
      echo ""

      OUTPUT_DIR_SERVER="$SCRIPT_DIR/output/rtt${rtt}/${pathval}/ablation_server"
      OUTPUT_DIR_CLIENT="$SCRIPT_DIR/output/rtt${rtt}/${pathval}/ablation_client"
      OUTPUT_DIR_BOTH="$SCRIPT_DIR/output/rtt${rtt}/${pathval}/ablation_both"
      mkdir -p "$OUTPUT_DIR_SERVER" "$OUTPUT_DIR_CLIENT" "$OUTPUT_DIR_BOTH"

      run_experiment_pass "server" "Server-Side SPA (RTT=${rtt}ms, pathval=$pathval)" "$rtt" "$OUTPUT_DIR_SERVER" "$pathval"
      run_experiment_pass "client" "Client-Side Hop (RTT=${rtt}ms, pathval=$pathval)" "$rtt" "$OUTPUT_DIR_CLIENT" "$pathval"
      run_experiment_pass "both"   "Both (RTT=${rtt}ms, pathval=$pathval)            " "$rtt" "$OUTPUT_DIR_BOTH" "$pathval"
    done
  done
fi

echo "[*] Generating plots..."
echo ""

OUTPUT_DIR="$SCRIPT_DIR/output"
docker run --rm \
  -v "$OUTPUT_DIR:/data" \
  -v "$SCRIPT_DIR/plot_ablation.py:/plot_ablation.py:ro" \
  python:3.10-slim \
  bash -c 'pip install -q matplotlib numpy 2>/dev/null && python3 /plot_ablation.py /data'

echo ""
echo "Done."
echo ""
echo "  Artifacts in: experiment/output/"
echo "    Per-RTT per-pathval per-mode throughput plots"
echo "    Combined normalized and absolute throughput plots"
echo "    SSL key files (.keys) for pcap decryption"
echo ""
