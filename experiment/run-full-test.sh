#!/bin/bash
set -e

# QUIX Full Address Hopping Verification
#
# This test verifies SPA frames and address migration by:
# 1. Assigning 256 addresses in fd00:abcd::1:0/120 to the server
# 2. Using policy routing so the server accepts packets on any of those addresses
# 3. Running multiple MASQUE connections to trigger SPA frames
# 4. Capturing packets to show multiple different IPv6 addresses in use
#
# Prerequisites: quix-experiment Docker image must be built (run run-experiment.sh first)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo "  QUIX Full Address Hopping Verification"
echo "============================================"
echo ""

# Clean up any previous run
docker compose down 2>/dev/null || true
docker stop quix-hop-server quix-hop-client 2>/dev/null || true
docker rm quix-hop-server quix-hop-client 2>/dev/null || true
docker network rm quix-hopping-net 2>/dev/null || true

# Create a Docker network with /64 subnet
echo "[1/5] Creating IPv6 network fd00:abcd::/64..."
docker network create --ipv6 --subnet fd00:abcd::/64 --gateway fd00:abcd::1 quix-hopping-net
echo ""

# Start the server container
echo "[2/5] Starting MASQUE server with /120 hopping range..."
docker run -d --rm \
  --name quix-hop-server \
  --hostname quix-hop-server \
  --network quix-hopping-net \
  --ip6 fd00:abcd::2 \
  --cap-add NET_ADMIN \
  quix-experiment \
  bash -c '
# Add 256 addresses in fd00:abcd::1:0/120 so the kernel responds to NDP
# and accepts UDP packets addressed to any of them
for i in $(seq 0 255); do
  ip -6 addr add fd00:abcd::1:$(printf "%x" $i)/128 dev eth0 nodad 2>/dev/null
done

# Policy routing: locally-generated outgoing packets use main table (unicast route)
# while incoming packets use table 200 which has a local route for the /120 range
ip -6 rule del prio 0 lookup local 2>/dev/null || true
ip -6 rule add iif lo prio 50 lookup main 2>/dev/null || true
ip -6 route add local fd00:abcd::1:0/120 dev lo table 200 2>/dev/null || true
ip -6 rule add prio 100 lookup 200 2>/dev/null || true
ip -6 rule add prio 200 lookup local 2>/dev/null || true

exec masque_server \
  --certificate_file=/certs/cert.pem \
  --key_file=/certs/key.pem \
  --port=4433 \
  --preferred_addr=fd00:abcd::1:1 \
  --server_ipv6_hopping=true \
  --send_spa_frames_every_n_packets=3 \
  --preferred_addr_prefix=120 \
  --enable_wf_defense=false \
  -v=1 \
  --stderrthreshold=0
'

# Wait for server to start
echo "   Waiting for server..."
for i in $(seq 1 15); do
  if docker exec quix-hop-server ss -uln 2>/dev/null | grep -q 4433; then
    echo "   Server ready after ${i}s"
    break
  fi
  sleep 1
done
echo "   Hopping range: fd00:abcd::1:0/120 (256 addresses)"
echo "   SPA frames: every 3 packets"
echo ""

# Run client with pcap capture
echo "[3/5] Running client with packet capture..."
echo ""

docker run --rm \
  --name quix-hop-client \
  --hostname quix-hop-client \
  --network quix-hopping-net \
  --ip6 fd00:abcd::3 \
  --cap-add NET_ADMIN \
  -v "$SCRIPT_DIR/output:/output" \
  quix-experiment \
  bash -c '
tcpdump -i eth0 -w /output/quix-hopping.pcap "udp and port 4433" 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

SERVER="[fd00:abcd::2]:4433"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Test 1: Server IPv6 Hopping (SPA frames)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Running 5 sequential MASQUE connections..."
echo ""

for i in $(seq 1 5); do
  timeout 8 masque_client \
    --disable_certificate_verification \
    --server_hopping=true \
    --client_hopping=false \
    --enable_wf_defense=false \
    --migrate_every_n_packets=3 \
    -v=1 \
    --stderrthreshold=0 \
    "${SERVER}" \
    https://example.org/ \
    2>&1 || true
done 2>&1 | tee /output/client-full.log | \
  grep -i "Received SPA frame\|preferred address.*validated\|Migrating path\|MASQUE.*connected\|:status" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Test 2: Server + Client Hopping"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Running 5 sequential connections with client hopping..."
echo ""

for i in $(seq 1 5); do
  timeout 8 masque_client \
    --disable_certificate_verification \
    --server_hopping=true \
    --client_hopping=true \
    --enable_wf_defense=false \
    --migrate_every_n_packets=3 \
    -v=1 \
    --stderrthreshold=0 \
    "${SERVER}" \
    https://example.org/ \
    2>&1 || true
done 2>&1 | tee -a /output/client-full.log | \
  grep -i "Received SPA frame\|preferred address.*validated\|Migrating path\|PerformClientMigration\|MASQUE.*connected\|:status" || true

# Stop capture
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null
sleep 1

echo ""
echo ""
echo "============================================"
echo "  Results"
echo "============================================"
echo ""

TOTAL=$(tcpdump -r /output/quix-hopping.pcap 2>/dev/null | wc -l)
echo "Total packets captured: $TOTAL"
echo ""

echo "Unique server-side IPv6 addresses (proof of SPA hopping):"
tcpdump -nn -r /output/quix-hopping.pcap 2>/dev/null | \
  grep -oP "fd00:abcd[0-9a-f:]*(?=\.4433)" | sort -u | sed "s/^/  /"
echo ""

SPA_COUNT=$(grep -c "Received SPA frame" /output/client-full.log 2>/dev/null) || SPA_COUNT=0
MIGRATION_COUNT=$(grep -c "validated.*Migrating path" /output/client-full.log 2>/dev/null) || MIGRATION_COUNT=0
echo "SPA frames received by client: $SPA_COUNT"
echo "Successful path migrations:    $MIGRATION_COUNT"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SPA Frame Events (first 15)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
grep -i "Received SPA frame\|Setting the server preferred" /output/client-full.log 2>/dev/null | head -15 | sed "s/^/  /"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Path Migrations (first 15)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
grep -i "validated.*Migrating path" /output/client-full.log 2>/dev/null | head -15 | sed "s/^/  /"
echo ""

echo "Pcap saved: experiment/output/quix-hopping.pcap"
echo "Full log:   experiment/output/client-full.log"
'

echo ""
echo "[4/5] Collecting server logs..."
docker logs quix-hop-server 2>&1 | grep -i "Writing SPA frame\|SPA_FRAME\|PATH_RESPONSE\|preferred" | head -20 > "$SCRIPT_DIR/output/server-spa.log" 2>/dev/null || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Server-Side SPA Frame Sending"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
cat "$SCRIPT_DIR/output/server-spa.log" 2>/dev/null | sed "s/^/  /"
echo ""

echo "[5/5] Cleanup..."
docker stop quix-hop-server 2>/dev/null || true
docker network rm quix-hopping-net 2>/dev/null || true

echo ""
echo "Done."
echo ""
echo "  Artifacts:"
echo "    experiment/output/quix-hopping.pcap  - Full packet capture"
echo "    experiment/output/client-full.log    - Verbose client log"
echo "    experiment/output/server-spa.log     - Server SPA frame events"
echo ""
echo "  Open in Wireshark:"
echo "    wireshark experiment/output/quix-hopping.pcap"
echo ""
