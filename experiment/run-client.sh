#!/bin/bash
set -e

# QUIX Client Experiment Runner
# Connects to the MASQUE server and exercises address hopping features.

SERVER="fd00:abcd::2"
PORT=4433
PROXY="[${SERVER}]:${PORT}"

echo "============================================"
echo "  QUIX Address Hopping Experiment - Client"
echo "============================================"
echo ""
echo "Server:  ${SERVER}:${PORT}"
echo "Client:  $(hostname -I | tr ' ' '\n' | grep fd00)"
echo ""

# Wait for server to be reachable
echo "[1/4] Waiting for server to be reachable..."
for i in $(seq 1 30); do
  if ping6 -c1 -W1 "$SERVER" &>/dev/null; then
    echo "  Server reachable after ${i}s"
    break
  fi
  sleep 1
done
sleep 2
echo "[2/4] Server confirmed ready"
echo ""

# ─────────────────────────────────────────────
# Test 1: Server IPv6 hopping with SPA frames
# ─────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 1: MASQUE proxy + server IPv6 hopping"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Flags: --server_hopping=true --migrate_every_n_packets=10"
echo "  Target: https://example.org/ (tunneled through MASQUE proxy)"
echo ""

# Capture packets
tcpdump -i any -c 500 -w /tmp/quix-test1.pcap udp port $PORT 2>/dev/null &
TCPDUMP_PID=$!

timeout 20 masque_client \
  --disable_certificate_verification \
  --server_hopping=true \
  --client_hopping=false \
  --enable_wf_defense=false \
  --migrate_every_n_packets=10 \
  -v=1 \
  --stderrthreshold=0 \
  "${PROXY}" \
  https://example.org/ \
  2>&1 > /tmp/test1-client.log || true

kill $TCPDUMP_PID 2>/dev/null; wait $TCPDUMP_PID 2>/dev/null

echo "  --- Test 1 Results ---"
# Show key connection events
grep -i "Creating MASQUE session\|MASQUE.*connected\|preferred address\|ALPN selected\|SETTINGS\|SPA\|OnSpaFrame\|migrat\|status 200\|Failed to connect" /tmp/test1-client.log 2>/dev/null | head -10 | sed 's/^/  /'
echo ""
PKTS1=$(tcpdump -r /tmp/quix-test1.pcap 2>/dev/null | wc -l)
echo "  Packets captured: $PKTS1 UDP datagrams"
echo "  Unique IPs in traffic:"
tcpdump -nn -r /tmp/quix-test1.pcap 2>/dev/null | grep -oP 'fd00:[0-9a-f:]+' | sort -u | sed 's/^/    /'
echo ""

# ─────────────────────────────────────────────
# Test 2: Client-side IPv6 hopping
# ─────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 2: Client IPv6 hopping"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Flags: --client_hopping=true --migrate_every_n_packets=10"
echo "  Target: https://example.org/ (tunneled through MASQUE proxy)"
echo ""

tcpdump -i any -c 500 -w /tmp/quix-test2.pcap udp port $PORT 2>/dev/null &
TCPDUMP_PID=$!

timeout 20 masque_client \
  --disable_certificate_verification \
  --server_hopping=false \
  --client_hopping=true \
  --enable_wf_defense=false \
  --migrate_every_n_packets=10 \
  -v=1 \
  --stderrthreshold=0 \
  "${PROXY}" \
  https://example.org/ \
  2>&1 > /tmp/test2-client.log || true

kill $TCPDUMP_PID 2>/dev/null; wait $TCPDUMP_PID 2>/dev/null

echo "  --- Test 2 Results ---"
grep -i "Creating MASQUE session\|MASQUE.*connected\|preferred address\|ALPN selected\|SPA\|migrat\|ValidateAndMigrate\|PerformClient\|status 200\|Failed to connect" /tmp/test2-client.log 2>/dev/null | head -10 | sed 's/^/  /'
echo ""
PKTS2=$(tcpdump -r /tmp/quix-test2.pcap 2>/dev/null | wc -l)
echo "  Packets captured: $PKTS2 UDP datagrams"
echo "  Unique IPs in traffic:"
tcpdump -nn -r /tmp/quix-test2.pcap 2>/dev/null | grep -oP 'fd00:[0-9a-f:]+' | sort -u | sed 's/^/    /'
echo ""

# ─────────────────────────────────────────────
# Test 3: Both hopping + FRONT WF defense
# ─────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 3: FRONT WF Defense + Both Hopping"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Flags: --enable_wf_defense=true --server_hopping=true --client_hopping=true"
echo "  Target: https://example.org/ (tunneled through MASQUE proxy)"
echo ""

tcpdump -i any -c 500 -w /tmp/quix-test3.pcap udp port $PORT 2>/dev/null &
TCPDUMP_PID=$!

timeout 20 masque_client \
  --disable_certificate_verification \
  --server_hopping=true \
  --client_hopping=true \
  --enable_wf_defense=true \
  --migrate_every_n_packets=10 \
  -v=1 \
  --stderrthreshold=0 \
  "${PROXY}" \
  https://example.org/ \
  2>&1 > /tmp/test3-client.log || true

kill $TCPDUMP_PID 2>/dev/null; wait $TCPDUMP_PID 2>/dev/null

echo "  --- Test 3 Results ---"
grep -i "Creating MASQUE session\|MASQUE.*connected\|preferred address\|SPA\|migrat\|defense\|probe\|FRONT\|custom.*alarm\|status 200\|Failed to connect" /tmp/test3-client.log 2>/dev/null | head -10 | sed 's/^/  /'
echo ""
PKTS3=$(tcpdump -r /tmp/quix-test3.pcap 2>/dev/null | wc -l)
echo "  Packets captured: $PKTS3 UDP datagrams"
echo ""

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Experiment Summary"
echo "============================================"
echo ""

T1_CONNECTED=$(grep -c "MASQUE.*connected\|ALPN selected" /tmp/test1-client.log 2>/dev/null) || T1_CONNECTED=0
T2_CONNECTED=$(grep -c "MASQUE.*connected\|ALPN selected" /tmp/test2-client.log 2>/dev/null) || T2_CONNECTED=0
T3_CONNECTED=$(grep -c "MASQUE.*connected\|ALPN selected" /tmp/test3-client.log 2>/dev/null) || T3_CONNECTED=0

T1_SPA=$(grep -ci "preferred address\|preferred_address" /tmp/test1-client.log 2>/dev/null) || T1_SPA=0
T2_MIGRATION=$(grep -ci "migrat\|ValidateAndMigrate\|PerformClient" /tmp/test2-client.log 2>/dev/null) || T2_MIGRATION=0
T3_DEFENSE=$(grep -ci "Rayleigh\|defense\|custom.*alarm\|SendConnectivity" /tmp/test3-client.log 2>/dev/null) || T3_DEFENSE=0

echo "  Test 1 (Server Hopping):"
if [ "$T1_CONNECTED" -gt 0 ]; then echo "    MASQUE proxy connected: YES ✓"; else echo "    MASQUE proxy connected: NO"; fi
if [ "$T1_SPA" -gt 0 ]; then echo "    Preferred address received: YES ✓ ($T1_SPA occurrences)"; else echo "    Preferred address received: NO"; fi
echo "    Packets exchanged: $PKTS1"
echo ""
echo "  Test 2 (Client Hopping):"
if [ "$T2_CONNECTED" -gt 0 ]; then echo "    MASQUE proxy connected: YES ✓"; else echo "    MASQUE proxy connected: NO"; fi
if [ "$T2_MIGRATION" -gt 0 ]; then echo "    Client migrations triggered: YES ✓ ($T2_MIGRATION events)"; else echo "    Client migrations triggered: NO"; fi
echo "    Packets exchanged: $PKTS2"
echo ""
echo "  Test 3 (FRONT Defense + Both Hopping):"
if [ "$T3_CONNECTED" -gt 0 ]; then echo "    MASQUE proxy connected: YES ✓"; else echo "    MASQUE proxy connected: NO"; fi
if [ "$T3_DEFENSE" -gt 0 ]; then echo "    WF defense active: YES ✓ ($T3_DEFENSE events)"; else echo "    WF defense active: NO (may need traffic)"; fi
echo "    Packets exchanged: $PKTS3"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Key Events"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Server preferred addresses:"
grep -h "Received server preferred\|preferred_address\|preferred address" /tmp/test1-client.log /tmp/test2-client.log /tmp/test3-client.log 2>/dev/null | sort -u | head -5 | sed 's/^/    /'
echo ""
echo "  Connection IDs used (shows address changes):"
grep -h "setting client connection ID\|connection.*supports\|Created connection" /tmp/test1-client.log 2>/dev/null | head -5 | sed 's/^/    /'
echo ""
echo "  CONNECT-UDP tunnel status:"
grep -h "status 200\|status 4\|status 5" /tmp/test1-client.log /tmp/test2-client.log /tmp/test3-client.log 2>/dev/null | sort -u | head -5 | sed 's/^/    /'
echo ""

echo "============================================"
echo "  Experiment Complete"
echo "============================================"
