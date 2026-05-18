#!/bin/bash
set -e

# QUIX Final Ablation Study on AWS
# All modes with client hopping prefix fix
# 5 runs per config, full pcapng with TLS keys on VPS

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SSH_KEY="$HOME/.ssh/aws-quix"

CLIENT_IP="13.56.226.30"
PROXY_IP="3.88.159.86"
SERVER_IP="54.226.82.155"
PROXY_IPV6="2600:1f18:6da3:7600:a6dc:abdb:b83a:625c"
PROXY_PREFIX="2600:1f18:6da3:7600:8bc4"
CLIENT_PREFIX="2600:1f1c:2d:e700:12f2"
PROXY_PREFIX_LEN=80

OUTPUT_DIR="$SCRIPT_DIR/output-aws"
NUM_RUNS=5
FREQUENCIES=(0 10 25 50 100 500 1000)
EXPECTED_HASH="5b31448712872eb4d26d275f20c66e10"

ssh_cmd() {
  local host=$1; shift
  ssh -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oConnectTimeout=10 -q -i "$SSH_KEY" ubuntu@"$host" "$@"
}

scp_cmd() {
  scp -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oConnectTimeout=10 -q -i "$SSH_KEY" "$@"
}

setup_proxy() {
  local freq=$1
  local mode=$2
  local spa_flag="--server_ipv6_hopping=false"

  if ([ "$mode" = "server" ] || [ "$mode" = "both" ]) && [ "$freq" -gt 0 ]; then
    spa_flag="--server_ipv6_hopping=true --send_spa_frames_every_n_ms=$freq"
  fi

  ssh_cmd "$PROXY_IP" bash -s << PROXY_EOF
sudo pkill masque_server 2>/dev/null; sleep 1
sudo rm -f /home/ubuntu/sslkeylogfile.txt
sudo sysctl -qw net.ipv4.ip_forward=1
sudo sysctl -qw net.ipv6.conf.all.forwarding=1
sudo iptables -t nat -C POSTROUTING -o ens5 -j MASQUERADE >/dev/null 2>&1 || sudo iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE
sudo ip -6 route add local ${PROXY_PREFIX}::/80 dev lo 2>/dev/null || true
sudo sysctl -qw net.ipv6.ip_nonlocal_bind=1
sudo bash -c 'nohup /home/ubuntu/masque_server \
  --certificate_file=/home/ubuntu/certs/cert.pem \
  --key_file=/home/ubuntu/certs/key.pem \
  --port=4433 \
  --preferred_addr=${PROXY_PREFIX}::0 \
  --preferred_addr_prefix=${PROXY_PREFIX_LEN} \
  $spa_flag \
  --stderrthreshold=3 -v=0 </dev/null >/home/ubuntu/server.log 2>&1 &'
sleep 2
ss -ulnp | grep -q 4433 && echo "OK" || echo "FAIL"
PROXY_EOF
}

run_download() {
  local mode=$1
  local freq=$2
  local run=$3
  local tag="${mode}_freq_${freq}_run${run}"

  local server_hop="--server_hopping=false"
  local client_hop="--client_hopping=false"
  local migrate_flag=""
  local prefix_flag=""

  if ([ "$mode" = "server" ] || [ "$mode" = "both" ]) && [ "$freq" -gt 0 ]; then
    server_hop="--server_hopping=true"
    migrate_flag="--migrate_every_n_ms=$freq"
  fi
  if ([ "$mode" = "client" ] || [ "$mode" = "both" ]) && [ "$freq" -gt 0 ]; then
    client_hop="--client_hopping=true"
    migrate_flag="--migrate_every_n_ms=$freq"
    prefix_flag="--client_hopping_prefix=${CLIENT_PREFIX}:: --client_hopping_prefix_len=80"
  fi

  local result
  result=$(ssh_cmd "$CLIENT_IP" bash -s << CLIENT_EOF
sudo pkill masque_client 2>/dev/null; sudo pkill tcpdump 2>/dev/null; sleep 1
mkdir -p /home/ubuntu/pcaps

sudo tcpdump -i ens5 -w /home/ubuntu/pcaps/${tag}.pcap udp port 4433 >/dev/null 2>&1 &
TCPDUMP_PID=\$!
sleep 1

sudo bash -c '/home/ubuntu/masque_client \
  --disable_certificate_verification \
  --masque_mode=connect-ip \
  --bring_up_tun=true \
  $server_hop \
  $client_hop \
  $migrate_flag \
  $prefix_flag \
  --stderrthreshold=3 -v=0 \
  "[$PROXY_IPV6]:4433" >/tmp/masque.log 2>&1 &'

for i in \$(seq 1 30); do
  if ip link show tun0 2>/dev/null | grep -q UP; then break; fi
  sleep 0.5
done

if ! ip link show tun0 2>/dev/null | grep -q UP; then
  sudo kill \$TCPDUMP_PID 2>/dev/null
  echo '{"freq": $freq, "run": $run, "mode": "$mode", "duration_ms": 0, "exit_code": 1, "hash_verified": false, "error": "tun_timeout"}'
  sudo pkill masque_client 2>/dev/null
  exit 0
fi

sudo ip route add $SERVER_IP/32 dev tun0 2>/dev/null || true

START=\$(date +%s%N)
curl -s -o /tmp/download --max-time 600 http://$SERVER_IP:8080/largefile
CURL_EC=\$?
END=\$(date +%s%N)

sudo kill \$TCPDUMP_PID 2>/dev/null; sleep 1

DURATION_MS=\$(( (END - START) / 1000000 ))
HASH=\$(md5sum /tmp/download 2>/dev/null | cut -d' ' -f1)

if [ "\$HASH" = "$EXPECTED_HASH" ] && [ "\$CURL_EC" = "0" ]; then
  VERIFIED="true"
else
  VERIFIED="false"
fi

echo "{\"freq\": $freq, \"run\": $run, \"mode\": \"$mode\", \"duration_ms\": \$DURATION_MS, \"exit_code\": \$CURL_EC, \"hash_verified\": \$VERIFIED, \"hash\": \"\$HASH\"}"

sudo ip route del $SERVER_IP/32 dev tun0 2>/dev/null || true
sudo pkill masque_client 2>/dev/null || true
rm -f /tmp/download
CLIENT_EOF
  )

  echo "$result" > "$OUTPUT_DIR/validate_freq_${freq}_run${run}.json"
  echo "    $result"

  # Embed TLS keys into pcap on client VPS
  ssh_cmd "$PROXY_IP" "sudo chmod 644 /home/ubuntu/sslkeylogfile.txt 2>/dev/null"
  scp_cmd ubuntu@"$PROXY_IP":/home/ubuntu/sslkeylogfile.txt /tmp/keylog_${tag}.tmp 2>/dev/null || true
  if [ -f "/tmp/keylog_${tag}.tmp" ]; then
    scp_cmd /tmp/keylog_${tag}.tmp ubuntu@"$CLIENT_IP":/home/ubuntu/pcaps/${tag}_keys.log 2>/dev/null
    rm -f /tmp/keylog_${tag}.tmp
    ssh_cmd "$CLIENT_IP" bash -s << EMBED_EOF
if [ -f /home/ubuntu/pcaps/${tag}.pcap ] && [ -f /home/ubuntu/pcaps/${tag}_keys.log ]; then
  editcap --inject-secrets tls,/home/ubuntu/pcaps/${tag}_keys.log /home/ubuntu/pcaps/${tag}.pcap /home/ubuntu/pcaps/${tag}.pcapng 2>/dev/null
  if [ -f /home/ubuntu/pcaps/${tag}.pcapng ]; then
    rm -f /home/ubuntu/pcaps/${tag}.pcap /home/ubuntu/pcaps/${tag}_keys.log
  fi
fi
EMBED_EOF
  fi
}

echo "============================================"
echo "  QUIX Final AWS Ablation Study"
echo "  Frequencies: ${FREQUENCIES[*]} ms"
echo "  Runs per config: ${NUM_RUNS}"
echo "  Client: $CLIENT_IP (us-west-1)"
echo "  Proxy:  $PROXY_IP (us-east-1)"
echo "  Server: $SERVER_IP (us-east-1)"
echo "  RTT: ~58ms (real cross-region)"
echo "  Bandwidth: uncapped"
echo "  Client hopping prefix: ${CLIENT_PREFIX}::/80"
echo "  Server hopping prefix: ${PROXY_PREFIX}::/80"
echo "  Pcaps: /home/ubuntu/pcaps/ on client VPS"
echo "============================================"
echo ""

ssh_cmd "$CLIENT_IP" "mkdir -p /home/ubuntu/pcaps"

# Ensure AnyIP is set up on client
ssh_cmd "$CLIENT_IP" "sudo ip -6 route add local ${CLIENT_PREFIX}::/80 dev lo 2>/dev/null || true; sudo sysctl -qw net.ipv6.ip_nonlocal_bind=1"

for mode in server client both; do
  MODE_DIR="$OUTPUT_DIR/rtt58/validate/ablation_${mode}"
  mkdir -p "$MODE_DIR"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Mode: $mode"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  for freq in "${FREQUENCIES[@]}"; do
    echo ""
    if [ "$freq" -eq 0 ]; then
      echo "  [$mode] NO MIGRATION (baseline) × ${NUM_RUNS} runs"
    else
      echo "  [$mode] Every ${freq}ms × ${NUM_RUNS} runs"
    fi

    for run in $(seq 1 $NUM_RUNS); do
      echo "  Run $run/$NUM_RUNS:"

      proxy_status=$(setup_proxy "$freq" "$mode")
      if [ "$proxy_status" != "OK" ]; then
        echo "    ERROR: Proxy failed to start"
        continue
      fi

      OUTPUT_DIR="$MODE_DIR"
      run_download "$mode" "$freq" "$run"
      OUTPUT_DIR="$SCRIPT_DIR/output-aws"

      sleep 2
    done
  done
done

echo ""
echo "Done. JSON results in: $OUTPUT_DIR/rtt58/validate/"
echo "Pcaps on client VPS: /home/ubuntu/pcaps/"
