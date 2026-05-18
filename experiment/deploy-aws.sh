#!/bin/bash
set -e

# Deploy QUIX experiment to AWS instances
# Reads instance details from ./final_instances
# Builds binaries on proxy (native x86_64), then distributes to all nodes

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SSH_KEY="$HOME/.ssh/aws-quix"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -q"

# Parse final_instances
CLIENT_IP=""
PROXY_IP=""
SERVER_IP=""
CLIENT_IPV6=""
PROXY_IPV6=""
SERVER_IPV6=""
CLIENT_PREFIX=""
PROXY_PREFIX=""
SERVER_PREFIX=""

while read -r region id ip ipv6 prefix name; do
  case "$name" in
    quix-client-final) CLIENT_IP="$ip"; CLIENT_IPV6="$ipv6"; CLIENT_PREFIX="$prefix" ;;
    quix-proxy-final)  PROXY_IP="$ip";  PROXY_IPV6="$ipv6";  PROXY_PREFIX="$prefix" ;;
    quix-server-final) SERVER_IP="$ip";  SERVER_IPV6="$ipv6";  SERVER_PREFIX="$prefix" ;;
  esac
done < "$SCRIPT_DIR/final_instances"

echo "=== QUIX AWS Deployment ==="
echo "  Client: $CLIENT_IP ($CLIENT_IPV6, prefix $CLIENT_PREFIX)"
echo "  Proxy:  $PROXY_IP ($PROXY_IPV6, prefix $PROXY_PREFIX)"
echo "  Server: $SERVER_IP ($SERVER_IPV6, prefix $SERVER_PREFIX)"
echo ""

ssh_cmd() {
  local host=$1
  shift
  ssh $SSH_OPTS -i "$SSH_KEY" ubuntu@"$host" "$@"
}

scp_to() {
  local host=$1
  local src=$2
  local dst=$3
  scp $SSH_OPTS -i "$SSH_KEY" "$src" ubuntu@"$host":"$dst"
}

# --- Step 1: Upload source to proxy and build ---
echo "[1/5] Uploading source to proxy for native build..."

# Create tarball of the source (excluding bazel cache, .git)
TARBALL="/tmp/quiche-src.tar.gz"
cd "$REPO_ROOT"
tar czf "$TARBALL" \
  --exclude='.git' \
  --exclude='bazel-*' \
  --exclude='experiment/output' \
  --exclude='*.pcap' \
  --exclude='*.pcapng' \
  .

scp_to "$PROXY_IP" "$TARBALL" "/tmp/quiche-src.tar.gz"
rm -f "$TARBALL"

echo "[2/5] Building binaries on proxy (this takes ~10-15 min first time)..."

ssh_cmd "$PROXY_IP" bash -s << 'BUILD_SCRIPT'
set -e

# Install build dependencies
if ! command -v bazel &>/dev/null; then
  echo "Installing build dependencies..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq clang lld curl git python3 zip unzip openjdk-21-jdk >/dev/null 2>&1

  # Install Bazel
  curl -fLo /tmp/bazel "https://github.com/bazelbuild/bazel/releases/download/8.2.1/bazel-8.2.1-linux-x86_64"
  sudo mv /tmp/bazel /usr/local/bin/bazel
  sudo chmod +x /usr/local/bin/bazel
  echo "Build tools installed."
fi

# Extract source
rm -rf /home/ubuntu/quiche
mkdir -p /home/ubuntu/quiche
cd /home/ubuntu/quiche
tar xzf /tmp/quiche-src.tar.gz
rm -f /tmp/quiche-src.tar.gz

# Build
export CC=clang
export CXX=clang++
echo "Building masque_server and masque_client..."
bazel build //quiche:masque_server //quiche:masque_client --noshow_progress 2>&1 | tail -5

# Copy binaries to known location
cp bazel-bin/quiche/masque_server /home/ubuntu/masque_server
cp bazel-bin/quiche/masque_client /home/ubuntu/masque_client
chmod +x /home/ubuntu/masque_server /home/ubuntu/masque_client
echo "Build complete."
BUILD_SCRIPT

echo "[3/5] Distributing binaries to client and server..."

# Copy binaries from proxy to local /tmp, then to other instances
scp $SSH_OPTS -i "$SSH_KEY" ubuntu@"$PROXY_IP":/home/ubuntu/masque_server /tmp/masque_server_x86
scp $SSH_OPTS -i "$SSH_KEY" ubuntu@"$PROXY_IP":/home/ubuntu/masque_client /tmp/masque_client_x86

scp_to "$CLIENT_IP" /tmp/masque_client_x86 "/home/ubuntu/masque_client"
scp_to "$SERVER_IP" /tmp/masque_server_x86 "/home/ubuntu/masque_server"

ssh_cmd "$CLIENT_IP" "chmod +x /home/ubuntu/masque_client"
ssh_cmd "$SERVER_IP" "chmod +x /home/ubuntu/masque_server"

rm -f /tmp/masque_server_x86 /tmp/masque_client_x86

echo "[4/5] Generating TLS certificates and setting up nodes..."

# Generate self-signed cert on proxy
ssh_cmd "$PROXY_IP" bash -s << 'CERT_SCRIPT'
mkdir -p /home/ubuntu/certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /home/ubuntu/certs/key.pem -out /home/ubuntu/certs/cert.pem \
  -days 365 -nodes -subj "/CN=quix-proxy" 2>/dev/null
echo "Certificates generated."
CERT_SCRIPT

# Setup origin server
ssh_cmd "$SERVER_IP" bash -s << 'ORIGIN_SCRIPT'
set -e
sudo apt-get update -qq
sudo apt-get install -y -qq python3 >/dev/null 2>&1
mkdir -p /home/ubuntu/srv
dd if=/dev/urandom of=/home/ubuntu/srv/largefile bs=1M count=100 2>/dev/null
md5sum /home/ubuntu/srv/largefile | cut -d' ' -f1 > /home/ubuntu/srv/largefile.md5
echo "Origin file ready: 100MB, MD5=$(cat /home/ubuntu/srv/largefile.md5)"
ORIGIN_SCRIPT

# Setup client dependencies
ssh_cmd "$CLIENT_IP" bash -s << 'CLIENT_SETUP'
set -e
sudo apt-get update -qq
sudo apt-get install -y -qq curl tcpdump iproute2 >/dev/null 2>&1
echo "Client dependencies installed."
CLIENT_SETUP

echo "[5/5] Writing run script..."

# Create the ablation run script for AWS
cat > "$SCRIPT_DIR/run-ablation-aws.sh" << RUNEOF
#!/bin/bash
set -e

# QUIX Ablation Study on AWS
# Client (us-west-1) -> Proxy (us-east-1) -> Origin (us-east-1)

SSH_KEY="$SSH_KEY"
SSH_OPTS="$SSH_OPTS"
CLIENT_IP="$CLIENT_IP"
PROXY_IP="$PROXY_IP"
SERVER_IP="$SERVER_IP"
CLIENT_IPV6="$CLIENT_IPV6"
PROXY_IPV6="$PROXY_IPV6"
SERVER_IPV6="$SERVER_IPV6"
CLIENT_PREFIX="$CLIENT_PREFIX"
PROXY_PREFIX="$PROXY_PREFIX"
SERVER_PREFIX="$SERVER_PREFIX"

SCRIPT_DIR="$SCRIPT_DIR"
OUTPUT_DIR="\$SCRIPT_DIR/output-aws"
NUM_RUNS=3
FREQUENCIES=(0 100 250 500 1000 2000 5000)

# Derive prefix base for hopping (strip the ::/80 suffix)
PROXY_PREFIX_BASE="\${PROXY_PREFIX%::/80}"
CLIENT_PREFIX_BASE="\${CLIENT_PREFIX%::/80}"

# Proxy prefix length
PROXY_PREFIX_LEN=80

ssh_cmd() {
  local host=\$1; shift
  ssh \$SSH_OPTS -i "\$SSH_KEY" ubuntu@"\$host" "\$@"
}

mkdir -p "\$OUTPUT_DIR"

echo "============================================"
echo "  QUIX AWS Ablation Study"
echo "  Frequencies: \${FREQUENCIES[*]} ms"
echo "  Runs: \$NUM_RUNS"
echo "  Client: \$CLIENT_IP (\$CLIENT_IPV6)"
echo "  Proxy:  \$PROXY_IP (\$PROXY_IPV6)"
echo "  Server: \$SERVER_IP (\$SERVER_IPV6)"
echo "  Proxy prefix: \$PROXY_PREFIX"
echo "  Client prefix: \$CLIENT_PREFIX"
echo "============================================"
echo ""

# Measure real RTT
echo "[*] Measuring RTT from client to proxy..."
RTT=\$(ssh_cmd "\$CLIENT_IP" "ping6 -c 5 \$PROXY_IPV6 2>/dev/null | tail -1 | awk -F'/' '{print \\\$5}'")
echo "    Real RTT: \${RTT}ms"
echo ""

# Get origin hash
EXPECTED_HASH=\$(ssh_cmd "\$SERVER_IP" "cat /home/ubuntu/srv/largefile.md5")
echo "[*] Origin MD5: \$EXPECTED_HASH"
echo ""

# Start origin HTTP server (background, persistent)
echo "[*] Starting origin HTTP server..."
ssh_cmd "\$SERVER_IP" "pkill -f 'python3 -m http.server' 2>/dev/null; cd /home/ubuntu/srv && nohup python3 -m http.server 8080 > /dev/null 2>&1 &"
sleep 2

run_experiment() {
  local mode=\$1
  local freq=\$2
  local run=\$3
  local tag="\${mode}_freq_\${freq}_run\${run}"

  echo "  [\$mode] freq=\${freq}ms run=\$run..."

  # Determine proxy flags
  local server_spa_flag="--server_ipv6_hopping=false"
  if ([ "\$mode" = "server" ] || [ "\$mode" = "both" ]) && [ "\$freq" -gt 0 ]; then
    server_spa_flag="--server_ipv6_hopping=true --send_spa_frames_every_n_ms=\$freq"
  fi

  # Kill previous proxy
  ssh_cmd "\$PROXY_IP" "pkill -f masque_server 2>/dev/null; sleep 1" || true

  # Start proxy
  ssh_cmd "\$PROXY_IP" "nohup /home/ubuntu/masque_server \\
    --certificate_file=/home/ubuntu/certs/cert.pem \\
    --key_file=/home/ubuntu/certs/key.pem \\
    --port=4433 \\
    --preferred_addr=\$PROXY_PREFIX_BASE:0 \\
    --preferred_addr_prefix=\$PROXY_PREFIX_LEN \\
    \$server_spa_flag \\
    -v=0 > /home/ubuntu/server_\${tag}.log 2>&1 &"

  sleep 3

  # Determine client flags
  local server_hop="--server_hopping=false"
  local client_hop="--client_hopping=false"
  local migrate_flag=""

  if ([ "\$mode" = "server" ] || [ "\$mode" = "both" ]) && [ "\$freq" -gt 0 ]; then
    server_hop="--server_hopping=true"
    migrate_flag="--migrate_every_n_ms=\$freq"
  fi
  if ([ "\$mode" = "client" ] || [ "\$mode" = "both" ]) && [ "\$freq" -gt 0 ]; then
    client_hop="--client_hopping=true"
    migrate_flag="--migrate_every_n_ms=\$freq"
  fi

  # Run download on client
  ssh_cmd "\$CLIENT_IP" bash -s << CLIENTEOF
set -e

# Start masque_client in TUN mode
sudo /home/ubuntu/masque_client --disable_certificate_verification \\
  --masque_mode=connect-ip \\
  --bring_up_tun=true \\
  \$server_hop \\
  \$client_hop \\
  \$migrate_flag \\
  -v=0 \\
  '[\$PROXY_IPV6]:4433' > /tmp/client_\${tag}.log 2>&1 &
MASQUE_PID=\\\$!

# Wait for TUN
for i in \\\$(seq 1 30); do
  if ip link show tun0 2>/dev/null | grep -q UP; then break; fi
  sleep 0.5
done
sleep 1

# Route to origin through TUN
sudo ip route add \$SERVER_IP/32 dev tun0 2>/dev/null || true

# Download
START_NS=\\\$(date +%s%N)
curl -s -o /tmp/download --max-time 600 http://\$SERVER_IP:8080/largefile
CURL_EC=\\\$?
END_NS=\\\$(date +%s%N)

DURATION_MS=\\\$(( (END_NS - START_NS) / 1000000 ))

# Verify hash
HASH=\\\$(md5sum /tmp/download 2>/dev/null | cut -d' ' -f1)
if [ "\\\$HASH" = "\$EXPECTED_HASH" ] && [ "\\\$CURL_EC" = "0" ]; then
  EC=0; VERIFIED="true"
else
  EC=1; VERIFIED="false"
fi

echo "{\\"freq\\": \$freq, \\"run\\": \$run, \\"mode\\": \\"\$mode\\", \\"duration_ms\\": \\\$DURATION_MS, \\"exit_code\\": \\\$EC, \\"hash_verified\\": \\\$VERIFIED, \\"curl_exit\\": \\\$CURL_EC}"

# Cleanup
sudo kill \\\$MASQUE_PID 2>/dev/null || true
sudo ip route del \$SERVER_IP/32 dev tun0 2>/dev/null || true
rm -f /tmp/download
CLIENTEOF

  # Save result
  ssh_cmd "\$CLIENT_IP" "cat /tmp/client_\${tag}.log" > "\$OUTPUT_DIR/\${tag}.log" 2>/dev/null || true
}

# Run ablation for each mode
for mode in server client both; do
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Mode: \$mode"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  for freq in "\${FREQUENCIES[@]}"; do
    for run in \$(seq 1 \$NUM_RUNS); do
      run_experiment "\$mode" "\$freq" "\$run"
    done
  done
done

echo ""
echo "Done. Results in \$OUTPUT_DIR/"
RUNEOF

chmod +x "$SCRIPT_DIR/run-ablation-aws.sh"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Next steps:"
echo "  1. Run the experiment:  ./run-ablation-aws.sh"
echo "  2. Results will be in:  output-aws/"
echo ""
echo "Or SSH manually:"
echo "  ssh -i $SSH_KEY ubuntu@$CLIENT_IP"
echo "  ssh -i $SSH_KEY ubuntu@$PROXY_IP"
echo "  ssh -i $SSH_KEY ubuntu@$SERVER_IP"
