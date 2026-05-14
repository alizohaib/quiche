#!/bin/bash
set -e

# QUIX Address Hopping Experiment - Launcher
#
# Prerequisites:
#   - Docker with Docker Compose v2
#   - Docker daemon with IPv6 support enabled
#
# Usage:
#   cd experiment/
#   ./run-experiment.sh              # Build and run
#   ./run-experiment.sh --no-build   # Run without rebuilding
#   ./run-experiment.sh --shell      # Drop into client shell for manual testing

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

NO_BUILD=false
SHELL_MODE=false
for arg in "$@"; do
  case $arg in
    --no-build) NO_BUILD=true ;;
    --shell) SHELL_MODE=true ;;
    --help|-h)
      echo "Usage: $0 [--no-build] [--shell] [--help]"
      echo ""
      echo "Options:"
      echo "  --no-build  Skip Docker image build (use existing image)"
      echo "  --shell     Start server, then drop into client container shell"
      echo "  --help      Show this help"
      exit 0
      ;;
  esac
done

echo "============================================"
echo "  QUIX Address Hopping Experiment"
echo "============================================"
echo ""
echo "This experiment demonstrates:"
echo "  1. Server-side IPv6 address hopping via SPA frames"
echo "  2. Client-side IPv6 address hopping (proactive migration)"
echo "  3. FRONT Website Fingerprinting defense (padded probes)"
echo ""

# Check Docker IPv6
echo "[*] Checking Docker IPv6 support..."
if ! docker network create --ipv6 --subnet fd00:ffff::/64 quix-ipv6-check &>/dev/null; then
  echo ""
  echo "ERROR: Docker IPv6 networking is not available."
  echo ""
  echo "Docker Desktop: Settings > Docker Engine > add to JSON:"
  echo '  { "ipv6": true, "fixed-cidr-v6": "fd00::/80" }'
  echo "Then Apply & Restart."
  exit 1
fi
docker network rm quix-ipv6-check &>/dev/null
echo "  IPv6: OK"
echo ""

if [ "$NO_BUILD" = false ]; then
  # Step 1: Ensure quiche-build image exists
  if ! docker image inspect quiche-build &>/dev/null; then
    echo "[*] Building quiche-build image (compiling masque binaries, ~10min first time)..."
    cd "$REPO_ROOT"
    docker build -t quiche-build -f Dockerfile.build .
    cd "$SCRIPT_DIR"
  else
    echo "[*] quiche-build image already exists"
  fi

  # Step 2: Build base runtime image
  echo "[*] Building experiment runtime image..."
  cd "$REPO_ROOT"
  docker build -t quix-experiment-base -f experiment/Dockerfile.experiment .
  cd "$SCRIPT_DIR"

  # Step 3: Extract binaries and create final image
  echo "[*] Extracting binaries and assembling final image..."
  TEMP_DIR=$(mktemp -d)
  BUILD_CID=$(docker create quiche-build)
  docker cp "$BUILD_CID:/src/quiche/bazel-bin/quiche/masque_server" "$TEMP_DIR/masque_server"
  docker cp "$BUILD_CID:/src/quiche/bazel-bin/quiche/masque_client" "$TEMP_DIR/masque_client"
  docker rm "$BUILD_CID" >/dev/null

  cp "$SCRIPT_DIR/run-client.sh" "$TEMP_DIR/run-client.sh"

  cat > "$TEMP_DIR/Dockerfile.final" <<'EOF'
FROM quix-experiment-base
COPY masque_server /usr/local/bin/masque_server
COPY masque_client /usr/local/bin/masque_client
COPY run-client.sh /experiment/run-client.sh
RUN chmod +x /usr/local/bin/masque_server /usr/local/bin/masque_client /experiment/run-client.sh
EOF

  docker build -t quix-experiment -f "$TEMP_DIR/Dockerfile.final" "$TEMP_DIR"
  rm -rf "$TEMP_DIR"
  echo "  Image ready: quix-experiment"
  echo ""
fi

# Verify image exists
if ! docker image inspect quix-experiment &>/dev/null; then
  echo "ERROR: quix-experiment image not found. Run without --no-build first."
  exit 1
fi

# Run
if [ "$SHELL_MODE" = true ]; then
  echo "[*] Starting server..."
  docker compose up -d masque-server
  sleep 3
  echo ""
  echo "[*] Server running. Dropping into client shell."
  echo ""
  echo "    Server address: [fd00:abcd::2]:4433"
  echo ""
  echo "    Example:"
  echo "      masque_client --disable_certificate_verification \\"
  echo "        --server_hopping=true '[fd00:abcd::2]:4433' https://example.org/"
  echo ""
  docker compose run --rm masque-client /bin/bash
  docker compose down 2>/dev/null
else
  echo "[*] Running automated experiment..."
  echo ""
  docker compose up --abort-on-container-exit 2>&1
  EXIT_CODE=${PIPESTATUS[0]}
  echo ""
  docker compose down 2>/dev/null
  exit $EXIT_CODE
fi
