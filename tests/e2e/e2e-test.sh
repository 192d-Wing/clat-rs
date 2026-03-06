#!/usr/bin/env bash
# 464XLAT End-to-End Test Orchestrator
#
# Builds container images, runs the full Client -> CLAT -> PLAT -> Server
# test topology, collects packet captures, and validates results.
#
# Usage:
#   ./tests/e2e/e2e-test.sh              # run tests and clean up
#   ./tests/e2e/e2e-test.sh --keep       # keep containers running after tests
#   ./tests/e2e/e2e-test.sh --pcap-only  # skip tests, just extract pcaps from a running stack
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE="docker compose -f $SCRIPT_DIR/docker-compose.yml -p clat-e2e"
PCAP_OUT="$PROJECT_ROOT/target/e2e-pcaps"

KEEP=false
PCAP_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=true ;;
        --pcap-only) PCAP_ONLY=true ;;
    esac
done

cleanup() {
    if ! $KEEP; then
        echo ""
        echo "Cleaning up containers..."
        $COMPOSE down -v --remove-orphans 2>/dev/null || true
    fi
}

extract_pcaps() {
    echo ""
    echo "Extracting packet captures to $PCAP_OUT ..."
    mkdir -p "$PCAP_OUT"

    # Copy pcaps from the shared volume via a temporary container
    local vol_name
    vol_name=$($COMPOSE config --volumes 2>/dev/null | head -1 || echo "pcap_data")
    docker run --rm \
        -v "clat-e2e_${vol_name}:/pcap:ro" \
        -v "$PCAP_OUT:/out" \
        debian:bookworm-slim \
        bash -c 'cp /pcap/*.pcap /out/ 2>/dev/null; ls -lh /out/*.pcap 2>/dev/null || echo "No pcap files found"'

    echo ""
    echo "Packet captures saved to:"
    ls -lh "$PCAP_OUT"/*.pcap 2>/dev/null || echo "  (none)"
    echo ""
    echo "Analyze with:"
    echo "  tcpdump -r $PCAP_OUT/clat.pcap -nn"
    echo "  tcpdump -r $PCAP_OUT/plat.pcap -nn"
    echo "  tcpdump -r $PCAP_OUT/server.pcap -nn"
    echo ""
    echo "Or open in Wireshark for detailed inspection."
}

validate_pcaps() {
    echo ""
    echo "Validating packet captures..."

    local errors=0

    # Check CLAT pcap has traffic (client shares CLAT network namespace)
    if [ -f "$PCAP_OUT/clat.pcap" ]; then
        local total_count
        total_count=$(tcpdump -r "$PCAP_OUT/clat.pcap" -nn 2>/dev/null | wc -l || echo 0)
        echo "  INFO: clat.pcap contains $total_count total packets"
    else
        echo "  SKIP: clat.pcap not found"
    fi

    # Check PLAT pcap has traffic
    if [ -f "$PCAP_OUT/plat.pcap" ]; then
        local total_count
        total_count=$(tcpdump -r "$PCAP_OUT/plat.pcap" -nn 2>/dev/null | wc -l || echo 0)
        echo "  INFO: plat.pcap contains $total_count total packets"
    else
        echo "  SKIP: plat.pcap not found"
    fi

    # Check server pcap has IPv4 traffic from PLAT pool
    if [ -f "$PCAP_OUT/server.pcap" ]; then
        local ipv4_count
        ipv4_count=$(tcpdump -r "$PCAP_OUT/server.pcap" -nn 'ip' 2>/dev/null | wc -l || echo 0)
        if [ "$ipv4_count" -gt 0 ]; then
            echo "  PASS: server.pcap contains $ipv4_count IPv4 packets"
        else
            echo "  FAIL: server.pcap has no IPv4 packets"
            ((errors++))
        fi
    else
        echo "  SKIP: server.pcap not found"
    fi

    return "$errors"
}

# ── Main ────────────────────────────────────────────────────────────

if $PCAP_ONLY; then
    extract_pcaps
    validate_pcaps || true
    exit 0
fi

trap cleanup EXIT

echo "============================================"
echo " 464XLAT End-to-End Test"
echo "============================================"
echo ""
echo "Building container images..."
$COMPOSE build

echo ""
echo "Starting test topology..."
echo "  client (10.46.0.2) -> clat (10.46.0.3) -> [IPv6 transit] -> plat (10.46.0.4) -> server (10.46.0.5)"
echo ""

# Start infrastructure services first
$COMPOSE up -d clat plat server

echo "Waiting for daemons to initialize..."
sleep 5

# Run the client (test runner) and capture exit code
echo ""
echo "Running tests..."
echo ""

TEST_EXIT=0
$COMPOSE run --rm client || TEST_EXIT=$?

# Extract and validate pcaps
extract_pcaps
validate_pcaps || true

# Print final status
echo ""
if [ "$TEST_EXIT" -eq 0 ]; then
    echo "ALL TESTS PASSED"
else
    echo "SOME TESTS FAILED (exit code: $TEST_EXIT)"
fi

exit "$TEST_EXIT"
