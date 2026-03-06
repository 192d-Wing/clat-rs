#!/usr/bin/env bash
# 464XLAT Benchmark Orchestrator
#
# Builds container images, runs the full benchmark suite through the
# CLAT -> PLAT translation path, and extracts results.
#
# Usage:
#   ./tests/e2e/bench-test.sh              # run benchmarks and clean up
#   ./tests/e2e/bench-test.sh --keep       # keep containers running after benchmarks
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE="docker compose -f $SCRIPT_DIR/docker-compose.yml -f $SCRIPT_DIR/docker-compose.bench.yml -p clat-bench"
RESULTS_OUT="$PROJECT_ROOT/target/bench-results"

KEEP=false

for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=true ;;
    esac
done

cleanup() {
    if ! $KEEP; then
        echo ""
        echo "Cleaning up containers..."
        $COMPOSE down -v --remove-orphans 2>/dev/null || true
    fi
}

extract_results() {
    echo ""
    echo "Extracting benchmark results to $RESULTS_OUT ..."
    mkdir -p "$RESULTS_OUT"

    local vol_name="bench_results"
    docker run --rm \
        -v "clat-bench_${vol_name}:/results:ro" \
        -v "$RESULTS_OUT:/out" \
        debian:bookworm-slim \
        bash -c 'cp /results/* /out/ 2>/dev/null; ls -lh /out/ 2>/dev/null || echo "No results found"'

    echo ""
    if [ -f "$RESULTS_OUT/benchmarks.csv" ]; then
        echo "Results saved to: $RESULTS_OUT/benchmarks.csv"
        echo ""
        column -t -s',' "$RESULTS_OUT/benchmarks.csv" 2>/dev/null || cat "$RESULTS_OUT/benchmarks.csv"
    fi
}

# ── Main ────────────────────────────────────────────────────────────

trap cleanup EXIT

echo "============================================"
echo " 464XLAT Benchmark Suite"
echo "============================================"
echo ""
echo "Building container images..."
$COMPOSE build

echo ""
echo "Starting benchmark topology..."
echo "  bench -> clat (10.46.0.3) -> [IPv6 transit] -> plat (10.46.0.4) -> server (10.46.0.5)"
echo ""

# Start infrastructure
$COMPOSE up -d clat plat server

echo "Waiting for daemons to initialize..."
sleep 8

# Run benchmarks
echo ""
echo "Running benchmarks..."
echo ""

BENCH_EXIT=0
$COMPOSE run --rm bench || BENCH_EXIT=$?

# Extract results
extract_results

echo ""
if [ "$BENCH_EXIT" -eq 0 ]; then
    echo "BENCHMARKS COMPLETE"
else
    echo "BENCHMARKS FAILED (exit code: $BENCH_EXIT)"
fi

exit "$BENCH_EXIT"
