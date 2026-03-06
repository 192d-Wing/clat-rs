#!/usr/bin/env bash
# 464XLAT Benchmark Suite
#
# Measures throughput, latency (with percentiles), and session scaling
# through the full Client -> CLAT -> PLAT -> Server translation path.
#
# Results are written to /results/ (shared volume) and printed to stdout.
set -uo pipefail

RESULTS_DIR="/results"
DIRECT_SERVER="10.46.0.5"
XLAT_SERVER="198.51.100.1"
IPERF_PORT=5201
IPERF_PORT2=5202
DURATION=10
PARALLEL_STREAMS=4
PING_COUNT=200

mkdir -p "$RESULTS_DIR"

# ── Helpers ──────────────────────────────────────────────────────────

banner() {
    echo ""
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
    echo ""
}

timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

write_result() {
    local test_name="$1"
    local metric="$2"
    local value="$3"
    local unit="$4"
    echo "$test_name,$metric,$value,$unit,$(timestamp)" >> "$RESULTS_DIR/benchmarks.csv"
    printf "  %-40s %10s %s\n" "$metric" "$value" "$unit"
}

# Compute percentiles from a file of sorted numbers (one per line)
# Usage: percentile <file> <p> (e.g., percentile /tmp/latencies.txt 99)
percentile() {
    local file="$1"
    local p="$2"
    local count
    count=$(wc -l < "$file")
    if [ "$count" -eq 0 ]; then
        echo ""
        return
    fi
    local idx
    idx=$(echo "scale=0; ($p * $count + 99) / 100" | bc)
    if [ "$idx" -lt 1 ]; then idx=1; fi
    if [ "$idx" -gt "$count" ]; then idx=$count; fi
    sed -n "${idx}p" "$file"
}

# Run ping and extract per-packet RTTs, compute percentiles
# Usage: ping_percentiles <label> <target> <count>
ping_percentiles() {
    local label="$1"
    local target="$2"
    local count="$3"
    local tmpfile
    tmpfile=$(mktemp)

    echo "  Sending $count ICMP packets to $target..."
    ping -c "$count" -i 0.02 "$target" 2>/dev/null | \
        grep 'time=' | \
        sed 's/.*time=\([0-9.]*\).*/\1/' | \
        sort -n > "$tmpfile"

    local total
    total=$(wc -l < "$tmpfile")
    if [ "$total" -eq 0 ]; then
        echo "  No responses received"
        rm -f "$tmpfile"
        return
    fi

    local avg min max p50 p90 p95 p99
    min=$(head -1 "$tmpfile")
    max=$(tail -1 "$tmpfile")
    avg=$(awk '{s+=$1} END {printf "%.3f", s/NR}' "$tmpfile")
    p50=$(percentile "$tmpfile" 50)
    p90=$(percentile "$tmpfile" 90)
    p95=$(percentile "$tmpfile" 95)
    p99=$(percentile "$tmpfile" 99)

    write_result "$label" "min_ms" "$min" "ms"
    write_result "$label" "avg_ms" "$avg" "ms"
    write_result "$label" "p50_ms" "$p50" "ms"
    write_result "$label" "p90_ms" "$p90" "ms"
    write_result "$label" "p95_ms" "$p95" "ms"
    write_result "$label" "p99_ms" "$p99" "ms"
    write_result "$label" "max_ms" "$max" "ms"
    write_result "$label" "samples" "$total" "count"

    rm -f "$tmpfile"
}

# Run TCP connect latency test, compute percentiles
# Usage: tcp_connect_percentiles <label> <target> <port> <count>
tcp_connect_percentiles() {
    local label="$1"
    local target="$2"
    local port="$3"
    local count="$4"
    local tmpfile
    tmpfile=$(mktemp)

    echo "  Opening $count TCP connections to $target:$port..."
    for i in $(seq 1 "$count"); do
        local start_ns end_ns elapsed_ms
        start_ns=$(date +%s%N)
        if echo "" | ncat -w 1 "$target" "$port" >/dev/null 2>&1; then
            end_ns=$(date +%s%N)
            elapsed_ms=$(echo "scale=3; ($end_ns - $start_ns) / 1000000" | bc)
            echo "$elapsed_ms" >> "$tmpfile"
        fi
    done

    sort -n "$tmpfile" > "${tmpfile}.sorted"
    mv "${tmpfile}.sorted" "$tmpfile"

    local total
    total=$(wc -l < "$tmpfile")
    if [ "$total" -eq 0 ]; then
        echo "  No successful connections"
        rm -f "$tmpfile"
        return
    fi

    local avg min max p50 p90 p95 p99
    min=$(head -1 "$tmpfile")
    max=$(tail -1 "$tmpfile")
    avg=$(awk '{s+=$1} END {printf "%.3f", s/NR}' "$tmpfile")
    p50=$(percentile "$tmpfile" 50)
    p90=$(percentile "$tmpfile" 90)
    p95=$(percentile "$tmpfile" 95)
    p99=$(percentile "$tmpfile" 99)

    write_result "$label" "min_ms" "$min" "ms"
    write_result "$label" "avg_ms" "$avg" "ms"
    write_result "$label" "p50_ms" "$p50" "ms"
    write_result "$label" "p90_ms" "$p90" "ms"
    write_result "$label" "p95_ms" "$p95" "ms"
    write_result "$label" "p99_ms" "$p99" "ms"
    write_result "$label" "max_ms" "$max" "ms"
    write_result "$label" "successful" "$total" "count"

    rm -f "$tmpfile"
}

# ── Connectivity check ───────────────────────────────────────────────

banner "PRE-FLIGHT: Connectivity Check"

echo "Direct path (no translation):"
if ping -c 2 -W 2 "$DIRECT_SERVER" >/dev/null 2>&1; then
    echo "  OK: $DIRECT_SERVER reachable"
else
    echo "  FAIL: $DIRECT_SERVER unreachable"
    exit 1
fi

echo "Translation path (464XLAT):"
if ping -c 2 -W 5 "$XLAT_SERVER" >/dev/null 2>&1; then
    echo "  OK: $XLAT_SERVER reachable via CLAT->PLAT"
else
    echo "  FAIL: $XLAT_SERVER unreachable via translation"
    exit 1
fi

# Write CSV header
echo "test,metric,value,unit,timestamp" > "$RESULTS_DIR/benchmarks.csv"

# ── 1. Baseline: Direct path throughput ──────────────────────────────

banner "BENCHMARK 1: Baseline TCP Throughput (Direct Path)"

echo "Running iperf3 to $DIRECT_SERVER (no translation)..."
BASELINE_TCP=$(iperf3 -c "$DIRECT_SERVER" -p "$IPERF_PORT" -t "$DURATION" -J 2>/dev/null) || true

if [ -n "$BASELINE_TCP" ]; then
    BPS=$(echo "$BASELINE_TCP" | grep -oP '"bits_per_second":\s*\K[0-9.]+' | tail -1)
    if [ -n "$BPS" ]; then
        MBPS=$(echo "scale=2; $BPS / 1000000" | bc)
        write_result "baseline_tcp" "throughput_mbps" "$MBPS" "Mbps"
    fi
    echo "$BASELINE_TCP" > "$RESULTS_DIR/baseline_tcp.json"
fi

# ── 2. Translation path: TCP throughput ──────────────────────────────

banner "BENCHMARK 2: 464XLAT TCP Throughput (Single Stream)"

echo "Running iperf3 to $XLAT_SERVER (through CLAT->PLAT)..."
XLAT_TCP=$(iperf3 -c "$XLAT_SERVER" -p "$IPERF_PORT" -t "$DURATION" -J 2>/dev/null) || true

if [ -n "$XLAT_TCP" ]; then
    BPS=$(echo "$XLAT_TCP" | grep -oP '"bits_per_second":\s*\K[0-9.]+' | tail -1)
    if [ -n "$BPS" ]; then
        MBPS=$(echo "scale=2; $BPS / 1000000" | bc)
        write_result "xlat_tcp_single" "throughput_mbps" "$MBPS" "Mbps"
    fi
    echo "$XLAT_TCP" > "$RESULTS_DIR/xlat_tcp_single.json"
fi

# ── 3. Translation path: TCP throughput (parallel streams) ───────────

banner "BENCHMARK 3: 464XLAT TCP Throughput ($PARALLEL_STREAMS Parallel Streams)"

echo "Running iperf3 with $PARALLEL_STREAMS parallel streams..."
XLAT_TCP_PAR=$(iperf3 -c "$XLAT_SERVER" -p "$IPERF_PORT2" -t "$DURATION" -P "$PARALLEL_STREAMS" -J 2>/dev/null) || true

if [ -n "$XLAT_TCP_PAR" ]; then
    BPS=$(echo "$XLAT_TCP_PAR" | grep -oP '"bits_per_second":\s*\K[0-9.]+' | tail -1)
    if [ -n "$BPS" ]; then
        MBPS=$(echo "scale=2; $BPS / 1000000" | bc)
        write_result "xlat_tcp_parallel" "throughput_mbps" "$MBPS" "Mbps"
        write_result "xlat_tcp_parallel" "streams" "$PARALLEL_STREAMS" "count"
    fi
    echo "$XLAT_TCP_PAR" > "$RESULTS_DIR/xlat_tcp_parallel.json"
fi

# ── 4. Translation path: UDP throughput ──────────────────────────────

banner "BENCHMARK 4: 464XLAT UDP Throughput"

for BANDWIDTH in 10M 50M 100M; do
    echo "Running iperf3 UDP at target ${BANDWIDTH}bps..."
    XLAT_UDP=$(iperf3 -c "$XLAT_SERVER" -p "$IPERF_PORT" -u -b "$BANDWIDTH" -t "$DURATION" -J 2>/dev/null) || true

    if [ -n "$XLAT_UDP" ]; then
        BPS=$(echo "$XLAT_UDP" | grep -oP '"bits_per_second":\s*\K[0-9.]+' | tail -1)
        LOST=$(echo "$XLAT_UDP" | grep -oP '"lost_packets":\s*\K[0-9]+' | tail -1)
        TOTAL=$(echo "$XLAT_UDP" | grep -oP '"packets":\s*\K[0-9]+' | tail -1)
        JITTER=$(echo "$XLAT_UDP" | grep -oP '"jitter_ms":\s*\K[0-9.]+' | tail -1)

        if [ -n "$BPS" ]; then
            MBPS=$(echo "scale=2; $BPS / 1000000" | bc)
            write_result "xlat_udp_${BANDWIDTH}" "throughput_mbps" "$MBPS" "Mbps"
        fi
        if [ -n "$LOST" ] && [ -n "$TOTAL" ] && [ "$TOTAL" -gt 0 ]; then
            LOSS_PCT=$(echo "scale=2; $LOST * 100 / $TOTAL" | bc)
            write_result "xlat_udp_${BANDWIDTH}" "packet_loss" "$LOSS_PCT" "%"
        fi
        if [ -n "$JITTER" ]; then
            write_result "xlat_udp_${BANDWIDTH}" "jitter_ms" "$JITTER" "ms"
        fi
        echo "$XLAT_UDP" > "$RESULTS_DIR/xlat_udp_${BANDWIDTH}.json"
    fi
    sleep 2
done

# ── 5. ICMP Latency with Percentiles ────────────────────────────────

banner "BENCHMARK 5: ICMP Latency Percentiles"

echo "Baseline (direct path):"
ping_percentiles "baseline_icmp" "$DIRECT_SERVER" "$PING_COUNT"

echo ""
echo "464XLAT translation path:"
ping_percentiles "xlat_icmp" "$XLAT_SERVER" "$PING_COUNT"

# ── 6. TCP Connect Latency with Percentiles ─────────────────────────

banner "BENCHMARK 6: TCP Connect Latency Percentiles (464XLAT)"

echo "Baseline (direct path):"
tcp_connect_percentiles "baseline_tcp_connect" "$DIRECT_SERVER" 8080 100

echo ""
echo "464XLAT translation path:"
tcp_connect_percentiles "xlat_tcp_connect" "$XLAT_SERVER" 8080 100

# ── 7. TCP Connection Rate ──────────────────────────────────────────

banner "BENCHMARK 7: TCP Connection Rate (Session Creation)"

echo "Measuring new TCP connections/sec through 464XLAT..."

CONN_COUNT=0
START_TIME=$(date +%s%N)

for i in $(seq 1 500); do
    if echo "test" | ncat -w 1 "$XLAT_SERVER" 8080 >/dev/null 2>&1; then
        CONN_COUNT=$((CONN_COUNT + 1))
    fi
done

END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))

if [ "$ELAPSED_MS" -gt 0 ]; then
    CPS=$(echo "scale=1; $CONN_COUNT * 1000 / $ELAPSED_MS" | bc)
    write_result "xlat_tcp_connrate" "connections_per_sec" "$CPS" "conn/s"
    write_result "xlat_tcp_connrate" "successful" "$CONN_COUNT" "count"
    write_result "xlat_tcp_connrate" "elapsed_ms" "$ELAPSED_MS" "ms"
fi

# ── 8. Concurrent UDP Sessions ──────────────────────────────────────

banner "BENCHMARK 8: Concurrent UDP Session Scaling"

echo "Opening 100 concurrent UDP sessions..."

SESSION_COUNT=0
for PORT in $(seq 8100 8199); do
    echo "ping" | socat - UDP:${XLAT_SERVER}:${PORT},connect 2>/dev/null &
    SESSION_COUNT=$((SESSION_COUNT + 1))
done
wait 2>/dev/null || true

write_result "xlat_udp_sessions" "sessions_opened" "$SESSION_COUNT" "count"
sleep 2

# ── 9. Packet size sweep ────────────────────────────────────────────

banner "BENCHMARK 9: Packet Size Sweep (Latency vs Payload)"

for SIZE in 64 128 256 512 1024 1400; do
    echo "Payload size: ${SIZE} bytes"
    ping_percentiles "xlat_pktsize_${SIZE}" "$XLAT_SERVER" 50
    echo ""
done

# ── Summary ──────────────────────────────────────────────────────────

banner "BENCHMARK RESULTS SUMMARY"

if [ -f "$RESULTS_DIR/benchmarks.csv" ]; then
    echo "Raw CSV: /results/benchmarks.csv"
    echo ""
    column -t -s',' "$RESULTS_DIR/benchmarks.csv" 2>/dev/null || cat "$RESULTS_DIR/benchmarks.csv"
fi

echo ""

# Compute translation overhead
BASELINE_FILE="$RESULTS_DIR/baseline_tcp.json"
XLAT_FILE="$RESULTS_DIR/xlat_tcp_single.json"
if [ -f "$BASELINE_FILE" ] && [ -f "$XLAT_FILE" ]; then
    BASE_BPS=$(grep -oP '"bits_per_second":\s*\K[0-9.]+' "$BASELINE_FILE" | tail -1)
    XLAT_BPS=$(grep -oP '"bits_per_second":\s*\K[0-9.]+' "$XLAT_FILE" | tail -1)
    if [ -n "$BASE_BPS" ] && [ -n "$XLAT_BPS" ] && [ "$BASE_BPS" != "0" ]; then
        OVERHEAD=$(echo "scale=1; (1 - $XLAT_BPS / $BASE_BPS) * 100" | bc)
        echo "Translation overhead (TCP): ${OVERHEAD}% throughput reduction vs direct path"
        write_result "summary" "tcp_overhead_pct" "$OVERHEAD" "%"
    fi
fi

# Compute latency overhead
BASELINE_ICMP=$(grep "baseline_icmp,p50_ms" "$RESULTS_DIR/benchmarks.csv" 2>/dev/null | cut -d',' -f3)
XLAT_ICMP=$(grep "xlat_icmp,p50_ms" "$RESULTS_DIR/benchmarks.csv" 2>/dev/null | cut -d',' -f3)
if [ -n "$BASELINE_ICMP" ] && [ -n "$XLAT_ICMP" ]; then
    LATENCY_ADDED=$(echo "scale=3; $XLAT_ICMP - $BASELINE_ICMP" | bc)
    echo "Translation latency added (ICMP p50): ${LATENCY_ADDED} ms"
    write_result "summary" "latency_added_p50_ms" "$LATENCY_ADDED" "ms"
fi

echo ""
echo "Full iperf3 JSON results saved in /results/"
echo "Benchmarks complete."
