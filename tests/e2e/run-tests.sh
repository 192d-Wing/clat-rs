#!/usr/bin/env bash
# End-to-end test suite run inside the client container.
# Tests the 464XLAT container topology: Client -> CLAT -> PLAT -> Server.
#
# The client shares the CLAT's network namespace (network_mode: service:clat)
# so it can route traffic through the clat0 TUN device for translation tests.
set -uo pipefail

PASS=0
FAIL=0
SKIP=0
SERVER="10.46.0.5"
CLAT_SOCK="/run/grpc/clat.sock"
PLAT_SOCK="/run/grpc/plat.sock"
# Translation test destination (secondary IP on server, routed through clat0)
XLAT_DST="198.51.100.1"

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); }
skip() { echo "  SKIP: $1"; ((SKIP++)); }

echo "============================================"
echo " 464XLAT End-to-End Test Suite"
echo "============================================"
echo ""

# ── Test 1: CLAT daemon is running and healthy ─────────────────────
echo "[Test 1] CLAT daemon health (gRPC GetStatus)"
CLAT_STATUS=$(clat-rs ctl status --grpc-socket "$CLAT_SOCK" 2>&1 || true)
if echo "$CLAT_STATUS" | grep -qi "translating"; then
    pass "CLAT daemon responding on gRPC"
else
    fail "CLAT daemon not responding: $CLAT_STATUS"
fi

# ── Test 2: PLAT daemon is running and healthy ─────────────────────
echo "[Test 2] PLAT daemon health (gRPC GetStatus)"
PLAT_STATUS=$(plat-rs ctl status --grpc-socket "$PLAT_SOCK" 2>&1 || true)
if echo "$PLAT_STATUS" | grep -qi "translating"; then
    pass "PLAT daemon responding on gRPC"
else
    fail "PLAT daemon not responding: $PLAT_STATUS"
fi

# ── Test 3: CLAT is actively translating ───────────────────────────
echo "[Test 3] CLAT translation state"
if echo "$CLAT_STATUS" | grep -qi "translating.*true"; then
    pass "CLAT is translating (TUN devices active)"
else
    fail "CLAT not in translating state"
fi

# ── Test 4: PLAT is actively translating ──────────────────────────
echo "[Test 4] PLAT translation state"
if echo "$PLAT_STATUS" | grep -qi "translating.*true"; then
    pass "PLAT is translating (TUN devices active)"
else
    fail "PLAT not in translating state"
fi

# ── Test 5: Network connectivity ──────────────────────────────────
echo "[Test 5] Network connectivity to server"
if ping -c 2 -W 3 "$SERVER" >/dev/null 2>&1; then
    pass "ICMP ping to server ($SERVER) succeeded"
else
    fail "ICMP ping to server ($SERVER) failed"
fi

# ── Test 6: TCP echo to server (direct) ────────────────────────────
echo "[Test 6] TCP echo to server (direct path)"
REPLY=$(echo "hello-e2e-tcp" | ncat -w 5 "$SERVER" 8080 2>/dev/null || true)
if [ "$REPLY" = "hello-e2e-tcp" ]; then
    pass "TCP echo returned correct payload"
else
    fail "TCP echo returned '$REPLY' (expected 'hello-e2e-tcp')"
fi

# ── Test 7: IPv6 connectivity between containers ─────────────────
echo "[Test 7] IPv6 connectivity (CLAT <-> PLAT transit)"
if ping -6 -c 2 -W 3 "fd46:e2e::4" >/dev/null 2>&1; then
    pass "IPv6 ping to PLAT (fd46:e2e::4) succeeded"
else
    fail "IPv6 ping to PLAT (fd46:e2e::4) failed"
fi

# ── Test 8: TUN devices exist ─────────────────────────────────────
echo "[Test 8] CLAT TUN devices"
TUNS_OK=true
for dev in clat0 clat6; do
    if ! ip link show "$dev" >/dev/null 2>&1; then
        fail "TUN device $dev not found"
        TUNS_OK=false
    fi
done
if $TUNS_OK; then
    pass "CLAT TUN devices clat0 and clat6 present"
fi

# ── Test 9: Translation path routes configured ────────────────────
echo "[Test 9] Translation routing"
ROUTES_OK=true
if ! ip -6 route show | grep -q "64:ff9b::/96"; then
    fail "Missing route for NAT64 prefix"
    ROUTES_OK=false
fi
if ! ip -6 route show | grep -q "fd00:c1a7:c1a7::/96"; then
    fail "Missing route for CLAT prefix"
    ROUTES_OK=false
fi
if ! ip route show | grep -q "198.51.100.0/24"; then
    fail "Missing route for translation test destination"
    ROUTES_OK=false
fi
if $ROUTES_OK; then
    pass "Translation routes configured correctly"
fi

# ── Test 10: TCP echo via translation path (464XLAT) ──────────────
echo "[Test 10] TCP echo via 464XLAT translation path"
if ip route show | grep -q "198.51.100.0/24.*clat0"; then
    XLAT_REPLY=$(echo "hello-xlat" | ncat -w 10 "$XLAT_DST" 8080 2>/dev/null || true)
    if [ "$XLAT_REPLY" = "hello-xlat" ]; then
        pass "464XLAT TCP echo returned correct payload via $XLAT_DST"
    else
        fail "464XLAT TCP echo returned '$XLAT_REPLY' (expected 'hello-xlat')"
    fi
else
    skip "Translation route not configured (clat0 not available)"
fi

# ── Test 11: PLAT session table via gRPC ──────────────────────────
echo "[Test 11] PLAT session table (gRPC ListSessions)"
SESSIONS=$(plat-rs ctl list-sessions --grpc-socket "$PLAT_SOCK" --limit 10 2>&1 || true)
if [ -n "$SESSIONS" ]; then
    pass "PLAT ListSessions gRPC endpoint responding"
else
    fail "PLAT ListSessions not responding"
fi

# ── Test 12: CLAT gRPC SetPrefix hot-swap ─────────────────────────
echo "[Test 12] CLAT gRPC SetPrefix hot-swap"
SET_RESULT=$(clat-rs ctl set-prefix "2001:db8:aa00::/48" --grpc-socket "$CLAT_SOCK" 2>&1 || true)
if echo "$SET_RESULT" | grep -qi "ok\|derived\|prefix"; then
    pass "CLAT SetPrefix gRPC endpoint responding"
    # Restore original prefix
    clat-rs ctl set-prefix "fd00:c1a7:c1a7::/48" --grpc-socket "$CLAT_SOCK" >/dev/null 2>&1 || true
else
    fail "CLAT SetPrefix failed: $SET_RESULT"
fi

# ── Test 13: Verify packet captures exist ─────────────────────────
echo "[Test 13] Packet capture files"
PCAP_OK=true
for f in /pcap/clat.pcap /pcap/plat.pcap /pcap/server.pcap; do
    if [ ! -f "$f" ]; then
        fail "Missing pcap: $f"
        PCAP_OK=false
    fi
done
if $PCAP_OK; then
    pass "All pcap files present"
fi

# ── Results ─────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo " Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
