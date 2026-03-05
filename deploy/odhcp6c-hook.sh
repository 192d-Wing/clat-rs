#!/bin/sh
# odhcp6c hook script for clat-rs
#
# Install to: /etc/odhcp6c/hook.d/clat-rs.sh
# odhcp6c calls this script with environment variables on PD events.
#
# Required env vars set by odhcp6c:
#   PREFIXES  — space-separated list of "prefix/len,preferred,valid" entries
#
# Usage with odhcp6c:
#   odhcp6c -P 48 -s /etc/odhcp6c/hook.d/clat-rs.sh eth0

CLAT_RS_GRPC_ADDR="${CLAT_RS_GRPC_ADDR:-[::1]:50051}"

case "$2" in
    bound|update|rebound|ra-updated)
        # PREFIXES is set by odhcp6c, e.g. "2001:db8:aa00::/48,3600,7200"
        if [ -n "$PREFIXES" ]; then
            # Extract the first prefix (before the comma)
            PREFIX=$(echo "$PREFIXES" | awk '{print $1}' | cut -d, -f1)
            if [ -n "$PREFIX" ]; then
                logger -t clat-rs "DHCPv6-PD received: $PREFIX"
                clat-rs ctl --grpc-addr "$CLAT_RS_GRPC_ADDR" set-prefix "$PREFIX"
                if [ $? -eq 0 ]; then
                    logger -t clat-rs "CLAT prefix updated via gRPC"
                else
                    logger -t clat-rs "failed to update CLAT prefix via gRPC"
                fi
            fi
        fi
        ;;
esac
