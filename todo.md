# TODO

## Current Sprint

- Integration/end-to-end tests — Test the full run() loop with mock TUN devices

## Backlog

- Prometheus metrics endpoint — Export counters as /metrics for Grafana dashboards (alongside gRPC)
- Systemd service files — Unit files with Type=notify, watchdog, and proper capabilities (CAP_NET_ADMIN, CAP_NET_RAW)
- Configuration hot-reload — Watch config file for changes (SIGHUP handler) instead of requiring daemon restart
- Full fragment reassembly — Currently non-first IPv6 fragments are dropped; RFC 6146 §3.5.1 requires reassembly
- Connection tracking for TCP — Track TCP state (SYN/FIN/RST) for tighter session timeouts
- Multi-queue XDP — Current XDP path only binds queue 0; scale to all NIC queues
