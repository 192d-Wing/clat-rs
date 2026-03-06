# TODO

- Metrics/observability — Add counters for dropped packets (rate-limited, bogon, reserved, exhausted), expose via gRPC status
- Logging improvements — Structured logging (e.g., tracing crate) instead of env_logger
- Graceful shutdown — Drain sessions, flush state on SIGTERM
- Integration/end-to-end tests — Test the full run() loop with mock TUN devices
