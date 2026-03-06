//! NIST-compliant structured JSON logging for NAT64 daemons.
//!
//! Provides JSON-formatted log output suitable for SIEM ingestion,
//! with optional syslog forwarding via libc `syslog()`. Complies with
//! NIST SP 800-92 (Guide to Computer Security Log Management) by including:
//!
//! - RFC 3339 timestamps with sub-second precision
//! - Severity level (mapped to syslog priorities)
//! - Source component identification
//! - Process ID and hostname for forensic correlation
//! - Structured key-value fields for security events
//!
//! # Usage
//!
//! ```no_run
//! nat64_logging::init(&nat64_logging::LogConfig {
//!     component: "plat-rs",
//!     syslog: false,
//!     log_filter: None,
//! });
//! ```

use tracing_subscriber::layer::SubscriberExt;

// Re-export so daemons can use `tracing::info!` etc.
pub use tracing;

/// Logging configuration.
pub struct LogConfig<'a> {
    /// Component name emitted in every log line (e.g., "plat-rs", "clat-rs").
    pub component: &'a str,
    /// Enable syslog output via libc `openlog()`/`syslog()`.
    /// On non-Unix platforms this is silently ignored.
    pub syslog: bool,
    /// Optional `RUST_LOG`-style filter directive override.
    /// When `None`, defaults to the `RUST_LOG` env var, or `info`.
    pub log_filter: Option<&'a str>,
}

/// Initialize the global tracing subscriber with JSON output and optional syslog.
///
/// Must be called once at startup before any logging occurs.
/// Panics if called more than once.
pub fn init(config: &LogConfig<'_>) {
    let filter_str = config
        .log_filter
        .map(String::from)
        .unwrap_or_else(|| std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()));

    let env_filter = tracing_subscriber::EnvFilter::try_new(&filter_str)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let pid = std::process::id();
    let hostname = gethostname();
    let component = config.component.to_string();

    // Bridge `log` crate macros (used by aya-log, tonic, etc.) into tracing
    if let Err(e) = tracing_log::LogTracer::init() {
        eprintln!("warning: tracing-log bridge already initialized: {e}");
    }

    // Macro to build the JSON layer (avoids repeating the non-nameable type)
    macro_rules! json_layer {
        () => {
            tracing_subscriber::fmt::layer()
                .json()
                .with_timer(tracing_subscriber::fmt::time::SystemTime)
                .with_target(true)
                .with_thread_ids(false)
                .with_current_span(true)
                .with_span_list(false)
                .map_event_format({
                    let component = component.clone();
                    let hostname = hostname.clone();
                    move |format| NistJsonFormat {
                        inner: format,
                        component: component.clone(),
                        pid,
                        hostname: hostname.clone(),
                    }
                })
                .with_writer(std::io::stdout as fn() -> std::io::Stdout)
        };
    }

    // Build subscriber with optional syslog
    #[cfg(unix)]
    if config.syslog {
        if let Some(syslog) = open_syslog(config.component) {
            let syslog_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_ansi(false)
                .with_writer(syslog);

            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(json_layer!())
                .with(syslog_layer);
            tracing::subscriber::set_global_default(subscriber)
                .expect("failed to set global tracing subscriber");
            return;
        }
        eprintln!("warning: syslog logger already initialized, skipping");
    }

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer!());
    tracing::subscriber::set_global_default(subscriber)
        .expect("failed to set global tracing subscriber");
}

/// Open the libc syslog connection.
#[cfg(unix)]
fn open_syslog(component: &str) -> Option<syslog_tracing::Syslog> {
    let mut ident_bytes = component.as_bytes().to_vec();
    ident_bytes.push(0);
    let identity = std::ffi::CString::from_vec_with_nul(ident_bytes).ok()?;

    syslog_tracing::Syslog::new(
        identity,
        syslog_tracing::Options::LOG_PID | syslog_tracing::Options::LOG_NDELAY,
        syslog_tracing::Facility::Daemon,
    )
}

/// Custom JSON formatter that injects NIST-required static fields
/// (component, pid, hostname) into every JSON log line.
#[derive(Clone)]
struct NistJsonFormat<F> {
    inner: F,
    component: String,
    pid: u32,
    hostname: String,
}

impl<S, N, F> tracing_subscriber::fmt::FormatEvent<S, N> for NistJsonFormat<F>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::format::FormatFields<'a> + 'static,
    F: tracing_subscriber::fmt::FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        // Format with inner JSON formatter into a buffer, then inject NIST fields
        let mut buf = String::with_capacity(256);
        let buf_writer = tracing_subscriber::fmt::format::Writer::new(&mut buf);
        self.inner.format_event(ctx, buf_writer, event)?;

        // Inject NIST fields before the trailing closing brace
        if let Some(pos) = buf.rfind('}') {
            use std::fmt::Write;
            let mut nist = String::with_capacity(80);
            write!(
                nist,
                ",\"component\":\"{}\",\"pid\":{},\"hostname\":\"{}\"",
                self.component, self.pid, self.hostname,
            )?;
            buf.insert_str(pos, &nist);
        }

        write!(writer, "{buf}")
    }
}

fn gethostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes a null-terminated string into buf
        let ret = unsafe { libc_gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if ret == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..len]).into_owned()
        } else {
            "unknown".into()
        }
    }
    #[cfg(not(unix))]
    {
        "unknown".into()
    }
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "gethostname"]
    fn libc_gethostname(name: *mut std::ffi::c_char, len: usize) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gethostname_returns_non_empty() {
        let name = gethostname();
        assert!(!name.is_empty());
        assert_ne!(name, "unknown");
    }

    #[test]
    fn test_log_config_defaults() {
        let config = LogConfig {
            component: "test",
            syslog: false,
            log_filter: None,
        };
        assert_eq!(config.component, "test");
        assert!(!config.syslog);
    }
}
