mod config;
mod ctl;
mod grpc;
mod packet_loop;
mod pool;
mod session;
mod state;
mod tun_device;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tonic::transport::Server;

use crate::config::Config;
use crate::grpc::PlatControlService;
use crate::grpc::pb::plat_control_server::PlatControlServer;
use crate::pool::Ipv4Pool;
use crate::state::{SecurityPolicy, SharedState, SourceRateLimiter};

#[derive(Parser)]
#[command(name = "plat-rs", about = "NAT64 PLAT gateway daemon (RFC 6146)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/plat-rs/config.yml", global = true)]
    config: PathBuf,

    /// gRPC listen address
    #[arg(long, default_value = "[::1]:50052", global = true)]
    grpc_addr: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Control a running plat-rs daemon via gRPC
    Ctl {
        #[command(subcommand)]
        action: CtlAction,
    },
}

#[derive(Subcommand)]
enum CtlAction {
    /// Set the NAT64 prefix on the running daemon
    SetPrefix {
        /// NAT64 prefix in CIDR notation (e.g., "64:ff9b::/96")
        prefix: String,
    },
    /// Query the daemon status
    Status,
    /// List active NAT64 sessions
    ListSessions {
        /// Maximum number of sessions to display (0 = all)
        #[arg(short, long, default_value = "50")]
        limit: u32,
    },
    /// Flush all active sessions
    FlushSessions,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nat64_logging::init(&nat64_logging::LogConfig {
        component: "plat-rs",
        syslog: false,
        log_filter: None,
    });

    let cli = Cli::parse();

    // Handle ctl subcommands (gRPC client mode)
    if let Some(Commands::Ctl { action }) = cli.command {
        let addr = format!("http://{}", cli.grpc_addr);
        return match action {
            CtlAction::SetPrefix { prefix } => ctl::set_prefix(&addr, &prefix).await,
            CtlAction::Status => ctl::status(&addr).await,
            CtlAction::ListSessions { limit } => ctl::list_sessions(&addr, limit).await,
            CtlAction::FlushSessions => ctl::flush_sessions(&addr).await,
        };
    }

    // Daemon mode
    tracing::info!(
        event_type = "lifecycle",
        action = "startup",
        config_path = %cli.config.display(),
        "plat-rs daemon starting"
    );
    let config = Config::load(&cli.config)?;

    let nat64_prefix = config.nat64_prefix();
    let pool_cidrs = config.parse_ipv4_pool()?;
    let pool = Ipv4Pool::new(&pool_cidrs, (config.port_range[0], config.port_range[1]))?;

    tracing::info!(
        "PLAT: NAT64 prefix {nat64_prefix}/96, pool {} addresses, max {} sessions",
        pool.addresses().len(),
        config.session.max_sessions,
    );

    let rate_limiter = SourceRateLimiter::new(
        config.security.max_new_sessions_per_source,
        config.security.rate_window_secs,
    );

    let state = Arc::new(SharedState::new(
        Some(nat64_prefix),
        config.uplink_interface.clone(),
        config.egress_interface().to_string(),
        pool,
        config.session.max_sessions,
        config.session.to_timeouts(),
        rate_limiter,
        SecurityPolicy {
            reject_bogon_v4_dst: config.security.reject_bogon_v4_dst,
            reject_reserved_v6_src: config.security.reject_reserved_v6_src,
        },
    ));

    // Drop privileges after TUN creation (Linux only)
    if config.security.drop_uid != 0 || config.security.drop_gid != 0 {
        tun_device::drop_privileges(&tun_device::DropPrivileges {
            uid: config.security.drop_uid,
            gid: config.security.drop_gid,
        })?;
    }

    // Spawn gRPC control server
    let grpc_addr: SocketAddr = cli.grpc_addr.parse()?;
    let grpc_state = Arc::clone(&state);
    tokio::spawn(async move {
        let service = PlatControlService::new(grpc_state);
        tracing::info!("gRPC control server listening on {grpc_addr}");
        if let Err(e) = Server::builder()
            .add_service(PlatControlServer::new(service))
            .serve(grpc_addr)
            .await
        {
            tracing::error!("gRPC server error: {e}");
        }
    });

    let result = packet_loop::run(&config, state).await;
    tracing::info!(
        event_type = "lifecycle",
        action = "shutdown",
        "plat-rs daemon stopped"
    );
    result
}
