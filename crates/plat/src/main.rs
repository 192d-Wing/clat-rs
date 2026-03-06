mod config;
mod ctl;
mod grpc;
mod packet_loop;
mod pool;
mod session;
mod state;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tonic::transport::Server;

use crate::config::Config;
use crate::grpc::PlatControlService;
use crate::grpc::pb::plat_control_server::PlatControlServer;
use crate::pool::Ipv4Pool;
use crate::state::SharedState;

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
    env_logger::init();

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
    log::info!("loading config from {}", cli.config.display());
    let config = Config::load(&cli.config)?;

    let nat64_prefix = config.nat64_prefix();
    let pool_cidrs = config.parse_ipv4_pool()?;
    let pool = Ipv4Pool::new(&pool_cidrs, (1024, 65535))?;

    log::info!(
        "PLAT: NAT64 prefix {nat64_prefix}/96, pool {} addresses, max {} sessions",
        pool.addresses().len(),
        config.session.max_sessions,
    );

    let state = Arc::new(SharedState::new(
        Some(nat64_prefix),
        config.uplink_interface.clone(),
        config.egress_interface().to_string(),
        pool,
        config.session.max_sessions,
        config.session.to_timeouts(),
    ));

    // Spawn gRPC control server
    let grpc_addr: SocketAddr = cli.grpc_addr.parse()?;
    let grpc_state = Arc::clone(&state);
    tokio::spawn(async move {
        let service = PlatControlService::new(grpc_state);
        log::info!("gRPC control server listening on {grpc_addr}");
        if let Err(e) = Server::builder()
            .add_service(PlatControlServer::new(service))
            .serve(grpc_addr)
            .await
        {
            log::error!("gRPC server error: {e}");
        }
    });

    packet_loop::run(&config, state).await
}
