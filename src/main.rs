mod addr;
mod checksum;
mod config;
mod ctl;
mod grpc;
mod icmp;
mod packet_loop;
mod state;
mod translate;
mod tun_device;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tonic::transport::Server;

use crate::config::Config;
use crate::grpc::ClatControlService;
use crate::grpc::pb::clat_control_server::ClatControlServer;
use crate::state::SharedState;

#[derive(Parser)]
#[command(name = "clat-rs", about = "464XLAT CLAT daemon (RFC 6877)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/clat-rs/config.yml", global = true)]
    config: PathBuf,

    /// gRPC listen address
    #[arg(long, default_value = "[::1]:50051", global = true)]
    grpc_addr: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Control a running clat-rs daemon via gRPC
    Ctl {
        #[command(subcommand)]
        action: CtlAction,
    },
}

#[derive(Subcommand)]
enum CtlAction {
    /// Set the DHCPv6-PD prefix on the running daemon
    SetPrefix {
        /// DHCPv6-PD prefix in CIDR notation (e.g., "2001:db8:aa00::/48")
        prefix: String,
    },
    /// Query the daemon status
    Status,
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
        };
    }

    // Daemon mode
    log::info!("loading config from {}", cli.config.display());
    let config = Config::load(&cli.config)?;

    let initial_prefix = config.clat_prefix().ok();
    let plat_prefix = config.plat_prefix();

    if let Some(prefix) = initial_prefix {
        log::info!(
            "CLAT: {} -> {}/96 (PLAT prefix: {}/96)",
            config.clat_ipv4_addr,
            prefix,
            plat_prefix,
        );
    } else {
        log::info!(
            "CLAT: {} -> (awaiting prefix via gRPC) (PLAT prefix: {}/96)",
            config.clat_ipv4_addr,
            plat_prefix,
        );
    }

    let state = Arc::new(SharedState::new(
        initial_prefix,
        plat_prefix,
        config.uplink_interface.clone(),
    ));

    // Spawn gRPC control server
    let grpc_addr: SocketAddr = cli.grpc_addr.parse()?;
    let grpc_state = Arc::clone(&state);
    tokio::spawn(async move {
        let service = ClatControlService::new(grpc_state);
        log::info!("gRPC control server listening on {grpc_addr}");
        if let Err(e) = Server::builder()
            .add_service(ClatControlServer::new(service))
            .serve(grpc_addr)
            .await
        {
            log::error!("gRPC server error: {e}");
        }
    });

    packet_loop::run(&config, state).await
}
