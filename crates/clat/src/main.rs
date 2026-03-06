mod config;
mod ctl;
mod grpc;
mod packet_loop;
mod state;
mod tun_device;
#[cfg(unix)]
mod uds;
#[cfg(all(target_os = "linux", feature = "xdp"))]
mod xdp;

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

    /// gRPC Unix domain socket path
    #[arg(long, default_value = uds::DEFAULT_SOCKET_PATH, global = true)]
    grpc_socket: String,
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
    nat64_logging::init(&nat64_logging::LogConfig {
        component: "clat-rs",
        syslog: false,
        log_filter: None,
    });

    let cli = Cli::parse();

    // Handle ctl subcommands (gRPC client mode)
    if let Some(Commands::Ctl { action }) = cli.command {
        return match action {
            CtlAction::SetPrefix { prefix } => ctl::set_prefix(&cli.grpc_socket, &prefix).await,
            CtlAction::Status => ctl::status(&cli.grpc_socket).await,
        };
    }

    // Daemon mode
    tracing::info!(
        event_type = "lifecycle",
        action = "startup",
        config_path = %cli.config.display(),
        "clat-rs daemon starting"
    );
    let config = Config::load(&cli.config)?;

    let initial_prefix = config.clat_prefix().ok();
    let plat_prefix = config.plat_prefix();

    if let Some(prefix) = initial_prefix {
        tracing::info!(
            "CLAT: {} -> {}/96 (PLAT prefix: {}/96)",
            config.clat_ipv4_addr,
            prefix,
            plat_prefix,
        );
    } else {
        tracing::info!(
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

    // Drop privileges after state creation (Linux only)
    if config.security.drop_uid != 0 || config.security.drop_gid != 0 {
        tun_device::drop_privileges(&tun_device::DropPrivileges {
            uid: config.security.drop_uid,
            gid: config.security.drop_gid,
        })?;
    }

    // Spawn gRPC control server on Unix domain socket
    let socket_path = std::path::PathBuf::from(&cli.grpc_socket);
    let incoming = uds::bind(&socket_path, 0o660)?;
    let grpc_state = Arc::clone(&state);
    let grpc_socket_path = socket_path.clone();
    tokio::spawn(async move {
        let service = ClatControlService::new(grpc_state);
        if let Err(e) = Server::builder()
            .add_service(ClatControlServer::new(service))
            .serve_with_incoming(incoming)
            .await
        {
            tracing::error!("gRPC server error: {e}");
        }
        uds::cleanup(&grpc_socket_path);
    });

    // Use XDP packet loop when the feature is enabled and xdp config is present
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    if config.xdp.is_some() {
        tracing::info!("XDP acceleration enabled — using AF_XDP packet path");
        let xdp_config = config.clone();
        let xdp_state = Arc::clone(&state);
        let handle = std::thread::spawn(move || xdp::run(&xdp_config, xdp_state));
        let result = handle
            .join()
            .map_err(|_| anyhow::anyhow!("XDP thread panicked"))?;
        uds::cleanup(&socket_path);
        tracing::info!(
            event_type = "lifecycle",
            action = "shutdown",
            "clat-rs daemon stopped (XDP)"
        );
        return result;
    }

    let result = packet_loop::run(&config, state).await;
    uds::cleanup(&socket_path);
    tracing::info!(
        event_type = "lifecycle",
        action = "shutdown",
        "clat-rs daemon stopped"
    );
    result
}
