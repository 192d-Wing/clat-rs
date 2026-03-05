mod addr;
mod checksum;
mod config;
mod icmp;
mod packet_loop;
mod translate;
mod tun_device;

use std::path::PathBuf;

use clap::Parser;

use crate::config::Config;

#[derive(Parser)]
#[command(name = "clat-rs", about = "464XLAT CLAT daemon (RFC 6877)")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/clat-rs/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    log::info!("loading config from {}", cli.config.display());
    let config = Config::load(&cli.config)?;

    log::info!(
        "CLAT: {} -> {} (PLAT prefix: {})",
        config.clat_ipv4_addr,
        config.clat_v6_prefix,
        config.plat_v6_prefix,
    );

    packet_loop::run(&config).await
}
