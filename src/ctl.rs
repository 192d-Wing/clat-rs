use crate::grpc::pb::clat_control_client::ClatControlClient;
use crate::grpc::pb::{GetStatusRequest, SetPrefixRequest};

const DEFAULT_ADDR: &str = "http://[::1]:50051";

/// Run the `ctl set-prefix` subcommand.
pub async fn set_prefix(addr: &str, pd_prefix: &str) -> anyhow::Result<()> {
    let endpoint = if addr.is_empty() { DEFAULT_ADDR } else { addr };
    let mut client = ClatControlClient::connect(endpoint.to_string()).await?;

    let response = client
        .set_prefix(SetPrefixRequest {
            dhcpv6_pd_prefix: pd_prefix.to_string(),
        })
        .await?;

    let resp = response.into_inner();
    println!("OK: derived CLAT prefix {}", resp.derived_clat_prefix);
    Ok(())
}

/// Run the `ctl status` subcommand.
pub async fn status(addr: &str) -> anyhow::Result<()> {
    let endpoint = if addr.is_empty() { DEFAULT_ADDR } else { addr };
    let mut client = ClatControlClient::connect(endpoint.to_string()).await?;

    let response = client.get_status(GetStatusRequest {}).await?;
    let s = response.into_inner();

    println!(
        "CLAT prefix:      {}",
        if s.clat_prefix.is_empty() {
            "(not set)"
        } else {
            &s.clat_prefix
        }
    );
    println!("PLAT prefix:      {}", s.plat_prefix);
    println!("Uplink interface: {}", s.uplink_interface);
    println!("Translating:      {}", s.translating);
    Ok(())
}
