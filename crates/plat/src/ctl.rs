use crate::grpc::pb::plat_control_client::PlatControlClient;
use crate::grpc::pb::{
    FlushSessionsRequest, GetStatusRequest, ListSessionsRequest, SetPrefixRequest,
};

const DEFAULT_ADDR: &str = "http://[::1]:50052";

pub async fn set_prefix(addr: &str, prefix: &str) -> anyhow::Result<()> {
    let endpoint = if addr.is_empty() { DEFAULT_ADDR } else { addr };
    let mut client = PlatControlClient::connect(endpoint.to_string()).await?;

    let response = client
        .set_prefix(SetPrefixRequest {
            nat64_prefix: prefix.to_string(),
        })
        .await?;

    let resp = response.into_inner();
    println!("OK: active NAT64 prefix {}", resp.active_prefix);
    Ok(())
}

pub async fn status(addr: &str) -> anyhow::Result<()> {
    let endpoint = if addr.is_empty() { DEFAULT_ADDR } else { addr };
    let mut client = PlatControlClient::connect(endpoint.to_string()).await?;

    let response = client.get_status(GetStatusRequest {}).await?;
    let s = response.into_inner();

    println!(
        "NAT64 prefix:      {}",
        if s.nat64_prefix.is_empty() {
            "(not set)"
        } else {
            &s.nat64_prefix
        }
    );
    println!("IPv4 pool:         {}", s.ipv4_pool.join(", "));
    println!("Active sessions:   {}", s.active_sessions);
    println!("Total translations:{}", s.total_translations);
    println!("Translating:       {}", s.translating);
    Ok(())
}

pub async fn list_sessions(addr: &str, limit: u32) -> anyhow::Result<()> {
    let endpoint = if addr.is_empty() { DEFAULT_ADDR } else { addr };
    let mut client = PlatControlClient::connect(endpoint.to_string()).await?;

    let response = client.list_sessions(ListSessionsRequest { limit }).await?;
    let resp = response.into_inner();

    if resp.sessions.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    println!(
        "{:<40} {:<16} {:<6} {:<6} {:<8} {:<8}",
        "SRC_V6", "POOL_V4", "PORT", "PROTO", "AGE", "IDLE"
    );
    for s in resp.sessions {
        println!(
            "{:<40} {:<16} {:<6} {:<6} {:<8} {:<8}",
            s.src_v6, s.pool_v4, s.mapped_port, s.protocol, s.age_secs, s.idle_secs
        );
    }
    Ok(())
}

pub async fn flush_sessions(addr: &str) -> anyhow::Result<()> {
    let endpoint = if addr.is_empty() { DEFAULT_ADDR } else { addr };
    let mut client = PlatControlClient::connect(endpoint.to_string()).await?;

    let response = client.flush_sessions(FlushSessionsRequest {}).await?;
    let resp = response.into_inner();

    println!("OK: flushed {} sessions", resp.flushed_count);
    Ok(())
}
