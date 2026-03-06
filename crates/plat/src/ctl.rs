use crate::grpc::pb::plat_control_client::PlatControlClient;
use crate::grpc::pb::{
    FlushSessionsRequest, GetStatusRequest, ListSessionsRequest, SetPrefixRequest,
};
use crate::uds;

pub async fn set_prefix(socket_path: &str, prefix: &str) -> anyhow::Result<()> {
    let channel = uds::connect(socket_path).await?;
    let mut client = PlatControlClient::new(channel);

    let response = client
        .set_prefix(SetPrefixRequest {
            nat64_prefix: prefix.to_string(),
        })
        .await?;

    let resp = response.into_inner();
    println!("OK: active NAT64 prefix {}", resp.active_prefix);
    Ok(())
}

pub async fn status(socket_path: &str) -> anyhow::Result<()> {
    let channel = uds::connect(socket_path).await?;
    let mut client = PlatControlClient::new(channel);

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

pub async fn list_sessions(socket_path: &str, limit: u32) -> anyhow::Result<()> {
    let channel = uds::connect(socket_path).await?;
    let mut client = PlatControlClient::new(channel);

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

pub async fn flush_sessions(socket_path: &str) -> anyhow::Result<()> {
    let channel = uds::connect(socket_path).await?;
    let mut client = PlatControlClient::new(channel);

    let response = client.flush_sessions(FlushSessionsRequest {}).await?;
    let resp = response.into_inner();

    println!("OK: flushed {} sessions", resp.flushed_count);
    Ok(())
}
