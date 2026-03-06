use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use tonic::{Request, Response, Status};

use crate::state::SharedState;

pub mod pb {
    tonic::include_proto!("plat");
}

use pb::plat_control_server::PlatControl;
use pb::{
    FlushSessionsRequest, FlushSessionsResponse, GetStatusRequest, ListSessionsRequest,
    ListSessionsResponse, PacketMetrics as PbPacketMetrics, SessionEntry, SetPrefixRequest,
    SetPrefixResponse, StatusResponse,
};

pub struct PlatControlService {
    state: Arc<SharedState>,
}

impl PlatControlService {
    pub fn new(state: Arc<SharedState>) -> Self {
        Self { state }
    }
}

fn protocol_name(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "other",
    }
}

#[tonic::async_trait]
impl PlatControl for PlatControlService {
    async fn set_prefix(
        &self,
        request: Request<SetPrefixRequest>,
    ) -> Result<Response<SetPrefixResponse>, Status> {
        let prefix_str = &request.get_ref().nat64_prefix;
        log::info!("gRPC SetPrefix called with: {prefix_str}");

        let prefix = nat64_core::prefix::parse_v6_prefix_96(prefix_str)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        self.state.set_prefix(prefix);

        Ok(Response::new(SetPrefixResponse {
            active_prefix: format!("{prefix}/96"),
        }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let nat64_prefix = self
            .state
            .current_prefix()
            .map(|p| format!("{p}/96"))
            .unwrap_or_default();

        let nat = self.state.nat.lock().unwrap();
        let pool_addrs: Vec<String> = nat.pool.addresses().iter().map(|a| a.to_string()).collect();
        let active_sessions = nat.sessions.len() as u64;
        drop(nat);

        let m = &self.state.metrics;
        let metrics = PbPacketMetrics {
            v6_to_v4_translated: m.v6_to_v4_translated.load(Ordering::Relaxed),
            v4_to_v6_translated: m.v4_to_v6_translated.load(Ordering::Relaxed),
            dropped_bogon_v4: m.dropped_bogon_v4.load(Ordering::Relaxed),
            dropped_reserved_v6: m.dropped_reserved_v6.load(Ordering::Relaxed),
            dropped_rate_limited: m.dropped_rate_limited.load(Ordering::Relaxed),
            dropped_session_exhausted: m.dropped_session_exhausted.load(Ordering::Relaxed),
            dropped_prefix_mismatch: m.dropped_prefix_mismatch.load(Ordering::Relaxed),
            dropped_invalid_packet: m.dropped_invalid_packet.load(Ordering::Relaxed),
        };

        Ok(Response::new(StatusResponse {
            nat64_prefix,
            ipv4_pool: pool_addrs,
            active_sessions,
            total_translations: self.state.translation_count(),
            translating: self.state.is_translating(),
            metrics: Some(metrics),
        }))
    }

    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let limit = request.get_ref().limit as usize;
        let nat = self.state.nat.lock().unwrap();
        let sessions = nat.sessions.list_sessions(limit);
        drop(nat);

        let now = Instant::now();
        let entries: Vec<SessionEntry> = sessions
            .into_iter()
            .map(|s| SessionEntry {
                src_v6: s.key.src_v6.to_string(),
                pool_v4: s.binding.pool_addr.to_string(),
                mapped_port: u32::from(s.binding.mapped_port),
                protocol: protocol_name(s.key.protocol).to_string(),
                age_secs: now.duration_since(s.binding.created).as_secs(),
                idle_secs: now.duration_since(s.binding.last_seen).as_secs(),
            })
            .collect();

        Ok(Response::new(ListSessionsResponse { sessions: entries }))
    }

    async fn flush_sessions(
        &self,
        _request: Request<FlushSessionsRequest>,
    ) -> Result<Response<FlushSessionsResponse>, Status> {
        let mut nat = self.state.nat.lock().unwrap();
        let crate::state::NatState { sessions, pool, .. } = &mut *nat;
        let flushed = sessions.flush_all(pool);
        drop(nat);

        log::info!("gRPC FlushSessions: flushed {flushed} sessions");

        Ok(Response::new(FlushSessionsResponse {
            flushed_count: flushed as u64,
        }))
    }
}
