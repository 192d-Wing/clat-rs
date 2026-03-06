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
        let prefix = nat64_core::prefix::parse_v6_prefix_96(prefix_str)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let old_prefix = self.state.current_prefix();
        self.state.set_prefix(prefix);

        tracing::info!(
            event_type = "admin",
            action = "set_prefix",
            new_prefix = %format!("{prefix}/96"),
            previous_prefix = %old_prefix.map(|p| format!("{p}/96")).unwrap_or_else(|| "none".into()),
            "NAT64 prefix updated via gRPC"
        );

        Ok(Response::new(SetPrefixResponse {
            active_prefix: format!("{prefix}/96"),
        }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        tracing::debug!(
            event_type = "admin",
            action = "get_status",
            "gRPC GetStatus called"
        );
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
        tracing::debug!(
            event_type = "admin",
            action = "list_sessions",
            limit = limit,
            "gRPC ListSessions called"
        );
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

        tracing::info!(
            event_type = "admin",
            action = "flush_sessions",
            flushed_count = flushed,
            "gRPC FlushSessions completed"
        );

        Ok(Response::new(FlushSessionsResponse {
            flushed_count: flushed as u64,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Ipv4Pool;
    use crate::session::SessionTimeouts;
    use crate::state::{SecurityPolicy, SourceRateLimiter};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_state(initial_prefix: Option<Ipv6Addr>) -> Arc<SharedState> {
        let cidrs = vec![(Ipv4Addr::new(198, 51, 100, 1), 32)];
        let pool = Ipv4Pool::new(&cidrs, (1024, 65535)).unwrap();
        Arc::new(SharedState::new(
            initial_prefix,
            "eth0".into(),
            "eth1".into(),
            pool,
            1000,
            SessionTimeouts::default(),
            SourceRateLimiter::new(100, 1),
            SecurityPolicy {
                reject_bogon_v4_dst: true,
                reject_reserved_v6_src: true,
            },
        ))
    }

    #[test]
    fn test_protocol_name() {
        assert_eq!(protocol_name(6), "tcp");
        assert_eq!(protocol_name(17), "udp");
        assert_eq!(protocol_name(1), "icmp");
        assert_eq!(protocol_name(0), "other");
        assert_eq!(protocol_name(255), "other");
    }

    #[tokio::test]
    async fn test_set_prefix_valid() {
        let state = test_state(None);
        let svc = PlatControlService::new(state.clone());

        let req = Request::new(SetPrefixRequest {
            nat64_prefix: "64:ff9b::/96".to_string(),
        });
        let resp = svc.set_prefix(req).await.unwrap();
        let inner = resp.into_inner();

        assert_eq!(inner.active_prefix, "64:ff9b::/96");
        assert!(state.current_prefix().is_some());
    }

    #[tokio::test]
    async fn test_set_prefix_invalid() {
        let state = test_state(None);
        let svc = PlatControlService::new(state.clone());

        let req = Request::new(SetPrefixRequest {
            nat64_prefix: "not-valid".to_string(),
        });
        let result = svc.set_prefix(req).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_set_prefix_replaces_existing() {
        let initial: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = test_state(Some(initial));
        let svc = PlatControlService::new(state.clone());

        let req = Request::new(SetPrefixRequest {
            nat64_prefix: "2001:db8::/96".to_string(),
        });
        svc.set_prefix(req).await.unwrap();

        let new_prefix = state.current_prefix().unwrap();
        assert_ne!(new_prefix, initial);
        assert_eq!(new_prefix, "2001:db8::".parse::<Ipv6Addr>().unwrap());
    }

    #[tokio::test]
    async fn test_get_status_no_prefix() {
        let state = test_state(None);
        let svc = PlatControlService::new(state.clone());

        let resp = svc
            .get_status(Request::new(GetStatusRequest {}))
            .await
            .unwrap();
        let s = resp.into_inner();

        assert_eq!(s.nat64_prefix, "");
        assert!(!s.translating);
        assert_eq!(s.active_sessions, 0);
        assert_eq!(s.total_translations, 0);
        assert!(s.metrics.is_some());
    }

    #[tokio::test]
    async fn test_get_status_with_prefix_and_translations() {
        let prefix: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = test_state(Some(prefix));
        state.set_translating(true);
        state.increment_translations();
        state.increment_translations();
        state.increment_translations();
        let svc = PlatControlService::new(state.clone());

        let resp = svc
            .get_status(Request::new(GetStatusRequest {}))
            .await
            .unwrap();
        let s = resp.into_inner();

        assert_eq!(s.nat64_prefix, "64:ff9b::/96");
        assert!(s.translating);
        assert_eq!(s.total_translations, 3);
        assert_eq!(s.ipv4_pool, vec!["198.51.100.1"]);
    }

    #[tokio::test]
    async fn test_get_status_metrics_zero_initially() {
        let state = test_state(None);
        let svc = PlatControlService::new(state);

        let resp = svc
            .get_status(Request::new(GetStatusRequest {}))
            .await
            .unwrap();
        let m = resp.into_inner().metrics.unwrap();

        assert_eq!(m.v6_to_v4_translated, 0);
        assert_eq!(m.v4_to_v6_translated, 0);
        assert_eq!(m.dropped_bogon_v4, 0);
        assert_eq!(m.dropped_reserved_v6, 0);
        assert_eq!(m.dropped_rate_limited, 0);
        assert_eq!(m.dropped_session_exhausted, 0);
        assert_eq!(m.dropped_prefix_mismatch, 0);
        assert_eq!(m.dropped_invalid_packet, 0);
    }

    #[tokio::test]
    async fn test_list_sessions_empty() {
        let state = test_state(None);
        let svc = PlatControlService::new(state);

        let resp = svc
            .list_sessions(Request::new(ListSessionsRequest { limit: 100 }))
            .await
            .unwrap();
        assert!(resp.into_inner().sessions.is_empty());
    }

    #[tokio::test]
    async fn test_flush_sessions_empty() {
        let state = test_state(None);
        let svc = PlatControlService::new(state);

        let resp = svc
            .flush_sessions(Request::new(FlushSessionsRequest {}))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().flushed_count, 0);
    }

    #[tokio::test]
    async fn test_flush_sessions_with_sessions() {
        use crate::session::SessionKey;

        let prefix: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = test_state(Some(prefix));

        // Create a session
        {
            let mut nat = state.nat.lock().unwrap();
            let key = SessionKey {
                src_v6: "2001:db8::1".parse().unwrap(),
                dst_v6: "64:ff9b::0808:0808".parse().unwrap(),
                protocol: 6,
                src_port: 12345,
                dst_port: 80,
            };
            let crate::state::NatState { sessions, pool, .. } = &mut *nat;
            let _ = sessions.lookup_or_create(key, pool);
        }

        let svc = PlatControlService::new(state);
        let resp = svc
            .flush_sessions(Request::new(FlushSessionsRequest {}))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().flushed_count, 1);
    }

    #[tokio::test]
    async fn test_list_sessions_with_limit() {
        use crate::session::SessionKey;

        let prefix: Ipv6Addr = "64:ff9b::".parse().unwrap();
        let state = test_state(Some(prefix));

        // Create multiple sessions
        {
            let mut nat = state.nat.lock().unwrap();
            let crate::state::NatState { sessions, pool, .. } = &mut *nat;
            for i in 0..5 {
                let key = SessionKey {
                    src_v6: "2001:db8::1".parse().unwrap(),
                    dst_v6: "64:ff9b::0808:0808".parse().unwrap(),
                    protocol: 6,
                    src_port: 10000 + i,
                    dst_port: 80,
                };
                let _ = sessions.lookup_or_create(key, pool);
            }
        }

        let svc = PlatControlService::new(state);

        // Limit to 3
        let resp = svc
            .list_sessions(Request::new(ListSessionsRequest { limit: 3 }))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().sessions.len(), 3);
    }
}
