use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::state::SharedState;

pub mod pb {
    tonic::include_proto!("clat");
}

use pb::clat_control_server::ClatControl;
use pb::{GetStatusRequest, SetPrefixRequest, SetPrefixResponse, StatusResponse};

pub struct ClatControlService {
    state: Arc<SharedState>,
}

impl ClatControlService {
    pub fn new(state: Arc<SharedState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ClatControl for ClatControlService {
    async fn set_prefix(
        &self,
        request: Request<SetPrefixRequest>,
    ) -> Result<Response<SetPrefixResponse>, Status> {
        let pd_prefix = &request.get_ref().dhcpv6_pd_prefix;
        let derived = nat64_core::prefix::derive_first_96_from_pd(pd_prefix)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let old_prefix = self.state.current_prefix();
        self.state.set_prefix(derived);

        tracing::info!(
            event_type = "admin",
            action = "dhcpv6_pd_update",
            pd_prefix = %pd_prefix,
            derived_clat_prefix = %format!("{derived}/96"),
            previous_prefix = %old_prefix.map(|p| format!("{p}/96")).unwrap_or_else(|| "none".into()),
            "DHCPv6-PD prefix updated via gRPC"
        );

        Ok(Response::new(SetPrefixResponse {
            derived_clat_prefix: format!("{derived}/96"),
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
        let clat_prefix = self
            .state
            .current_prefix()
            .map(|p| format!("{p}/96"))
            .unwrap_or_default();

        Ok(Response::new(StatusResponse {
            clat_prefix,
            plat_prefix: format!("{}/96", self.state.plat_prefix),
            uplink_interface: self.state.uplink_interface.clone(),
            translating: self.state.is_translating(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn test_state(initial_prefix: Option<Ipv6Addr>) -> Arc<SharedState> {
        let plat: Ipv6Addr = "64:ff9b::".parse().unwrap();
        Arc::new(SharedState::new(initial_prefix, plat, "eth0".to_string()))
    }

    #[tokio::test]
    async fn test_set_prefix_valid_pd() {
        let state = test_state(None);
        let svc = ClatControlService::new(state.clone());

        let req = Request::new(SetPrefixRequest {
            dhcpv6_pd_prefix: "2001:db8:abcd::/48".to_string(),
        });
        let resp = svc.set_prefix(req).await.unwrap();
        let inner = resp.into_inner();

        assert!(inner.derived_clat_prefix.ends_with("/96"));
        assert!(state.current_prefix().is_some());
    }

    #[tokio::test]
    async fn test_set_prefix_invalid_pd() {
        let state = test_state(None);
        let svc = ClatControlService::new(state.clone());

        let req = Request::new(SetPrefixRequest {
            dhcpv6_pd_prefix: "not-a-prefix".to_string(),
        });
        let result = svc.set_prefix(req).await;
        assert!(result.is_err());

        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_set_prefix_updates_existing() {
        let initial: Ipv6Addr = "2001:db8:1111::".parse().unwrap();
        let state = test_state(Some(initial));
        let svc = ClatControlService::new(state.clone());

        assert_eq!(state.current_prefix(), Some(initial));

        let req = Request::new(SetPrefixRequest {
            dhcpv6_pd_prefix: "2001:db8:2222::/48".to_string(),
        });
        svc.set_prefix(req).await.unwrap();

        // Prefix should have changed
        let new_prefix = state.current_prefix().unwrap();
        assert_ne!(new_prefix, initial);
    }

    #[tokio::test]
    async fn test_get_status_no_prefix() {
        let state = test_state(None);
        let svc = ClatControlService::new(state.clone());

        let resp = svc
            .get_status(Request::new(GetStatusRequest {}))
            .await
            .unwrap();
        let s = resp.into_inner();

        assert_eq!(s.clat_prefix, "");
        assert_eq!(s.plat_prefix, "64:ff9b::/96");
        assert_eq!(s.uplink_interface, "eth0");
        assert!(!s.translating);
    }

    #[tokio::test]
    async fn test_get_status_with_prefix() {
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let state = test_state(Some(prefix));
        let svc = ClatControlService::new(state.clone());

        let resp = svc
            .get_status(Request::new(GetStatusRequest {}))
            .await
            .unwrap();
        let s = resp.into_inner();

        assert_eq!(s.clat_prefix, "2001:db8::/96");
        assert!(!s.translating);
    }

    #[tokio::test]
    async fn test_get_status_translating() {
        let state = test_state(None);
        state.set_translating(true);
        let svc = ClatControlService::new(state.clone());

        let resp = svc
            .get_status(Request::new(GetStatusRequest {}))
            .await
            .unwrap();
        assert!(resp.into_inner().translating);
    }
}
