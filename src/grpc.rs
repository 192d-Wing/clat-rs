use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::config::derive_first_96_from_pd;
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
        log::info!("gRPC SetPrefix called with: {pd_prefix}");

        let derived = derive_first_96_from_pd(pd_prefix)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        self.state.set_prefix(derived);

        Ok(Response::new(SetPrefixResponse {
            derived_clat_prefix: format!("{derived}/96"),
        }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
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
