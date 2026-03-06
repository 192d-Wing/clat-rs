//! Unix domain socket helpers for the gRPC control plane.
//!
//! Provides UDS server binding (with restrictive permissions) and client
//! connection for `ctl` subcommands.

use std::path::{Path, PathBuf};

use tokio::net::UnixStream;
use tokio_stream::wrappers::UnixListenerStream;

/// Default socket path for the plat-rs gRPC control plane.
pub const DEFAULT_SOCKET_PATH: &str = "/run/plat-rs/control.sock";

/// Bind a Unix domain socket at `path` and return a stream of connections.
///
/// - Removes any stale socket file at `path`.
/// - Creates the parent directory (mode 0750) if it doesn't exist.
/// - Sets socket permissions to `mode` (e.g., 0o660).
pub fn bind(path: &Path, mode: u32) -> std::io::Result<UnixListenerStream> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        set_permissions(parent, 0o750)?;
    }

    // Remove stale socket
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    set_permissions(path, mode)?;

    tracing::info!(
        event_type = "lifecycle",
        action = "bind_uds",
        path = %path.display(),
        mode = format_args!("{mode:#o}"),
        "gRPC control socket bound"
    );

    Ok(UnixListenerStream::new(listener))
}

/// Set file/directory permissions.
fn set_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Connect to a Unix domain socket for gRPC client operations.
pub async fn connect(path: &str) -> anyhow::Result<tonic::transport::Channel> {
    let path = PathBuf::from(path);

    // tonic requires a valid URI even for UDS; the actual connection ignores it.
    let channel = tonic::transport::Endpoint::try_from("http://[::]:0")?
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await?;

    Ok(channel)
}

/// Remove the socket file on shutdown.
pub fn cleanup(path: &Path) {
    if path.exists()
        && let Err(e) = std::fs::remove_file(path)
    {
        tracing::warn!(
            event_type = "lifecycle",
            action = "cleanup_socket",
            path = %path.display(),
            error = %e,
            "failed to remove socket file"
        );
    }
}
