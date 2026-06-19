//! Forensic event helpers. Each function emits a single structured JSON log
//! line tagged with an `event` field for easy downstream filtering.

use std::net::SocketAddr;
use tracing::info;

/// A new TCP/SSH connection was accepted.
pub fn connection_opened(session_id: u64, peer: SocketAddr) {
    info!(event = "connection_opened", session_id, peer = %peer);
}

/// An authentication attempt was observed. `secret` is the captured password
/// for password auth, or `None` for other methods.
pub fn auth_attempt(
    session_id: u64,
    peer: SocketAddr,
    username: &str,
    method: &str,
    secret: Option<&str>,
    accepted: bool,
) {
    info!(
        event = "auth_attempt",
        session_id,
        peer = %peer,
        username,
        method,
        password = secret.unwrap_or(""),
        accepted,
    );
}

/// A connection was refused before the SSH handshake because a concurrency
/// limit was reached. `reason` is `"global_limit"` or `"per_ip_limit"`.
pub fn connection_rejected(peer: SocketAddr, reason: &str) {
    info!(event = "connection_rejected", peer = %peer, reason);
}

/// The session ended.
pub fn connection_closed(session_id: u64, peer: SocketAddr) {
    info!(event = "connection_closed", session_id, peer = %peer);
}
