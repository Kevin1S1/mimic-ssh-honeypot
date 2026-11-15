use super::{peer_parts, sanitise_field};
use std::net::SocketAddr;

#[allow(clippy::too_many_arguments)]
pub fn auth_attempt(
    session_id: u64,
    peer: SocketAddr,
    username: &str,
    method: &str,
    secret: Option<&str>,
    fingerprint: Option<&str>,
    accepted: bool,
) {
    let (src_ip, src_port) = peer_parts(peer);
    let username = sanitise_field(username);
    let method = sanitise_field(method);
    let password = sanitise_field(secret.unwrap_or(""));
    let key_fingerprint = sanitise_field(fingerprint.unwrap_or(""));

    macro_rules! attempt {
        ($level:ident) => {
            emit!(
                $level,
                "auth_attempt",
                session_id,
                peer = %peer,
                src_ip,
                src_port,
                username = %username,
                method = %method,
                password = %password,
                key_fingerprint = %key_fingerprint,
                accepted,
            )
        };
    }
    if accepted {
        attempt!(warn)
    } else {
        attempt!(info)
    }
}
