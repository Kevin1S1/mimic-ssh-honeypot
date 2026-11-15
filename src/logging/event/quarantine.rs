use super::{peer_parts, sanitise_field};
use std::net::SocketAddr;

#[allow(clippy::too_many_arguments)]
pub fn upload(
    session_id: u64,
    peer: SocketAddr,
    name: &str,
    dest: &str,
    size: u64,
    sha256: &str,
    stored_sha256: &str,
    stored_path: &str,
    truncated: bool,
) {
    let (src_ip, src_port) = peer_parts(peer);
    let name = sanitise_field(name);
    let dest = sanitise_field(dest);
    let sha256 = sanitise_field(sha256);
    let stored_sha256 = sanitise_field(stored_sha256);
    let stored_path = sanitise_field(stored_path);

    emit!(
        warn,
        "upload",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        name = %name,
        dest = %dest,
        size,
        sha256 = %sha256,
        stored_sha256 = %stored_sha256,
        stored_path = %stored_path,
        truncated,
    );
}

pub fn quarantine_session_cap(session_id: u64, peer: SocketAddr) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        warn,
        "quarantine_session_cap",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
    );
}

pub fn quarantine_global_cap(session_id: u64, peer: SocketAddr) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        warn,
        "quarantine_global_cap",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
    );
}

pub fn quarantine_error(session_id: u64, peer: SocketAddr, error: &str) {
    let (src_ip, src_port) = peer_parts(peer);
    let error = sanitise_field(error);
    emit!(
        warn,
        "quarantine_error",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        error = %error,
    );
}
