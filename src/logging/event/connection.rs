use super::{peer_parts, sanitise_field};
use std::net::SocketAddr;

pub fn connection_opened(session_id: u64, peer: SocketAddr) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "connection_opened",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
    );
}

pub fn client_banner(session_id: u64, peer: SocketAddr, banner: &str) {
    let (src_ip, src_port) = peer_parts(peer);
    let banner = sanitise_field(banner);
    emit!(
        info,
        "client_banner",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        banner = %banner,
    );
}

pub fn connection_rejected(peer: SocketAddr, reason: &str) {
    let (src_ip, src_port) = peer_parts(peer);
    let reason = sanitise_field(reason);
    emit!(
        info,
        "connection_rejected",
        peer = %peer,
        src_ip,
        src_port,
        reason = %reason,
    );
}

pub fn connection_closed(
    session_id: u64,
    peer: SocketAddr,
    duration_secs: u64,
    command_count: u64,
) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "connection_closed",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        duration_secs,
        command_count,
    );
}

pub fn session_timeout(session_id: u64, peer: SocketAddr) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "session_timeout",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
    );
}

pub fn login_timeout(session_id: u64, peer: SocketAddr) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "login_timeout",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
    );
}
