use super::{peer_parts, sanitise_field};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandSource {
    Interactive,

    Exec,

    Pipe,

    Heredoc,

    Script,

    Transfer,
}

impl CommandSource {
    fn as_str(self) -> &'static str {
        match self {
            CommandSource::Interactive => "interactive",
            CommandSource::Exec => "exec",
            CommandSource::Pipe => "pipe",
            CommandSource::Heredoc => "heredoc",
            CommandSource::Script => "script",
            CommandSource::Transfer => "transfer",
        }
    }
}

pub fn command(
    session_id: u64,
    peer: SocketAddr,
    command: &str,
    source: CommandSource,
    status: Option<i32>,
) {
    let (src_ip, src_port) = peer_parts(peer);
    let command = sanitise_field(command);
    emit!(
        info,
        "command",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        command = %command,
        source = source.as_str(),
        status = status.unwrap_or(-1),
    );
}

pub fn subsystem_request(session_id: u64, peer: SocketAddr, subsystem: &str, accepted: bool) {
    let (src_ip, src_port) = peer_parts(peer);
    let subsystem = sanitise_field(subsystem);
    emit!(
        info,
        "subsystem_request",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        subsystem = %subsystem,
        accepted,
    );
}

pub fn download(session_id: u64, peer: SocketAddr, tool: &str, url: &str, dest: &str) {
    let (src_ip, src_port) = peer_parts(peer);
    let tool = sanitise_field(tool);
    let url = sanitise_field(url);
    let dest = sanitise_field(dest);
    emit!(
        info,
        "download",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        tool = %tool,
        url = %url,
        dest = %dest,
    );
}
