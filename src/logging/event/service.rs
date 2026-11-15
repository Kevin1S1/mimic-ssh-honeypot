use super::sanitise_field;

pub fn listening(addr: &str, port: u16, max_sessions: usize, per_ip_connections: usize) {
    emit!(
        info,
        "listening",
        addr,
        port,
        max_sessions,
        per_ip_connections,
    );
}

pub fn shutdown() {
    emit!(info, "shutdown",);
}

pub fn log_retention_pruned(removed: usize, retention_days: usize) {
    emit!(info, "log_retention_pruned", removed, retention_days,);
}

pub fn accept_error(error: &str) {
    let error = sanitise_field(error);
    emit!(warn, "accept_error", error = %error,);
}
