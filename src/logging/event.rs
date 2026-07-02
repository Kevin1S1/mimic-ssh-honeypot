//! Forensic event helpers. Each function emits a single structured JSON log
//! line tagged with an `event` field for easy downstream filtering.

use std::net::SocketAddr;
use std::sync::OnceLock;
use tracing::info;

/// Process-wide sensor name, set once at startup.
static SENSOR_NAME: OnceLock<String> = OnceLock::new();

/// Store the sensor name so every subsequent event log line includes it.
pub fn init(name: &str) {
    SENSOR_NAME
        .set(name.to_owned())
        .expect("event::init called more than once");
}

fn sensor_name() -> &'static str {
    SENSOR_NAME.get().map_or("mimic", |s| s.as_str())
}

/// A new TCP/SSH connection was accepted.
pub fn connection_opened(session_id: u64, peer: SocketAddr) {
    info!(event = "connection_opened", sensor_name = sensor_name(), session_id, peer = %peer);
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
        sensor_name = sensor_name(),
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
    info!(event = "connection_rejected", sensor_name = sensor_name(), peer = %peer, reason);
}

/// The session ended.
pub fn connection_closed(session_id: u64, peer: SocketAddr) {
    info!(event = "connection_closed", sensor_name = sensor_name(), session_id, peer = %peer);
}

/// An attacker fetched a remote URL with `wget`/`curl`. `dest` is the VFS path
/// the body was "saved" to (or `-` for stdout). No real request was made.
pub fn download(session_id: u64, peer: SocketAddr, tool: &str, url: &str, dest: &str) {
    info!(event = "download", sensor_name = sensor_name(), session_id, peer = %peer, tool, url, dest);
}

/// A command line was submitted by the client (interactive shell or one-shot
/// `exec`). Logged verbatim for forensic replay.
pub fn command(session_id: u64, peer: SocketAddr, command: &str) {
    info!(event = "command", sensor_name = sensor_name(), session_id, peer = %peer, command);
}

/// A file was uploaded via SCP and written to the quarantine store. `name` is
/// the attacker-supplied filename, `dest` the path it was materialised at in
/// the emulated filesystem, `sha256` the content hash (also its quarantine
/// filename), and `stored_path` where the bytes landed on the real disk
/// (empty if the quarantine write failed). `truncated` flags uploads capped at
/// the configured size limit.
#[allow(clippy::too_many_arguments)]
pub fn upload(
    session_id: u64,
    peer: SocketAddr,
    name: &str,
    dest: &str,
    size: u64,
    sha256: &str,
    stored_path: &str,
    truncated: bool,
) {
    info!(
        event = "upload",
        sensor_name = sensor_name(),
        session_id,
        peer = %peer,
        name,
        dest,
        size,
        sha256,
        stored_path,
        truncated,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::build_subscriber;
    use serde_json::Value;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::EnvFilter;

    /// In-memory sink so tests can capture exactly what the production
    /// formatter would write to stdout.
    #[derive(Clone, Default)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `body` against the real JSON pipeline and return the raw captured
    /// output together with one parsed `Value` per emitted line.
    fn capture(body: impl FnOnce()) -> (String, Vec<Value>) {
        let buffer = BufferWriter::default();
        let subscriber = build_subscriber(EnvFilter::new("info"), buffer.clone());

        tracing::subscriber::with_default(subscriber, body);

        let raw = String::from_utf8(buffer.0.lock().unwrap().clone()).expect("utf-8 log output");
        let parsed = raw
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("each log line must be valid JSON"))
            .collect();
        (raw, parsed)
    }

    fn peer() -> SocketAddr {
        "203.0.113.7:54321".parse().unwrap()
    }

    /// The structured fields live under the `fields` object in the JSON output.
    fn fields(value: &Value) -> &Value {
        &value["fields"]
    }

    #[test]
    fn each_event_is_one_valid_json_line_with_expected_fields() {
        let (_, events) = capture(|| {
            connection_opened(1, peer());
            auth_attempt(1, peer(), "root", "password", Some("hunter2"), false);
            connection_rejected(peer(), "per_ip_limit");
            connection_closed(1, peer());
        });

        assert_eq!(events.len(), 4, "one JSON line per event");

        let opened = fields(&events[0]);
        assert_eq!(opened["event"], "connection_opened");
        assert_eq!(opened["session_id"], 1);
        assert_eq!(opened["peer"], "203.0.113.7:54321");
        assert_eq!(opened["sensor_name"], "mimic");

        let auth = fields(&events[1]);
        assert_eq!(auth["event"], "auth_attempt");
        assert_eq!(auth["username"], "root");
        assert_eq!(auth["method"], "password");
        assert_eq!(auth["password"], "hunter2");
        assert_eq!(auth["accepted"], false);
        assert_eq!(auth["sensor_name"], "mimic");

        let rejected = fields(&events[2]);
        assert_eq!(rejected["event"], "connection_rejected");
        assert_eq!(rejected["reason"], "per_ip_limit");
        assert_eq!(rejected["sensor_name"], "mimic");

        let closed = fields(&events[3]);
        assert_eq!(closed["event"], "connection_closed");
        assert_eq!(closed["session_id"], 1);
        assert_eq!(closed["sensor_name"], "mimic");
    }

    #[test]
    fn download_event_records_tool_url_and_dest() {
        let (_, events) = capture(|| {
            download(3, peer(), "wget", "http://evil.example/x.sh", "/root/x.sh");
        });
        let dl = fields(&events[0]);
        assert_eq!(dl["event"], "download");
        assert_eq!(dl["tool"], "wget");
        assert_eq!(dl["url"], "http://evil.example/x.sh");
        assert_eq!(dl["dest"], "/root/x.sh");
    }

    #[test]
    fn public_key_auth_records_no_password() {
        let (_, events) = capture(|| {
            auth_attempt(9, peer(), "admin", "publickey", None, false);
        });

        let auth = fields(&events[0]);
        assert_eq!(auth["method"], "publickey");
        assert_eq!(auth["password"], "");
    }

    /// Attacker-controlled fields must never be able to forge or split a log
    /// line. Newlines, carriage returns, and escape sequences are escaped by
    /// the JSON encoder, so a crafted credential stays inside a single record.
    #[test]
    fn attacker_input_cannot_forge_or_split_log_lines() {
        let malicious_user = "root\n{\"event\":\"connection_opened\",\"session_id\":1337}";
        let malicious_pass = "p\rass\u{1b}[31mword\u{0007}\twith\u{0000}controls";

        let (raw, events) = capture(|| {
            auth_attempt(
                1,
                peer(),
                malicious_user,
                "password",
                Some(malicious_pass),
                false,
            );
        });

        // A single event in, a single line out — the embedded newline did not
        // create a second, forged record.
        assert_eq!(events.len(), 1, "control chars must not split the record");

        // Raw control characters never appear unescaped in the byte stream.
        let payload = raw.trim_end_matches('\n');
        assert!(!payload.contains('\r'), "carriage return must be escaped");
        assert!(!payload.contains('\u{1b}'), "escape byte must be escaped");
        assert!(!payload.contains('\u{0000}'), "NUL must be escaped");

        // Round-tripped values are preserved exactly for forensic fidelity.
        let auth = fields(&events[0]);
        assert_eq!(auth["username"], malicious_user);
        assert_eq!(auth["password"], malicious_pass);
    }
}
