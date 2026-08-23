//! Forensic event helpers. Each function emits a single structured JSON log
//! line tagged with an `event` field for easy downstream filtering.

use std::net::SocketAddr;
use std::sync::OnceLock;

/// Process-wide sensor name, set once at startup.
static SENSOR_NAME: OnceLock<String> = OnceLock::new();

/// Store the sensor name and mint this process's boot id, so every subsequent
/// event log line carries both.
pub fn init(name: &str) {
    SENSOR_NAME
        .set(name.to_owned())
        .expect("event::init called more than once");
    // `session_id` is a per-process counter that restarts at 1, so on its own it
    // collides across restarts and a SIEM correlating on it silently merges
    // unrelated sessions. `boot_id` makes the pair unique; consumers key on both.
    BOOT_ID
        .set(format!("{:016x}", rand::random::<u64>()))
        .expect("event::init called more than once");
}

fn sensor_name() -> &'static str {
    SENSOR_NAME.get().map_or("mimic", |s| s.as_str())
}

/// Process-wide boot id, set once at startup alongside the sensor name.
static BOOT_ID: OnceLock<String> = OnceLock::new();

fn boot_id() -> &'static str {
    BOOT_ID.get().map_or("0000000000000000", |s| s.as_str())
}

/// Split a peer address into the two fields a SIEM data model wants.
///
/// `peer` is kept as-is for continuity, but Splunk CIM (`src_ip`/`src_port`)
/// and ECS (`source.ip`/`source.port`) both want them typed and separate — and
/// re-splitting the combined string downstream is a parser bug waiting to
/// happen for IPv6 peers, which carry their own colons inside brackets.
fn peer_parts(peer: SocketAddr) -> (String, u16) {
    (peer.ip().to_string(), peer.port())
}

/// The ECS envelope stamped on every event.
///
/// Emitting these means a consumer maps nothing: previously the Filebeat recipe
/// in `README.md` synthesised them with `add_fields`, which only helped Elastic
/// users and put the values in every operator's shipper config instead of in the
/// sensor that knows them.
const EVENT_KIND: &str = "event";
const EVENT_CATEGORY: &str = "intrusion_detection";
const EVENT_DATASET: &str = "mimic.ssh";
const ECS_VERSION: &str = "8.11.0";

/// Emit one event line at `$level` with the common envelope filled in.
///
/// The envelope is eight fields on sixteen events; writing it out at each call
/// site is how one of them ends up missing a field that a dashboard groups by.
macro_rules! emit {
    ($level:ident, $event:literal, $($rest:tt)*) => {
        tracing::$level!(
            event = $event,
            sensor_name = sensor_name(),
            boot_id = boot_id(),
            event_kind = EVENT_KIND,
            event_category = EVENT_CATEGORY,
            event_dataset = EVENT_DATASET,
            ecs_version = ECS_VERSION,
            $($rest)*
        )
    };
}

/// A new TCP/SSH connection was accepted.
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

/// The client's SSH identification string, as sent in the version exchange.
///
/// `SSH-2.0-libssh2_1.9.0` / `SSH-2.0-Go` / `SSH-2.0-paramiko_2.7.2` separates
/// commodity botnet tooling from an interactive client faster than anything
/// else available, so it is worth its own event rather than a field on one.
pub fn client_banner(session_id: u64, peer: SocketAddr, banner: &str) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "client_banner",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        banner,
    );
}

/// The listener is up and accepting connections.
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

/// The process was asked to stop and is shutting the listener down.
pub fn shutdown() {
    emit!(info, "shutdown",);
}

/// The retention sweep deleted rotated log files that aged past
/// `logging.retention_days`. Emitted only when something was actually removed,
/// so a quiet sensor stays quiet.
pub fn log_retention_pruned(removed: usize, retention_days: usize) {
    emit!(info, "log_retention_pruned", removed, retention_days,);
}

/// `accept()` failed. Transient (fd exhaustion, and similar), not fatal.
pub fn accept_error(error: &str) {
    emit!(warn, "accept_error", error,);
}

/// A session hit the absolute lifetime cap and was disconnected.
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

/// A session reached its cumulative quarantine-write cap; later uploads in this
/// session are logged but not stored on disk.
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

/// Writing a captured payload to the quarantine store failed. This is the only
/// signal that a capture was lost, so it carries the full field set.
pub fn quarantine_error(session_id: u64, peer: SocketAddr, error: &str) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        warn,
        "quarantine_error",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        error,
    );
}

/// An authentication attempt was observed. `secret` is the captured password
/// for password auth, or `None` for other methods; `fingerprint` is the offered
/// key's SHA-256 fingerprint for public-key auth, or `None` otherwise. Attackers
/// reuse key material across campaigns, which makes the fingerprint a pivotable
/// IOC in a way a sprayed password rarely is.
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
    // A credential that worked is the moment the box stopped being a doorbell
    // and started being a shell. Failed attempts are the background radiation of
    // any internet-facing sensor and would drown it at the same level.
    macro_rules! attempt {
        ($level:ident) => {
            emit!(
                $level,
                "auth_attempt",
                session_id,
                peer = %peer,
                src_ip,
                src_port,
                username,
                method,
                password = secret.unwrap_or(""),
                key_fingerprint = fingerprint.unwrap_or(""),
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

/// A connection was refused before the SSH handshake because a concurrency
/// limit was reached. `reason` is `"global_limit"` or `"per_ip_limit"`.
pub fn connection_rejected(peer: SocketAddr, reason: &str) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "connection_rejected",
        peer = %peer,
        src_ip,
        src_port,
        reason,
    );
}

/// The session ended. `duration_secs` and `command_count` summarise it so a
/// dashboard can rank sessions without first correlating every command event
/// back to its session.
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

/// An attacker fetched a remote URL with `wget`/`curl`. `dest` is the VFS path
/// the body was "saved" to (or `-` for stdout). No real request was made.
pub fn download(session_id: u64, peer: SocketAddr, tool: &str, url: &str, dest: &str) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "download",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        tool,
        url,
        dest,
    );
}

/// How a command line reached the shell. The distinction is close to a binary
/// bot-versus-human classifier: a human types into an interactive session, while
/// automation overwhelmingly arrives as a one-shot `exec` or a piped script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandSource {
    /// Typed at a line editor on a channel with a PTY.
    Interactive,
    /// A one-shot `ssh host 'cmd'`.
    Exec,
    /// A line read from a shell channel that asked for no terminal.
    Pipe,
    /// A here-document, logged whole once its delimiter closed it.
    Heredoc,
    /// One line of a script `sh` ran out of the VFS, or of a payload piped into
    /// it. Never typed by the client — this is the body of a dropper.
    Script,
    /// A synthetic marker for a sub-protocol the command line started (SCP).
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

/// A command line was submitted by the client. Logged verbatim for forensic
/// replay.
///
/// `status` is the exit code the emulated command returned, or `None` when the
/// line is logged before it runs. A 127 answers the most useful question a
/// honeypot operator has — which commands did attackers expect to work that this
/// box does not implement — so it also drives what to emulate next.
pub fn command(
    session_id: u64,
    peer: SocketAddr,
    command: &str,
    source: CommandSource,
    status: Option<i32>,
) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "command",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        command,
        source = source.as_str(),
        status = status.unwrap_or(-1),
    );
}

/// An SSH subsystem request (such as `sftp`) was received from the client.
pub fn subsystem_request(session_id: u64, peer: SocketAddr, subsystem: &str, accepted: bool) {
    let (src_ip, src_port) = peer_parts(peer);
    emit!(
        info,
        "subsystem_request",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        subsystem,
        accepted,
    );
}

/// A file was uploaded via SCP or SFTP and written to the quarantine store.
/// `name` is the attacker-supplied filename, `dest` the path it was
/// materialised at in the emulated filesystem, `sha256` the hash of the
/// complete payload as it came off the wire (what an IOC lookup needs),
/// `stored_sha256` the hash of the bytes actually kept — also the quarantine
/// filename — and `stored_path` where those bytes landed on the real disk (empty
/// if the quarantine write failed). `truncated` flags uploads capped at the
/// configured size limit; the two hashes are identical unless it is set.
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
    // An attacker who got a payload onto the box is past reconnaissance, so
    // this routes with the quarantine failures rather than with the noise.
    emit!(
        warn,
        "upload",
        session_id,
        peer = %peer,
        src_ip,
        src_port,
        name,
        dest,
        size,
        sha256,
        stored_sha256,
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
            auth_attempt(1, peer(), "root", "password", Some("hunter2"), None, false);
            connection_rejected(peer(), "per_ip_limit");
            connection_closed(1, peer(), 42, 7);
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

    /// Every event carries the same envelope, and the two that a SOC should be
    /// able to page on are the two that are not INFO. Both properties are the
    /// kind that rot silently: a new event added without the envelope, or a
    /// successful login quietly demoted, breaks routing without failing
    /// anything else.
    #[test]
    fn every_event_carries_the_envelope_and_the_right_level() {
        let (_, events) = capture(|| {
            listening("0.0.0.0", 22, 100, 10);
            shutdown();
            accept_error("too many open files");
            connection_opened(1, peer());
            client_banner(1, peer(), "SSH-2.0-libssh2_1.9.0");
            auth_attempt(1, peer(), "root", "password", Some("a"), None, false);
            auth_attempt(1, peer(), "root", "password", Some("b"), None, true);
            connection_rejected(peer(), "per_ip_limit");
            command(1, peer(), "id", CommandSource::Exec, Some(0));
            download(1, peer(), "curl", "http://x/y", "-");
            subsystem_request(1, peer(), "sftp", true);
            upload(
                1,
                peer(),
                "x.sh",
                "/tmp/x.sh",
                3,
                "aa",
                "aa",
                "/q/aa",
                false,
            );
            quarantine_session_cap(1, peer());
            quarantine_error(1, peer(), "disk full");
            session_timeout(1, peer());
            connection_closed(1, peer(), 1, 1);
            log_retention_pruned(2, 30);
        });
        assert_eq!(events.len(), 17, "one line per event, every type covered");

        for event in &events {
            let f = fields(event);
            let name = &f["event"];
            assert_eq!(f["sensor_name"], "mimic", "{name}");
            assert!(f["boot_id"].is_string(), "{name}");
            assert_eq!(f["event_kind"], "event", "{name}");
            assert_eq!(f["event_category"], "intrusion_detection", "{name}");
            assert_eq!(f["event_dataset"], "mimic.ssh", "{name}");
            assert_eq!(f["ecs_version"], "8.11.0", "{name}");
        }

        let level_of = |name: &str, accepted: Option<bool>| {
            events
                .iter()
                .find(|e| {
                    fields(e)["event"] == name
                        && accepted.is_none_or(|a| fields(e)["accepted"] == a)
                })
                .map(|e| e["level"].as_str().unwrap().to_string())
                .unwrap_or_else(|| panic!("no {name} event"))
        };

        // Worth routing on: someone got in, or got a payload onto the box.
        assert_eq!(level_of("auth_attempt", Some(true)), "WARN");
        assert_eq!(level_of("upload", None), "WARN");
        // The same event that failed is background noise, and stays INFO.
        assert_eq!(level_of("auth_attempt", Some(false)), "INFO");
        assert_eq!(level_of("command", None), "INFO");
        assert_eq!(level_of("connection_opened", None), "INFO");
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
    fn subsystem_request_event_records_name_and_status() {
        let (_, events) = capture(|| {
            subsystem_request(4, peer(), "sftp", true);
            subsystem_request(4, peer(), "custom", false);
        });
        assert_eq!(events.len(), 2);
        let sftp = fields(&events[0]);
        assert_eq!(sftp["event"], "subsystem_request");
        assert_eq!(sftp["session_id"], 4);
        assert_eq!(sftp["subsystem"], "sftp");
        assert_eq!(sftp["accepted"], true);

        let custom = fields(&events[1]);
        assert_eq!(custom["event"], "subsystem_request");
        assert_eq!(custom["subsystem"], "custom");
        assert_eq!(custom["accepted"], false);
    }

    #[test]
    fn public_key_auth_records_no_password() {
        let (_, events) = capture(|| {
            auth_attempt(
                9,
                peer(),
                "admin",
                "publickey",
                None,
                Some("SHA256:abc123"),
                false,
            );
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
                None,
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
