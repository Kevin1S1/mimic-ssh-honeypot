use super::*;
use crate::logging::build_subscriber;
use serde_json::Value;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

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
        quarantine_global_cap(1, peer());
        quarantine_error(1, peer(), "disk full");
        session_timeout(1, peer());
        login_timeout(1, peer());
        connection_closed(1, peer(), 1, 1);
        log_retention_pruned(2, 30);
    });
    assert_eq!(events.len(), 19, "one line per event, every type covered");

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
                fields(e)["event"] == name && accepted.is_none_or(|a| fields(e)["accepted"] == a)
            })
            .map(|e| e["level"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("no {name} event"))
    };

    assert_eq!(level_of("auth_attempt", Some(true)), "WARN");
    assert_eq!(level_of("upload", None), "WARN");

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

    assert_eq!(events.len(), 1, "control chars must not split the record");

    let payload = raw.trim_end_matches('\n');
    assert!(!payload.contains('\r'), "carriage return must be escaped");
    assert!(!payload.contains('\u{1b}'), "escape byte must be escaped");
    assert!(!payload.contains('\u{0000}'), "NUL must be escaped");

    let auth = fields(&events[0]);
    assert_eq!(auth["username"], malicious_user);
    assert_eq!(
        auth["password"],
        "p\rass\\x1b[31mword\\x07\twith\\x00controls"
    );
}

#[test]
fn sanitise_field_escapes_terminal_control_sequences() {
    assert_eq!(sanitise_field("normal_text_123"), "normal_text_123");
    assert_eq!(sanitise_field("hello\tworld\n"), "hello\tworld\n");
    assert_eq!(
        sanitise_field("\x1b[31;1mRED\x1b[0m\x08\x07"),
        "\\x1b[31;1mRED\\x1b[0m\\x08\\x07"
    );
}
