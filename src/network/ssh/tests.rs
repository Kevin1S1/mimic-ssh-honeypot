use super::quarantine::QUARANTINE_SESSION_MULTIPLIER;
use super::screen::{SCREEN_HOME, SCREEN_REFRESH};
use super::*;
use crate::config::AuthConfig;
use crate::network::limiter::ConnectionRegistry;
use crate::network::scp::CompletedFile;
use crate::network::sftp;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use tokio::net::TcpListener;
use tokio::time::Instant;

type ClientHandle = russh::client::Handle<TestClient>;
type ClientChannel = russh::Channel<russh::client::Msg>;

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mimic-{tag}-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn handler_with(config: Config, global_quarantine_bytes: Arc<AtomicU64>) -> MimicHandler {
    let max_upload_bytes = config.max_upload_bytes;
    let registry = ConnectionRegistry::new(10, 10);
    let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let guard = registry.try_acquire(peer.ip()).expect("slot available");
    let shared = SharedState {
        config: Arc::new(config),
        persona: Arc::new(crate::persona::Persona::sample()),
        global_quarantine_bytes,
    };
    let local = "127.0.0.1:2222".parse().unwrap();
    let mut handler = MimicHandler::new(&shared, 1, peer, local, guard);
    handler.authenticated.store(true, Ordering::Relaxed);
    handler.username = "root".to_string();
    handler.scp = Some(ScpSink::new("/tmp".to_string(), false, max_upload_bytes));
    handler
}

fn test_handler(quarantine_dir: PathBuf, max_upload_bytes: u64) -> MimicHandler {
    let config = Config {
        quarantine_dir,
        max_upload_bytes,
        ..Config::default()
    };
    handler_with(config, Arc::new(AtomicU64::new(0)))
}

fn scp_file(name: &str, data: Vec<u8>) -> CompletedFile {
    CompletedFile {
        name: name.to_string(),
        rel_dir: String::new(),
        mode: 0o644,
        size: data.len() as u64,
        data,
        payload_sha256: String::new(),
        truncated: false,
    }
}

fn disk_usage(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .expect("quarantine dir created")
        .filter_map(|e| e.ok())
        .map(|e| e.metadata().expect("metadata").len())
        .sum()
}

fn assert_session_cap_holds(tag: &str, mut store: impl FnMut(&mut MimicHandler, u64, Vec<u8>)) {
    let dir = TestDir::new(tag);
    let max_upload_bytes = 1024u64;
    let mut handler = test_handler(dir.path().to_path_buf(), max_upload_bytes);
    let cap = max_upload_bytes * QUARANTINE_SESSION_MULTIPLIER;

    let file_size: usize = 1000;
    let num_files = (cap / file_size as u64) + 5;
    for i in 0..num_files {
        store(&mut handler, i, vec![i as u8; file_size]);
    }

    let total_on_disk = disk_usage(dir.path());
    assert!(
        total_on_disk <= cap,
        "quarantine disk usage {total_on_disk} exceeded session cap {cap}"
    );
    assert!(
        handler.quarantine_store.session_bytes() <= cap,
        "tracked quarantine_bytes {} exceeded cap {cap}",
        handler.quarantine_store.session_bytes()
    );
}

#[test]
fn quarantine_disk_writes_are_capped_per_session() {
    assert_session_cap_holds("quarantine-cap", |handler, i, data| {
        handler.store_upload(scp_file(&format!("f{i}"), data));
    });
}

#[test]
fn sftp_quarantine_disk_writes_are_capped_per_session() {
    assert_session_cap_holds("sftp-quarantine-cap", |handler, i, data| {
        handler.store_sftp_upload(sftp::SftpCompletedUpload {
            name: format!("sftp_f{i}"),
            dest_path: format!("/tmp/sftp_f{i}"),
            mode: 0o644,
            size: data.len() as u64,
            data,
            payload_sha256: String::new(),
            truncated: false,
        });
    });
}

#[test]
fn quarantine_disk_writes_are_capped_globally() {
    let dir = TestDir::new("quarantine-global-cap");
    let max_upload_bytes = 1024u64;
    let global_cap = 2000u64;
    let shared_global = Arc::new(AtomicU64::new(0));

    let config = || Config {
        quarantine_dir: dir.path().to_path_buf(),
        max_upload_bytes,
        quarantine_max_total_bytes: Some(global_cap),
        ..Config::default()
    };
    let mut handler1 = handler_with(config(), Arc::clone(&shared_global));
    let mut handler2 = handler_with(config(), Arc::clone(&shared_global));

    handler1.store_upload(scp_file("h1_file", vec![1u8; 1000]));
    handler2.store_upload(scp_file("h2_file1", vec![2u8; 1000]));
    handler2.store_upload(scp_file("h2_file2", vec![3u8; 1000]));

    let total_on_disk = disk_usage(dir.path());
    assert!(
        total_on_disk <= global_cap,
        "quarantine disk usage {total_on_disk} exceeded global cap {global_cap}"
    );
    assert_eq!(total_on_disk, 2000);
}

#[test]
fn a_refused_or_deduplicated_upload_releases_its_global_reservation() {
    let dir = TestDir::new("quarantine-reservation");
    let shared_global = Arc::new(AtomicU64::new(0));
    let config = Config {
        quarantine_dir: dir.path().to_path_buf(),
        max_upload_bytes: 1024,
        quarantine_max_total_bytes: Some(2000),
        ..Config::default()
    };
    let mut handler = handler_with(config, Arc::clone(&shared_global));

    handler.store_upload(scp_file("first", vec![1u8; 1000]));
    assert_eq!(shared_global.load(Ordering::Relaxed), 1000);

    handler.store_upload(scp_file("same-bytes", vec![1u8; 1000]));
    assert_eq!(
        shared_global.load(Ordering::Relaxed),
        1000,
        "a deduplicated upload writes nothing and must not hold a reservation"
    );

    handler.store_upload(scp_file("too-big", vec![2u8; 1001]));
    assert_eq!(
        shared_global.load(Ordering::Relaxed),
        1000,
        "an upload refused by the global cap must not be counted"
    );

    handler.store_upload(scp_file("fits", vec![3u8; 1000]));
    assert_eq!(shared_global.load(Ordering::Relaxed), 2000);
    assert_eq!(disk_usage(dir.path()), 2000);
}

#[test]
fn a_failed_quarantine_write_releases_its_global_reservation() {
    let dir = TestDir::new("quarantine-io-failure");
    // A regular file where the quarantine directory should be makes every
    // write fail.
    std::fs::write(dir.path(), b"not a directory").expect("blocker file");
    let shared_global = Arc::new(AtomicU64::new(0));
    let config = Config {
        quarantine_dir: dir.path().to_path_buf(),
        max_upload_bytes: 1024,
        ..Config::default()
    };
    let mut handler = handler_with(config, Arc::clone(&shared_global));

    handler.store_upload(scp_file("doomed", vec![1u8; 1000]));
    assert_eq!(shared_global.load(Ordering::Relaxed), 0);
    assert_eq!(handler.quarantine_store.session_bytes(), 0);
    let _ = std::fs::remove_file(dir.path());
}

#[test]
fn sftp_replies_are_held_until_the_peer_drains_and_the_backlog_is_capped() {
    let mut backlog = OutputBacklog::default();

    backlog.hold(vec![1, 2]);
    assert_eq!(backlog.release(true), vec![1, 2], "a draining peer gets it");
    assert!(backlog.release(true).is_empty());

    backlog.hold(vec![3]);
    backlog.hold(vec![4, 5]);
    assert!(
        backlog.release(false).is_empty(),
        "nothing more is queued behind a peer that is not reading"
    );
    assert_eq!(backlog.release(true), vec![3, 4, 5], "order is preserved");

    backlog.hold(vec![0u8; MAX_PENDING_OUTPUT_BYTES]);
    assert!(!backlog.overflowed());
    assert!(backlog.release(false).is_empty());
    backlog.hold(vec![0u8; 1]);
    assert!(
        backlog.overflowed(),
        "a peer that never drains must trip the ceiling"
    );
}

#[test]
fn the_output_meter_trips_past_the_ceiling_and_resets_when_the_peer_catches_up() {
    let mut meter = OutputMeter::default();
    let megabyte = 1024 * 1024;
    let writes_that_fit = MAX_PENDING_OUTPUT_BYTES / (megabyte + QUEUED_WRITE_OVERHEAD_BYTES);

    for _ in 0..writes_that_fit {
        assert!(meter.charge(megabyte), "output under the ceiling passes");
    }
    assert!(!meter.charge(megabyte), "an unread peer is cut off");

    meter.peer_caught_up();
    assert!(meter.charge(megabyte), "a peer that reads starts over");
}

#[test]
fn the_output_meter_charges_each_write_more_than_its_payload() {
    let mut meter = OutputMeter::default();
    let one_byte_writes = MAX_PENDING_OUTPUT_BYTES / (1 + QUEUED_WRITE_OVERHEAD_BYTES);

    for _ in 0..one_byte_writes {
        assert!(meter.charge(1));
    }
    assert!(
        !meter.charge(1),
        "tiny writes are bounded by their queue cost, not their payload"
    );
}

#[test]
fn accept_after_grants_on_the_nth_attempt() {
    let mut handler = test_handler(std::env::temp_dir(), 1024);
    handler.config = Arc::new(Config {
        auth: AuthConfig {
            mode: AuthMode::AcceptAfter,
            accept_after: 2,
            credentials: Vec::new(),
        },
        ..Config::default()
    });

    let mut decisions = Vec::new();
    for _ in 0..3 {
        handler.auth_attempts += 1;
        decisions.push(handler.decide_auth("root", "hunter2"));
    }
    assert_eq!(decisions, vec![false, true, true]);
}

#[test]
fn motd_is_the_stock_debian_banner() {
    let handler = test_handler(std::env::temp_dir(), 1024);
    let expected = format!(
        "Linux {} 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64\n\
         \n\
         The programs included with the Debian GNU/Linux system are free software;\n\
         the exact distribution terms for each program are described in the\n\
         individual files in /usr/share/doc/*/copyright.\n\
         \n\
         Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\n\
         permitted by applicable law.\n",
        handler.config.hostname
    );
    assert_eq!(handler.motd(), expected);
}

#[test]
fn only_one_channel_is_active_at_a_time() {
    let mut handler = test_handler(std::env::temp_dir(), 1024);
    assert!(handler.try_open_channel(1));
    assert!(!handler.try_open_channel(2));

    handler.close_channel(1);
    assert!(handler.try_open_channel(2));
}

struct TestClient;

impl russh::client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn honeypot_with(tag: &str, max_session_secs: u64) -> (ClientHandle, TestDir) {
    honeypot_for(tag, max_session_secs, russh::client::Config::default()).await
}

async fn honeypot_for(
    tag: &str,
    max_session_secs: u64,
    client_config: russh::client::Config,
) -> (ClientHandle, TestDir) {
    let dir = TestDir::new(tag);
    let probe = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let config = Config {
        listen_addr: "127.0.0.1".parse().expect("loopback"),
        port,

        idle_timeout_secs: 600,
        max_session_secs,
        host_key_dir: dir.path().join("host_keys"),
        quarantine_dir: dir.path().join("quarantine"),
        ..Config::default()
    };
    tokio::spawn(async move {
        let _ = serve(Arc::new(config)).await;
    });

    let client_config = Arc::new(client_config);
    let mut handle = loop {
        match russh::client::connect(Arc::clone(&client_config), ("127.0.0.1", port), TestClient)
            .await
        {
            Ok(handle) => break handle,

            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    assert!(handle
        .authenticate_password("root", "hunter2")
        .await
        .expect("auth request")
        .success());
    (handle, dir)
}

async fn honeypot(tag: &str) -> (ClientHandle, TestDir) {
    honeypot_with(tag, 1800).await
}

async fn open_channel(handle: &ClientHandle) -> ClientChannel {
    handle
        .channel_open_session()
        .await
        .expect("session channel")
}

async fn request_pty(channel: &ClientChannel) {
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("pty request");
}

async fn shell_session(tag: &str) -> (ClientHandle, ClientChannel, TestDir) {
    let (handle, dir) = honeypot(tag).await;
    let channel = open_channel(&handle).await;
    request_pty(&channel).await;
    channel.request_shell(true).await.expect("shell request");
    (handle, channel, dir)
}

async fn pipe_shell_session(tag: &str) -> (ClientHandle, ClientChannel, TestDir) {
    let (handle, dir) = honeypot(tag).await;
    let channel = open_channel(&handle).await;
    channel.request_shell(true).await.expect("shell request");
    (handle, channel, dir)
}

async fn exec_session(
    tag: &str,
    command: &[u8],
    pty: bool,
) -> (ClientHandle, ClientChannel, TestDir) {
    let (handle, dir) = honeypot(tag).await;
    let channel = open_channel(&handle).await;
    if pty {
        request_pty(&channel).await;
    }
    channel.exec(true, command).await.expect("exec");
    (handle, channel, dir)
}

async fn drain_until_closed(channel: &mut ClientChannel) -> (Vec<u8>, Option<u32>) {
    let (seen, _, status) = drain_streams(channel).await;
    (seen, status)
}

async fn read_for(channel: &mut ClientChannel, window: Duration) -> Vec<u8> {
    let mut seen = Vec::new();
    let _ = tokio::time::timeout(window, async {
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::Data { ref data } = msg {
                seen.extend_from_slice(data);
            }
        }
    })
    .await;
    seen
}

async fn read_text(channel: &mut ClientChannel, window: Duration) -> String {
    String::from_utf8_lossy(&read_for(channel, window).await).into_owned()
}

async fn drain_streams(channel: &mut ClientChannel) -> (Vec<u8>, Vec<u8>, Option<u32>) {
    let mut seen = Vec::new();
    let mut errs = Vec::new();
    let mut status = None;
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => seen.extend_from_slice(data),
                russh::ChannelMsg::ExtendedData { ref data, ext }
                    if ext == SSH_EXTENDED_DATA_STDERR =>
                {
                    errs.extend_from_slice(data)
                }
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
    })
    .await
    .expect("server closed the session");
    (seen, errs, status)
}

#[tokio::test]
async fn session_cap_disconnects_a_live_session() {
    const CAP_SECS: u64 = 1;

    let (handle, _dir) = honeypot_with("session-cap", CAP_SECS).await;
    let mut channel = open_channel(&handle).await;
    channel.request_shell(true).await.expect("shell request");

    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(15), async {
        while channel.wait().await.is_some() {}
    })
    .await
    .expect("session outlived max_session_secs");

    assert!(
        started.elapsed() >= Duration::from_secs(CAP_SECS).saturating_sub(Duration::from_millis(200)),
        "session ended after {:?}, before the {CAP_SECS}s cap — something other than the cap closed it",
        started.elapsed()
    );
}

#[tokio::test]
async fn ctrl_d_logs_out_and_ends_the_session() {
    let (_handle, mut channel, _dir) = shell_session("ctrl-d").await;

    channel.data(&b"\x04"[..]).await.expect("send ctrl-d");
    let (seen, status) = drain_until_closed(&mut channel).await;

    let tail = String::from_utf8_lossy(&seen);
    assert!(
        tail.ends_with("logout\r\n"),
        "expected the session to end with a logout line, got {tail:?}"
    );
    assert_eq!(status, Some(0), "missing exit status");
}

#[tokio::test]
async fn client_eof_ends_the_session() {
    let (_handle, mut channel, _dir) = shell_session("client-eof").await;

    channel.eof().await.expect("send eof");
    let (seen, status) = drain_until_closed(&mut channel).await;

    let tail = String::from_utf8_lossy(&seen);
    assert!(
        tail.ends_with("logout\r\n"),
        "expected the session to end with a logout line, got {tail:?}"
    );
    assert_eq!(status, Some(0), "missing exit status");
}

#[tokio::test]
async fn exit_reports_a_status() {
    let (_handle, mut channel, _dir) = shell_session("shell-exit").await;

    channel.data(&b"exit 42\r"[..]).await.expect("send exit");
    let (seen, status) = drain_until_closed(&mut channel).await;

    let tail = String::from_utf8_lossy(&seen);
    assert!(
        tail.ends_with("logout\r\n"),
        "expected the session to end with a logout line, got {tail:?}"
    );
    assert_eq!(status, Some(42), "missing exit status");
}

#[tokio::test]
async fn exec_without_a_pty_sends_bare_lf() {
    let (_handle, mut channel, _dir) = exec_session("exec-lf", b"echo hello", false).await;

    let (seen, status) = drain_until_closed(&mut channel).await;

    assert_eq!(seen, b"hello\n", "exec output should be LF-terminated");
    assert_eq!(status, Some(0), "missing exit status");
}

#[tokio::test]
async fn exec_with_a_pty_still_sends_crlf() {
    let (_handle, mut channel, _dir) = exec_session("exec-crlf", b"echo hello", true).await;

    let (seen, _) = drain_until_closed(&mut channel).await;

    assert_eq!(seen, b"hello\r\n", "a PTY exec should be CRLF-terminated");
}

#[tokio::test]
async fn exec_without_a_pty_sends_errors_as_extended_data() {
    let (_handle, mut channel, _dir) = exec_session("exec-stderr", b"nosuchcmd", false).await;

    let (seen, errs, status) = drain_streams(&mut channel).await;

    assert_eq!(seen, b"", "an error must not reach stdout");
    assert_eq!(errs, b"-bash: nosuchcmd: command not found\n");
    assert_eq!(status, Some(127), "missing exit status");
}

#[tokio::test]
async fn a_pty_channel_sends_no_extended_data() {
    let (_handle, mut channel, _dir) = exec_session("pty-stderr", b"nosuchcmd", true).await;

    let (seen, errs, _) = drain_streams(&mut channel).await;

    assert_eq!(seen, b"-bash: nosuchcmd: command not found\r\n");
    assert!(errs.is_empty(), "a PTY channel has no second stream");
}

#[tokio::test]
async fn a_shell_without_a_pty_runs_no_line_editor() {
    let (_handle, mut channel, _dir) = pipe_shell_session("no-pty-shell").await;
    channel
        .data(&b"echo one\nwhoami\nls /nope\nexit\n"[..])
        .await
        .expect("send script");
    channel.eof().await.expect("send eof");

    let (seen, errs, status) = drain_streams(&mut channel).await;
    let out = String::from_utf8_lossy(&seen);

    assert!(out.contains("Debian GNU/Linux"), "missing motd: {out:?}");

    assert!(!out.contains("root@debian"), "prompt leaked: {out:?}");
    assert!(!out.contains("\x1b["), "erase sequence leaked: {out:?}");
    assert!(!out.contains('\r'), "CR leaked onto a channel with no pty");
    assert!(!out.contains("Last login"), "lastlog leaked: {out:?}");
    assert!(!out.contains("logout"), "logout leaked: {out:?}");

    assert!(out.ends_with("one\nroot\n"), "unexpected output: {out:?}");
    assert_eq!(
        errs,
        b"ls: cannot access '/nope': No such file or directory\n"
    );

    assert_eq!(status, Some(2), "missing exit status");
}

const NEAR_OUTPUT_CAP: &[u8] = b"seq 1 150000\n";

async fn output_of_one_capped_command(tag: &str) -> usize {
    let (_handle, mut channel, _dir) = exec_session(tag, NEAR_OUTPUT_CAP, false).await;
    let (seen, status) = drain_until_closed(&mut channel).await;
    assert_eq!(status, Some(0));
    seen.len()
}

fn lines_past_the_ceiling(bytes_per_line: usize) -> usize {
    MAX_PENDING_OUTPUT_BYTES / bytes_per_line + 3
}

#[tokio::test]
async fn exec_output_near_the_cap_arrives_whole() {
    let len = output_of_one_capped_command("cap-exec").await;
    assert!(
        len > 900 * 1024,
        "the probe should sit near the 1 MiB cap, got {len}"
    );
}

#[tokio::test]
async fn a_peer_that_keeps_reading_gets_more_output_than_the_ceiling() {
    let one = output_of_one_capped_command("cap-reading").await;
    let lines = lines_past_the_ceiling(one);
    let (_handle, mut channel, _dir) = pipe_shell_session("reading-peer").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    let mut seen = 0;
    for sent in 1..=lines {
        channel.data(NEAR_OUTPUT_CAP).await.expect("send line");
        while seen < sent * one {
            let msg = channel.wait().await.expect("channel stays open");
            if let russh::ChannelMsg::Data { ref data } = msg {
                seen += data.len();
            }
        }
    }
    channel.eof().await.expect("send eof");
    let (_, status) = drain_until_closed(&mut channel).await;

    assert!(seen > MAX_PENDING_OUTPUT_BYTES, "only {seen} bytes seen");
    assert_eq!(status, Some(0), "a peer that keeps reading is not cut off");
}

#[tokio::test]
async fn output_piled_up_faster_than_the_peer_can_read_drops_the_connection() {
    let one = output_of_one_capped_command("cap-unread").await;
    let lines = lines_past_the_ceiling(one);
    let (_handle, mut channel, _dir) = pipe_shell_session("unread-output").await;

    let script = NEAR_OUTPUT_CAP.repeat(lines);
    channel.data(&script[..]).await.expect("send script");

    let mut seen = 0;
    let mut status = None;
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => seen += data.len(),
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
    })
    .await
    .expect("server dropped the connection");

    assert_eq!(status, None, "the session was cut off, not finished");
    assert!(
        seen < lines * one,
        "the whole script's output must not have been queued: {seen}"
    );
}

#[tokio::test]
async fn top_holds_the_screen_until_q() {
    let (_handle, mut channel, _dir) = shell_session("top-hold").await;

    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"top\r"[..]).await.expect("send top");

    let held = read_text(&mut channel, SCREEN_REFRESH + Duration::from_secs(2)).await;

    let frames = held.matches("Tasks:").count();
    assert!(
        frames >= 2,
        "expected a repaint with no further input, saw {frames} frame(s): {held:?}"
    );

    assert!(held.contains(SCREEN_HOME), "no screen-home before a frame");

    assert!(
        !held.contains("root@debian"),
        "prompt drawn under top: {held:?}"
    );

    channel.data(&b"q"[..]).await.expect("send q");
    let after = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(
        after.contains("root@debian"),
        "no prompt after q: {after:?}"
    );

    let quiet = read_for(&mut channel, SCREEN_REFRESH + Duration::from_secs(1)).await;
    assert!(
        quiet.is_empty(),
        "the redraw timer outlived the display: {:?}",
        String::from_utf8_lossy(&quiet)
    );
}

#[tokio::test]
async fn vi_holds_the_screen_until_colon_quit() {
    let (_handle, mut channel, _dir) = shell_session("vi-hold").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"echo hello > f.txt\r"[..])
        .await
        .expect("send echo");
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"vi f.txt\r"[..]).await.expect("send vi");
    let held = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(held.contains("hello"), "file contents missing: {held:?}");
    assert!(held.contains("~\r\n"), "no filler rows: {held:?}");
    assert!(
        !held.contains("root@debian"),
        "prompt drawn under vi: {held:?}"
    );

    channel.data(&b":q!\r"[..]).await.expect("send :q!");
    let after = read_text(&mut channel, Duration::from_millis(400)).await;
    let clear_at = after.find(SCREEN_HOME);
    let prompt_at = after.find("root@debian");
    assert!(
        clear_at.is_some(),
        "vi should clear the screen on the way out: {after:?}"
    );
    assert!(prompt_at.is_some(), "no prompt after :q!: {after:?}");
    assert!(
        clear_at < prompt_at,
        "screen not cleared before the prompt: {after:?}"
    );
    assert!(
        !after.contains("~\r\n"),
        "vi's buffer view leaked past the quit: {after:?}"
    );
}

#[tokio::test]
async fn nano_holds_the_screen_until_ctrl_x() {
    let (_handle, mut channel, _dir) = shell_session("nano-hold").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"echo hi > f.txt\r"[..])
        .await
        .expect("send echo");
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"nano f.txt\r"[..]).await.expect("send nano");
    let held = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(held.contains("GNU nano"), "no title bar: {held:?}");
    assert!(held.contains("f.txt"), "no filename in the title: {held:?}");
    assert!(held.contains("^X Exit"), "no shortcut bar: {held:?}");
    assert!(
        !held.contains("root@debian"),
        "prompt drawn under nano: {held:?}"
    );

    channel.data(&b"\x18"[..]).await.expect("send ctrl-x");
    let after = read_text(&mut channel, Duration::from_millis(400)).await;
    let clear_at = after.find(SCREEN_HOME);
    let prompt_at = after.find("root@debian");
    assert!(
        clear_at.is_some(),
        "nano should clear the screen on the way out: {after:?}"
    );
    assert!(prompt_at.is_some(), "no prompt after ^X: {after:?}");
    assert!(
        clear_at < prompt_at,
        "screen not cleared before the prompt: {after:?}"
    );
}

#[tokio::test]
async fn nc_listen_holds_the_screen_until_ctrl_c() {
    let (_handle, mut channel, _dir) = shell_session("nc-listen-hold").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"nc -l 4444\r"[..])
        .await
        .expect("send nc -l");
    let held = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(
        !held.contains("root@debian"),
        "prompt drawn while listening: {held:?}"
    );

    channel.data(&b"\x03"[..]).await.expect("send ctrl-c");
    let after = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(after.contains("^C\r\n"), "no ^C echo: {after:?}");
    assert!(
        !after.contains(SCREEN_HOME),
        "nc -l painted nothing, so there is nothing to clear: {after:?}"
    );
    assert!(
        after.contains("root@debian"),
        "no prompt after Ctrl-C: {after:?}"
    );
}

#[tokio::test]
async fn screen_holds_do_not_leak_state_into_the_next_one() {
    let (_handle, mut channel, _dir) = shell_session("screen-hold-chain").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"nc -l 4444\r"[..])
        .await
        .expect("send nc -l");
    read_for(&mut channel, Duration::from_millis(300)).await;
    channel.data(&b"\x03"[..]).await.expect("send ctrl-c");
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"top\r"[..]).await.expect("send top");
    let held = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(
        held.contains("Tasks:"),
        "top after nc -l should paint normally: {held:?}"
    );
    channel.data(&b"q"[..]).await.expect("send q");
    let after_top = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(
        after_top.contains("root@debian"),
        "top after nc -l should still quit on q: {after_top:?}"
    );

    channel
        .data(&b"vi missing.txt\r"[..])
        .await
        .expect("send vi");
    let held = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(
        held.contains("[New File]"),
        "vi after top should paint normally: {held:?}"
    );

    channel.data(&b"q"[..]).await.expect("send q (ignored)");
    let ignored = read_text(&mut channel, Duration::from_millis(300)).await;
    assert!(
        !ignored.contains("root@debian"),
        "vi quit on top's key, not its own: {ignored:?}"
    );
    channel.data(&b":q!\r"[..]).await.expect("send :q!");
    let after_vi = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(
        after_vi.contains("root@debian"),
        "vi after top should still quit on :q!: {after_vi:?}"
    );
}

#[tokio::test]
async fn passwd_suppresses_echo_for_both_prompts() {
    let (_handle, mut channel, _dir) = shell_session("passwd-echo").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"passwd\r"[..]).await.expect("send passwd");
    let first = read_text(&mut channel, Duration::from_millis(300)).await;
    assert!(first.contains("New password: "), "{first:?}");

    channel.data(&b"hunter2\r"[..]).await.expect("first answer");
    let second = read_text(&mut channel, Duration::from_millis(300)).await;
    assert!(
        second.contains("Retype new password: "),
        "second prompt missing: {second:?}"
    );
    assert!(
        !second.contains("hunter2"),
        "the first answer was echoed: {second:?}"
    );
    assert!(
        !second.contains("root@debian"),
        "PS1 was drawn over the second prompt: {second:?}"
    );

    channel
        .data(&b"hunter2\r"[..])
        .await
        .expect("second answer");
    let done = read_text(&mut channel, Duration::from_millis(300)).await;
    assert!(done.contains("updated successfully"), "{done:?}");
    assert!(!done.contains("hunter2"), "the secret was echoed: {done:?}");

    assert!(done.contains("root@debian"), "no prompt after: {done:?}");
}

#[tokio::test]
async fn exec_top_prints_once_and_exits() {
    let (_handle, mut channel, _dir) = exec_session("exec-top", b"top", false).await;

    let (seen, _, status) = drain_streams(&mut channel).await;
    let out = String::from_utf8_lossy(&seen);

    assert_eq!(
        out.matches("Tasks:").count(),
        1,
        "expected one dump: {out:?}"
    );
    assert!(!out.contains(SCREEN_HOME), "exec should not paint a screen");
    assert_eq!(status, Some(0));
}

#[tokio::test]
async fn a_heredoc_collects_its_body_under_a_pty() {
    let (_handle, mut channel, _dir) = shell_session("heredoc-pty").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"cat << EOF > /tmp/x\r"[..])
        .await
        .expect("open");
    let prompt = read_text(&mut channel, Duration::from_millis(400)).await;
    assert!(prompt.contains("> "), "no PS2 continuation: {prompt:?}");
    assert!(
        !prompt.contains("root@debian"),
        "drew PS1 mid-document: {prompt:?}"
    );

    channel
        .data(&b"line one\rline two\rEOF\r"[..])
        .await
        .expect("body");
    read_for(&mut channel, Duration::from_millis(400)).await;

    channel.data(&b"cat /tmp/x\r"[..]).await.expect("read back");
    let seen = read_text(&mut channel, Duration::from_millis(500)).await;
    assert!(
        seen.contains("line one\r\nline two\r\n"),
        "body did not reach the file: {seen:?}"
    );
}

#[tokio::test]
async fn a_heredoc_collects_its_body_over_a_pipe() {
    let (_handle, mut channel, _dir) = pipe_shell_session("heredoc-pipe").await;
    channel
        .data(&b"cat << EOF\npayload\nEOF\necho after\n"[..])
        .await
        .expect("send script");
    channel.eof().await.expect("send eof");

    let (seen, _, status) = drain_streams(&mut channel).await;
    let out = String::from_utf8_lossy(&seen);

    assert!(out.ends_with("payload\nafter\n"), "unexpected: {out:?}");
    assert!(
        !out.contains("> "),
        "a PS2 leaked onto a channel with no pty"
    );
    assert_eq!(status, Some(0));
}

#[tokio::test]
async fn exec_heredoc_ends_at_end_of_input() {
    let (_handle, mut channel, _dir) = exec_session("heredoc-exec", b"cat << EOF", false).await;

    let (seen, errs, status) = drain_streams(&mut channel).await;

    assert_eq!(seen, b"", "an empty body wrote to stdout");
    assert!(
        String::from_utf8_lossy(&errs).contains("here-document delimited by end-of-file"),
        "missing warning: {:?}",
        String::from_utf8_lossy(&errs)
    );
    assert_eq!(status, Some(0));
}

#[tokio::test]
async fn exec_exit_prints_no_logout() {
    let (_handle, mut channel, _dir) =
        exec_session("exec-exit-quiet", b"echo a; exit 3", false).await;

    let (seen, _, status) = drain_streams(&mut channel).await;

    assert_eq!(seen, b"a\n", "an exec channel announced a logout");
    assert_eq!(status, Some(3), "exit status lost");
}

#[tokio::test]
async fn a_shell_without_a_pty_runs_an_unterminated_last_line() {
    let (_handle, mut channel, _dir) = pipe_shell_session("no-pty-partial").await;
    channel.data(&b"echo tail"[..]).await.expect("send script");
    channel.eof().await.expect("send eof");

    let (seen, _, status) = drain_streams(&mut channel).await;
    let out = String::from_utf8_lossy(&seen);

    assert!(out.ends_with("tail\n"), "last line did not run: {out:?}");
    assert_eq!(status, Some(0));
}

#[tokio::test]
async fn a_later_exec_channel_does_not_inherit_the_pty() {
    let (handle, _dir) = honeypot("exec-after-shell").await;

    let mut shell = open_channel(&handle).await;
    request_pty(&shell).await;
    shell.request_shell(true).await.expect("shell request");
    shell.data(&b"\x04"[..]).await.expect("send ctrl-d");
    drain_until_closed(&mut shell).await;

    let mut channel = open_channel(&handle).await;
    channel.exec(true, &b"echo hello"[..]).await.expect("exec");
    let (seen, _) = drain_until_closed(&mut channel).await;

    assert_eq!(seen, b"hello\n", "the PTY leaked into a later exec channel");
}

#[tokio::test]
async fn sleep_holds_the_reply_back_for_its_interval() {
    const NAP: Duration = Duration::from_millis(700);

    let (handle, _dir) = honeypot("sleep-delay").await;
    let mut channel = open_channel(&handle).await;

    let started = Instant::now();
    channel
        .exec(true, &b"sleep 0.7; echo awake"[..])
        .await
        .expect("exec");
    let (seen, status) = drain_until_closed(&mut channel).await;

    assert_eq!(seen, b"awake\n");
    assert_eq!(status, Some(0));
    assert!(
        started.elapsed() >= NAP,
        "`sleep 0.7` returned after only {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_sleep_cannot_outlast_the_session_cap() {
    const CAP_SECS: u64 = 2;

    let (handle, _dir) = honeypot_with("sleep-cap", CAP_SECS).await;
    let mut channel = open_channel(&handle).await;
    channel.request_shell(false).await.expect("shell request");

    channel
        .data(&b"sleep 20\nsleep 20\nsleep 20\n"[..])
        .await
        .expect("queued sleeps");
    tokio::time::timeout(Duration::from_secs(15), async {
        while channel.wait().await.is_some() {}
    })
    .await
    .expect("queued sleeps kept the session alive past max_session_secs");
}

#[test]
fn the_shell_pid_follows_the_persona_and_the_session() {
    let dir = TestDir::new("shell-pid");
    let mut handler = test_handler(dir.path().to_path_buf(), 1024);

    let first = handler.shell().pid;
    assert_eq!(first, handler.persona.shell_pid(1));
    assert_eq!(
        handler.shell().execute("echo $$").stdout.trim(),
        first.to_string()
    );

    handler.session_id = 2;
    handler.shell = None;
    assert!(
        handler.shell().pid > first,
        "a later session should get a higher PID"
    );
}

fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| name.to_string()).collect()
}

fn spelled<N: AsRef<str>>(names: &[N]) -> Vec<String> {
    names.iter().map(|name| name.as_ref().to_string()).collect()
}

// Expected lists: `ssh -vv` against a stock Debian 12 sshd, less what russh
// lacks (sntrup761x25519-sha512@openssh.com and the umac-* MACs).
#[test]
fn the_algorithm_proposal_is_that_of_openssh_9_2_on_debian() {
    let prefs = server::debian_openssh_preferred();

    assert_eq!(
        spelled(&prefs.kex),
        owned(&[
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
            "kex-strict-s-v00@openssh.com",
        ])
    );
    assert_eq!(
        prefs.key.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        owned(&[
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ecdsa-sha2-nistp256",
            "ssh-ed25519",
        ])
    );
    assert_eq!(
        spelled(&prefs.cipher),
        owned(&[
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
        ])
    );
    assert_eq!(
        spelled(&prefs.mac),
        owned(&[
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1",
        ])
    );
    assert_eq!(
        spelled(&prefs.compression),
        owned(&["none", "zlib@openssh.com"])
    );
}

#[tokio::test]
async fn the_newly_advertised_algorithms_actually_negotiate() {
    use russh::keys::{Algorithm, EcdsaCurve};
    use std::borrow::Cow;

    let client_config = russh::client::Config {
        preferred: russh::Preferred {
            kex: Cow::Borrowed(&[russh::kex::DH_GEX_SHA256]),
            key: Cow::Owned(vec![Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            }]),
            cipher: Cow::Borrowed(&[russh::cipher::AES_128_GCM]),
            ..russh::Preferred::DEFAULT
        },
        ..russh::client::Config::default()
    };
    let (handle, _dir) = honeypot_for("new-algos", 1800, client_config).await;
    let mut channel = open_channel(&handle).await;
    channel.exec(true, &b"echo hello"[..]).await.expect("exec");

    let (seen, status) = drain_until_closed(&mut channel).await;
    assert_eq!(seen, b"hello\n");
    assert_eq!(status, Some(0));
}

#[test]
fn the_ecdsa_host_key_is_served_but_does_not_move_the_persona() {
    use russh::keys::Algorithm;

    let dir = TestDir::new("ecdsa-hostkey");
    let keys = crate::network::hostkey::load_or_create(dir.path()).expect("host keys");
    let is_ecdsa =
        |key: &russh::keys::PrivateKey| matches!(key.algorithm(), Algorithm::Ecdsa { .. });
    assert!(keys.iter().any(is_ecdsa));

    let files = server::host_key_files(&keys);
    assert!(files.iter().any(|(name, line)| {
        name == "ssh_host_ecdsa_key.pub" && line.starts_with("ecdsa-sha2-nistp256 ")
    }));

    let before_ecdsa: Vec<_> = keys.iter().filter(|key| !is_ecdsa(key)).cloned().collect();
    assert_eq!(before_ecdsa.len(), keys.len() - 1);
    assert_eq!(
        server::persona_seed(&keys, "sensor"),
        server::persona_seed(&before_ecdsa, "sensor"),
        "adding the ECDSA key must not change an existing sensor's persona"
    );
}
