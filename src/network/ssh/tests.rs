use super::quarantine::QUARANTINE_SESSION_MULTIPLIER;
use super::screen::{SCREEN_HOME, SCREEN_REFRESH};
use super::*;
use crate::config::AuthConfig;
use crate::network::limiter::ConnectionRegistry;
use crate::network::scp::CompletedFile;
use crate::network::sftp;
use tokio::net::TcpListener;
use tokio::time::Instant;

/// Build a `MimicHandler` wired to a real (temp-dir) quarantine store, with
/// no real network I/O involved, so `store_upload` can be exercised
/// directly.
fn test_handler(quarantine_dir: std::path::PathBuf, max_upload_bytes: u64) -> MimicHandler {
    let config = Arc::new(Config {
        quarantine_dir,
        max_upload_bytes,
        ..Config::default()
    });
    let registry = ConnectionRegistry::new(10, 10);
    let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let guard = registry.try_acquire(peer.ip()).expect("slot available");
    let shared = SharedState {
        config,
        persona: Arc::new(crate::persona::Persona::sample()),
        global_quarantine_bytes: Arc::new(AtomicU64::new(0)),
    };
    let local = "127.0.0.1:2222".parse().unwrap();
    let mut handler = MimicHandler::new(&shared, 1, peer, local, guard);
    handler.authenticated.store(true, Ordering::Relaxed);
    handler.username = "root".to_string();
    handler.scp = Some(ScpSink::new("/tmp".to_string(), false, max_upload_bytes));
    handler
}

#[test]
fn quarantine_disk_writes_are_capped_per_session() {
    let dir = std::env::temp_dir().join(format!(
        "mimic-quarantine-cap-test-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let max_upload_bytes = 1024u64;
    let mut handler = test_handler(dir.clone(), max_upload_bytes);
    let cap = max_upload_bytes * QUARANTINE_SESSION_MULTIPLIER;

    // Upload well past the cap worth of distinct (non-deduplicating) files.
    let file_size: usize = 1000;
    let num_files = (cap / file_size as u64) + 5;
    for i in 0..num_files {
        handler.store_upload(CompletedFile {
            name: format!("f{i}"),
            rel_dir: String::new(),
            mode: 0o644,
            data: vec![i as u8; file_size], // distinct content per file
            size: file_size as u64,
            payload_sha256: String::new(),
            truncated: false,
        });
    }

    let total_on_disk: u64 = std::fs::read_dir(&dir)
        .expect("quarantine dir created")
        .filter_map(|e| e.ok())
        .map(|e| e.metadata().expect("metadata").len())
        .sum();
    assert!(
        total_on_disk <= cap,
        "quarantine disk usage {total_on_disk} exceeded session cap {cap}"
    );
    assert!(
        handler.quarantine_bytes <= cap,
        "tracked quarantine_bytes {} exceeded cap {cap}",
        handler.quarantine_bytes
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sftp_quarantine_disk_writes_are_capped_per_session() {
    let dir = std::env::temp_dir().join(format!(
        "mimic-sftp-quarantine-cap-test-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let max_upload_bytes = 1024u64;
    let mut handler = test_handler(dir.clone(), max_upload_bytes);
    let cap = max_upload_bytes * QUARANTINE_SESSION_MULTIPLIER;

    let file_size: usize = 1000;
    let num_files = (cap / file_size as u64) + 5;
    for i in 0..num_files {
        handler.store_sftp_upload(sftp::SftpCompletedUpload {
            name: format!("sftp_f{i}"),
            dest_path: format!("/tmp/sftp_f{i}"),
            mode: 0o644,
            data: vec![i as u8; file_size],
            size: file_size as u64,
            payload_sha256: String::new(),
            truncated: false,
        });
    }

    let total_on_disk: u64 = std::fs::read_dir(&dir)
        .expect("quarantine dir created")
        .filter_map(|e| e.ok())
        .map(|e| e.metadata().expect("metadata").len())
        .sum();
    assert!(
        total_on_disk <= cap,
        "quarantine disk usage {total_on_disk} exceeded session cap {cap}"
    );
    assert!(
        handler.quarantine_bytes <= cap,
        "tracked quarantine_bytes {} exceeded cap {cap}",
        handler.quarantine_bytes
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quarantine_disk_writes_are_capped_globally() {
    let dir = std::env::temp_dir().join(format!(
        "mimic-quarantine-global-cap-test-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let max_upload_bytes = 1024u64;
    let global_cap = 2000u64;
    let shared_global = Arc::new(AtomicU64::new(0));

    let mut handler1 = test_handler(dir.clone(), max_upload_bytes);
    handler1.config = Arc::new(Config {
        quarantine_dir: dir.clone(),
        max_upload_bytes,
        quarantine_max_total_bytes: Some(global_cap),
        ..Config::default()
    });
    handler1.global_quarantine_bytes = Arc::clone(&shared_global);

    let mut handler2 = test_handler(dir.clone(), max_upload_bytes);
    handler2.config = Arc::new(Config {
        quarantine_dir: dir.clone(),
        max_upload_bytes,
        quarantine_max_total_bytes: Some(global_cap),
        ..Config::default()
    });
    handler2.global_quarantine_bytes = Arc::clone(&shared_global);

    // Upload in handler1
    handler1.store_upload(CompletedFile {
        name: "h1_file".to_string(),
        rel_dir: String::new(),
        mode: 0o644,
        data: vec![1u8; 1000],
        size: 1000,
        payload_sha256: String::new(),
        truncated: false,
    });

    // Upload in handler2 (second session, distinct content)
    handler2.store_upload(CompletedFile {
        name: "h2_file1".to_string(),
        rel_dir: String::new(),
        mode: 0o644,
        data: vec![2u8; 1000],
        size: 1000,
        payload_sha256: String::new(),
        truncated: false,
    });

    // Third upload in handler2 should hit global cap (1000 + 1000 + 1000 > 2000)
    handler2.store_upload(CompletedFile {
        name: "h2_file2".to_string(),
        rel_dir: String::new(),
        mode: 0o644,
        data: vec![3u8; 1000],
        size: 1000,
        payload_sha256: String::new(),
        truncated: false,
    });

    let total_on_disk: u64 = std::fs::read_dir(&dir)
        .expect("quarantine dir created")
        .filter_map(|e| e.ok())
        .map(|e| e.metadata().expect("metadata").len())
        .sum();
    assert!(
        total_on_disk <= global_cap,
        "quarantine disk usage {total_on_disk} exceeded global cap {global_cap}"
    );
    assert_eq!(total_on_disk, 2000);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `accept_after = N` accepts the Nth attempt, not the (N+1)th — the README
/// and `deploy/mimic.toml` promise an operator that exact count.
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
fn only_one_channel_is_active_at_a_time() {
    let mut handler = test_handler(std::env::temp_dir(), 1024);
    assert!(handler.try_open_channel(1));
    assert!(!handler.try_open_channel(2));

    handler.close_channel(1);
    assert!(handler.try_open_channel(2));
}

/// Minimal client that trusts whatever host key the honeypot presents.
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

/// `max_session_secs` must actually end the session, not just log that it
/// expired. The cap has to disconnect the session task explicitly: wrapping
/// the `RunningSession` in a `tokio::time::timeout` only drops its
/// `JoinHandle`, which detaches the session and leaves it serving commands
/// (and holding its connection slot) until the idle timeout.
#[tokio::test]
async fn session_cap_disconnects_a_live_session() {
    const CAP_SECS: u64 = 1;

    let dir = std::env::temp_dir().join(format!("mimic-session-cap-test-{}", std::process::id()));
    // Reserve a free port from the OS, then hand it to the listener.
    let probe = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let config = Config {
        listen_addr: "127.0.0.1".parse().expect("loopback"),
        port,
        max_session_secs: CAP_SECS,
        // Long enough that only the lifetime cap can end this session.
        idle_timeout_secs: 600,
        host_key_dir: dir.join("host_keys"),
        quarantine_dir: dir.join("quarantine"),
        ..Config::default()
    };
    tokio::spawn(async move {
        let _ = serve(Arc::new(config)).await;
    });

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = loop {
        match russh::client::connect(Arc::clone(&client_config), ("127.0.0.1", port), TestClient)
            .await
        {
            Ok(handle) => break handle,
            // The listener may not have bound yet.
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    assert!(handle
        .authenticate_password("root", "hunter2")
        .await
        .expect("auth request")
        .success());

    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel.request_shell(true).await.expect("shell request");

    // Drain the shell output; the server — not the client — must close this.
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

    let _ = std::fs::remove_dir_all(&dir);
}

/// Start a honeypot on a free port with both timeouts far away, so only the
/// session ending on its own can close a channel, and authenticate against
/// it. Returns the client handle and the temp dir to clean up.
async fn honeypot(tag: &str) -> (russh::client::Handle<TestClient>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("mimic-{tag}-test-{}", std::process::id()));
    let probe = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let config = Config {
        listen_addr: "127.0.0.1".parse().expect("loopback"),
        port,
        // Long enough that neither timeout can be what ends the session.
        idle_timeout_secs: 600,
        max_session_secs: 1800,
        host_key_dir: dir.join("host_keys"),
        quarantine_dir: dir.join("quarantine"),
        ..Config::default()
    };
    tokio::spawn(async move {
        let _ = serve(Arc::new(config)).await;
    });

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = loop {
        match russh::client::connect(Arc::clone(&client_config), ("127.0.0.1", port), TestClient)
            .await
        {
            Ok(handle) => break handle,
            // The listener may not have bound yet.
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

/// A honeypot plus an interactive shell channel with a PTY on it. Returns
/// the client handle (which must outlive the channel), the channel, and
/// the temp dir to clean up.
async fn shell_session(
    tag: &str,
) -> (
    russh::client::Handle<TestClient>,
    russh::Channel<russh::client::Msg>,
    std::path::PathBuf,
) {
    let (handle, dir) = honeypot(tag).await;
    let channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("pty request");
    channel.request_shell(true).await.expect("shell request");
    (handle, channel, dir)
}

/// Read the channel until the server closes it, returning everything it
/// sent and the exit status it reported (`None` if it sent none). Fails
/// rather than hangs if the server never closes.
async fn drain_until_closed(
    channel: &mut russh::Channel<russh::client::Msg>,
) -> (Vec<u8>, Option<u32>) {
    let (seen, _, status) = drain_streams(channel).await;
    (seen, status)
}

/// Collect whatever the server sends over `window`, then stop. Unlike
/// [`drain_until_closed`] this expects the channel to stay open, so it is
/// what a display that keeps painting has to be measured with.
async fn read_for(channel: &mut russh::Channel<russh::client::Msg>, window: Duration) -> Vec<u8> {
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

/// Drain a channel keeping the two data streams apart, as the client's own
/// stdout and stderr do.
async fn drain_streams(
    channel: &mut russh::Channel<russh::client::Msg>,
) -> (Vec<u8>, Vec<u8>, Option<u32>) {
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

/// Ctrl-D on an empty line ends the session, and a login shell says so
/// before it goes — silence there is the tell, since MIMIC's own `exit`
/// prints `logout`.
#[tokio::test]
async fn ctrl_d_logs_out_and_ends_the_session() {
    let (_handle, mut channel, dir) = shell_session("ctrl-d").await;

    channel.data(&b"\x04"[..]).await.expect("send ctrl-d");
    let (seen, status) = drain_until_closed(&mut channel).await;

    let tail = String::from_utf8_lossy(&seen);
    assert!(
        tail.ends_with("logout\r\n"),
        "expected the session to end with a logout line, got {tail:?}"
    );
    assert_eq!(status, Some(0), "missing exit status");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A client closing stdin is end-of-input to the shell: a real sshd ends
/// the session right there. Lingering until the idle timeout both looks
/// wrong and holds a connection slot for every abandoned probe.
#[tokio::test]
async fn client_eof_ends_the_session() {
    let (_handle, mut channel, dir) = shell_session("client-eof").await;

    channel.eof().await.expect("send eof");
    let (seen, status) = drain_until_closed(&mut channel).await;

    let tail = String::from_utf8_lossy(&seen);
    assert!(
        tail.ends_with("logout\r\n"),
        "expected the session to end with a logout line, got {tail:?}"
    );
    assert_eq!(status, Some(0), "missing exit status");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `exit` is the third way out of the shell, and all three have to report
/// the same status; without one `ssh` reports 255, which no real server
/// does for a shell that exited cleanly.
#[tokio::test]
async fn exit_reports_a_status() {
    let (_handle, mut channel, dir) = shell_session("shell-exit").await;

    channel.data(&b"exit 42\r"[..]).await.expect("send exit");
    let (seen, status) = drain_until_closed(&mut channel).await;

    let tail = String::from_utf8_lossy(&seen);
    assert!(
        tail.ends_with("logout\r\n"),
        "expected the session to end with a logout line, got {tail:?}"
    );
    assert_eq!(status, Some(42), "missing exit status");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A one-shot `exec` has no PTY, so a real sshd sends the command's own
/// LF-terminated bytes. Rewriting them to CRLF is a byte-comparison tell
/// for anything that diffs output against a known-good host.
#[tokio::test]
async fn exec_without_a_pty_sends_bare_lf() {
    let (handle, dir) = honeypot("exec-lf").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel.exec(true, &b"echo hello"[..]).await.expect("exec");

    let (seen, status) = drain_until_closed(&mut channel).await;

    assert_eq!(seen, b"hello\n", "exec output should be LF-terminated");
    assert_eq!(status, Some(0), "missing exit status");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `ssh -t host cmd` does ask for a PTY, and then CRLF is what a real
/// server sends — the rule is per channel, not per command path.
#[tokio::test]
async fn exec_with_a_pty_still_sends_crlf() {
    let (handle, dir) = honeypot("exec-crlf").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("pty request");
    channel.exec(true, &b"echo hello"[..]).await.expect("exec");

    let (seen, _) = drain_until_closed(&mut channel).await;

    assert_eq!(seen, b"hello\r\n", "a PTY exec should be CRLF-terminated");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A real sshd running a command without a PTY has two streams to write
/// to, and sends stderr as extended data. Putting the error on stdout is
/// visible from the client the moment it writes `2>/dev/null` — and the
/// bytes still have to be bare LF, like everything else on this channel.
#[tokio::test]
async fn exec_without_a_pty_sends_errors_as_extended_data() {
    let (handle, dir) = honeypot("exec-stderr").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel.exec(true, &b"nosuchcmd"[..]).await.expect("exec");

    let (seen, errs, status) = drain_streams(&mut channel).await;

    assert_eq!(seen, b"", "an error must not reach stdout");
    assert_eq!(errs, b"-bash: nosuchcmd: command not found\n");
    assert_eq!(status, Some(127), "missing exit status");

    let _ = std::fs::remove_dir_all(&dir);
}

/// With a PTY there is only one stream: a real sshd never sends extended
/// data on a channel that asked for a terminal, because the command's two
/// descriptors are both the tty.
#[tokio::test]
async fn a_pty_channel_sends_no_extended_data() {
    let (handle, dir) = honeypot("pty-stderr").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("pty request");
    channel.exec(true, &b"nosuchcmd"[..]).await.expect("exec");

    let (seen, errs, _) = drain_streams(&mut channel).await;

    assert_eq!(seen, b"-bash: nosuchcmd: command not found\r\n");
    assert!(errs.is_empty(), "a PTY channel has no second stream");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `ssh -T host < script` asks for a shell with no terminal. Real bash
/// finds a pipe on stdin and runs non-interactively: no readline, so no
/// prompt, no echo of the line, and none of the `\x1b[K` erase sequences
/// redrawing one needs — and no `logout`, which only an interactive login
/// shell prints. Sending any of that to a client that asked for no
/// terminal is a tell on its own.
#[tokio::test]
async fn a_shell_without_a_pty_runs_no_line_editor() {
    let (handle, dir) = honeypot("no-pty-shell").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel.request_shell(true).await.expect("shell request");
    channel
        .data(&b"echo one\nwhoami\nls /nope\nexit\n"[..])
        .await
        .expect("send script");
    channel.eof().await.expect("send eof");

    let (seen, errs, status) = drain_streams(&mut channel).await;
    let out = String::from_utf8_lossy(&seen);

    // The MOTD still arrives: it comes from the PAM session, which opens
    // whether or not a terminal was allocated.
    assert!(out.contains("Debian GNU/Linux"), "missing motd: {out:?}");
    // Everything a terminal would have added is absent.
    assert!(!out.contains("root@debian"), "prompt leaked: {out:?}");
    assert!(!out.contains("\x1b["), "erase sequence leaked: {out:?}");
    assert!(!out.contains('\r'), "CR leaked onto a channel with no pty");
    assert!(!out.contains("Last login"), "lastlog leaked: {out:?}");
    assert!(!out.contains("logout"), "logout leaked: {out:?}");
    // What the commands actually wrote is all that is left, split by
    // stream and LF-terminated.
    assert!(out.ends_with("one\nroot\n"), "unexpected output: {out:?}");
    assert_eq!(
        errs,
        b"ls: cannot access '/nope': No such file or directory\n"
    );
    // A shell that ended cleanly reports a status; without one `ssh`
    // reports 255, which no real server does.
    assert_eq!(status, Some(2), "missing exit status");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Real `top` holds the screen and repaints until `q`. One snapshot and an
/// immediate prompt is the tell this closes: the display has to keep
/// arriving with no further input, and the clock in its header has to move.
#[tokio::test]
async fn top_holds_the_screen_until_q() {
    let (_handle, mut channel, dir) = shell_session("top-hold").await;
    // Drain the login banner and first prompt.
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"top\r"[..]).await.expect("send top");
    // Long enough for the paint plus at least one timed repaint.
    let held = read_for(&mut channel, SCREEN_REFRESH + Duration::from_secs(2)).await;
    let held = String::from_utf8_lossy(&held).into_owned();

    let frames = held.matches("Tasks:").count();
    assert!(
        frames >= 2,
        "expected a repaint with no further input, saw {frames} frame(s): {held:?}"
    );
    // A full-screen program homes the cursor and erases before painting,
    // so each frame lands on top of the last instead of scrolling.
    assert!(held.contains(SCREEN_HOME), "no screen-home before a frame");
    // No prompt while the display owns the terminal.
    assert!(
        !held.contains("root@debian"),
        "prompt drawn under top: {held:?}"
    );

    // `q` quits, and the shell comes back.
    channel.data(&b"q"[..]).await.expect("send q");
    let after = read_for(&mut channel, Duration::from_millis(400)).await;
    let after = String::from_utf8_lossy(&after).into_owned();
    assert!(
        after.contains("root@debian"),
        "no prompt after q: {after:?}"
    );

    // The redraw task is gone: nothing more arrives once it has quit.
    let quiet = read_for(&mut channel, SCREEN_REFRESH + Duration::from_secs(1)).await;
    assert!(
        quiet.is_empty(),
        "the redraw timer outlived the display: {:?}",
        String::from_utf8_lossy(&quiet)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `vi` paints a read-only view of the target and holds the terminal until
/// its own quit sequence — `:` followed by `q!` and Enter — clears the
/// screen and hands the prompt back. Unlike `top` it never repaints on its
/// own: nothing further arrives while it holds.
#[tokio::test]
async fn vi_holds_the_screen_until_colon_quit() {
    let (_handle, mut channel, dir) = shell_session("vi-hold").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"echo hello > f.txt\r"[..])
        .await
        .expect("send echo");
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"vi f.txt\r"[..]).await.expect("send vi");
    let held = read_for(&mut channel, Duration::from_millis(400)).await;
    let held = String::from_utf8_lossy(&held).into_owned();
    assert!(held.contains("hello"), "file contents missing: {held:?}");
    assert!(held.contains("~\r\n"), "no filler rows: {held:?}");
    assert!(
        !held.contains("root@debian"),
        "prompt drawn under vi: {held:?}"
    );

    // `:q!` followed by Enter quits and hands the prompt back.
    channel.data(&b":q!\r"[..]).await.expect("send :q!");
    let after = read_for(&mut channel, Duration::from_millis(400)).await;
    let after = String::from_utf8_lossy(&after).into_owned();
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

    let _ = std::fs::remove_dir_all(&dir);
}

/// `nano` holds the terminal until Ctrl-X, its real quit key, rather than
/// `top`'s `q` or `vi`'s colon commands.
#[tokio::test]
async fn nano_holds_the_screen_until_ctrl_x() {
    let (_handle, mut channel, dir) = shell_session("nano-hold").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"echo hi > f.txt\r"[..])
        .await
        .expect("send echo");
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"nano f.txt\r"[..]).await.expect("send nano");
    let held = read_for(&mut channel, Duration::from_millis(400)).await;
    let held = String::from_utf8_lossy(&held).into_owned();
    assert!(held.contains("GNU nano"), "no title bar: {held:?}");
    assert!(held.contains("f.txt"), "no filename in the title: {held:?}");
    assert!(held.contains("^X Exit"), "no shortcut bar: {held:?}");
    assert!(
        !held.contains("root@debian"),
        "prompt drawn under nano: {held:?}"
    );

    channel.data(&b"\x18"[..]).await.expect("send ctrl-x");
    let after = read_for(&mut channel, Duration::from_millis(400)).await;
    let after = String::from_utf8_lossy(&after).into_owned();
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

    let _ = std::fs::remove_dir_all(&dir);
}

/// `nc -l` holds the terminal with no display of its own — a real listener
/// prints nothing before a connection arrives — and only Ctrl-C gets it
/// back, echoed the way an interrupted foreground command is rather than
/// clearing a screen that was never painted.
#[tokio::test]
async fn nc_listen_holds_the_screen_until_ctrl_c() {
    let (_handle, mut channel, dir) = shell_session("nc-listen-hold").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"nc -l 4444\r"[..])
        .await
        .expect("send nc -l");
    let held = read_for(&mut channel, Duration::from_millis(400)).await;
    let held = String::from_utf8_lossy(&held).into_owned();
    assert!(
        !held.contains("root@debian"),
        "prompt drawn while listening: {held:?}"
    );

    channel.data(&b"\x03"[..]).await.expect("send ctrl-c");
    let after = read_for(&mut channel, Duration::from_millis(400)).await;
    let after = String::from_utf8_lossy(&after).into_owned();
    assert!(after.contains("^C\r\n"), "no ^C echo: {after:?}");
    assert!(
        !after.contains(SCREEN_HOME),
        "nc -l painted nothing, so there is nothing to clear: {after:?}"
    );
    assert!(
        after.contains("root@debian"),
        "no prompt after Ctrl-C: {after:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A screen hold's kind, and `vi`'s colon-command buffer, must not survive
/// past the quit that ends it — a stale `ScreenKind` or leftover `colon`
/// state from one hold would silently misinterpret the next one's
/// keystrokes. Chains three different kinds (`Listen`, `Top`, `Editor`) end
/// to end to catch exactly that.
#[tokio::test]
async fn screen_holds_do_not_leak_state_into_the_next_one() {
    let (_handle, mut channel, dir) = shell_session("screen-hold-chain").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"nc -l 4444\r"[..])
        .await
        .expect("send nc -l");
    read_for(&mut channel, Duration::from_millis(300)).await;
    channel.data(&b"\x03"[..]).await.expect("send ctrl-c");
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"top\r"[..]).await.expect("send top");
    let held = read_for(&mut channel, Duration::from_millis(400)).await;
    let held = String::from_utf8_lossy(&held).into_owned();
    assert!(
        held.contains("Tasks:"),
        "top after nc -l should paint normally: {held:?}"
    );
    channel.data(&b"q"[..]).await.expect("send q");
    let after_top = read_for(&mut channel, Duration::from_millis(400)).await;
    let after_top = String::from_utf8_lossy(&after_top).into_owned();
    assert!(
        after_top.contains("root@debian"),
        "top after nc -l should still quit on q: {after_top:?}"
    );

    channel
        .data(&b"vi missing.txt\r"[..])
        .await
        .expect("send vi");
    let held = read_for(&mut channel, Duration::from_millis(400)).await;
    let held = String::from_utf8_lossy(&held).into_owned();
    assert!(
        held.contains("[New File]"),
        "vi after top should paint normally: {held:?}"
    );
    // `top`'s quit key alone must not also quit `vi` — only its own colon
    // command may.
    channel.data(&b"q"[..]).await.expect("send q (ignored)");
    let ignored = read_for(&mut channel, Duration::from_millis(300)).await;
    let ignored = String::from_utf8_lossy(&ignored).into_owned();
    assert!(
        !ignored.contains("root@debian"),
        "vi quit on top's key, not its own: {ignored:?}"
    );
    channel.data(&b":q!\r"[..]).await.expect("send :q!");
    let after_vi = read_for(&mut channel, Duration::from_millis(400)).await;
    let after_vi = String::from_utf8_lossy(&after_vi).into_owned();
    assert!(
        after_vi.contains("root@debian"),
        "vi after top should still quit on :q!: {after_vi:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `passwd` asks twice, and *both* answers must be collected with echo
/// suppressed. One answer leaving another prompt outstanding is the case
/// the prompt loop originally missed: it would have drawn `PS1` over the
/// second prompt, echoed the secret in clear on the attacker's terminal,
/// and then run it as a command line.
#[tokio::test]
async fn passwd_suppresses_echo_for_both_prompts() {
    let (_handle, mut channel, dir) = shell_session("passwd-echo").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel.data(&b"passwd\r"[..]).await.expect("send passwd");
    let first = read_for(&mut channel, Duration::from_millis(300)).await;
    let first = String::from_utf8_lossy(&first).into_owned();
    assert!(first.contains("New password: "), "{first:?}");

    channel.data(&b"hunter2\r"[..]).await.expect("first answer");
    let second = read_for(&mut channel, Duration::from_millis(300)).await;
    let second = String::from_utf8_lossy(&second).into_owned();
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
    let done = read_for(&mut channel, Duration::from_millis(300)).await;
    let done = String::from_utf8_lossy(&done).into_owned();
    assert!(done.contains("updated successfully"), "{done:?}");
    assert!(!done.contains("hunter2"), "the secret was echoed: {done:?}");
    // The shell comes back afterwards.
    assert!(done.contains("root@debian"), "no prompt after: {done:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A one-shot `exec` has no terminal to hold, so `ssh host top` must print
/// its dump and exit rather than hanging until the idle timeout.
#[tokio::test]
async fn exec_top_prints_once_and_exits() {
    let (handle, dir) = honeypot("exec-top").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel.exec(true, &b"top"[..]).await.expect("exec");

    let (seen, _, status) = drain_streams(&mut channel).await;
    let out = String::from_utf8_lossy(&seen);

    assert_eq!(
        out.matches("Tasks:").count(),
        1,
        "expected one dump: {out:?}"
    );
    assert!(!out.contains(SCREEN_HOME), "exec should not paint a screen");
    assert_eq!(status, Some(0));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A here-document spans lines, so the network layer has to collect them:
/// under a PTY behind bash's `PS2` continuation prompt, echoing as usual,
/// and over a pipe simply as the lines that follow. Dropping a script into
/// a file with `cat << EOF > file` is one of the most common things a bot
/// does, so the body has to reach the command and only the opening line may
/// be logged as a command.
#[tokio::test]
async fn a_heredoc_collects_its_body_under_a_pty() {
    let (_handle, mut channel, dir) = shell_session("heredoc-pty").await;
    read_for(&mut channel, Duration::from_millis(300)).await;

    channel
        .data(&b"cat << EOF > /tmp/x\r"[..])
        .await
        .expect("open");
    let prompt = read_for(&mut channel, Duration::from_millis(400)).await;
    let prompt = String::from_utf8_lossy(&prompt).into_owned();
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
    let seen = read_for(&mut channel, Duration::from_millis(500)).await;
    let seen = String::from_utf8_lossy(&seen).into_owned();
    assert!(
        seen.contains("line one\r\nline two\r\n"),
        "body did not reach the file: {seen:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same document over a channel with no terminal, where the body is
/// simply the next lines of the script.
#[tokio::test]
async fn a_heredoc_collects_its_body_over_a_pipe() {
    let (handle, dir) = honeypot("heredoc-pipe").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel.request_shell(true).await.expect("shell request");
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

    let _ = std::fs::remove_dir_all(&dir);
}

/// A one-shot `exec` can never be fed a body, so the document ends at
/// end-of-input with bash's warning rather than hanging to the idle
/// timeout.
#[tokio::test]
async fn exec_heredoc_ends_at_end_of_input() {
    let (handle, dir) = honeypot("heredoc-exec").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel.exec(true, &b"cat << EOF"[..]).await.expect("exec");

    let (seen, errs, status) = drain_streams(&mut channel).await;

    assert_eq!(seen, b"", "an empty body wrote to stdout");
    assert!(
        String::from_utf8_lossy(&errs).contains("here-document delimited by end-of-file"),
        "missing warning: {:?}",
        String::from_utf8_lossy(&errs)
    );
    assert_eq!(status, Some(0));

    let _ = std::fs::remove_dir_all(&dir);
}

/// `logout` is what an *interactive* login shell prints as it exits, so
/// `ssh host exit` — a one-shot command, never interactive — must print
/// nothing while still reporting the status.
#[tokio::test]
async fn exec_exit_prints_no_logout() {
    let (handle, dir) = honeypot("exec-exit-quiet").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .exec(true, &b"echo a; exit 3"[..])
        .await
        .expect("exec");

    let (seen, _, status) = drain_streams(&mut channel).await;

    assert_eq!(seen, b"a\n", "an exec channel announced a logout");
    assert_eq!(status, Some(3), "exit status lost");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A script whose last line has no trailing newline still runs, the way
/// bash runs what it has when the pipe reaches EOF.
#[tokio::test]
async fn a_shell_without_a_pty_runs_an_unterminated_last_line() {
    let (handle, dir) = honeypot("no-pty-partial").await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("session channel");
    channel.request_shell(true).await.expect("shell request");
    channel.data(&b"echo tail"[..]).await.expect("send script");
    channel.eof().await.expect("send eof");

    let (seen, _, status) = drain_streams(&mut channel).await;
    let out = String::from_utf8_lossy(&seen);

    assert!(out.ends_with("tail\n"), "last line did not run: {out:?}");
    assert_eq!(status, Some(0));

    let _ = std::fs::remove_dir_all(&dir);
}

/// `pty-req` is per channel. A connection that runs an interactive session
/// and then an `exec` — what an SSH ControlMaster does — must not carry the
/// first channel's line endings into the second.
#[tokio::test]
async fn a_later_exec_channel_does_not_inherit_the_pty() {
    let (handle, dir) = honeypot("exec-after-shell").await;

    let mut shell = handle
        .channel_open_session()
        .await
        .expect("session channel");
    shell
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("pty request");
    shell.request_shell(true).await.expect("shell request");
    shell.data(&b"\x04"[..]).await.expect("send ctrl-d");
    drain_until_closed(&mut shell).await;

    let mut channel = handle
        .channel_open_session()
        .await
        .expect("second session channel");
    channel.exec(true, &b"echo hello"[..]).await.expect("exec");
    let (seen, _) = drain_until_closed(&mut channel).await;

    assert_eq!(seen, b"hello\n", "the PTY leaked into a later exec channel");

    let _ = std::fs::remove_dir_all(&dir);
}
