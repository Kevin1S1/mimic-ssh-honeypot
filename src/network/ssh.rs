//! SSH protocol engine built on `russh`.
//!
//! Drives the handshake, credential capture, and a full interactive
//! line-editing shell over the emulated Debian filesystem. SCP uploads are
//! intercepted, content-addressed, and quarantined. The only real I/O in this
//! file is host-key persistence and the quarantine store; everything the
//! attacker "runs" is a pure in-memory state machine.

use crate::config::{AuthMode, Config};
use crate::logging::event;
use crate::logging::event::CommandSource;
use crate::network::limiter::{ConnectionGuard, ConnectionRegistry};
use crate::network::scp::{self, ScpMode, ScpSink};
use crate::network::sftp::{self, SftpSession};
use crate::shell::complete::{self, Completion};
use crate::shell::line::{is_continuation, LineEditor, Reaction};
use crate::shell::{Capture, Output, Shell};

use anyhow::{Context, Result};
use russh::server::{Auth, Config as ServerConfig, Handler, Msg, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet};
// What `Handle::data` takes, reached through russh's own re-export so this
// stays free of a direct `bytes` dependency.
use russh::keys::ssh_encoding::bytes::Bytes;
use sha2::{Digest, Sha256};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::Instant;

/// Maximum bytes accepted for a single command line, on both the interactive
/// path (line editor buffer) and the one-shot `exec` path. Without the exec
/// cap, a client could ship a command bounded only by the SSH packet limit
/// straight into the logs and parser.
const MAX_COMMAND_LEN: usize = 4096;

/// What a login shell prints when it reaches end-of-input, matching the `exit`
/// builtin's own output. Line endings are applied by [`MimicHandler::out`].
const LOGOUT: &str = "logout\n";

/// The `data_type_code` RFC 4254 §5.2 assigns to stderr — the only one defined.
const SSH_EXTENDED_DATA_STDERR: u32 = 1;

/// Build the russh server config and serve connections forever.
pub async fn serve(config: Arc<Config>) -> Result<()> {
    // Persist host keys so the server fingerprint stays stable across restarts.
    let host_keys = super::hostkey::load_or_create(&config.host_key_dir)?;

    // This deployment's fabricated hardware identity, seeded from the host key
    // so it is stable across restarts (like the fingerprint) but different on
    // every sensor. Reading the key material is real I/O and belongs here; the
    // persona itself is pure data the emulation layers consume.
    let persona = Arc::new(
        crate::persona::Persona::from_seed(persona_seed(&host_keys, &config.sensor_name))
            .with_host_keys(host_key_files(&host_keys)),
    );

    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    methods.push(MethodKind::PublicKey);

    let server_config = Arc::new(ServerConfig {
        server_id: russh::SshId::Standard(std::borrow::Cow::Owned(config.server_id.clone())),
        methods,
        // Algorithm ordering trimmed to resemble Debian 12 OpenSSH 9.2's
        // server offer (no sntrup761, umac, or group-exchange).
        preferred: debian_openssh_preferred(),
        auth_rejection_time: Duration::from_secs(2),
        // NOT a fingerprint, despite how it reads: russh applies this only to
        // the `none` probe every client sends first to discover auth methods
        // (see `initial_auth_until` in russh's `server::encrypted`). Real sshd
        // answers that probe immediately; password and publickey rejections
        // still take the full two seconds. Without it every connection would
        // stall 2s before the password prompt, which *would* be a tell.
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        // Debian 12 sshd defaults to `MaxAuthTries 6`; russh defaults to 10.
        // A client that keeps getting prompted past six is a one-connection
        // honeypot check.
        max_auth_attempts: crate::config::MAX_AUTH_ATTEMPTS as usize,
        inactivity_timeout: Some(Duration::from_secs(config.idle_timeout_secs)),
        keys: host_keys,
        ..Default::default()
    });

    // Connection caps are enforced at accept time, before any crypto state is
    // allocated, so a connection flood is shed cheaply.
    let registry = ConnectionRegistry::new(config.max_sessions, config.per_ip_connections);
    let session_counter = Arc::new(AtomicU64::new(1));

    let listener = TcpListener::bind((config.listen_addr, config.port))
        .await
        .with_context(|| format!("binding {}:{}", config.listen_addr, config.port))?;

    event::listening(
        &config.listen_addr.to_string(),
        config.port,
        config.max_sessions,
        config.per_ip_connections,
    );

    loop {
        let accepted = tokio::select! {
            // Returning on a termination signal is what lets `main` unwind and
            // drop the logging `WorkerGuard`, which is the only thing that
            // flushes the file appender's buffered lines. Without it the
            // process is killed where it stands and whatever is still in the
            // appender's channel is lost — on every `docker restart` /
            // `systemctl restart`, which `deploy/daily-reset.sh` performs
            // daily by design.
            () = shutdown_signal() => {
                event::shutdown();
                return Ok(());
            }
            result = listener.accept() => result,
        };

        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                // Transient accept errors (e.g. fd exhaustion) shouldn't kill
                // the listener; back off briefly and keep serving.
                event::accept_error(&err.to_string());
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        // Reserve a slot, or drop the connection if a limit is reached.
        let guard = match registry.try_acquire(peer.ip()) {
            Ok(guard) => guard,
            Err(reason) => {
                event::connection_rejected(peer, reason.as_str());
                drop(stream);
                continue;
            }
        };

        let session_id = session_counter.fetch_add(1, Ordering::Relaxed);
        event::connection_opened(session_id, peer);

        let local = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::new(config.listen_addr, config.port));

        let handler = MimicHandler {
            config: Arc::clone(&config),
            persona: Arc::clone(&persona),
            session_id,
            peer,
            local,
            pty: false,
            auth_attempts: 0,
            username: String::new(),
            editor: LineEditor::new(MAX_COMMAND_LEN, 1000),
            shell_started: false,
            shell: None,
            active_channel: None,
            scp: None,
            sftp: None,
            quarantine_bytes: 0,
            password_buf: None,
            line_buf: Vec::new(),
            screen: None,
            pty_term: None,
            accepted_env: Vec::new(),
            banner_logged: false,
            opened_at: std::time::Instant::now(),
            command_count: 0,
            _guard: guard,
        };

        let server_config = Arc::clone(&server_config);
        let deadline = Instant::now() + Duration::from_secs(config.max_session_secs);
        tokio::spawn(async move {
            match russh::server::run_stream(server_config, stream, handler).await {
                Ok(session) => {
                    // Bound the absolute session lifetime, independent of the
                    // idle timeout, so no connection can be held open forever.
                    // The cap has to ask the session to disconnect: a
                    // `RunningSession` only wraps the session task's
                    // `JoinHandle`, so dropping it (as a `timeout` would)
                    // detaches that task and leaves the session — and the
                    // connection slot its handler holds — running.
                    let watchdog = tokio::spawn({
                        let handle = session.handle();
                        async move {
                            tokio::time::sleep_until(deadline).await;
                            event::session_timeout(session_id, peer);
                            let _ = handle
                                .disconnect(Disconnect::ByApplication, String::new(), String::new())
                                .await;
                        }
                    });

                    if let Err(err) = session.await {
                        tracing::debug!(
                            event = "session_error",
                            session_id,
                            error = %err,
                        );
                    }
                    watchdog.abort();
                }
                Err(err) => {
                    tracing::debug!(
                        event = "handshake_error",
                        session_id,
                        error = %err,
                    );
                }
            }
        });
    }
}

/// This deployment's `/etc/ssh/*.pub` files, taken from the keys actually being
/// served.
///
/// Only public halves: `to_openssh` on a `PublicKey` emits exactly the line a
/// real `.pub` file holds, which every client already receives during the key
/// exchange. Fabricating these instead would be a contradiction an attacker can
/// check with one `ssh-keygen -lf` against the fingerprint their own client
/// recorded.
fn host_key_files(keys: &[russh::keys::PrivateKey]) -> Vec<(String, String)> {
    keys.iter()
        .filter_map(|key| {
            let public = key.public_key();
            let stem = match public.algorithm() {
                russh::keys::Algorithm::Ed25519 => "ssh_host_ed25519_key",
                russh::keys::Algorithm::Rsa { .. } => "ssh_host_rsa_key",
                russh::keys::Algorithm::Ecdsa { .. } => "ssh_host_ecdsa_key",
                _ => return None,
            };
            let line = public.to_openssh().ok()?;
            Some((format!("{stem}.pub"), format!("{line}\n")))
        })
        .collect()
}

/// Derive this deployment's persona seed from its host keys and sensor name.
///
/// The host key is already the thing that must not change between restarts, so
/// binding the emulated hardware to it gives the persona the same stability for
/// free — and two sensors never share a key, so they never share an identity.
fn persona_seed(keys: &[russh::keys::PrivateKey], sensor_name: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"mimic-persona-v1");
    hasher.update(sensor_name.as_bytes());
    for key in keys {
        // The *public* half is enough to be unique per deployment, and keeps
        // private key material out of every derived value.
        if let Ok(blob) = key.public_key().to_openssh() {
            hasher.update(blob.as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(seed)
}

/// Resolve once the process is asked to stop.
///
/// SIGTERM is what `docker stop` and `systemctl restart` send, so it is the
/// signal that matters for a clean flush; Ctrl-C is handled too for a honeypot
/// run in the foreground. On non-Unix (a development platform only) there is no
/// SIGTERM, so Ctrl-C is the whole story.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            // Without a handler the default disposition still terminates the
            // process; we simply lose the clean flush. Not worth refusing to
            // serve over.
            Err(err) => {
                tracing::warn!(event = "signal_handler_error", error = %err);
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Algorithm preference list shaped to resemble a stock Debian 12 OpenSSH 9.2
/// server. Algorithms OpenSSH offers but russh does not implement
/// (`sntrup761x25519-sha512`, `diffie-hellman-group-exchange-sha256`, `umac-*`)
/// are necessarily absent; the relative ordering of what remains is preserved.
fn debian_openssh_preferred() -> russh::Preferred {
    use std::borrow::Cow;
    russh::Preferred {
        kex: Cow::Borrowed(&[
            russh::kex::CURVE25519,
            russh::kex::CURVE25519_PRE_RFC_8731,
            russh::kex::ECDH_SHA2_NISTP256,
            russh::kex::ECDH_SHA2_NISTP384,
            russh::kex::ECDH_SHA2_NISTP521,
            russh::kex::DH_G16_SHA512,
            russh::kex::DH_G14_SHA256,
            // Server-side protocol extension markers, as real OpenSSH advertises.
            russh::kex::EXTENSION_SUPPORT_AS_SERVER,
            russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
        ]),
        cipher: Cow::Borrowed(&[
            russh::cipher::CHACHA20_POLY1305,
            russh::cipher::AES_128_CTR,
            russh::cipher::AES_192_CTR,
            russh::cipher::AES_256_CTR,
            russh::cipher::AES_256_GCM,
        ]),
        mac: Cow::Borrowed(&[
            russh::mac::HMAC_SHA256_ETM,
            russh::mac::HMAC_SHA512_ETM,
            russh::mac::HMAC_SHA1_ETM,
            russh::mac::HMAC_SHA256,
            russh::mac::HMAC_SHA512,
            russh::mac::HMAC_SHA1,
        ]),
        ..russh::Preferred::DEFAULT
    }
}

/// Per-connection handler holding connection state and credentials captured
/// during the SSH handshake.
struct MimicHandler {
    /// Shared runtime configuration (auth policy, hostname, ...).
    config: Arc<Config>,
    session_id: u64,
    peer: SocketAddr,
    /// Local end of the accepted socket, reported to the session as
    /// `SSH_CLIENT`/`SSH_CONNECTION` the way a real sshd does.
    local: SocketAddr,
    /// Whether the client asked for a PTY; a real sshd only sets `SSH_TTY` when
    /// one was allocated.
    pty: bool,
    auth_attempts: u32,
    username: String,
    /// Interactive readline-style editor (cursor, history, completion) for the
    /// PTY session.
    editor: LineEditor,
    /// Whether the active channel is running the interactive shell. A real
    /// login shell reacts to end-of-input; an `exec` or SCP channel has no
    /// shell to log out of, so the two must not be confused.
    shell_started: bool,
    /// The emulated shell, created lazily once a session channel opens.
    shell: Option<Shell>,
    /// Only one channel may use the connection-scoped shell/editor state at a
    /// time. Sequential channels are allowed after the active one closes.
    active_channel: Option<u32>,
    /// Active SCP upload sink, when the channel is running `scp -t`.
    scp: Option<ScpSink>,
    /// Active SFTP session, when the channel requested the `sftp` subsystem.
    sftp: Option<SftpSession>,
    /// Cumulative bytes this session has written to the real-disk quarantine
    /// store. Bounds disk growth from a flood of distinct small uploads (the
    /// content-addressed dedup only bounds *repeated* payloads).
    quarantine_bytes: u64,
    /// When `Some`, the shell is waiting on a password line (e.g. after `su`):
    /// input bytes are collected here with echo suppressed until Enter, then
    /// handed to [`Shell::resume`].
    password_buf: Option<Vec<u8>>,
    /// Input collected on a shell channel with no PTY, where there is no line
    /// editor to hold it. Bounded by [`MAX_COMMAND_LEN`] like every other path
    /// that accepts a command line.
    line_buf: Vec<u8>,
    /// The redraw task of a full-screen command holding the terminal (`top`).
    /// While it is `Some`, input goes to the display rather than the editor.
    screen: Option<ScreenHold>,
    /// The terminal type, width, and height the client asked for in `pty-req`.
    /// Real sshd exports these into the session; inventing our own values while
    /// echoing back `channel_success` is a one-command tell.
    pty_term: Option<PtyRequest>,
    /// Locale variables the client sent with `env` requests and the server
    /// accepted. Applied when the shell is built, the way a real sshd does.
    accepted_env: Vec<(String, String)>,
    /// Whether the client's SSH identification string has been logged yet. The
    /// banner is only reachable once a `Session` is in hand, so it is emitted
    /// at the first channel rather than at accept time.
    banner_logged: bool,
    /// When this connection was accepted, for the `connection_closed` summary.
    opened_at: std::time::Instant,
    /// How many `command` events this session has emitted.
    command_count: u64,
    /// This deployment's fabricated hardware identity, handed to every shell
    /// this connection builds.
    persona: Arc<crate::persona::Persona>,
    /// Holds this connection's slot in the global/per-IP limiter; releasing it
    /// on drop frees the slot for the next connection.
    _guard: ConnectionGuard,
}

/// What the client asked for in `pty-req`, kept so the session environment can
/// reflect it rather than inventing a terminal the client never requested.
struct PtyRequest {
    term: String,
    cols: u32,
    rows: u32,
}

/// How often a full-screen command repaints. Real `top`'s default delay.
const SCREEN_REFRESH: Duration = Duration::from_secs(3);

/// Move the cursor home and erase what is below it — what a full-screen program
/// sends before painting a frame, so each redraw lands on top of the last.
const SCREEN_HOME: &str = "\x1b[H\x1b[J";

/// A full-screen command holding the terminal. Dropping this aborts the redraw
/// task, so the timer cannot outlive the channel it paints — closing the
/// channel, ending the session, or quitting the display all stop it.
struct ScreenHold {
    redraw: tokio::task::JoinHandle<()>,
}

impl Drop for ScreenHold {
    fn drop(&mut self) {
        self.redraw.abort();
    }
}

/// Per-session ceiling on real-disk quarantine writes, as a multiple of
/// `max_upload_bytes`. Bounds one session's disk footprint to a fixed multiple
/// of its largest single allowed upload, closing the gap where many distinct
/// small files could otherwise grow the quarantine store without limit for the
/// duration of a session.
const QUARANTINE_SESSION_MULTIPLIER: u64 = 32;

impl MimicHandler {
    fn try_open_channel(&mut self, channel: u32) -> bool {
        if self.active_channel.is_some() {
            return false;
        }
        self.active_channel = Some(channel);
        true
    }

    /// Finalise any SFTP write handles that never received `SSH_FXP_CLOSE`,
    /// storing and logging what they hold.
    ///
    /// Every path that ends an SFTP transfer routes through here — a clean
    /// `channel_eof`, a channel close, and the handler's own `Drop`. Only the
    /// last of those is guaranteed to run: `channel_close` is a protocol message
    /// russh never delivers when the peer sends a reset or simply vanishes, and
    /// `channel_eof` additionally requires the client to half-close cleanly. A
    /// transfer cut short by the session watchdog, the idle timeout, or a
    /// dropped socket is exactly the case where the payload matters most, so it
    /// must not be the case where it is discarded.
    fn drain_sftp_uploads(&mut self) {
        let Some(sftp) = self.sftp.take() else {
            return;
        };
        // No shell means nothing was ever fed to the subsystem, so there is
        // nothing in flight to recover.
        let uploads = match self.shell.as_mut() {
            Some(shell) => sftp.into_pending_uploads(shell),
            None => return,
        };
        for upload in uploads {
            self.store_sftp_upload(upload);
        }
    }

    fn close_channel(&mut self, channel: u32) {
        if self.active_channel == Some(channel) {
            // Before the shell is torn down: the drain writes into its VFS.
            self.drain_sftp_uploads();
            self.active_channel = None;
            self.editor = LineEditor::new(MAX_COMMAND_LEN, 1000);
            self.shell = None;
            self.scp = None;
            self.sftp = None;
            self.password_buf = None;
            self.line_buf.clear();
            // Dropping the hold aborts its redraw task, so a timer never
            // outlives the channel it was painting.
            self.screen = None;
            self.shell_started = false;
            // `pty-req` is per channel: a connection that runs an interactive
            // session and then an `exec` must not carry the PTY's line endings
            // (or `SSH_TTY`) into the second channel.
            self.pty = false;
        }
    }

    /// Tear the channel down the way a finished session does: report the
    /// command's exit status, end-of-file, close, and release the
    /// connection-scoped shell state for the next one. Every path that ends a
    /// channel goes through here, so none of them can forget the status — a
    /// channel closed without one makes `ssh` report 255.
    fn end_channel(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        status: u32,
    ) -> Result<(), russh::Error> {
        session.exit_status_request(channel, status)?;
        session.eof(channel)?;
        session.close(channel)?;
        self.close_channel(channel.number());
        Ok(())
    }

    /// Encode server output for this channel. A PTY turns the shell's `\n`
    /// into `\r\n`; without one, a real sshd passes the bytes through
    /// unchanged, so `ssh host cmd` must not gain carriage returns.
    fn out(&self, text: &str) -> Vec<u8> {
        if self.pty {
            text.replace('\n', "\r\n").into_bytes()
        } else {
            text.as_bytes().to_vec()
        }
    }

    /// Write a finished command line's output to the channel.
    ///
    /// With a PTY both streams share the terminal, so a real sshd has only the
    /// data channel to write to. Without one they stay apart: stdout on the
    /// data channel and stderr as `SSH_EXTENDED_DATA_STDERR`, so
    /// `ssh host nosuchcmd 2>/dev/null` prints nothing.
    fn write_output(
        &self,
        channel: ChannelId,
        output: &Output,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if self.pty {
            if !output.text.is_empty() {
                session.data(channel, self.out(&output.text))?;
            }
            return Ok(());
        }
        if !output.stdout.is_empty() {
            session.data(channel, self.out(&output.stdout))?;
        }
        if !output.stderr.is_empty() {
            session.extended_data(channel, SSH_EXTENDED_DATA_STDERR, self.out(&output.stderr))?;
        }
        Ok(())
    }

    /// Emit what one completed line produced and end the channel if the line
    /// finished the session. Returns whether the session ended.
    async fn deliver(
        &mut self,
        channel: ChannelId,
        output: &Output,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        self.drain_captures();
        // Response latency scaled by how much this command produced, so the
        // timing profile correlates with workload the way a real shell's does.
        jitter_for(output.text.len() + output.stdout.len() + output.stderr.len()).await;
        self.write_output(channel, output, session)?;
        if output.exit {
            self.end_channel(channel, session, output.status as u32)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Run one submitted command line, logging it as the session's next
    /// command. Returns whether the session ended.
    async fn submit_line(
        &mut self,
        channel: ChannelId,
        line: &str,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            self.shell().record_history(&trimmed);
        }
        let result = self.shell().execute(&trimmed);
        // A line that only opened a here-document is logged when the document
        // closes, with its body: the body is the payload, and a capture
        // holding `cat << EOF > drop.sh` without the script is worth little.
        let parked = self.shell().pending.as_ref().is_some_and(|p| p.echoes());
        if !trimmed.is_empty() && !parked {
            let source = if self.pty {
                CommandSource::Interactive
            } else {
                CommandSource::Pipe
            };
            self.log_command(&trimmed, source, Some(result.status));
        }
        self.deliver(channel, &result, session).await
    }

    /// Log a here-document that has just closed, as the single command it is.
    fn log_closed_heredoc(&mut self) {
        if let Some(text) = self.shell().heredoc_log.take() {
            self.log_command(&text, CommandSource::Heredoc, None);
        }
    }

    /// Emit one `command` event and count it toward the session summary.
    ///
    /// Every command log goes through here so the count on `connection_closed`
    /// cannot drift from the number of events actually emitted.
    fn log_command(&mut self, text: &str, source: CommandSource, status: Option<i32>) {
        self.command_count += 1;
        event::command(self.session_id, self.peer, text, source, status);
    }

    /// Take over the terminal with a full-screen display, repainting it every
    /// [`SCREEN_REFRESH`] until the client quits.
    ///
    /// The emulation layers own no clock, so the display arrives as a value
    /// that can render itself at any instant and the timer lives here. The task
    /// holds a session handle rather than a borrow of the shell, and stops on
    /// the first write that fails — which is what a closed session looks like
    /// from the outside — so it cannot outlive the connection even if nothing
    /// aborts it first.
    fn hold_screen(
        &mut self,
        channel: ChannelId,
        screen: crate::commands::system::TopScreen,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let first = format!("{SCREEN_HOME}{}", screen.render());
        session.data(channel, self.out(&first))?;
        let handle = session.handle();
        let pty = self.pty;
        let redraw = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SCREEN_REFRESH);
            // The first tick fires immediately; the frame above is that one.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let frame = format!("{SCREEN_HOME}{}", screen.render());
                let bytes = if pty {
                    frame.replace('\n', "\r\n").into_bytes()
                } else {
                    frame.into_bytes()
                };
                if handle.data(channel, Bytes::from(bytes)).await.is_err() {
                    return;
                }
            }
        });
        self.screen = Some(ScreenHold { redraw });
        Ok(())
    }

    /// Feed a keystroke to a display holding the terminal. Returns whether the
    /// display is still up.
    ///
    /// Real `top` quits on `q`, and Ctrl-C kills it like any foreground job;
    /// every other key is consumed by the display rather than echoed, which is
    /// the whole point of holding the screen.
    fn screen_input(&mut self, byte: u8) -> bool {
        match byte {
            b'q' | 0x03 => {
                // Dropping the hold aborts the redraw task.
                self.screen = None;
                false
            }
            _ => true,
        }
    }

    /// Feed input to a shell channel that never asked for a PTY.
    ///
    /// Real bash checks whether its input is a terminal and, finding a pipe,
    /// runs non-interactively: no readline, so no prompt, no echo of what was
    /// typed, and none of the `\x1b[K` erase sequences redrawing a line needs.
    /// It simply reads a line and runs it. Sending any of that to a client that
    /// asked for no terminal is a tell on its own.
    async fn feed_no_tty(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        for &byte in data {
            match byte {
                // A client piping a file sends bare LF; tolerate a CRLF one.
                b'\r' => {}
                b'\n' => {
                    let line = String::from_utf8_lossy(&std::mem::take(&mut self.line_buf))
                        .trim_end_matches('\r')
                        .to_string();
                    if self.run_no_tty_line(channel, &line, session).await? {
                        return Ok(());
                    }
                }
                // Bounded like every other path that accepts a command line;
                // past the cap the rest of the line is dropped, exactly as an
                // oversized `exec` request is truncated.
                _ => {
                    if self.line_buf.len() < MAX_COMMAND_LEN {
                        self.line_buf.push(byte);
                    }
                }
            }
        }
        Ok(())
    }

    /// Run one line read without a terminal, routing it to a pending prompt
    /// (e.g. `su` waiting on a password) when there is one. Returns whether the
    /// session ended.
    async fn run_no_tty_line(
        &mut self,
        channel: ChannelId,
        line: &str,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        if self.shell().pending.is_some() {
            // The prompt was written to the channel; with no terminal there is
            // no echo to suppress, so the next line is simply the answer.
            let output = self.shell().resume(line);
            self.log_closed_heredoc();
            return self.deliver(channel, &output, session).await;
        }
        self.submit_line(channel, line, session).await
    }

    /// Apply the configured authentication policy to one attempt.
    fn decide_auth(&self, user: &str, password: &str) -> bool {
        match self.config.auth.mode {
            AuthMode::AcceptAll => true,
            AuthMode::RejectAll => false,
            AuthMode::AcceptAfter => self.auth_attempts >= self.config.auth.accept_after,
            AuthMode::Credentials => self
                .config
                .auth
                .credentials
                .iter()
                .any(|c| c.username == user && c.password == password),
        }
    }

    /// Emit the client's SSH identification string, once per connection.
    ///
    /// `remote_sshid` is only reachable through a `Session`, which the auth
    /// callbacks do not receive — so the earliest hook is the first channel
    /// request. A scanner that disconnects before opening a channel is not
    /// recorded, which is the ceiling of doing this without patching russh.
    fn log_client_banner(&mut self, session: &Session) {
        if self.banner_logged {
            return;
        }
        self.banner_logged = true;
        let banner = String::from_utf8_lossy(session.remote_sshid()).into_owned();
        if !banner.is_empty() {
            event::client_banner(self.session_id, self.peer, &banner);
        }
    }

    /// Borrow the session shell, creating it on first use from the captured
    /// username and configured hostname.
    fn shell(&mut self) -> &mut Shell {
        if self.shell.is_none() {
            let mut shell = Shell::with_persona(
                &self.username,
                &self.config.hostname,
                (*self.persona).clone(),
            );
            // Every real sshd exports the connection details into the session
            // environment; a shell without them is a one-line honeypot tell.
            // The values are the client's own address and the socket it dialled,
            // so they stay consistent with anything the attacker can check.
            let (peer_ip, peer_port) = (self.peer.ip(), self.peer.port());
            shell.env.set(
                "SSH_CLIENT",
                &format!("{peer_ip} {peer_port} {}", self.local.port()),
            );
            shell.env.set(
                "SSH_CONNECTION",
                &format!(
                    "{peer_ip} {peer_port} {} {}",
                    self.local.ip(),
                    self.local.port()
                ),
            );
            if self.pty {
                // Matches the `tty` command; unset for exec, like a real sshd.
                shell.env.set("SSH_TTY", "/dev/pts/0");
            }
            // What the client asked for in `pty-req`, not what we would have
            // picked. `echo $TERM` returning a terminal the client never named
            // is a one-command tell.
            if let Some(pty) = self.pty_term.as_ref() {
                shell.env.set("TERM", &pty.term);
                shell.env.set("COLUMNS", &pty.cols.to_string());
                shell.env.set("LINES", &pty.rows.to_string());
            }
            // Locale variables the client sent and `env_request` accepted.
            for (key, value) in &self.accepted_env {
                shell.env.set(key, value);
            }
            self.shell = Some(shell);
        }
        self.shell.as_mut().expect("shell just initialised")
    }

    /// Compute and apply a tab-completion for the word at the cursor. Returns
    /// the bytes to send to the client (empty if nothing to do).
    fn complete_current_word(&mut self) -> Vec<u8> {
        let (word, is_command) = self.editor.current_word();
        let completion = {
            let shell = self.shell();
            complete::complete(shell, &word, is_command)
        };
        match completion {
            Completion::None => Vec::new(),
            Completion::Single {
                replacement,
                add_space,
            } => self.editor.apply_completion(&replacement, add_space),
            Completion::Listing(items) => {
                let listing = format_columns(&items);
                self.editor.show_listing(&listing)
            }
        }
    }

    /// The message-of-the-day shown after a successful login. The leading
    /// kernel line mirrors Debian's `/etc/update-motd.d/10-uname` output. Line
    /// endings are applied by [`MimicHandler::out`], like any other output.
    fn motd(&self) -> String {
        format!(
            "Linux {host} 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64\n\
             \n\
             The programs included with the Debian GNU/Linux system are free software;\n\
             the exact distribution terms for each program are described in the\n\
             individual files in /usr/share/doc/*/copyright.\n\
             \n\
             Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\n\
             permitted by applicable law.\n",
            host = self.config.hostname,
        )
    }

    /// Drain and log any captures (downloads) the last command produced.
    fn drain_captures(&mut self) {
        let (session_id, peer) = (self.session_id, self.peer);
        let captures = std::mem::take(&mut self.shell().captures);
        for capture in captures {
            match capture {
                Capture::Download { tool, url, dest } => {
                    event::download(session_id, peer, &tool, &url, &dest);
                }
                Capture::ScriptCommand { line, status } => {
                    // A line out of a dropped script, not one the client typed.
                    // Without this the log shows `sh /tmp/x.sh` and nothing of
                    // what it did — which is the intelligence running the body
                    // exists to recover.
                    self.log_command(&line, CommandSource::Script, Some(status));
                }
                Capture::PasswordChange { target, password } => {
                    // A password set non-interactively. Logged as an auth event
                    // so credential dashboards pick it up alongside guesses —
                    // this is the secret the attacker chose, which is at least
                    // as interesting as the ones they tried.
                    event::auth_attempt(
                        session_id,
                        peer,
                        &target,
                        "chpasswd",
                        Some(&password),
                        None,
                        true,
                    );
                }
                Capture::SuAuth { target, password } => {
                    // A guessed password entered at an `su` prompt: log it as an
                    // authentication attempt (accepted, matching the switch).
                    event::auth_attempt(
                        session_id,
                        peer,
                        &target,
                        "su",
                        Some(&password),
                        None,
                        true,
                    );
                }
            }
        }
    }

    /// Persist one SCP-uploaded file: write it into the session VFS, copy it to
    /// the quarantine store on the real filesystem, and emit an `upload` event.
    fn store_upload(&mut self, file: scp::CompletedFile) {
        let (session_id, peer) = (self.session_id, self.peer);
        let quarantine_dir = self.config.quarantine_dir.clone();

        // Content-address the captured bytes so identical payloads dedupe and
        // the attacker-supplied filename never influences the stored path. This
        // hashes what is stored; `file.payload_sha256` covers the whole upload,
        // and the two differ once the cap truncates it.
        let mut hasher = Sha256::new();
        hasher.update(&file.data);
        let stored_sha256 = hex(&hasher.finalize());

        // Resolve the destination path inside the emulated filesystem.
        let target = self
            .scp
            .as_ref()
            .map(|s| s.target().to_string())
            .unwrap_or_else(|| "/tmp".to_string());
        let recursive = self.scp.as_ref().map(|s| s.recursive()).unwrap_or(false);
        let dest_path = self.write_to_vfs(&target, recursive, &file);

        // Write to the quarantine store (real I/O is permitted in this layer),
        // unless this session has already hit its cumulative disk-write cap.
        // The VFS mirror above is unaffected — it has its own independent
        // node/byte caps — so the attacker's session still looks consistent.
        let cap = self
            .config
            .max_upload_bytes
            .saturating_mul(QUARANTINE_SESSION_MULTIPLIER);
        let stored_path = if self.quarantine_bytes.saturating_add(file.data.len() as u64) > cap {
            event::quarantine_session_cap(session_id, peer);
            String::new()
        } else {
            match write_quarantine(&quarantine_dir, &stored_sha256, &file.data) {
                Ok((p, written)) => {
                    self.quarantine_bytes += written;
                    p
                }
                Err(err) => {
                    event::quarantine_error(session_id, peer, &err.to_string());
                    String::new()
                }
            }
        };

        event::upload(
            session_id,
            peer,
            &file.name,
            &dest_path,
            file.size,
            &file.payload_sha256,
            &stored_sha256,
            &stored_path,
            file.truncated,
        );
    }

    /// Persist one SFTP-uploaded file: copy it to the quarantine store on the
    /// real filesystem, and emit an `upload` event. (The file is already written
    /// to the session VFS during SFTP close).
    fn store_sftp_upload(&mut self, upload: sftp::SftpCompletedUpload) {
        let (session_id, peer) = (self.session_id, self.peer);
        let quarantine_dir = self.config.quarantine_dir.clone();

        let mut hasher = Sha256::new();
        hasher.update(&upload.data);
        let stored_sha256 = hex(&hasher.finalize());

        let cap = self
            .config
            .max_upload_bytes
            .saturating_mul(QUARANTINE_SESSION_MULTIPLIER);
        let stored_path = if self
            .quarantine_bytes
            .saturating_add(upload.data.len() as u64)
            > cap
        {
            event::quarantine_session_cap(session_id, peer);
            String::new()
        } else {
            match write_quarantine(&quarantine_dir, &stored_sha256, &upload.data) {
                Ok((p, written)) => {
                    self.quarantine_bytes += written;
                    p
                }
                Err(err) => {
                    event::quarantine_error(session_id, peer, &err.to_string());
                    String::new()
                }
            }
        };

        event::upload(
            session_id,
            peer,
            &upload.name,
            &upload.dest_path,
            upload.size,
            &upload.payload_sha256,
            &stored_sha256,
            &stored_path,
            upload.truncated,
        );
    }

    /// Materialise an uploaded file in the session VFS, returning its absolute
    /// path. Best-effort: failures are non-fatal for the honeypot.
    fn write_to_vfs(&mut self, target: &str, recursive: bool, file: &scp::CompletedFile) -> String {
        let (uid, gid) = (self.shell().uid, self.shell().gid);
        let cwd = self.shell().cwd;

        // Determine the directory the file lands in and its final name.
        let (dir_path, name): (String, String) = {
            let shell = self.shell();
            let target_abs = abs_path(&shell.vfs.path_of(cwd), target);
            let mut base = target_abs.clone();
            if !file.rel_dir.is_empty() {
                base = format!("{}/{}", base.trim_end_matches('/'), file.rel_dir);
            }

            let target_is_dir = shell
                .vfs
                .resolve(cwd, &base)
                .map(|id| shell.vfs.node(id).meta.is_dir())
                .unwrap_or(false);

            if target_is_dir || target.ends_with('/') || recursive || !file.rel_dir.is_empty() {
                (base, file.name.clone())
            } else {
                // Target names the file itself.
                let (d, n) = crate::vfs::Vfs::split_path(base.trim_end_matches('/'));
                (d.to_string(), n.to_string())
            }
        };

        let shell = self.shell();
        let parent = shell.vfs.mkdir_p(&dir_path, 0o755, uid, gid);
        let id = shell.vfs.add_file(
            parent,
            &name,
            file.data.clone(),
            file.mode & 0o7777,
            uid,
            gid,
        );
        shell.vfs.path_of(id)
    }
}

/// Hex-encode a byte slice.
pub(super) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Resolve `path` against `cwd` into an absolute path string (no VFS lookup).
fn abs_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{path}")
    } else {
        format!("{cwd}/{path}")
    }
}

/// Write `data` to `<dir>/<sha256>` (deduplicating by content hash), creating
/// `dir` if needed. Returns `(stored_path, newly_written_bytes)`. Files are created
/// non-executable and owner-read/write only (`0600`) at creation time so a
/// captured payload can never be run from the quarantine store and is never
/// briefly world/group-readable between the write and a chmod.
fn write_quarantine(
    dir: &std::path::Path,
    sha256: &str,
    data: &[u8],
) -> std::io::Result<(String, u64)> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(sha256);
    // Content-addressed store: identical payloads dedupe. `create_new` also
    // closes the exists()-then-write TOCTOU — if a concurrent session already
    // stored the same bytes, `AlreadyExists` is success, not an error.
    // Write to a scratch name and rename into place, so the store's invariant —
    // the filename is the SHA-256 of the contents — holds even if the write
    // fails partway. A direct write that dies on ENOSPC would leave a truncated
    // file under a valid hash name, and every later upload of the same payload
    // would then take the `AlreadyExists` path and report that corrupt file as
    // successfully stored. `rename` is atomic on both target platforms.
    let newly_written = if path.exists() {
        0
    } else {
        let staging = dir.join(format!("{sha256}.partial"));
        // A concurrent session storing the same payload is using the same
        // staging name; `create_new` makes exactly one of them the writer and
        // the other falls back to the dedup path below.
        match create_restricted(&staging) {
            Ok(mut file) => {
                let result = file.write_all(data).and_then(|()| file.sync_all());
                drop(file);
                if let Err(e) = result {
                    let _ = std::fs::remove_file(&staging);
                    return Err(e);
                }
                match std::fs::rename(&staging, &path) {
                    Ok(()) => data.len() as u64,
                    Err(e) => {
                        let _ = std::fs::remove_file(&staging);
                        return Err(e);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => 0,
            Err(e) => return Err(e),
        }
    };
    let stored = path.to_string_lossy().into_owned();
    // `Path::join` appends a backslash on Windows, so a forward-slash
    // `quarantine_dir` from the config yields `C:/data\ab12…` — one logged
    // path in two separator styles. Normalise so `stored_path` is a usable
    // key. Windows-only: a backslash is a legal filename byte on Unix.
    #[cfg(windows)]
    let stored = stored.replace('\\', "/");
    Ok((stored, newly_written))
}

/// Create `path` for writing with owner-only (`0600`) permissions set at
/// creation time on Unix, failing if it already exists.
#[cfg(unix)]
fn create_restricted(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_restricted(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

impl Handler for MimicHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.auth_attempts += 1;
        let accepted = self.decide_auth(user, password);

        event::auth_attempt(
            self.session_id,
            self.peer,
            user,
            "password",
            Some(password),
            None,
            accepted,
        );

        if accepted {
            self.username = user.to_string();
            jitter_for(0).await;
            Ok(Auth::Accept)
        } else {
            jitter_for(0).await;
            // Keep offering the password method so the client re-prompts.
            // With `proceed_with_methods: None`, russh removes `password` from
            // the offered set on rejection, leaving only `publickey` — the
            // client then aborts after one wrong password with
            // "Permission denied (publickey)", an obvious honeypot tell. Real
            // sshd re-prompts (up to MaxAuthTries), which is also required for
            // `accept_after` to ever see a second attempt on one connection.
            let mut proceed_with_methods = MethodSet::empty();
            proceed_with_methods.push(MethodKind::Password);
            Ok(Auth::Reject {
                proceed_with_methods: Some(proceed_with_methods),
                partial_success: false,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_attempts += 1;
        // The offered key is intelligence in its own right: campaigns reuse key
        // material, so the fingerprint pivots across sessions and sensors in a
        // way a sprayed password does not.
        let fingerprint = key.fingerprint(Default::default()).to_string();
        event::auth_attempt(
            self.session_id,
            self.peer,
            user,
            "publickey",
            None,
            Some(&fingerprint),
            false,
        );

        // Reject public-key auth so clients fall back to password, which we can
        // capture in cleartext.
        let mut proceed_with_methods = MethodSet::empty();
        proceed_with_methods.push(MethodKind::Password);
        Ok(Auth::Reject {
            proceed_with_methods: Some(proceed_with_methods),
            partial_success: false,
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.log_client_banner(session);
        Ok(self.try_open_channel(channel.id().number()))
    }

    /// A real Debian sshd always answers `pty-req` with success. russh's
    /// default `Handler` impl leaves the request unanswered (neither success
    /// nor failure), which is a cheap, passive tell for anything that checks
    /// the reply — most interactive `ssh` clients send this before `shell`.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty = true;
        self.log_client_banner(session);
        // A real sshd exports the requested terminal into the session, so
        // `echo $TERM` answers with what the client asked for. Bounded and
        // sanitised because it is attacker-controlled and reaches `env` output.
        self.pty_term = Some(PtyRequest {
            term: sanitise_term(term),
            cols: if col_width == 0 {
                80
            } else {
                col_width.min(10_000)
            },
            rows: if row_height == 0 {
                24
            } else {
                row_height.min(10_000)
            },
        });
        session.channel_success(channel)?;
        Ok(())
    }

    /// Mirrors Debian's default `sshd_config` (`AcceptEnv LANG LC_*`): only
    /// locale variables are actually accepted, everything else is refused —
    /// same as a real server, and again explicitly replied to rather than
    /// left hanging.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if variable_name == "LANG" || variable_name.starts_with("LC_") {
            // Debian's stock *client* ssh_config ships `SendEnv LANG LC_*`, so
            // ordinary clients hit this on every connection. Answering
            // `channel_success` and then discarding the value is worse than
            // refusing it: the server says "accepted" and `echo $LANG` still
            // reports the built-in default.
            const MAX_ACCEPTED_ENV: usize = 32;
            if self.accepted_env.len() < MAX_ACCEPTED_ENV {
                self.accepted_env.push((
                    variable_name.to_string(),
                    sanitise_env_value(variable_value),
                ));
            }
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    /// Terminal resizes have no effect on non-interactive output here, but a
    /// real server still acknowledges the request.
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // A resize updates COLUMNS/LINES for anything run afterwards, the way
        // bash's SIGWINCH handler does.
        if let Some(pty) = self.pty_term.as_mut() {
            if col_width > 0 {
                pty.cols = col_width.min(10_000);
            }
            if row_height > 0 {
                pty.rows = row_height.min(10_000);
            }
        }
        if let Some(shell) = self.shell.as_mut() {
            if let Some(pty) = self.pty_term.as_ref() {
                shell.env.set("COLUMNS", &pty.cols.to_string());
                shell.env.set("LINES", &pty.rows.to_string());
            }
        }
        session.channel_success(channel)?;
        Ok(())
    }

    /// SFTP subsystem is emulated for upload capture and file inspection;
    /// other subsystems report failure explicitly, the same way a real sshd
    /// does for an unsupported subsystem.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            event::subsystem_request(self.session_id, self.peer, "sftp", true);
            self.sftp = Some(SftpSession::new());
            session.channel_success(channel)?;
            Ok(())
        } else {
            event::subsystem_request(self.session_id, self.peer, name, false);
            session.channel_failure(channel)?;
            Ok(())
        }
    }

    /// Agent forwarding is not emulated.
    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        session.channel_failure(channel)?;
        Ok(false)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.shell_started = true;
        // Set per channel, not once when the shell is built: the shell outlives
        // the channel that created it, and the next one may be an `exec`.
        let pty = self.pty;
        self.shell().interactive = pty;
        // The MOTD comes from the PAM session, which opens whether or not a
        // terminal was allocated, so it is printed either way.
        let banner = self.out(&self.motd());
        session.data(channel, banner)?;
        if !self.pty {
            // Everything below belongs to a terminal. sshd prints the previous
            // login from the branch that allocated the pty, and the prompt is
            // the line editor's — bash runs no readline over a pipe.
            return Ok(());
        }
        // PAM prints the previous login right before handing off to the shell.
        // Kept in lockstep with the session `last` lists as the previous one.
        let (prev, _) = crate::clock::prev_login();
        let last_login = self.out(&format!(
            "Last login: {} from {}\n",
            crate::clock::format(prev, "%a %b %e %H:%M:%S %Y"),
            crate::clock::PREV_LOGIN_FROM,
        ));
        session.data(channel, last_login)?;
        let prompt = self.shell().prompt();
        self.editor.set_prompt(&prompt);
        session.data(channel, self.editor.render().to_vec())?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let cmd = String::from_utf8_lossy(&data[..data.len().min(MAX_COMMAND_LEN)]);
        let cmd = cmd.trim().to_string();

        // SCP transfer requests keep the channel open and drive a sub-protocol
        // over subsequent `data` frames rather than running a one-shot command.
        if let Some(mode) = scp::parse_scp(&cmd) {
            match mode {
                ScpMode::Sink { target, recursive } => {
                    self.log_command(&cmd, CommandSource::Exec, None);
                    self.log_command(
                        &format!("[scp upload to {target}]"),
                        CommandSource::Transfer,
                        None,
                    );
                    self.scp = Some(ScpSink::new(
                        target,
                        recursive,
                        self.config.max_upload_bytes,
                    ));
                    // Signal "ready" so the client starts sending control messages.
                    session.data(channel, vec![0u8])?;
                    return Ok(());
                }
                ScpMode::Source { path } => {
                    // Download-from-honeypot is not emulated: report not found.
                    self.log_command(&cmd, CommandSource::Exec, Some(1));
                    let msg = format!("\x01scp: {path}: No such file or directory\n");
                    session.data(channel, msg.into_bytes())?;
                    self.end_channel(channel, session, 1)?;
                    return Ok(());
                }
            }
        }

        // A one-shot `exec` is never interactive, whatever the previous channel
        // on this connection was.
        self.shell().interactive = false;
        let mut result = self.shell().execute(&cmd);
        // A here-document opened by a one-shot command can never be fed, so it
        // ends at end-of-input with bash's warning — what `bash -c` does with
        // the same string.
        if let Some(finished) = self.shell().finish_heredoc_at_eof() {
            self.log_closed_heredoc();
            result = finished;
        }
        // A one-shot `exec` has no interactive stdin, so drop any prompt a
        // command left pending (e.g. `su` awaiting a password).
        self.shell().pending = None;
        // Logged after the run so the event carries the exit status: a 127 is
        // the signal that names a command worth emulating next.
        self.log_command(&cmd, CommandSource::Exec, Some(result.status));
        self.drain_captures();
        jitter_for(result.text.len() + result.stdout.len() + result.stderr.len()).await;
        self.write_output(channel, &result, session)?;
        self.end_channel(channel, session, result.status as u32)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Route bytes to the SFTP subsystem when active.
        if self.sftp.is_some() {
            // Builds the shell if this is the first use, so the borrow below
            // always finds one.
            let _ = self.shell();
            let (resp, uploads) = {
                let max_bytes = self.config.max_upload_bytes;
                let shell = self.shell.as_mut().expect("shell just initialised");
                let sftp = self.sftp.as_mut().expect("sftp active");
                sftp.feed(data, shell, max_bytes)
            };
            for upload in uploads {
                self.store_sftp_upload(upload);
            }
            if !resp.is_empty() {
                session.data(channel, resp)?;
            }
            return Ok(());
        }

        // Route bytes to the SCP sink when an upload is in progress.
        if self.scp.is_some() {
            let (acks, files) = self.scp.as_mut().expect("scp active").feed(data);
            for file in files {
                self.store_upload(file);
            }
            if !acks.is_empty() {
                session.data(channel, acks)?;
            }
            return Ok(());
        }

        // A shell channel that asked for no terminal reads lines rather than
        // running a line editor over them.
        if !self.pty {
            return self.feed_no_tty(channel, data, session).await;
        }

        // A full-screen command has the terminal: keystrokes drive the display,
        // not the line editor, until it quits and hands the prompt back.
        let mut rest = data;
        if self.screen.is_some() {
            let quit_at = data.iter().position(|&byte| !self.screen_input(byte));
            let Some(i) = quit_at else {
                return Ok(());
            };
            // Real `top` clears the screen on its way out.
            let bytes = self.out(SCREEN_HOME);
            session.data(channel, bytes)?;
            let prompt = self.shell().prompt();
            self.editor.set_prompt(&prompt);
            session.data(channel, self.editor.render().to_vec())?;
            // Anything typed after the quit key is ordinary input again.
            rest = &data[i + 1..];
        }

        for &byte in rest {
            // A command (e.g. `su`) is waiting for a password line: collect
            // bytes with echo suppressed until Enter, then resume the shell.
            if self.password_buf.is_some() {
                match byte {
                    b'\r' | b'\n' => {
                        let password = String::from_utf8_lossy(
                            self.password_buf.as_ref().expect("collecting"),
                        )
                        .into_owned();
                        self.password_buf = None;
                        session.data(channel, b"\r\n".to_vec())?;

                        let output = self.shell().resume(&password);
                        if self.deliver(channel, &output, session).await? {
                            return Ok(());
                        }
                        // One answer can leave another prompt outstanding —
                        // `passwd` asks twice — so stay in echo-suppressed
                        // collection rather than drawing `PS1` over it.
                        if self.shell().pending.as_ref().is_some_and(|p| !p.echoes()) {
                            self.password_buf = Some(Vec::new());
                            continue;
                        }
                        let prompt = self.shell().prompt();
                        self.editor.set_prompt(&prompt);
                        session.data(channel, self.editor.render().to_vec())?;
                    }
                    0x03 => {
                        // Ctrl-C aborts the prompt, like a real terminal.
                        self.password_buf = None;
                        self.shell().pending = None;
                        session.data(channel, b"\r\n".to_vec())?;
                        let prompt = self.shell().prompt();
                        self.editor.set_prompt(&prompt);
                        session.data(channel, self.editor.render().to_vec())?;
                    }
                    0x08 | 0x7f => {
                        // Backspace: edit the buffer without echoing. Drop the
                        // whole character, not one byte of it.
                        if let Some(buf) = self.password_buf.as_mut() {
                            while buf.pop().is_some_and(is_continuation) {}
                        }
                    }
                    0x20..=0x7e | 0x80..=0xff => {
                        // Printable byte: buffer it (bounded), no echo.
                        if let Some(buf) = self.password_buf.as_mut() {
                            if buf.len() < MAX_COMMAND_LEN {
                                buf.push(byte);
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }

            match self.editor.input(byte) {
                Reaction::Ignore => {}
                Reaction::Write(bytes) => {
                    session.data(channel, bytes)?;
                }
                Reaction::Complete => {
                    let bytes = self.complete_current_word();
                    if !bytes.is_empty() {
                        session.data(channel, bytes)?;
                    }
                }
                Reaction::Eof => {
                    // Ctrl-D on an empty line is end-of-input to a login
                    // shell, which announces itself before exiting — printed
                    // on the prompt line, exactly as `exit` does after its
                    // echoed newline.
                    let bytes = self.out(LOGOUT);
                    session.data(channel, bytes)?;
                    let status = self.shell().last_status as u32;
                    self.end_channel(channel, session, status)?;
                    return Ok(());
                }
                Reaction::Submit { echo, line } => {
                    session.data(channel, echo)?;

                    // A here-document body line is not a command: it answers
                    // the line that opened the document, and only that line is
                    // logged and run.
                    let ended = if self.shell().pending.as_ref().is_some_and(|p| p.echoes()) {
                        let output = self.shell().resume(&line);
                        self.log_closed_heredoc();
                        self.deliver(channel, &output, session).await?
                    } else {
                        self.submit_line(channel, &line, session).await?
                    };
                    if ended {
                        return Ok(());
                    }
                    // A command took the screen (`top`): it paints itself and
                    // keeps the terminal until the client quits it, so no
                    // prompt is drawn.
                    if let Some(screen) = self.shell().screen.take() {
                        self.hold_screen(channel, screen, session)?;
                        continue;
                    }
                    // A command left an interactive prompt pending (e.g. `su`
                    // asking for a password, `<< EOF` collecting a body): a
                    // password is collected with echo suppressed, while a
                    // here-document body is ordinary input under `PS2`.
                    let continuation = match self.shell().pending.as_ref() {
                        None => None,
                        Some(pending) if !pending.echoes() => {
                            self.password_buf = Some(Vec::new());
                            continue;
                        }
                        Some(pending) => pending.prompt(),
                    };
                    let prompt = match continuation {
                        Some(ps2) => ps2.to_string(),
                        None => self.shell().prompt(),
                    };
                    self.editor.set_prompt(&prompt);
                    session.data(channel, self.editor.render().to_vec())?;
                }
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // An SCP or SFTP client signals end-of-transfer by closing its half of the
        // channel; finish the exchange with a success status.
        if self.scp.take().is_some() {
            self.end_channel(channel, session, 0)?;
        } else if self.sftp.is_some() {
            // Builds the shell if this is the first use, as above.
            let _ = self.shell();
            self.drain_sftp_uploads();
            self.end_channel(channel, session, 0)?;
        } else if self.shell_started && self.active_channel == Some(channel.number()) {
            // The client closed stdin. That is end-of-input to the shell just
            // as Ctrl-D is, so it ends immediately rather than holding the
            // session — and its connection slot — until the idle timeout.
            if !self.pty {
                // A script whose last line has no newline still runs, the way
                // bash runs what it has when the pipe reaches EOF.
                if !self.line_buf.is_empty() {
                    let line = String::from_utf8_lossy(&std::mem::take(&mut self.line_buf))
                        .trim_end_matches('\r')
                        .to_string();
                    if self.run_no_tty_line(channel, &line, session).await? {
                        return Ok(());
                    }
                }
                // A script that stops mid-body still runs what it opened.
                if let Some(output) = self.shell().finish_heredoc_at_eof() {
                    self.log_closed_heredoc();
                    if self.deliver(channel, &output, session).await? {
                        return Ok(());
                    }
                }
                // `logout` is what an *interactive* login shell prints on its
                // way out. Reading a pipe, bash prints nothing.
                let status = self.shell().last_status as u32;
                self.end_channel(channel, session, status)?;
                return Ok(());
            }
            let bytes = self.out(LOGOUT);
            session.data(channel, bytes)?;
            let status = self.shell().last_status as u32;
            self.end_channel(channel, session, status)?;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.close_channel(channel.number());
        Ok(())
    }
}

impl Drop for MimicHandler {
    fn drop(&mut self) {
        // The last-resort drain. A session torn down by the watchdog, the idle
        // timeout, or a vanished socket reaches here and nowhere else, so an
        // upload still in flight is captured rather than lost.
        self.drain_sftp_uploads();
        let duration_secs = self.opened_at.elapsed().as_secs();
        event::connection_closed(
            self.session_id,
            self.peer,
            duration_secs,
            self.command_count,
        );
    }
}

/// Keep only what a terminal name can legally hold, bounded.
///
/// `TERM` is attacker-controlled and reaches `env` output, so it is restricted
/// to the character class terminfo names actually use. An empty or hostile value
/// falls back to what a client that sent nothing would get.
fn sanitise_term(term: &str) -> String {
    let cleaned: String = term
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "xterm-256color".to_string()
    } else {
        cleaned
    }
}

/// Strip control characters from an accepted `env` value and bound its length.
///
/// `Env::set` bounds length too, but a locale value reaches the terminal through
/// `env`/`printenv` output, so escape sequences come out here rather than at the
/// far end.
fn sanitise_env_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}

/// Sleep for a short interval before answering, shaped by how much work the
/// command implied.
///
/// Real shell latency is heavy-tailed and correlates with what ran: a builtin
/// answers in microseconds, a filesystem walk takes far longer. A flat uniform
/// delay applied to every command is its own fingerprint — a scanner timing
/// fifty commands recovers a clean uniform distribution with no correlation to
/// workload, which no real box produces. Scaling by output size is a cheap proxy
/// for work done, and the multiplicative noise gives the right-skewed shape.
///
/// ponytail: output size is a proxy, not a cost model — `sleep 10` still
/// returns promptly. Upgrade if commands gain modelled execution costs.
async fn jitter_for(output_bytes: usize) {
    // Base cost of a round trip through a shell, in microseconds.
    let base = 900u64;
    // Roughly a microsecond per byte formatted and written.
    let work = (output_bytes as u64).saturating_mul(1).min(240_000);
    // Multiplicative noise: the product of two uniforms is right-skewed, so the
    // tail is long without a hard ceiling in the wrong place.
    let noise = rand::random_range(40..=170) * rand::random_range(40..=170) / 100;
    let micros = (base + work).saturating_mul(noise) / 100;
    tokio::time::sleep(Duration::from_micros(micros.clamp(400, 450_000))).await;
}

/// Lay candidate strings out in newline-separated columns the way bash prints
/// ambiguous completions. Kept simple: a single space-padded grid.
fn format_columns(items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let width = items.iter().map(String::len).max().unwrap_or(0) + 2;
    let cols = (80 / width).max(1);
    let mut out = String::new();
    for (i, item) in items.iter().enumerate() {
        out.push_str(item);
        if (i + 1) % cols == 0 || i + 1 == items.len() {
            out.push('\n');
        } else {
            for _ in item.len()..width {
                out.push(' ');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::network::limiter::ConnectionRegistry;
    use crate::network::scp::CompletedFile;

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
        MimicHandler {
            config,
            persona: Arc::new(crate::persona::Persona::sample()),
            session_id: 1,
            peer,
            local: "127.0.0.1:2222".parse().unwrap(),
            pty: false,
            auth_attempts: 0,
            username: "root".to_string(),
            editor: LineEditor::new(MAX_COMMAND_LEN, 1000),
            shell_started: false,
            shell: None,
            active_channel: None,
            scp: Some(ScpSink::new("/tmp".to_string(), false, max_upload_bytes)),
            sftp: None,
            quarantine_bytes: 0,
            password_buf: None,
            line_buf: Vec::new(),
            screen: None,
            pty_term: None,
            accepted_env: Vec::new(),
            banner_logged: false,
            opened_at: std::time::Instant::now(),
            command_count: 0,
            _guard: guard,
        }
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
            _key: &russh::keys::ssh_key::PublicKey,
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

        let dir =
            std::env::temp_dir().join(format!("mimic-session-cap-test-{}", std::process::id()));
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
            match russh::client::connect(
                Arc::clone(&client_config),
                ("127.0.0.1", port),
                TestClient,
            )
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
            match russh::client::connect(
                Arc::clone(&client_config),
                ("127.0.0.1", port),
                TestClient,
            )
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
    async fn read_for(
        channel: &mut russh::Channel<russh::client::Msg>,
        window: Duration,
    ) -> Vec<u8> {
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
}
