//! SSH protocol engine built on `russh`.
//!
//! Drives the handshake, credential capture, and a full interactive
//! line-editing shell over the emulated Debian filesystem. SCP uploads are
//! intercepted, content-addressed, and quarantined. The only real I/O in this
//! file is host-key persistence and the quarantine store; everything the
//! attacker "runs" is a pure in-memory state machine.

use crate::config::{AuthMode, Config};
use crate::logging::event;
use crate::network::limiter::{ConnectionGuard, ConnectionRegistry};
use crate::network::scp::{self, ScpMode, ScpSink};
use crate::shell::complete::{self, Completion};
use crate::shell::line::{LineEditor, Reaction};
use crate::shell::{Capture, Shell};

use anyhow::{Context, Result};
use russh::server::{Auth, Config as ServerConfig, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use sha2::{Digest, Sha256};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Maximum bytes accepted for a single command line, on both the interactive
/// path (line editor buffer) and the one-shot `exec` path. Without the exec
/// cap, a client could ship a command bounded only by the SSH packet limit
/// straight into the logs and parser.
const MAX_COMMAND_LEN: usize = 4096;

/// Build the russh server config and serve connections forever.
pub async fn serve(config: Arc<Config>) -> Result<()> {
    // Persist host keys so the server fingerprint stays stable across restarts.
    let host_keys = super::hostkey::load_or_create(&config.host_key_dir)?;

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
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
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

    tracing::info!(
        event = "listening",
        sensor_name = config.sensor_name.as_str(),
        addr = %config.listen_addr,
        port = config.port,
        max_sessions = config.max_sessions,
        per_ip_connections = config.per_ip_connections,
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // Transient accept errors (e.g. fd exhaustion) shouldn't kill
                // the listener; back off briefly and keep serving.
                tracing::warn!(event = "accept_error", error = %err);
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

        let handler = MimicHandler {
            config: Arc::clone(&config),
            session_id,
            peer,
            auth_attempts: 0,
            username: String::new(),
            editor: LineEditor::new(MAX_COMMAND_LEN, 1000),
            shell: None,
            active_channel: None,
            scp: None,
            quarantine_bytes: 0,
            password_buf: None,
            _guard: guard,
        };

        let server_config = Arc::clone(&server_config);
        let max_session = Duration::from_secs(config.max_session_secs);
        tokio::spawn(async move {
            match russh::server::run_stream(server_config, stream, handler).await {
                Ok(session) => {
                    // Bound the absolute session lifetime, independent of the
                    // idle timeout, so no connection can be held open forever.
                    match tokio::time::timeout(max_session, session).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            tracing::debug!(
                                event = "session_error",
                                session_id,
                                error = %err,
                            );
                        }
                        Err(_) => {
                            tracing::info!(event = "session_timeout", session_id);
                        }
                    }
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
    auth_attempts: u32,
    username: String,
    /// Interactive readline-style editor (cursor, history, completion) for the
    /// PTY session.
    editor: LineEditor,
    /// The emulated shell, created lazily once a session channel opens.
    shell: Option<Shell>,
    /// Only one channel may use the connection-scoped shell/editor state at a
    /// time. Sequential channels are allowed after the active one closes.
    active_channel: Option<u32>,
    /// Active SCP upload sink, when the channel is running `scp -t`.
    scp: Option<ScpSink>,
    /// Cumulative bytes this session has written to the real-disk quarantine
    /// store. Bounds disk growth from a flood of distinct small uploads (the
    /// content-addressed dedup only bounds *repeated* payloads).
    quarantine_bytes: u64,
    /// When `Some`, the shell is waiting on a password line (e.g. after `su`):
    /// input bytes are collected here with echo suppressed until Enter, then
    /// handed to [`Shell::resume`].
    password_buf: Option<Vec<u8>>,
    /// Holds this connection's slot in the global/per-IP limiter; releasing it
    /// on drop frees the slot for the next connection.
    _guard: ConnectionGuard,
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

    fn close_channel(&mut self, channel: u32) {
        if self.active_channel == Some(channel) {
            self.active_channel = None;
            self.editor = LineEditor::new(MAX_COMMAND_LEN, 1000);
            self.shell = None;
            self.scp = None;
            self.password_buf = None;
        }
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

    /// Borrow the session shell, creating it on first use from the captured
    /// username and configured hostname.
    fn shell(&mut self) -> &mut Shell {
        if self.shell.is_none() {
            self.shell = Some(Shell::new(&self.username, &self.config.hostname));
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
    /// kernel line mirrors Debian's `/etc/update-motd.d/10-uname` output.
    fn motd(&self) -> String {
        format!(
            "Linux {host} 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64\r\n\
             \r\n\
             The programs included with the Debian GNU/Linux system are free software;\r\n\
             the exact distribution terms for each program are described in the\r\n\
             individual files in /usr/share/doc/*/copyright.\r\n\
             \r\n\
             Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\r\n\
             permitted by applicable law.\r\n",
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
                Capture::SuAuth { target, password } => {
                    // A guessed password entered at an `su` prompt: log it as an
                    // authentication attempt (accepted, matching the switch).
                    event::auth_attempt(session_id, peer, &target, "su", Some(&password), true);
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
        // the attacker-supplied filename never influences the stored path.
        let mut hasher = Sha256::new();
        hasher.update(&file.data);
        let sha256 = hex(&hasher.finalize());

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
            tracing::warn!(event = "quarantine_session_cap", session_id);
            String::new()
        } else {
            match write_quarantine(&quarantine_dir, &sha256, &file.data) {
                Ok(p) => {
                    self.quarantine_bytes += file.data.len() as u64;
                    p
                }
                Err(err) => {
                    tracing::warn!(
                        event = "quarantine_error",
                        session_id,
                        error = %err,
                    );
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
            &sha256,
            &stored_path,
            file.truncated,
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
fn hex(bytes: &[u8]) -> String {
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
/// `dir` if needed. Returns the stored file's path. Files are created
/// non-executable and owner-read/write only (`0600`) at creation time so a
/// captured payload can never be run from the quarantine store and is never
/// briefly world/group-readable between the write and a chmod.
fn write_quarantine(dir: &std::path::Path, sha256: &str, data: &[u8]) -> std::io::Result<String> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(sha256);
    // Content-addressed store: identical payloads dedupe. `create_new` also
    // closes the exists()-then-write TOCTOU — if a concurrent session already
    // stored the same bytes, `AlreadyExists` is success, not an error.
    match create_restricted(&path) {
        Ok(mut file) => file.write_all(data)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    Ok(path.to_string_lossy().into_owned())
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
            accepted,
        );

        if accepted {
            self.username = user.to_string();
            jitter().await;
            Ok(Auth::Accept)
        } else {
            jitter().await;
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
        _key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_attempts += 1;
        event::auth_attempt(self.session_id, self.peer, user, "publickey", None, false);

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
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(self.try_open_channel(channel.id().number()))
    }

    /// A real Debian sshd always answers `pty-req` with success. russh's
    /// default `Handler` impl leaves the request unanswered (neither success
    /// nor failure), which is a cheap, passive tell for anything that checks
    /// the reply — most interactive `ssh` clients send this before `shell`.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
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
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if variable_name == "LANG" || variable_name.starts_with("LC_") {
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
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    /// No subsystem (SFTP included) is emulated; report failure explicitly,
    /// the same way a real sshd does for an unsupported subsystem, instead of
    /// silently dropping the request.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
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
        let banner = self.motd();
        session.data(channel, banner.into_bytes())?;
        // PAM prints the previous login right before handing off to the shell.
        // Kept in lockstep with the fabricated `last`/`w` session.
        session.data(
            channel,
            b"Last login: Mon Jun 24 10:01:33 2024 from 10.0.0.5\r\n".to_vec(),
        )?;
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
        let cmd = String::from_utf8_lossy(&data[..data.len().min(MAX_COMMAND_LEN)]);
        let cmd = cmd.trim().to_string();
        event::command(self.session_id, self.peer, &cmd);

        // SCP transfer requests keep the channel open and drive a sub-protocol
        // over subsequent `data` frames rather than running a one-shot command.
        if let Some(mode) = scp::parse_scp(&cmd) {
            match mode {
                ScpMode::Sink { target, recursive } => {
                    event::command(
                        self.session_id,
                        self.peer,
                        &format!("[scp upload to {target}]"),
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
                    let msg = format!("\x01scp: {path}: No such file or directory\n");
                    session.data(channel, msg.into_bytes())?;
                    session.exit_status_request(channel, 1)?;
                    session.eof(channel)?;
                    session.close(channel)?;
                    self.close_channel(channel.number());
                    return Ok(());
                }
            }
        }

        let result = self.shell().execute(&cmd);
        // A one-shot `exec` has no interactive stdin, so drop any prompt a
        // command left pending (e.g. `su` awaiting a password).
        self.shell().pending = None;
        self.drain_captures();
        jitter().await;
        if !result.text.is_empty() {
            session.data(channel, crlf(&result.text))?;
        }
        session.exit_status_request(channel, result.status as u32)?;
        session.eof(channel)?;
        session.close(channel)?;
        self.close_channel(channel.number());
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
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

        for &byte in data {
            // A command (e.g. `su`) is waiting for a password line: collect
            // bytes with echo suppressed until Enter, then resume the shell.
            if self.password_buf.is_some() {
                match byte {
                    b'\r' | b'\n' => {
                        let password = String::from_utf8_lossy(self.password_buf.as_ref().unwrap())
                            .into_owned();
                        self.password_buf = None;
                        session.data(channel, b"\r\n".to_vec())?;

                        let output = self.shell().resume(&password);
                        self.drain_captures();
                        jitter().await;

                        if !output.text.is_empty() {
                            session.data(channel, crlf(&output.text))?;
                        }
                        if output.exit {
                            session.eof(channel)?;
                            session.close(channel)?;
                            self.close_channel(channel.number());
                            return Ok(());
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
                        // Backspace: edit the buffer without echoing.
                        if let Some(buf) = self.password_buf.as_mut() {
                            buf.pop();
                        }
                    }
                    0x20..=0x7e => {
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
                    session.eof(channel)?;
                    session.close(channel)?;
                    self.close_channel(channel.number());
                    return Ok(());
                }
                Reaction::Submit { echo, line } => {
                    session.data(channel, echo)?;

                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() {
                        event::command(self.session_id, self.peer, &trimmed);
                        self.shell().record_history(&trimmed);
                    }

                    let result = self.shell().execute(&trimmed);
                    self.drain_captures();

                    // Small randomised delay so response latency is not
                    // perfectly uniform (a passive timing tell).
                    jitter().await;

                    if !result.text.is_empty() {
                        session.data(channel, crlf(&result.text))?;
                    }
                    if result.exit {
                        session.eof(channel)?;
                        session.close(channel)?;
                        self.close_channel(channel.number());
                        return Ok(());
                    }
                    // A command left an interactive prompt pending (e.g. `su`
                    // asking for a password): switch to no-echo collection
                    // instead of drawing a new shell prompt.
                    if self.shell().pending.is_some() {
                        self.password_buf = Some(Vec::new());
                        continue;
                    }
                    let prompt = self.shell().prompt();
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
        // An SCP client signals end-of-transfer by closing its half of the
        // channel; finish the exchange with a success status.
        if self.scp.take().is_some() {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
            self.close_channel(channel.number());
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
        event::connection_closed(self.session_id, self.peer);
    }
}

/// Sleep for a small randomised interval. Real OpenSSH + bash responses carry
/// natural jitter; perfectly uniform latency is a passive honeypot tell.
async fn jitter() {
    let ms = rand::random_range(2..=18);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Convert LF line endings to CRLF for transmission over the SSH PTY. Command
/// output uses bare `\n`; terminals expect `\r\n`.
fn crlf(text: &str) -> Vec<u8> {
    text.replace('\n', "\r\n").into_bytes()
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
            session_id: 1,
            peer,
            auth_attempts: 0,
            username: "root".to_string(),
            editor: LineEditor::new(MAX_COMMAND_LEN, 1000),
            shell: None,
            active_channel: None,
            scp: Some(ScpSink::new("/tmp".to_string(), false, max_upload_bytes)),
            quarantine_bytes: 0,
            password_buf: None,
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
    fn only_one_channel_is_active_at_a_time() {
        let mut handler = test_handler(std::env::temp_dir(), 1024);
        assert!(handler.try_open_channel(1));
        assert!(!handler.try_open_channel(2));

        handler.close_channel(1);
        assert!(handler.try_open_channel(2));
    }
}
