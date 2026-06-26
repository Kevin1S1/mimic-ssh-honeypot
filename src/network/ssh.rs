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
            editor: LineEditor::new(4096, 1000),
            shell: None,
            scp: None,
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
    /// Active SCP upload sink, when the channel is running `scp -t`.
    scp: Option<ScpSink>,
    /// Holds this connection's slot in the global/per-IP limiter; releasing it
    /// on drop frees the slot for the next connection.
    _guard: ConnectionGuard,
}

impl MimicHandler {
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

        // Write to the quarantine store (real I/O is permitted in this layer).
        let stored_path = match write_quarantine(&quarantine_dir, &sha256, &file.data) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(
                    event = "quarantine_error",
                    session_id,
                    error = %err,
                );
                String::new()
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
/// `dir` if needed. Returns the stored file's path. Files are written
/// non-executable and owner-read/write only (`0600`) so a captured payload can
/// never be run from the quarantine store.
fn write_quarantine(dir: &std::path::Path, sha256: &str, data: &[u8]) -> std::io::Result<String> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(sha256);
    if !path.exists() {
        std::fs::write(&path, data)?;
        restrict_permissions(&path)?;
    }
    Ok(path.to_string_lossy().into_owned())
}

/// Set owner-only read/write permissions (`0600`) on `path`. No-op on
/// platforms without Unix permission bits.
fn restrict_permissions(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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
            Ok(Auth::Reject {
                proceed_with_methods: None,
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
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let banner = self.motd();
        session.data(channel, banner.into_bytes())?;
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
        let cmd = String::from_utf8_lossy(data);
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
                    return Ok(());
                }
            }
        }

        let result = self.shell().execute(&cmd);
        self.drain_captures();
        jitter().await;
        if !result.text.is_empty() {
            session.data(channel, crlf(&result.text))?;
        }
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
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
                        return Ok(());
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
        }
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
