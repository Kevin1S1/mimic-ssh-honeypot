use crate::config::{AuthMode, Config};
use crate::logging::event;
use crate::logging::event::CommandSource;
use crate::network::limiter::{ConnectionGuard, ConnectionRegistry};
use crate::network::scp::{self, ScpMode, ScpSink};
use crate::network::sftp::{self, SftpSession};
use crate::shell::complete::{self, Completion};
use crate::shell::line::{is_continuation, LineEditor, Reaction};
use crate::shell::{Capture, Output, Screen, Shell};

use anyhow::{Context, Result};
use russh::server::{Auth, ChannelOpenHandle, Config as ServerConfig, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, Disconnect, MethodKind, MethodSet};

use russh::keys::ssh_encoding::bytes::Bytes;
use sha2::{Digest, Sha256};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::Instant;

const MAX_COMMAND_LEN: usize = 4096;

const LOGOUT: &str = "logout\n";

const SSH_EXTENDED_DATA_STDERR: u32 = 1;

const LOGIN_GRACE: Duration = Duration::from_secs(120);

pub async fn serve(config: Arc<Config>) -> Result<()> {
    let host_keys = super::hostkey::load_or_create(&config.host_key_dir)?;

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

        preferred: debian_openssh_preferred(),
        auth_rejection_time: Duration::from_secs(2),

        auth_rejection_time_initial: Some(Duration::from_secs(0)),

        max_auth_attempts: crate::config::MAX_AUTH_ATTEMPTS as usize,
        inactivity_timeout: Some(Duration::from_secs(config.idle_timeout_secs)),
        keys: host_keys,
        ..Default::default()
    });

    let registry = ConnectionRegistry::new(config.max_sessions, config.per_ip_connections);
    let session_counter = Arc::new(AtomicU64::new(1));
    let initial_quarantine_bytes = measure_dir_size(&config.quarantine_dir);
    let global_quarantine_bytes = Arc::new(AtomicU64::new(initial_quarantine_bytes));

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
            () = shutdown_signal() => {
                event::shutdown();
                return Ok(());
            }
            result = listener.accept() => result,
        };

        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                event::accept_error(&err.to_string());
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

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
        let authenticated = Arc::new(AtomicBool::new(false));

        let handler = MimicHandler {
            config: Arc::clone(&config),
            persona: Arc::clone(&persona),
            session_id,
            peer,
            local,
            pty: false,
            auth_attempts: 0,
            authenticated: Arc::clone(&authenticated),
            username: String::new(),
            editor: LineEditor::new(MAX_COMMAND_LEN, 1000),
            shell_started: false,
            shell: None,
            active_channel: None,
            scp: None,
            sftp: None,
            quarantine_bytes: 0,
            global_quarantine_bytes: Arc::clone(&global_quarantine_bytes),
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
        let login_deadline = Instant::now() + LOGIN_GRACE;
        let deadline = Instant::now() + Duration::from_secs(config.max_session_secs);
        tokio::spawn(async move {
            match russh::server::run_stream(server_config, stream, handler).await {
                Ok(session) => {
                    let watchdog = tokio::spawn({
                        let handle = session.handle();
                        async move {
                            tokio::time::sleep_until(login_deadline.min(deadline)).await;
                            if authenticated.load(Ordering::Relaxed) {
                                tokio::time::sleep_until(deadline).await;
                                event::session_timeout(session_id, peer);
                            } else {
                                event::login_timeout(session_id, peer);
                            }
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

fn persona_seed(keys: &[russh::keys::PrivateKey], sensor_name: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"mimic-persona-v1");
    hasher.update(sensor_name.as_bytes());
    for key in keys {
        if let Ok(blob) = key.public_key().to_openssh() {
            hasher.update(blob.as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(seed)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,

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

struct MimicHandler {
    config: Arc<Config>,
    session_id: u64,
    peer: SocketAddr,

    local: SocketAddr,

    pty: bool,
    auth_attempts: u32,

    authenticated: Arc<AtomicBool>,
    username: String,

    editor: LineEditor,

    shell_started: bool,

    shell: Option<Shell>,

    active_channel: Option<u32>,

    scp: Option<ScpSink>,

    sftp: Option<SftpSession>,

    quarantine_bytes: u64,

    global_quarantine_bytes: Arc<AtomicU64>,

    password_buf: Option<Vec<u8>>,

    line_buf: Vec<u8>,

    screen: Option<ScreenHold>,

    pty_term: Option<PtyRequest>,

    accepted_env: Vec<(String, String)>,

    banner_logged: bool,

    opened_at: std::time::Instant,

    command_count: u64,

    persona: Arc<crate::persona::Persona>,

    _guard: ConnectionGuard,
}

struct PtyRequest {
    term: String,
    cols: u32,
    rows: u32,
}

const SCREEN_REFRESH: Duration = Duration::from_secs(3);

const SCREEN_HOME: &str = "\x1b[H\x1b[J";

struct ScreenHold {
    kind: ScreenKind,

    colon: Option<String>,

    redraw: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ScreenHold {
    fn drop(&mut self) {
        if let Some(redraw) = &self.redraw {
            redraw.abort();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScreenKind {
    Top,
    Vi,
    Nano,
    Listen,
}

fn vi_screen_input(hold: &mut ScreenHold, byte: u8) -> bool {
    if byte == 0x03 {
        return true;
    }
    if let Some(buf) = hold.colon.as_mut() {
        match byte {
            b'\r' | b'\n' => {
                let cmd = std::mem::take(buf);
                hold.colon = None;
                return matches!(cmd.as_str(), "q" | "q!" | "wq" | "wq!" | "x");
            }
            0x1b => hold.colon = None,
            0x08 | 0x7f => {
                buf.pop();
            }
            0x20..=0x7e => buf.push(byte as char),
            _ => {}
        }
    } else if byte == b':' {
        hold.colon = Some(String::new());
    }
    false
}

const QUARANTINE_SESSION_MULTIPLIER: u64 = 32;

const QUARANTINE_GLOBAL_MULTIPLIER: u64 = 64;

fn measure_dir_size(dir: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

impl MimicHandler {
    fn try_open_channel(&mut self, channel: u32) -> bool {
        if self.active_channel.is_some() {
            return false;
        }
        self.active_channel = Some(channel);
        true
    }

    fn drain_sftp_uploads(&mut self) {
        let Some(sftp) = self.sftp.take() else {
            return;
        };

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
            self.drain_sftp_uploads();
            self.active_channel = None;
            self.editor = LineEditor::new(MAX_COMMAND_LEN, 1000);
            self.shell = None;
            self.scp = None;
            self.sftp = None;
            self.password_buf = None;
            self.line_buf.clear();

            self.screen = None;
            self.shell_started = false;

            self.pty = false;
        }
    }

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

    fn out(&self, text: &str) -> Vec<u8> {
        if self.pty {
            text.replace('\n', "\r\n").into_bytes()
        } else {
            text.as_bytes().to_vec()
        }
    }

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

    async fn deliver(
        &mut self,
        channel: ChannelId,
        output: &Output,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        self.drain_captures();

        jitter_for(output.text.len() + output.stdout.len() + output.stderr.len()).await;
        self.write_output(channel, output, session)?;
        if output.exit {
            self.end_channel(channel, session, output.status as u32)?;
            return Ok(true);
        }
        Ok(false)
    }

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

    fn log_closed_heredoc(&mut self) {
        if let Some(text) = self.shell().heredoc_log.take() {
            self.log_command(&text, CommandSource::Heredoc, None);
        }
    }

    fn log_command(&mut self, text: &str, source: CommandSource, status: Option<i32>) {
        self.command_count += 1;
        event::command(self.session_id, self.peer, text, source, status);
    }

    fn hold_screen(
        &mut self,
        channel: ChannelId,
        screen: Screen,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        match screen {
            Screen::Top(top) => {
                let first = format!("{SCREEN_HOME}{}", top.render());
                session.data(channel, self.out(&first))?;
                let handle = session.handle();
                let pty = self.pty;
                let redraw = tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(SCREEN_REFRESH);

                    ticker.tick().await;
                    loop {
                        ticker.tick().await;
                        let frame = format!("{SCREEN_HOME}{}", top.render());
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
                self.screen = Some(ScreenHold {
                    kind: ScreenKind::Top,
                    colon: None,
                    redraw: Some(redraw),
                });
            }
            Screen::Editor(editor) => {
                let kind = match editor.kind() {
                    crate::commands::text::EditorKind::Vi => ScreenKind::Vi,
                    crate::commands::text::EditorKind::Nano => ScreenKind::Nano,
                };
                let first = format!("{SCREEN_HOME}{}", editor.render());
                session.data(channel, self.out(&first))?;
                self.screen = Some(ScreenHold {
                    kind,
                    colon: None,
                    redraw: None,
                });
            }
            Screen::Listen => {
                self.screen = Some(ScreenHold {
                    kind: ScreenKind::Listen,
                    colon: None,
                    redraw: None,
                });
            }
        }
        Ok(())
    }

    fn screen_input(&mut self, byte: u8) -> bool {
        let Some(hold) = self.screen.as_mut() else {
            return false;
        };
        let quit = match hold.kind {
            ScreenKind::Top => byte == b'q' || byte == 0x03,
            ScreenKind::Nano => byte == 0x18 || byte == 0x03,
            ScreenKind::Listen => byte == 0x03,
            ScreenKind::Vi => vi_screen_input(hold, byte),
        };
        if quit {
            self.screen = None;
        }
        !quit
    }

    async fn feed_no_tty(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        for &byte in data {
            match byte {
                b'\r' => {}
                b'\n' => {
                    let line = String::from_utf8_lossy(&std::mem::take(&mut self.line_buf))
                        .trim_end_matches('\r')
                        .to_string();
                    if self.run_no_tty_line(channel, &line, session).await? {
                        return Ok(());
                    }
                }

                _ => {
                    if self.line_buf.len() < MAX_COMMAND_LEN {
                        self.line_buf.push(byte);
                    }
                }
            }
        }
        Ok(())
    }

    async fn run_no_tty_line(
        &mut self,
        channel: ChannelId,
        line: &str,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        if self.shell().pending.is_some() {
            let output = self.shell().resume(line);
            self.log_closed_heredoc();
            return self.deliver(channel, &output, session).await;
        }
        self.submit_line(channel, line, session).await
    }

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

    fn shell(&mut self) -> &mut Shell {
        if self.shell.is_none() {
            let mut shell = Shell::with_persona(
                &self.username,
                &self.config.hostname,
                (*self.persona).clone(),
            );

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
                shell.env.set("SSH_TTY", "/dev/pts/0");
            }

            if let Some(pty) = self.pty_term.as_ref() {
                shell.env.set("TERM", &pty.term);
                shell.env.set("COLUMNS", &pty.cols.to_string());
                shell.env.set("LINES", &pty.rows.to_string());
            }

            for (key, value) in &self.accepted_env {
                shell.env.set(key, value);
            }
            self.shell = Some(shell);
        }
        self.shell.as_mut().expect("shell just initialised")
    }

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

    fn drain_captures(&mut self) {
        let (session_id, peer) = (self.session_id, self.peer);
        let captures = std::mem::take(&mut self.shell().captures);
        for capture in captures {
            match capture {
                Capture::Download { tool, url, dest } => {
                    event::download(session_id, peer, &tool, &url, &dest);
                }
                Capture::ScriptCommand { line, status } => {
                    self.log_command(&line, CommandSource::Script, Some(status));
                }
                Capture::PasswordChange { target, password } => {
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

    fn store_upload(&mut self, file: scp::CompletedFile) {
        let (session_id, peer) = (self.session_id, self.peer);
        let quarantine_dir = self.config.quarantine_dir.clone();

        let mut hasher = Sha256::new();
        hasher.update(&file.data);
        let stored_sha256 = hex(&hasher.finalize());

        let target = self
            .scp
            .as_ref()
            .map(|s| s.target().to_string())
            .unwrap_or_else(|| "/tmp".to_string());
        let recursive = self.scp.as_ref().map(|s| s.recursive()).unwrap_or(false);
        let dest_path = self.write_to_vfs(&target, recursive, &file);

        let session_cap = self
            .config
            .max_upload_bytes
            .saturating_mul(QUARANTINE_SESSION_MULTIPLIER);
        let global_cap = self.config.quarantine_max_total_bytes.unwrap_or_else(|| {
            self.config
                .max_upload_bytes
                .saturating_mul(QUARANTINE_GLOBAL_MULTIPLIER)
        });
        let current_global = self.global_quarantine_bytes.load(Ordering::Relaxed);

        let stored_path =
            if self.quarantine_bytes.saturating_add(file.data.len() as u64) > session_cap {
                event::quarantine_session_cap(session_id, peer);
                String::new()
            } else if current_global.saturating_add(file.data.len() as u64) > global_cap {
                event::quarantine_global_cap(session_id, peer);
                String::new()
            } else {
                match write_quarantine(&quarantine_dir, &stored_sha256, &file.data) {
                    Ok((p, written)) => {
                        self.quarantine_bytes += written;
                        self.global_quarantine_bytes
                            .fetch_add(written, Ordering::Relaxed);
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

    fn store_sftp_upload(&mut self, upload: sftp::SftpCompletedUpload) {
        let (session_id, peer) = (self.session_id, self.peer);
        let quarantine_dir = self.config.quarantine_dir.clone();

        let mut hasher = Sha256::new();
        hasher.update(&upload.data);
        let stored_sha256 = hex(&hasher.finalize());

        let session_cap = self
            .config
            .max_upload_bytes
            .saturating_mul(QUARANTINE_SESSION_MULTIPLIER);
        let global_cap = self.config.quarantine_max_total_bytes.unwrap_or_else(|| {
            self.config
                .max_upload_bytes
                .saturating_mul(QUARANTINE_GLOBAL_MULTIPLIER)
        });
        let current_global = self.global_quarantine_bytes.load(Ordering::Relaxed);

        let stored_path = if self
            .quarantine_bytes
            .saturating_add(upload.data.len() as u64)
            > session_cap
        {
            event::quarantine_session_cap(session_id, peer);
            String::new()
        } else if current_global.saturating_add(upload.data.len() as u64) > global_cap {
            event::quarantine_global_cap(session_id, peer);
            String::new()
        } else {
            match write_quarantine(&quarantine_dir, &stored_sha256, &upload.data) {
                Ok((p, written)) => {
                    self.quarantine_bytes += written;
                    self.global_quarantine_bytes
                        .fetch_add(written, Ordering::Relaxed);
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

    fn write_to_vfs(&mut self, target: &str, recursive: bool, file: &scp::CompletedFile) -> String {
        let (uid, gid) = (self.shell().uid, self.shell().gid);
        let cwd = self.shell().cwd;

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
                let (d, n) = crate::vfs::Vfs::split_path(base.trim_end_matches('/'));
                (d.to_string(), n.to_string())
            }
        };

        let intended = format!("{}/{name}", dir_path.trim_end_matches('/'));
        let shell = self.shell();
        let Some(parent) = shell.vfs.mkdir_p(&dir_path, 0o755, uid, gid) else {
            return intended;
        };
        let id = shell.vfs.add_file(
            parent,
            &name,
            file.data.clone(),
            file.mode & 0o7777,
            uid,
            gid,
        );
        if id == parent {
            return intended;
        }
        shell.vfs.path_of(id)
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn abs_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{path}")
    } else {
        format!("{cwd}/{path}")
    }
}

fn write_quarantine(
    dir: &std::path::Path,
    sha256: &str,
    data: &[u8],
) -> std::io::Result<(String, u64)> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(sha256);

    let newly_written = if path.exists() {
        0
    } else {
        let staging = dir.join(format!("{sha256}.partial"));

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

    #[cfg(windows)]
    let stored = stored.replace('\\', "/");
    Ok((stored, newly_written))
}

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
            self.authenticated.store(true, Ordering::Relaxed);
            jitter_for(0).await;
            Ok(Auth::Accept)
        } else {
            jitter_for(0).await;

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
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.auth_attempts += 1;

        let fingerprint = key.public_key.fingerprint(Default::default()).to_string();
        event::auth_attempt(
            self.session_id,
            self.peer,
            user,
            "publickey",
            None,
            Some(&fingerprint),
            false,
        );

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
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log_client_banner(session);
        if self.try_open_channel(channel.id().number()) {
            reply.accept().await;
        } else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        }
        Ok(())
    }

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

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if variable_name == "LANG" || variable_name.starts_with("LC_") {
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

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
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

        let pty = self.pty;
        self.shell().interactive = pty;

        let banner = self.out(&self.motd());
        session.data(channel, banner)?;
        if !self.pty {
            return Ok(());
        }

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

                    session.data(channel, vec![0u8])?;
                    return Ok(());
                }
                ScpMode::Source { path } => {
                    self.log_command(&cmd, CommandSource::Exec, Some(1));
                    let msg = format!("\x01scp: {path}: No such file or directory\n");
                    session.data(channel, msg.into_bytes())?;
                    self.end_channel(channel, session, 1)?;
                    return Ok(());
                }
            }
        }

        self.shell().interactive = false;
        let mut result = self.shell().execute(&cmd);

        if let Some(finished) = self.shell().finish_heredoc_at_eof() {
            self.log_closed_heredoc();
            result = finished;
        }

        self.shell().pending = None;

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
        if self.sftp.is_some() {
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

        if !self.pty {
            return self.feed_no_tty(channel, data, session).await;
        }

        let mut rest = data;
        if let Some(kind) = self.screen.as_ref().map(|hold| hold.kind) {
            let quit_at = data.iter().position(|&byte| !self.screen_input(byte));
            let Some(i) = quit_at else {
                return Ok(());
            };
            let bytes = match kind {
                ScreenKind::Listen => self.out("^C\n"),
                ScreenKind::Top | ScreenKind::Vi | ScreenKind::Nano => self.out(SCREEN_HOME),
            };
            session.data(channel, bytes)?;
            let prompt = self.shell().prompt();
            self.editor.set_prompt(&prompt);
            session.data(channel, self.editor.render().to_vec())?;

            rest = &data[i + 1..];
        }

        for &byte in rest {
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

                        if self.shell().pending.as_ref().is_some_and(|p| !p.echoes()) {
                            self.password_buf = Some(Vec::new());
                            continue;
                        }
                        let prompt = self.shell().prompt();
                        self.editor.set_prompt(&prompt);
                        session.data(channel, self.editor.render().to_vec())?;
                    }
                    0x03 => {
                        self.password_buf = None;
                        self.shell().pending = None;
                        session.data(channel, b"\r\n".to_vec())?;
                        let prompt = self.shell().prompt();
                        self.editor.set_prompt(&prompt);
                        session.data(channel, self.editor.render().to_vec())?;
                    }
                    0x08 | 0x7f => {
                        if let Some(buf) = self.password_buf.as_mut() {
                            while buf.pop().is_some_and(is_continuation) {}
                        }
                    }
                    0x20..=0x7e | 0x80..=0xff => {
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
                    let bytes = self.out(LOGOUT);
                    session.data(channel, bytes)?;
                    let status = self.shell().last_status as u32;
                    self.end_channel(channel, session, status)?;
                    return Ok(());
                }
                Reaction::Submit { echo, line } => {
                    session.data(channel, echo)?;

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

                    if let Some(screen) = self.shell().screen.take() {
                        self.hold_screen(channel, screen, session)?;
                        continue;
                    }

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
        if self.scp.take().is_some() {
            self.end_channel(channel, session, 0)?;
        } else if self.sftp.is_some() {
            let _ = self.shell();
            self.drain_sftp_uploads();
            self.end_channel(channel, session, 0)?;
        } else if self.shell_started && self.active_channel == Some(channel.number()) {
            if !self.pty {
                if !self.line_buf.is_empty() {
                    let line = String::from_utf8_lossy(&std::mem::take(&mut self.line_buf))
                        .trim_end_matches('\r')
                        .to_string();
                    if self.run_no_tty_line(channel, &line, session).await? {
                        return Ok(());
                    }
                }

                if let Some(output) = self.shell().finish_heredoc_at_eof() {
                    self.log_closed_heredoc();
                    if self.deliver(channel, &output, session).await? {
                        return Ok(());
                    }
                }

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

fn sanitise_env_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}

async fn jitter_for(output_bytes: usize) {
    let base = 900u64;

    let work = (output_bytes as u64).saturating_mul(1).min(240_000);

    let noise = rand::random_range(40..=170) * rand::random_range(40..=170) / 100;
    let micros = (base + work).saturating_mul(noise) / 100;
    tokio::time::sleep(Duration::from_micros(micros.clamp(400, 450_000))).await;
}

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
            authenticated: Arc::new(AtomicBool::new(true)),
            username: "root".to_string(),
            editor: LineEditor::new(MAX_COMMAND_LEN, 1000),
            shell_started: false,
            shell: None,
            active_channel: None,
            scp: Some(ScpSink::new("/tmp".to_string(), false, max_upload_bytes)),
            sftp: None,
            quarantine_bytes: 0,
            global_quarantine_bytes: Arc::new(AtomicU64::new(0)),
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

        let file_size: usize = 1000;
        let num_files = (cap / file_size as u64) + 5;
        for i in 0..num_files {
            handler.store_upload(CompletedFile {
                name: format!("f{i}"),
                rel_dir: String::new(),
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

        handler1.store_upload(CompletedFile {
            name: "h1_file".to_string(),
            rel_dir: String::new(),
            mode: 0o644,
            data: vec![1u8; 1000],
            size: 1000,
            payload_sha256: String::new(),
            truncated: false,
        });

        handler2.store_upload(CompletedFile {
            name: "h2_file1".to_string(),
            rel_dir: String::new(),
            mode: 0o644,
            data: vec![2u8; 1000],
            size: 1000,
            payload_sha256: String::new(),
            truncated: false,
        });

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

    #[tokio::test]
    async fn session_cap_disconnects_a_live_session() {
        const CAP_SECS: u64 = 1;

        let dir =
            std::env::temp_dir().join(format!("mimic-session-cap-test-{}", std::process::id()));

        let probe = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);

        let config = Config {
            listen_addr: "127.0.0.1".parse().expect("loopback"),
            port,
            max_session_secs: CAP_SECS,

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

    async fn drain_until_closed(
        channel: &mut russh::Channel<russh::client::Msg>,
    ) -> (Vec<u8>, Option<u32>) {
        let (seen, _, status) = drain_streams(channel).await;
        (seen, status)
    }

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

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn top_holds_the_screen_until_q() {
        let (_handle, mut channel, dir) = shell_session("top-hold").await;

        read_for(&mut channel, Duration::from_millis(300)).await;

        channel.data(&b"top\r"[..]).await.expect("send top");

        let held = read_for(&mut channel, SCREEN_REFRESH + Duration::from_secs(2)).await;
        let held = String::from_utf8_lossy(&held).into_owned();

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
        let after = read_for(&mut channel, Duration::from_millis(400)).await;
        let after = String::from_utf8_lossy(&after).into_owned();
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

        let _ = std::fs::remove_dir_all(&dir);
    }

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

        assert!(done.contains("root@debian"), "no prompt after: {done:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

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
