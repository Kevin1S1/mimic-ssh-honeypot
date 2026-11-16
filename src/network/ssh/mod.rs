mod exec;
mod input;
mod quarantine;
mod screen;
mod server;
mod terminal;

pub use server::serve;

use input::{OutputBacklog, OutputMeter};
use quarantine::QuarantineStore;
use screen::ScreenHold;
use server::SharedState;
use terminal::{
    format_columns, is_locale_variable, sanitise_env_value, sanitise_term, terminal_dimension,
    PtyRequest, DEFAULT_COLS, DEFAULT_ROWS, MAX_ACCEPTED_ENV,
};

use crate::config::{AuthMode, Config};
use crate::logging::event;
use crate::logging::event::CommandSource;
use crate::network::limiter::ConnectionGuard;
use crate::network::scp::{self, ScpSink};
use crate::network::sftp::SftpSession;
use crate::shell::complete::{self, Completion};
use crate::shell::line::LineEditor;
use crate::shell::{Capture, Output, Shell};

use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_COMMAND_LEN: usize = 4096;

// Ceiling on SFTP reply bytes held back for a peer that has stopped advancing
// its receive window. russh queues such data in an unbounded per-channel
// VecDeque and exposes only whether that queue is empty, not its size, so
// replies are held in `OutputBacklog` (whose size is known exactly) and handed
// to russh only once its queue has drained. Several windows' worth (OpenSSH's
// window is 2 MiB) of slack before the peer is treated as abusive and the
// channel is dropped.
const MAX_PENDING_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

// What one queued write costs beyond its payload: russh keeps each write as
// its own queue entry with its own allocation, so a flood of one-byte echoes
// would otherwise be charged far less than the memory it holds.
const QUEUED_WRITE_OVERHEAD_BYTES: usize = 64;

const LOGOUT: &str = "logout\n";

const SSH_EXTENDED_DATA_STDERR: u32 = 1;

const HISTORY_CAPACITY: usize = 1000;

const PTY_DEVICE: &str = "/dev/pts/0";

const KERNEL_RELEASE: &str = "6.1.0-21-amd64";
const KERNEL_VERSION: &str = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)";
const MACHINE: &str = "x86_64";
const DEBIAN_NOTICE: &str = "\
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
";

const JITTER_BASE_MICROS: u64 = 900;
const JITTER_MICROS_PER_OUTPUT_BYTE: u64 = 1;
const JITTER_MAX_WORK_MICROS: u64 = 240_000;
const JITTER_NOISE_PERCENT: std::ops::RangeInclusive<u64> = 40..=170;
const JITTER_MIN_MICROS: u64 = 400;
const JITTER_MAX_MICROS: u64 = 450_000;
const PERCENT: u64 = 100;

fn new_line_editor() -> LineEditor {
    LineEditor::new(MAX_COMMAND_LEN, HISTORY_CAPACITY)
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

    sftp_backlog: OutputBacklog,

    output_meter: OutputMeter,

    draining_channels: Vec<ChannelId>,

    quarantine_store: QuarantineStore,

    password_buf: Option<Vec<u8>>,

    line_buf: Vec<u8>,

    screen: Option<ScreenHold>,

    pty_term: Option<PtyRequest>,

    accepted_env: Vec<(String, String)>,

    banner_logged: bool,

    opened_at: std::time::Instant,

    session_deadline: tokio::time::Instant,

    command_count: u64,

    persona: Arc<crate::persona::Persona>,

    _guard: ConnectionGuard,
}

impl MimicHandler {
    fn new(
        shared: &SharedState,
        session_id: u64,
        peer: SocketAddr,
        local: SocketAddr,
        guard: ConnectionGuard,
    ) -> Self {
        Self {
            config: Arc::clone(&shared.config),
            persona: Arc::clone(&shared.persona),
            session_id,
            peer,
            local,
            pty: false,
            auth_attempts: 0,
            authenticated: Arc::new(AtomicBool::new(false)),
            username: String::new(),
            editor: new_line_editor(),
            shell_started: false,
            shell: None,
            active_channel: None,
            scp: None,
            sftp: None,
            sftp_backlog: OutputBacklog::default(),
            output_meter: OutputMeter::default(),
            draining_channels: Vec::new(),
            quarantine_store: QuarantineStore::new(
                &shared.config,
                Arc::clone(&shared.global_quarantine_bytes),
            ),
            password_buf: None,
            line_buf: Vec::new(),
            screen: None,
            pty_term: None,
            accepted_env: Vec::new(),
            banner_logged: false,
            opened_at: std::time::Instant::now(),
            session_deadline: tokio::time::Instant::now()
                + Duration::from_secs(shared.config.max_session_secs),
            command_count: 0,
            _guard: guard,
        }
    }

    // A channel this side has closed stays alive inside russh until the output
    // queued on it has gone out. A new channel is refused until then, so a
    // peer that reads nothing cannot stack one queue per channel.
    fn earlier_output_drained(&mut self, session: &Session) -> bool {
        self.draining_channels
            .retain(|&closed| session.has_pending_data(closed));
        self.draining_channels.is_empty()
    }

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
            self.editor = new_line_editor();
            self.shell = None;
            self.scp = None;
            self.sftp = None;
            self.sftp_backlog = OutputBacklog::default();
            self.output_meter = OutputMeter::default();
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
        if session.has_pending_data(channel) {
            self.draining_channels.push(channel);
        }
        self.close_channel(channel.number());
        Ok(())
    }

    // Shell, exec, screen and SCP output all goes through here. russh sends
    // what the peer's window allows and queues the rest without bound, and
    // everything written during one callback sits in memory until that
    // callback returns. The meter counts what has been written since a
    // callback last began with russh's queue empty; a peer that lets that pass
    // the ceiling is not reading, and the connection is dropped.
    fn send(
        &mut self,
        channel: ChannelId,
        bytes: Vec<u8>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.charge_output(bytes.len())?;
        session.data(channel, bytes)
    }

    fn send_stderr(
        &mut self,
        channel: ChannelId,
        bytes: Vec<u8>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.charge_output(bytes.len())?;
        session.extended_data(channel, SSH_EXTENDED_DATA_STDERR, bytes)
    }

    fn charge_output(&mut self, len: usize) -> Result<(), russh::Error> {
        if self.output_meter.charge(len) {
            return Ok(());
        }
        tracing::debug!(
            event = "output_backlog_exceeded",
            session_id = self.session_id,
        );
        Err(russh::Error::Disconnect)
    }

    fn note_peer_progress(&mut self, channel: ChannelId, session: &Session) {
        if !session.has_pending_data(channel) {
            self.output_meter.peer_caught_up();
        }
    }

    fn out(&self, text: &str) -> Vec<u8> {
        encode_output(text, self.pty)
    }

    fn write_output(
        &mut self,
        channel: ChannelId,
        output: &Output,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if self.pty {
            return self.send(channel, self.out(&output.text), session);
        }
        self.send(channel, self.out(&output.stdout), session)?;
        self.send_stderr(channel, self.out(&output.stderr), session)
    }

    async fn respond(
        &mut self,
        channel: ChannelId,
        output: &Output,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.drain_captures();
        self.wait_out_owed_delay().await;
        jitter_for(output.text.len() + output.stdout.len() + output.stderr.len()).await;
        self.write_output(channel, output, session)
    }

    // What `sleep` asked for. An async timer, so no runtime worker is held;
    // only this session stalls. It is cut short at the session deadline so a
    // batch of queued `sleep` lines cannot outlast the watchdog's disconnect.
    async fn wait_out_owed_delay(&mut self) {
        let owed = self.shell().take_owed_delay();
        if owed.is_zero() {
            return;
        }
        let until = (tokio::time::Instant::now() + owed).min(self.session_deadline);
        tokio::time::sleep_until(until).await;
    }

    fn show_prompt(
        &mut self,
        channel: ChannelId,
        prompt: &str,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.editor.set_prompt(prompt);
        let rendered = self.editor.render().to_vec();
        self.send(channel, rendered, session)
    }

    fn show_shell_prompt(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let prompt = self.shell().prompt();
        self.show_prompt(channel, &prompt, session)
    }

    fn end_shell_channel(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let status = self.shell().last_status as u32;
        self.end_channel(channel, session, status)
    }

    fn logout(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        self.send(channel, self.out(LOGOUT), session)?;
        self.end_shell_channel(channel, session)
    }

    async fn deliver(
        &mut self,
        channel: ChannelId,
        output: &Output,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        self.respond(channel, output, session).await?;
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
            shell.pid = self.persona.shell_pid(self.session_id);
            for (key, value) in self.connection_env() {
                shell.env.set(&key, &value);
            }
            self.shell = Some(shell);
        }
        self.shell.as_mut().expect("shell just initialised")
    }

    fn connection_env(&self) -> Vec<(String, String)> {
        let (peer_ip, peer_port) = (self.peer.ip(), self.peer.port());
        let (local_ip, local_port) = (self.local.ip(), self.local.port());
        let mut env = vec![
            (
                "SSH_CLIENT".to_string(),
                format!("{peer_ip} {peer_port} {local_port}"),
            ),
            (
                "SSH_CONNECTION".to_string(),
                format!("{peer_ip} {peer_port} {local_ip} {local_port}"),
            ),
        ];
        if self.pty {
            env.push(("SSH_TTY".to_string(), PTY_DEVICE.to_string()));
        }
        if let Some(pty) = self.pty_term.as_ref() {
            env.push(("TERM".to_string(), pty.term.clone()));
            env.extend(pty.size_env().map(|(key, value)| (key.to_string(), value)));
        }
        env.extend(self.accepted_env.iter().cloned());
        env
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
            "Linux {host} {KERNEL_RELEASE} {KERNEL_VERSION} {MACHINE}\n\n{DEBIAN_NOTICE}",
            host = self.config.hostname,
        )
    }

    fn log_accepted_password(&self, target: &str, method: &str, password: &str) {
        event::auth_attempt(
            self.session_id,
            self.peer,
            target,
            method,
            Some(password),
            None,
            true,
        );
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
                    self.log_accepted_password(&target, "chpasswd", &password);
                }
                Capture::SuAuth { target, password } => {
                    self.log_accepted_password(&target, "su", &password);
                }
            }
        }
    }
}

fn encode_output(text: &str, pty: bool) -> Vec<u8> {
    if pty {
        text.replace('\n', "\r\n").into_bytes()
    } else {
        text.as_bytes().to_vec()
    }
}

fn send_if_any(
    session: &mut Session,
    channel: ChannelId,
    bytes: Vec<u8>,
) -> Result<(), russh::Error> {
    if !bytes.is_empty() {
        session.data(channel, bytes)?;
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

            Ok(reject_but_offer_password())
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

        Ok(reject_but_offer_password())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log_client_banner(session);
        if self.earlier_output_drained(session) && self.try_open_channel(channel.id().number()) {
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
            cols: terminal_dimension(col_width, DEFAULT_COLS),
            rows: terminal_dimension(row_height, DEFAULT_ROWS),
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
        if !is_locale_variable(variable_name) {
            session.channel_failure(channel)?;
            return Ok(());
        }

        if self.accepted_env.len() < MAX_ACCEPTED_ENV {
            self.accepted_env.push((
                variable_name.to_string(),
                sanitise_env_value(variable_value),
            ));
        }
        session.channel_success(channel)?;
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
            pty.cols = terminal_dimension(col_width, pty.cols);
            pty.rows = terminal_dimension(row_height, pty.rows);
            if let Some(shell) = self.shell.as_mut() {
                pty.export_size(shell);
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
        self.send(channel, banner, session)?;
        if !self.pty {
            return Ok(());
        }

        let (prev, _) = crate::clock::prev_login();
        let last_login = self.out(&format!(
            "Last login: {} from {}\n",
            crate::clock::format(prev, "%a %b %e %H:%M:%S %Y"),
            crate::clock::PREV_LOGIN_FROM,
        ));
        self.send(channel, last_login, session)?;
        self.show_shell_prompt(channel, session)
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
            return self.start_scp(channel, &cmd, mode, session);
        }
        self.run_exec(channel, &cmd, session).await
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.sftp.is_some() {
            return self.feed_sftp(channel, data, session);
        }
        self.note_peer_progress(channel, session);
        if self.scp.is_some() {
            return self.feed_scp(channel, data, session);
        }

        if !self.pty {
            return self.feed_no_tty(channel, data, session).await;
        }
        let Some(rest) = self.feed_screen(channel, data, session)? else {
            return Ok(());
        };
        for &byte in rest {
            if self.feed_terminal_byte(channel, byte, session).await? {
                return Ok(());
            }
        }
        Ok(())
    }

    async fn window_adjusted(
        &mut self,
        channel: ChannelId,
        _new_size: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // russh has already flushed what the new window allows; if that emptied
        // its queue, the replies held back for this peer can follow.
        if self.active_channel != Some(channel.number()) {
            return Ok(());
        }
        if self.sftp.is_some() {
            return self.pump_sftp_output(channel, session);
        }
        self.note_peer_progress(channel, session);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.note_peer_progress(channel, session);
        if self.scp.take().is_some() {
            self.end_channel(channel, session, 0)?;
        } else if self.sftp.is_some() {
            let _ = self.shell();
            self.drain_sftp_uploads();
            // The client is done sending; whatever replies are still held are
            // bounded by the backlog ceiling, so hand them over before closing.
            send_if_any(session, channel, self.sftp_backlog.release(true))?;
            self.end_channel(channel, session, 0)?;
        } else if self.shell_started && self.active_channel == Some(channel.number()) {
            if self.pty {
                self.logout(channel, session)?;
            } else {
                self.end_no_tty_shell(channel, session).await?;
            }
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

fn reject_but_offer_password() -> Auth {
    let mut proceed_with_methods = MethodSet::empty();
    proceed_with_methods.push(MethodKind::Password);
    Auth::Reject {
        proceed_with_methods: Some(proceed_with_methods),
        partial_success: false,
    }
}

async fn jitter_for(output_bytes: usize) {
    let work = (output_bytes as u64)
        .saturating_mul(JITTER_MICROS_PER_OUTPUT_BYTE)
        .min(JITTER_MAX_WORK_MICROS);
    let noise_percent = rand::random_range(JITTER_NOISE_PERCENT)
        * rand::random_range(JITTER_NOISE_PERCENT)
        / PERCENT;
    let micros = (JITTER_BASE_MICROS + work).saturating_mul(noise_percent) / PERCENT;
    let micros = micros.clamp(JITTER_MIN_MICROS, JITTER_MAX_MICROS);
    tokio::time::sleep(Duration::from_micros(micros)).await;
}

#[cfg(test)]
mod tests;
