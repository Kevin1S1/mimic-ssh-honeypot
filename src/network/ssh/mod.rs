mod exec;
mod input;
mod quarantine;
mod screen;
mod server;
mod terminal;

pub(super) use quarantine::hex;
pub use server::serve;

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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_COMMAND_LEN: usize = 4096;

const LOGOUT: &str = "logout\n";

const SSH_EXTENDED_DATA_STDERR: u32 = 1;

const HISTORY_CAPACITY: usize = 1000;

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
            quarantine_bytes: 0,
            global_quarantine_bytes: Arc::clone(&shared.global_quarantine_bytes),
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

    async fn respond(
        &mut self,
        channel: ChannelId,
        output: &Output,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.drain_captures();
        jitter_for(output.text.len() + output.stdout.len() + output.stderr.len()).await;
        self.write_output(channel, output, session)
    }

    fn show_prompt(
        &mut self,
        channel: ChannelId,
        prompt: &str,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.editor.set_prompt(prompt);
        session.data(channel, self.editor.render().to_vec())?;
        Ok(())
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
        session.data(channel, self.out(LOGOUT))?;
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
                pty.export_size(&mut shell);
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
    let base = 900u64;

    let work = (output_bytes as u64).saturating_mul(1).min(240_000);

    let noise = rand::random_range(40..=170) * rand::random_range(40..=170) / 100;
    let micros = (base + work).saturating_mul(noise) / 100;
    tokio::time::sleep(Duration::from_micros(micros.clamp(400, 450_000))).await;
}

#[cfg(test)]
mod tests;
