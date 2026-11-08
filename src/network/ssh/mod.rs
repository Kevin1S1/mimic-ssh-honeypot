//! SSH protocol engine built on `russh`.
//!
//! Drives the handshake, credential capture, and a full interactive
//! line-editing shell over the emulated Debian filesystem. SCP uploads are
//! intercepted, content-addressed, and quarantined. The only real I/O in this
//! file is host-key persistence and the quarantine store; everything the
//! attacker "runs" is a pure in-memory state machine.

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

const HISTORY_CAPACITY: usize = 1000;

fn new_line_editor() -> LineEditor {
    LineEditor::new(MAX_COMMAND_LEN, HISTORY_CAPACITY)
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
    /// Set once a login is accepted; the session watchdog reads it to enforce
    /// [`LOGIN_GRACE`].
    authenticated: Arc<AtomicBool>,
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
    /// Shared tracker for total real-disk quarantine usage across all active sessions.
    global_quarantine_bytes: Arc<AtomicU64>,
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
            self.editor = new_line_editor();
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

    /// Emit what one completed line produced and end the channel if the line
    /// finished the session. Returns whether the session ended.
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
                pty.export_size(&mut shell);
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
                    self.log_accepted_password(&target, "chpasswd", &password);
                }
                Capture::SuAuth { target, password } => {
                    // A guessed password entered at an `su` prompt: log it as an
                    // authentication attempt (accepted, matching the switch).
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
            // Keep offering the password method so the client re-prompts.
            // With `proceed_with_methods: None`, russh removes `password` from
            // the offered set on rejection, leaving only `publickey` — the
            // client then aborts after one wrong password with
            // "Permission denied (publickey)", an obvious honeypot tell. Real
            // sshd re-prompts (up to MaxAuthTries), which is also required for
            // `accept_after` to ever see a second attempt on one connection.
            Ok(reject_but_offer_password())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.auth_attempts += 1;
        // The offered key is intelligence in its own right: campaigns reuse key
        // material, so the fingerprint pivots across sessions and sensors in a
        // way a sprayed password does not.
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

        // Reject public-key auth so clients fall back to password, which we can
        // capture in cleartext.
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
            cols: terminal_dimension(col_width, DEFAULT_COLS),
            rows: terminal_dimension(row_height, DEFAULT_ROWS),
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
        if !is_locale_variable(variable_name) {
            session.channel_failure(channel)?;
            return Ok(());
        }
        // Debian's stock *client* ssh_config ships `SendEnv LANG LC_*`, so
        // ordinary clients hit this on every connection. Answering
        // `channel_success` and then discarding the value is worse than
        // refusing it: the server says "accepted" and `echo $LANG` still
        // reports the built-in default.
        if self.accepted_env.len() < MAX_ACCEPTED_ENV {
            self.accepted_env.push((
                variable_name.to_string(),
                sanitise_env_value(variable_value),
            ));
        }
        session.channel_success(channel)?;
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
            pty.cols = terminal_dimension(col_width, pty.cols);
            pty.rows = terminal_dimension(row_height, pty.rows);
            if let Some(shell) = self.shell.as_mut() {
                pty.export_size(shell);
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

        // SCP transfer requests keep the channel open and drive a sub-protocol
        // over subsequent `data` frames rather than running a one-shot command.
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
        // A shell channel that asked for no terminal reads lines rather than
        // running a line editor over them.
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

fn reject_but_offer_password() -> Auth {
    let mut proceed_with_methods = MethodSet::empty();
    proceed_with_methods.push(MethodKind::Password);
    Auth::Reject {
        proceed_with_methods: Some(proceed_with_methods),
        partial_success: false,
    }
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

#[cfg(test)]
mod tests;
