use super::terminal::{BACKSPACE, CTRL_C, DELETE};
use super::{
    send_if_any, MimicHandler, MAX_COMMAND_LEN, MAX_PENDING_OUTPUT_BYTES,
    QUEUED_WRITE_OVERHEAD_BYTES,
};
use crate::shell::line::{is_continuation, Reaction};
use russh::server::Session;
use russh::ChannelId;

/// SFTP replies generated but not yet handed to russh.
///
/// russh sends what the peer's window allows and queues the rest without
/// bound. Replies are parked here while that queue is non-empty, so the bytes
/// outstanding for a peer that is not reading are bounded by this buffer plus
/// one release, and this buffer's size is known exactly.
#[derive(Default)]
pub(super) struct OutputBacklog {
    held: Vec<u8>,
}

impl OutputBacklog {
    pub(super) fn hold(&mut self, mut bytes: Vec<u8>) {
        if self.held.is_empty() {
            self.held = bytes;
        } else {
            self.held.append(&mut bytes);
        }
    }

    /// Everything held, if the peer has drained what russh already had queued;
    /// nothing otherwise.
    pub(super) fn release(&mut self, peer_drained: bool) -> Vec<u8> {
        if peer_drained {
            std::mem::take(&mut self.held)
        } else {
            Vec::new()
        }
    }

    pub(super) fn overflowed(&self) -> bool {
        self.held.len() > MAX_PENDING_OUTPUT_BYTES
    }
}

/// Upper bound on the shell, exec, screen and SCP output that russh may still
/// be holding for the peer.
///
/// russh reports only whether its queue is empty, so this counts every byte
/// written since the queue was last seen empty at the start of a callback. It
/// overstates the queue (the peer may have read part of it) and never
/// understates it.
#[derive(Default)]
pub(super) struct OutputMeter {
    unread: usize,
}

impl OutputMeter {
    pub(super) fn peer_caught_up(&mut self) {
        self.unread = 0;
    }

    /// Records one write; false once the peer is too far behind.
    pub(super) fn charge(&mut self, len: usize) -> bool {
        self.unread = self
            .unread
            .saturating_add(len)
            .saturating_add(QUEUED_WRITE_OVERHEAD_BYTES);
        self.unread <= MAX_PENDING_OUTPUT_BYTES
    }
}

impl MimicHandler {
    /// Hands held SFTP replies to russh once its own queue for the channel is
    /// empty. Called after each feed and on every window adjustment.
    ///
    /// russh also empties its queue when a key re-exchange completes, which has
    /// no handler callback; replies held across one go out on the peer's next
    /// packet or window adjustment instead.
    pub(super) fn pump_sftp_output(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let peer_drained = !session.has_pending_data(channel);
        send_if_any(session, channel, self.sftp_backlog.release(peer_drained))
    }

    pub(super) fn feed_sftp(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), russh::Error> {
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
        self.sftp_backlog.hold(resp);
        self.pump_sftp_output(channel, session)?;
        // Backpressure: a client that pipelines READs without reading the
        // replies would otherwise grow the outbound queue without limit.
        if self.sftp_backlog.overflowed() {
            tracing::debug!(
                event = "sftp_output_backlog_exceeded",
                session_id = self.session_id,
            );
            return self.end_channel(channel, session, 0);
        }
        Ok(())
    }

    pub(super) fn feed_scp(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let (acks, files) = self.scp.as_mut().expect("scp active").feed(data);
        for file in files {
            self.store_upload(file);
        }
        self.send(channel, acks, session)
    }

    pub(super) async fn feed_terminal_byte(
        &mut self,
        channel: ChannelId,
        byte: u8,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        if self.password_buf.is_some() {
            return self.feed_password_byte(channel, byte, session).await;
        }
        match self.editor.input(byte) {
            Reaction::Ignore => {}
            Reaction::Write(bytes) => self.send(channel, bytes, session)?,
            Reaction::Complete => {
                let bytes = self.complete_current_word();
                self.send(channel, bytes, session)?;
            }
            Reaction::Eof => {
                self.logout(channel, session)?;
                return Ok(true);
            }
            Reaction::Submit { echo, line } => {
                self.send(channel, echo, session)?;
                return self.submit_terminal_line(channel, &line, session).await;
            }
        }
        Ok(false)
    }

    pub(super) async fn submit_terminal_line(
        &mut self,
        channel: ChannelId,
        line: &str,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        let ended = if self.shell().pending.as_ref().is_some_and(|p| p.echoes()) {
            let output = self.shell().resume(line);
            self.log_closed_heredoc();
            self.deliver(channel, &output, session).await?
        } else {
            self.submit_line(channel, line, session).await?
        };
        if ended {
            return Ok(true);
        }

        if let Some(screen) = self.shell().screen.take() {
            self.hold_screen(channel, screen, session)?;
            return Ok(false);
        }

        let continuation = match self.shell().pending.as_ref() {
            None => None,
            Some(pending) if !pending.echoes() => {
                self.password_buf = Some(Vec::new());
                return Ok(false);
            }
            Some(pending) => pending.prompt(),
        };
        match continuation {
            Some(ps2) => self.show_prompt(channel, ps2, session)?,
            None => self.show_shell_prompt(channel, session)?,
        }
        Ok(false)
    }

    pub(super) async fn feed_password_byte(
        &mut self,
        channel: ChannelId,
        byte: u8,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        match byte {
            b'\r' | b'\n' => return self.submit_password(channel, session).await,
            CTRL_C => {
                self.password_buf = None;
                self.shell().pending = None;
                self.send(channel, b"\r\n".to_vec(), session)?;
                self.show_shell_prompt(channel, session)?;
            }
            BACKSPACE | DELETE => {
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
        Ok(false)
    }

    pub(super) async fn submit_password(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        let password = self.password_buf.take().unwrap_or_default();
        let password = String::from_utf8_lossy(&password).into_owned();
        self.send(channel, b"\r\n".to_vec(), session)?;

        let output = self.shell().resume(&password);
        if self.deliver(channel, &output, session).await? {
            return Ok(true);
        }

        if self.shell().pending.as_ref().is_some_and(|p| !p.echoes()) {
            self.password_buf = Some(Vec::new());
            return Ok(false);
        }
        self.show_shell_prompt(channel, session)?;
        Ok(false)
    }

    pub(super) async fn feed_no_tty(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        for &byte in data {
            match byte {
                b'\r' => {}
                b'\n' => {
                    let line = self.take_no_tty_line();
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

    pub(super) async fn end_no_tty_shell(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if !self.line_buf.is_empty() {
            let line = self.take_no_tty_line();
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

        self.end_shell_channel(channel, session)
    }

    pub(super) fn take_no_tty_line(&mut self) -> String {
        String::from_utf8_lossy(&std::mem::take(&mut self.line_buf))
            .trim_end_matches('\r')
            .to_string()
    }

    pub(super) async fn run_no_tty_line(
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
}
