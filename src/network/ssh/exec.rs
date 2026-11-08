use super::MimicHandler;
use crate::logging::event::CommandSource;
use crate::network::scp::{ScpMode, ScpSink};
use russh::server::Session;
use russh::ChannelId;

const SCP_READY: u8 = 0;
const SCP_FAILURE_STATUS: i32 = 1;
impl MimicHandler {
    pub(super) fn start_scp(
        &mut self,
        channel: ChannelId,
        cmd: &str,
        mode: ScpMode,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        match mode {
            ScpMode::Sink { target, recursive } => {
                self.log_command(cmd, CommandSource::Exec, None);
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
                session.data(channel, vec![SCP_READY])?;
                Ok(())
            }
            ScpMode::Source { path } => {
                // Download-from-honeypot is not emulated: report not found.
                self.log_command(cmd, CommandSource::Exec, Some(SCP_FAILURE_STATUS));
                let msg = format!("\x01scp: {path}: No such file or directory\n");
                session.data(channel, msg.into_bytes())?;
                self.end_channel(channel, session, SCP_FAILURE_STATUS as u32)
            }
        }
    }

    pub(super) async fn run_exec(
        &mut self,
        channel: ChannelId,
        cmd: &str,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        // A one-shot `exec` is never interactive, whatever the previous channel
        // on this connection was.
        self.shell().interactive = false;
        let mut result = self.shell().execute(cmd);
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
        self.log_command(cmd, CommandSource::Exec, Some(result.status));
        self.respond(channel, &result, session).await?;
        self.end_channel(channel, session, result.status as u32)
    }
}
