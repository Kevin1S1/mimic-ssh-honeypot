use super::expand::Expansion;
use super::{parser, Capture, Output, Shell};
use crate::commands;

const HEREDOC_PROMPT: &str = "> ";
const PASSWORD_MISMATCH: &str = "Sorry, passwords do not match.\n\
                                 passwd: Authentication token manipulation error\n\
                                 passwd: password unchanged\n";

/// A follow-up line of input a command is waiting for. While a shell has a
/// pending prompt, the network layer collects the next line (with echo
/// suppressed) and feeds it back via [`Shell::resume`], rather than treating it
/// as a new command.
#[derive(Debug, Clone)]
pub enum Pending {
    /// `su [USER]` is waiting for the target's password before switching.
    SuPassword {
        /// The account to become once a password is supplied.
        target: String,
    },
    /// `passwd [USER]` is collecting a new secret. Real `passwd` asks twice and
    /// refuses if the two differ, so both prompts are emulated: the second one
    /// is where a script that pipes the same line twice succeeds and a typo
    /// fails, which is the behaviour a bot's `passwd` wrapper is written for.
    NewPassword {
        /// The account whose password is being set.
        target: String,
        /// The first answer, once given.
        first: Option<String>,
    },
    /// A here-document (`cat << EOF`) is collecting its body. The line that
    /// opened it runs once a line holds the delimiter and nothing else.
    Heredoc {
        /// The command line with the `<<` operator and delimiter removed.
        command: String,
        /// The line exactly as it was typed, for the capture.
        raw: String,
        /// What ends the body, and how the body is treated.
        doc: parser::Heredoc,
        /// The lines collected so far, each newline-terminated.
        body: String,
    },
}

impl Pending {
    /// Whether the client's answer is echoed back as it is typed. A password
    /// is not; a here-document body is ordinary input and bash's readline
    /// echoes it under its continuation prompt.
    pub fn echoes(&self) -> bool {
        matches!(self, Pending::Heredoc { .. })
    }

    /// The prompt shown while this is outstanding, if the shell draws one.
    /// `su` writes its own; a here-document gets bash's `PS2`.
    pub fn prompt(&self) -> Option<&'static str> {
        match self {
            Pending::SuPassword { .. } | Pending::NewPassword { .. } => None,
            Pending::Heredoc { .. } => Some(HEREDOC_PROMPT),
        }
    }
}

impl Shell {
    /// Complete a [`Pending`] interactive prompt with the line the client just
    /// entered (e.g. the password for `su`). Clears the pending state and
    /// returns the resulting output.
    pub fn resume(&mut self, input: &str) -> Output {
        match self.pending.take() {
            Some(Pending::SuPassword { target }) => self.answer_su(&target, input),
            Some(Pending::NewPassword {
                target,
                first: None,
            }) => {
                self.pending = Some(Pending::NewPassword {
                    target,
                    first: Some(input.to_string()),
                });
                Output::written("Retype new password: ", "", 0)
            }
            Some(Pending::NewPassword {
                target,
                first: Some(first),
            }) => self.confirm_new_password(&target, &first, input),
            Some(Pending::Heredoc {
                command,
                raw,
                doc,
                body,
            }) => self.collect_heredoc_line(command, raw, doc, body, input),
            None => Output::default(),
        }
    }

    fn answer_su(&mut self, target: &str, password: &str) -> Output {
        // Capture the attempted password as forensic data, then switch.
        // The honeypot keeps the attacker engaged rather than gating on
        // a real credential (same rationale as `sudo`/`su`), but a
        // realistic `Password:` prompt still has to appear first.
        self.captures.push(Capture::SuAuth {
            target: target.to_string(),
            password: password.to_string(),
        });
        self.switch_user(target);
        Output::default()
    }

    fn confirm_new_password(&mut self, target: &str, first: &str, retyped: &str) -> Output {
        if first != retyped {
            return Output::written("", PASSWORD_MISMATCH, 1);
        }
        // The plaintext is the forensic value; the emulated shadow file
        // only ever holds a crypt-shaped placeholder.
        self.captures.push(Capture::PasswordChange {
            target: target.to_string(),
            password: first.to_string(),
        });
        commands::admin::set_shadow_entry(self, target);
        Output::written("passwd: password updated successfully\n", "", 0)
    }

    fn collect_heredoc_line(
        &mut self,
        command: String,
        raw: String,
        doc: parser::Heredoc,
        mut body: String,
        input: &str,
    ) -> Output {
        let line = if doc.strip_tabs {
            input.trim_start_matches('\t')
        } else {
            input
        };
        if line == doc.delimiter {
            return self.run_heredoc(&command, &raw, &doc, body);
        }
        body.push_str(line);
        body.push('\n');
        // The body grows a line at a time from the client, so it is
        // capped like every other buffer an attacker can drive.
        commands::truncate_stream(&mut body, commands::MAX_COMMAND_OUTPUT_BYTES);
        self.pending = Some(Pending::Heredoc {
            command,
            raw,
            doc,
            body,
        });
        Output::default()
    }

    /// End a here-document at end-of-input rather than at its delimiter.
    ///
    /// A script that stops mid-body still runs the command with what it has,
    /// and bash warns on the way — so `ssh host 'cat << EOF'`, which can never
    /// supply a body, behaves the way `bash -c` does with the same string.
    pub fn finish_heredoc_at_eof(&mut self) -> Option<Output> {
        let Some(Pending::Heredoc {
            command,
            raw,
            doc,
            body,
        }) = self.pending.take()
        else {
            return None;
        };
        let mut out = self.run_heredoc(&command, &raw, &doc, body);
        out.prepend_stderr(&format!(
            "-bash: warning: here-document delimited by end-of-file (wanted `{}')\n",
            doc.delimiter
        ));
        Some(out)
    }

    /// Run the line a here-document was opened on, with the collected body as
    /// its stdin.
    fn run_heredoc(
        &mut self,
        command: &str,
        raw: &str,
        doc: &parser::Heredoc,
        body: String,
    ) -> Output {
        self.pending = None;
        // The body *is* the payload — a dropped script, a crontab, a key — so
        // the capture records the document whole rather than a bare `cat` with
        // the interesting part missing. Logged here, once, when it closes:
        // the body lines are not commands and are never logged as such.
        self.heredoc_log = Some(format!("{raw}\n{body}{}", doc.delimiter));
        // An unquoted delimiter leaves the body subject to expansion, which is
        // how `cat << EOF` interpolates `$HOME`; a quoted one takes it as-is.
        let text = if doc.expand {
            self.expand_with(&body, Expansion::Literal)
        } else {
            body
        };
        self.heredoc_stdin = Some(text);
        let out = self.execute(command);
        // A command that ignored stdin leaves the body behind; it belongs to
        // this line only.
        self.heredoc_stdin = None;
        out
    }
}
