use super::expand::Expansion;
use super::{parser, Capture, Output, Shell};
use crate::commands;

const HEREDOC_PROMPT: &str = "> ";
const PASSWORD_MISMATCH: &str = "Sorry, passwords do not match.\n\
                                 passwd: Authentication token manipulation error\n\
                                 passwd: password unchanged\n";

#[derive(Debug, Clone)]
pub enum Pending {
    SuPassword {
        target: String,
    },

    NewPassword {
        target: String,

        first: Option<String>,
    },

    Heredoc {
        command: String,

        raw: String,

        doc: parser::Heredoc,

        body: String,
    },
}

impl Pending {
    pub fn echoes(&self) -> bool {
        matches!(self, Pending::Heredoc { .. })
    }

    pub fn prompt(&self) -> Option<&'static str> {
        match self {
            Pending::SuPassword { .. } | Pending::NewPassword { .. } => None,
            Pending::Heredoc { .. } => Some(HEREDOC_PROMPT),
        }
    }
}

impl Shell {
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

        commands::truncate_stream(&mut body, commands::MAX_COMMAND_OUTPUT_BYTES);
        self.pending = Some(Pending::Heredoc {
            command,
            raw,
            doc,
            body,
        });
        Output::default()
    }

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

    fn run_heredoc(
        &mut self,
        command: &str,
        raw: &str,
        doc: &parser::Heredoc,
        body: String,
    ) -> Output {
        self.pending = None;

        self.heredoc_log = Some(format!("{raw}\n{body}{}", doc.delimiter));

        let text = if doc.expand {
            self.expand_with(&body, Expansion::Literal)
        } else {
            body
        };
        self.heredoc_stdin = Some(text);
        let out = self.execute(command);

        self.heredoc_stdin = None;
        out
    }
}
