use super::redirect::Sinks;
use super::{parser, push_capped, Output, Pending, Shell};
use crate::commands::{self, CommandResult};

const SYNTAX_ERROR_STATUS: i32 = 2;
const REDIRECT_FAILURE_STATUS: i32 = 1;
const EMPTY_SEGMENT_ERROR: &str = "-bash: syntax error near unexpected token `&&'\n";

impl Shell {
    pub fn execute(&mut self, line: &str) -> Output {
        self.captures.clear();

        if self.nesting == 0 {
            self.subst_budget = commands::MAX_COMMAND_OUTPUT_BYTES;

            self.subst_stderr.clear();
            if self.park_heredoc(line) {
                return Output::default();
            }
        }

        let mut out = Output::default();
        let mut ran_status = None;

        for segment in parser::split_segments(parser::strip_comment(line)) {
            if segment.text.trim().is_empty() {
                if segment.run_if != parser::Separator::Always {
                    return Output::written("", EMPTY_SEGMENT_ERROR, SYNTAX_ERROR_STATUS);
                }
                continue;
            }
            if !segment.run_if.permits(ran_status.unwrap_or(0)) {
                continue;
            }
            let Some(result) = self.run_pipeline(segment.text) else {
                continue;
            };
            ran_status = Some(result.status);
            self.last_status = result.status;
            out.push(&result.output, &result.stderr);
            if result.exit {
                out.exit = true;
                break;
            }
            if truncate_over_line_budget(&mut out) {
                break;
            }
        }

        if let Some(status) = ran_status {
            out.status = status;
        }
        out
    }

    fn park_heredoc(&mut self, line: &str) -> bool {
        let Some((doc, command)) = parser::split_heredoc(parser::strip_comment(line)) else {
            return false;
        };
        self.pending = Some(Pending::Heredoc {
            command,
            raw: line.to_string(),
            doc,
            body: String::new(),
        });
        true
    }

    fn run_pipeline(&mut self, segment: &str) -> Option<CommandResult> {
        let stages = parser::split_pipeline(segment);
        let last_stage = stages.len() - 1;

        let mut piped: Option<String> = self.heredoc_stdin.take();
        let mut last: Option<CommandResult> = None;
        let mut stderr = String::new();

        for (i, stage) in stages.iter().enumerate() {
            let (text, redirects) = match parser::split_redirects(stage) {
                Ok(split) => split,
                Err(message) => return Some(CommandResult::err(message, SYNTAX_ERROR_STATUS)),
            };

            let argv = self.parse_line(&text);
            let sinks = match self.open_redirects(&redirects) {
                Ok(sinks) => sinks,

                Err(message) => return Some(CommandResult::err(message, REDIRECT_FAILURE_STATUS)),
            };

            push_capped(&mut stderr, &std::mem::take(&mut self.subst_stderr));

            if argv.is_empty() {
                continue;
            }
            let stdout_is_tty =
                i == last_stage && sinks.stdout_reaches_client() && self.subst_depth == 0;
            let mut result = self.run_stage(&argv, piped.take(), stdout_is_tty, &sinks);
            push_capped(&mut stderr, &std::mem::take(&mut result.stderr));
            piped = Some(result.output.clone());
            last = Some(result);
        }

        if let Some(result) = last.as_mut() {
            result.stderr = stderr;
            return last;
        }
        (!stderr.is_empty()).then(|| CommandResult::streams("", stderr, 0))
    }

    fn run_stage(
        &mut self,
        argv: &[String],
        stdin: Option<String>,
        stdout_is_tty: bool,
        sinks: &Sinks,
    ) -> CommandResult {
        self.stdin = stdin;
        self.stdout_is_tty = stdout_is_tty;
        let result = commands::dispatch(self, argv);
        self.stdin = None;
        self.stdout_is_tty = true;
        self.route_output(result, sinks)
    }
}

fn truncate_over_line_budget(out: &mut Output) -> bool {
    let budget = commands::MAX_COMMAND_OUTPUT_BYTES;
    if out.text.len() < budget {
        return false;
    }
    commands::truncate_stream(&mut out.text, budget);
    commands::truncate_stream(&mut out.stdout, budget);
    commands::truncate_stream(&mut out.stderr, budget);
    true
}
