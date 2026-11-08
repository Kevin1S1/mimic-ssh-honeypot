use super::redirect::Sinks;
use super::{parser, push_capped, Output, Pending, Shell};
use crate::commands::{self, CommandResult};

const SYNTAX_ERROR_STATUS: i32 = 2;
const REDIRECT_FAILURE_STATUS: i32 = 1;
const EMPTY_SEGMENT_ERROR: &str = "-bash: syntax error near unexpected token `&&'\n";

impl Shell {
    /// Run one command line: cut off any `#` comment, split what is left on
    /// `;`, `&&`, and `||`, then for each segment expand variables, tokenize,
    /// dispatch to the command registry, and record the resulting `$?`. Empty
    /// lines — and comment-only ones — are no-ops that leave `$?` alone.
    pub fn execute(&mut self, line: &str) -> Output {
        self.captures.clear();
        // A substitution runs its body through here too; the budget belongs to
        // the line the attacker typed, so only that one refills it.
        if self.nesting == 0 {
            self.subst_budget = commands::MAX_COMMAND_OUTPUT_BYTES;
            // Every path that expands words drains this, but clearing it here
            // means a caller that expands outside a pipeline (a prompt, a
            // completion) cannot leave text to surface on the next line.
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
                    // `&& cmd` with nothing in front of it, as bash sees it.
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

    /// A here-document needs the lines that follow, which only the
    /// network layer can read, so the line is parked and the body is
    /// collected through `resume`. Nested runs — a substitution, an
    /// `sh -c` — have no further input to read, so they never park.
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

    /// Run one segment as a pipeline: each stage's *stdout* becomes the next
    /// stage's stdin, and only the last stage's stdout reaches the client.
    /// Every stage's stderr reaches the client, the way a real pipeline shares
    /// one terminal between all of them — `cat /nope | wc -l` prints the error
    /// and counts nothing, rather than counting the error.
    /// Returns `None` if the segment held no command at all.
    ///
    /// Filters (`cat`, `grep`, `head`, `tail`, `wc`) read [`Shell::stdin`] when
    /// they get no file operand, exactly as they read real stdin. A stage that
    /// ignores stdin — `ls`, say — behaves as it would in a real pipeline: the
    /// upstream output is simply discarded.
    fn run_pipeline(&mut self, segment: &str) -> Option<CommandResult> {
        let stages = parser::split_pipeline(segment);
        let last_stage = stages.len() - 1;
        // A here-document body is the first stage's stdin, exactly as a pipe
        // from an upstream stage would be.
        let mut piped: Option<String> = self.heredoc_stdin.take();
        let mut last: Option<CommandResult> = None;
        let mut stderr = String::new();

        for (i, stage) in stages.iter().enumerate() {
            let (text, redirects) = match parser::split_redirects(stage) {
                Ok(split) => split,
                Err(message) => return Some(CommandResult::err(message, SYNTAX_ERROR_STATUS)),
            };
            // Words are expanded before the targets are opened, so
            // `echo $(cat f) > f` reads `f` before the redirect truncates it —
            // the order bash performs the two in.
            let argv = self.parse_line(&text);
            let sinks = match self.open_redirects(&redirects) {
                Ok(sinks) => sinks,
                // bash opens the targets before it runs the command, so a
                // redirect that cannot be opened means nothing runs at all.
                Err(message) => return Some(CommandResult::err(message, REDIRECT_FAILURE_STATUS)),
            };
            // Expanding the words above may have run a substitution that wrote
            // to stderr; that happened before this command's redirections, so
            // it goes straight to the terminal rather than through the sinks.
            push_capped(&mut stderr, &std::mem::take(&mut self.subst_stderr));
            // A stage that is nothing but a redirect (`> f`) still opens it.
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
        // Every stage's stderr rides out on the last stage's result, which is
        // the one the segment reports. A segment that ran no command at all
        // still reports what expanding it wrote.
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

/// The per-command cap bounds one command; a chained line has to be
/// bounded as a whole, or `cat big; cat big; ...` multiplies it by
/// the number of segments the line has room for. The two streams
/// share the budget, so splitting the output between them does not
/// buy an attacker a second helping.
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
