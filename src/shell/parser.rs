//! Minimal POSIX-ish command-line tokenizer.
//!
//! Splits a line into argument words, honouring single quotes, double quotes,
//! and backslash escaping, cuts a `#` comment off a line, splits a compound
//! line on `;`, `&&`, and `||`, a segment into pipeline stages on `|`, and a
//! stage's output redirections off its command text. This is deliberately
//! small: heredocs are intentionally unsupported. Variable expansion — and the
//! command substitution the splitters below skip over — happens *before*
//! tokenization in [`crate::shell::Shell`].

/// A `$(…)`, `` `…` `` or `$((…))` region found in a raw line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// Byte index just past the closing delimiter.
    pub end: usize,
    /// Byte range of the text between the delimiters.
    pub body: (usize, usize),
    /// `$((…))`: the body is an arithmetic expression, not a command line.
    pub arithmetic: bool,
}

/// Recognise a substitution starting at byte `i`, returning where it ends and
/// what is inside it.
///
/// A substitution is one word to bash, so everything that splits a *raw* line —
/// comments, `;`/`&&`/`||`, pipes, redirections — has to step over it whole, or
/// `echo $(ls | wc -l)` becomes two pipeline stages and `$((3>2))` becomes a
/// redirect. Quoting inside the body is tracked (`$(echo ')')` does not end
/// early) and `$(…)` nests; backticks do not nest in bash either, so the scan
/// for the closing one is flat. Returns `None` for an unterminated region,
/// which leaves the caller scanning it as ordinary text.
pub fn substitution_at(line: &str, i: usize) -> Option<Substitution> {
    let bytes = line.as_bytes();
    match bytes.get(i)? {
        b'`' => {
            let mut j = i + 1;
            while j < bytes.len() {
                match bytes[j] {
                    b'\\' => j += 1,
                    b'`' => {
                        return Some(Substitution {
                            end: j + 1,
                            body: (i + 1, j),
                            arithmetic: false,
                        })
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        b'$' if bytes.get(i + 1) == Some(&b'(') => {
            // `$((` is read as arithmetic, as bash's own ambiguity resolves it
            // for everything but a subshell written `$( (cmd) )`.
            let arithmetic = bytes.get(i + 2) == Some(&b'(');
            let mut depth = 0usize;
            let mut in_single = false;
            let mut in_double = false;
            let mut j = i + 1;

            while j < bytes.len() {
                match bytes[j] {
                    b'\\' if !in_single => j += 1,
                    b'\'' if !in_double => in_single = !in_single,
                    b'"' if !in_single => in_double = !in_double,
                    b'(' if !in_single && !in_double => depth += 1,
                    b')' if !in_single && !in_double => {
                        depth -= 1;
                        if depth == 0 {
                            // Closing an arithmetic region takes two `)`, so
                            // the body never runs past its own start.
                            let body = if arithmetic {
                                (i + 3, j - 1)
                            } else {
                                (i + 2, j)
                            };
                            return Some(Substitution {
                                end: j + 1,
                                body,
                                arithmetic,
                            });
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => None,
    }
}

/// Cut a `#` comment off the end of `line`, returning what is left to run.
///
/// Bash starts a comment at an unquoted, unescaped `#` that begins a word — so
/// `echo a # b` runs `echo a`, while `echo a#b`, `echo '#!/bin/sh'` and `$#`
/// keep their `#` as data. A comment runs to the end of the line and swallows
/// any separator in it, which is why this happens before [`split_segments`]
/// rather than per segment. Like the splitting that follows, it runs on the raw
/// line, before variable expansion, so a `#` arriving in a variable's value
/// stays data instead of commenting out the rest of the line.
pub fn strip_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    // A `#` only opens a comment at the start of a word: at the start of the
    // line, after whitespace, or after an operator character that ended one.
    let mut word_start = true;

    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if escaped {
            escaped = false;
            word_start = false;
            i += 1;
            continue;
        }
        // A `#` inside `$(…)` comments out the rest of *that* command, which is
        // the substitution's business, not this line's.
        if !in_single {
            if let Some(subst) = substitution_at(line, i) {
                i = subst.end;
                word_start = false;
                continue;
            }
        }
        match c {
            b'\\' if !in_single => escaped = true,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if word_start && !in_single && !in_double => return &line[..i],
            b';' | b'&' | b'|' if !in_single && !in_double => {
                word_start = true;
                i += 1;
                continue;
            }
            c if c.is_ascii_whitespace() && !in_single && !in_double => {
                word_start = true;
                i += 1;
                continue;
            }
            _ => {}
        }
        word_start = false;
        i += 1;
    }
    line
}

/// Whether a segment runs, based on how the previous one exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separator {
    /// Start of the line, or after `;`: run unconditionally.
    Always,
    /// After `&&`: run only if the previous command succeeded.
    AndIf,
    /// After `||`: run only if the previous command failed.
    OrIf,
}

/// One command of a compound line, with the operator that gates it.
#[derive(Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    /// The condition under which this segment runs.
    pub run_if: Separator,
    /// The command text, without the surrounding operators.
    pub text: &'a str,
}

/// Split `line` on `;`, `&&`, and `||`, ignoring operators inside quotes or
/// escaped by a backslash.
///
/// Splitting happens on the raw line, before variable expansion, so a `;` that
/// arrives in a variable's value stays data instead of becoming a separator —
/// the same order a real shell uses, and the reason an expanded value cannot
/// smuggle in an extra command.
pub fn split_segments(line: &str) -> Vec<Segment<'_>> {
    let mut segments = Vec::new();
    let mut run_if = Separator::Always;
    let mut start = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if !in_single {
            if let Some(subst) = substitution_at(line, i) {
                i = subst.end;
                continue;
            }
        }
        match c {
            b'\\' if !in_single => escaped = true,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b';' | b'&' | b'|' if !in_single && !in_double => {
                let (width, next) = match (c, bytes.get(i + 1)) {
                    (b';', _) => (1, Separator::Always),
                    (b'&', Some(b'&')) => (2, Separator::AndIf),
                    (b'|', Some(b'|')) => (2, Separator::OrIf),
                    // A single `&` or `|` is not a separator here: background
                    // jobs and pipes are not emulated, so they stay literal.
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                segments.push(Segment {
                    run_if,
                    text: &line[start..i],
                });
                run_if = next;
                i += width;
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }

    segments.push(Segment {
        run_if,
        text: &line[start..],
    });
    segments
}

/// Split one segment into pipeline stages on `|`, ignoring pipes inside quotes
/// or escaped by a backslash. `||` is a separator, not a pipe, and is handled
/// by [`split_segments`] before this runs.
pub fn split_pipeline(segment: &str) -> Vec<&str> {
    let mut stages = Vec::new();
    let mut start = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if !in_single {
            if let Some(subst) = substitution_at(segment, i) {
                i = subst.end;
                continue;
            }
        }
        match bytes[i] {
            b'\\' if !in_single => escaped = true,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'|' if !in_single && !in_double => {
                stages.push(&segment[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    stages.push(&segment[start..]);
    stages
}

/// Which of a command's output streams a redirection applies to. The emulator
/// produces one output string per command rather than two real file
/// descriptors, so these select how that string is routed rather than naming
/// separate buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// `>` / `1>`.
    Stdout,
    /// `2>`.
    Stderr,
    /// `&>`: both at once.
    Both,
}

/// Where a redirected stream ends up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A file path, exactly as written — quotes and `$VAR` are still in it,
    /// because a redirect target is expanded like any other word.
    File {
        /// The unexpanded path word.
        path: String,
        /// `>>` appends instead of truncating.
        append: bool,
    },
    /// `N>&M`: this stream goes wherever the named one goes.
    Dup(Stream),
}

/// One output redirection stripped off a pipeline stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// The stream being redirected.
    pub stream: Stream,
    /// Where it goes.
    pub target: Target,
}

/// Strip the output redirections (`>`, `>>`, `2>`, `&>`, `2>&1`, ...) off one
/// pipeline stage, returning the remaining command text and the redirections in
/// the order they were written.
///
/// Like [`split_segments`] and [`split_pipeline`], this runs on the raw stage
/// text *before* variable expansion, so a `>` arriving in a variable's value
/// stays data instead of becoming an operator. The target path is left
/// unexpanded for the caller, because bash does expand that word.
///
/// Returns `Err` with the bash error text for a redirect with no target
/// (`echo hi >`) or an unsupported descriptor (`2>&3`).
pub fn split_redirects(stage: &str) -> Result<(String, Vec<Redirect>), String> {
    let bytes = stage.as_bytes();
    let mut command = String::new();
    let mut redirects = Vec::new();
    let mut copy_from = 0;
    // Start of the word `i` is inside, and whether that word is free of quotes
    // and escapes — only a bare `1`, `2`, or `&` counts as a descriptor prefix.
    let mut word_start = 0;
    let mut plain_word = true;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        // `$((3>2))` is one word, not a redirect, and a `>` inside `$(…)`
        // belongs to the command being substituted.
        if !in_single {
            if let Some(subst) = substitution_at(stage, i) {
                i = subst.end;
                plain_word = false;
                continue;
            }
        }
        match c {
            b'\\' if !in_single => {
                escaped = true;
                plain_word = false;
            }
            b'\'' if !in_double => {
                in_single = !in_single;
                plain_word = false;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                plain_word = false;
            }
            b'>' if !in_single && !in_double => {
                let prefix = if plain_word {
                    &stage[word_start..i]
                } else {
                    ""
                };
                // `echo a>b` redirects and keeps `a` as an argument; only an
                // exact `1`, `2`, or `&` is consumed as the descriptor.
                let (stream, op_start) = match prefix {
                    "1" => (Stream::Stdout, word_start),
                    "2" => (Stream::Stderr, word_start),
                    "&" => (Stream::Both, word_start),
                    _ => (Stream::Stdout, i),
                };

                let mut j = i + 1;
                let append = bytes.get(j) == Some(&b'>');
                if append {
                    j += 1;
                }

                let (target, end) = if !append && bytes.get(j) == Some(&b'&') {
                    let mut k = j + 1;
                    while k < bytes.len() && bytes[k].is_ascii_digit() {
                        k += 1;
                    }
                    match &stage[j + 1..k] {
                        "1" => (Target::Dup(Stream::Stdout), k),
                        "2" => (Target::Dup(Stream::Stderr), k),
                        fd => {
                            return Err(format!("-bash: {fd}: Bad file descriptor\n"));
                        }
                    }
                } else {
                    let mut k = j;
                    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    let end = word_end(stage, k);
                    if end == k {
                        return Err(
                            "-bash: syntax error near unexpected token `newline'\n".to_string()
                        );
                    }
                    (
                        Target::File {
                            path: stage[k..end].to_string(),
                            append,
                        },
                        end,
                    )
                };

                command.push_str(&stage[copy_from..op_start]);
                redirects.push(Redirect { stream, target });
                copy_from = end;
                i = end;
                word_start = end;
                plain_word = true;
                continue;
            }
            c if c.is_ascii_whitespace() && !in_single && !in_double => {
                word_start = i + 1;
                plain_word = true;
            }
            _ => {}
        }
        i += 1;
    }

    command.push_str(&stage[copy_from..]);
    Ok((command, redirects))
}

/// Index one past the end of the word starting at `start`, stopping at unquoted
/// whitespace or the start of another redirection.
fn word_end(s: &str, start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut i = start;

    while i < bytes.len() {
        let c = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        // `> $(echo f)` names one target word, spaces and all.
        if !in_single {
            if let Some(subst) = substitution_at(s, i) {
                i = subst.end;
                continue;
            }
        }
        match c {
            b'\\' if !in_single => escaped = true,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'>' | b'<' if !in_single && !in_double => break,
            c if c.is_ascii_whitespace() && !in_single && !in_double => break,
            _ => {}
        }
        i += 1;
    }
    i
}

/// Split `line` into argument words. Quotes group whitespace; backslash escapes
/// the next character outside quotes, and inside double quotes only the four
/// characters bash lets it escape there (`$`, `` ` ``, `"`, `\`) — every other
/// backslash inside double quotes is an ordinary character, which is how
/// `echo -e "a\tb"` reaches `echo` with its escapes still in it.
pub fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut has_token = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                has_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                has_token = true;
            }
            '\\' if !in_single => match chars.peek() {
                // Inside double quotes a backslash is only special in front of
                // these; anywhere else there it is a literal character that the
                // command receives, so `echo -e "a\tb"` still has a `\t` to
                // interpret and `grep "\." f` matches a literal dot.
                Some(&next) if !in_double || matches!(next, '$' | '`' | '"' | '\\') => {
                    cur.push(next);
                    chars.next();
                    has_token = true;
                }
                Some(_) => {
                    cur.push('\\');
                    has_token = true;
                }
                // A trailing backslash with nothing after it.
                None => {}
            },
            c if c.is_whitespace() && !in_single && !in_double => {
                if has_token {
                    tokens.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }

    if has_token {
        tokens.push(cur);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(line: &str) -> Vec<(Separator, &str)> {
        split_segments(line)
            .into_iter()
            .map(|s| (s.run_if, s.text))
            .collect()
    }

    #[test]
    fn a_substitution_is_one_word_to_every_splitter() {
        // Separators, pipes, redirects and comments inside `$(…)` belong to the
        // command being substituted, not to the line holding it.
        assert_eq!(
            strip_comment("echo $(ls # inner) # outer"),
            "echo $(ls # inner) "
        );
        assert_eq!(
            split("echo $(a; b) && c"),
            vec![
                (Separator::Always, "echo $(a; b) "),
                (Separator::AndIf, " c"),
            ]
        );
        assert_eq!(
            split_pipeline("echo $(a | b) | c"),
            vec!["echo $(a | b) ", " c"]
        );
        assert_eq!(
            split_redirects("echo $((3>2))").unwrap(),
            ("echo $((3>2))".to_string(), vec![])
        );
        // The target word is still found, substitution and all.
        assert_eq!(
            split_redirects("echo hi > $(echo /tmp/f)").unwrap(),
            (
                "echo hi ".to_string(),
                vec![Redirect {
                    stream: Stream::Stdout,
                    target: Target::File {
                        path: "$(echo /tmp/f)".to_string(),
                        append: false,
                    },
                }]
            )
        );
        // Backticks and quoting inside the body are handled too, and a single
        // quote around the whole thing turns it back into ordinary text.
        assert_eq!(split_pipeline("echo `a | b` c"), vec!["echo `a | b` c"]);
        assert_eq!(
            split_pipeline("echo $(a ')' | b)"),
            vec!["echo $(a ')' | b)"]
        );
        assert_eq!(split_pipeline("echo '$(a | b)'"), vec!["echo '$(a | b)'"]);
        // An unterminated one is scanned as the ordinary text it looks like.
        assert_eq!(split_pipeline("echo $(a | b"), vec!["echo $(a ", " b"]);
    }

    #[test]
    fn splits_on_operators() {
        assert_eq!(
            split("cd /tmp; wget http://x/a && chmod +x a || echo fail"),
            vec![
                (Separator::Always, "cd /tmp"),
                (Separator::Always, " wget http://x/a "),
                (Separator::AndIf, " chmod +x a "),
                (Separator::OrIf, " echo fail"),
            ]
        );
    }

    #[test]
    fn operators_inside_quotes_or_escaped_are_literal() {
        assert_eq!(
            split("echo 'a; b'"),
            vec![(Separator::Always, "echo 'a; b'")]
        );
        assert_eq!(
            split(r#"echo "a && b""#),
            vec![(Separator::Always, r#"echo "a && b""#)]
        );
        assert_eq!(split(r"echo a\;b"), vec![(Separator::Always, r"echo a\;b")]);
    }

    #[test]
    fn single_ampersand_and_pipe_stay_literal() {
        assert_eq!(split("echo a & b"), vec![(Separator::Always, "echo a & b")]);
        assert_eq!(split("echo a | b"), vec![(Separator::Always, "echo a | b")]);
    }

    #[test]
    fn a_comment_runs_to_the_end_of_the_line() {
        assert_eq!(strip_comment("# just a comment"), "");
        assert_eq!(strip_comment("echo a # b"), "echo a ");
        assert_eq!(strip_comment("   # indented"), "   ");
        // The comment swallows the rest of the line, separators included.
        assert_eq!(strip_comment("echo a # b; echo c"), "echo a ");
        assert_eq!(strip_comment("echo a;# b && echo c"), "echo a;");
        assert_eq!(strip_comment("echo a |# b"), "echo a |");
    }

    #[test]
    fn a_hash_that_does_not_start_a_word_is_data() {
        // Mid-word, quoted, or escaped: all literal, as in bash.
        assert_eq!(strip_comment("echo a#b"), "echo a#b");
        assert_eq!(
            strip_comment("echo '#!/bin/sh' > /tmp/x"),
            "echo '#!/bin/sh' > /tmp/x"
        );
        assert_eq!(
            strip_comment(r##"echo "# not a comment""##),
            r##"echo "# not a comment""##
        );
        assert_eq!(strip_comment(r"echo \# hash"), r"echo \# hash");
        assert_eq!(strip_comment("echo $#"), "echo $#");
        assert_eq!(strip_comment("echo ''#x"), "echo ''#x");
    }

    fn file(path: &str, append: bool) -> Target {
        Target::File {
            path: path.to_string(),
            append,
        }
    }

    #[test]
    fn strips_the_redirect_off_the_command() {
        let (command, redirects) = split_redirects("echo hi > /tmp/f").unwrap();
        assert_eq!(command, "echo hi ");
        assert_eq!(
            redirects,
            vec![Redirect {
                stream: Stream::Stdout,
                target: file("/tmp/f", false),
            }]
        );

        let (command, redirects) = split_redirects("ls -l >> log 2>&1").unwrap();
        assert_eq!(command, "ls -l  ");
        assert_eq!(
            redirects,
            vec![
                Redirect {
                    stream: Stream::Stdout,
                    target: file("log", true),
                },
                Redirect {
                    stream: Stream::Stderr,
                    target: Target::Dup(Stream::Stdout),
                },
            ]
        );
    }

    #[test]
    fn recognises_every_descriptor_form() {
        for (line, stream, append) in [
            ("cmd 1> f", Stream::Stdout, false),
            ("cmd 1>> f", Stream::Stdout, true),
            ("cmd 2> f", Stream::Stderr, false),
            ("cmd 2>> f", Stream::Stderr, true),
            ("cmd &> f", Stream::Both, false),
            ("cmd &>> f", Stream::Both, true),
        ] {
            let (command, redirects) = split_redirects(line).unwrap();
            assert_eq!(command.trim(), "cmd", "{line}");
            assert_eq!(
                redirects,
                vec![Redirect {
                    stream,
                    target: file("f", append),
                }],
                "{line}"
            );
        }
    }

    #[test]
    fn arguments_survive_a_redirect_anywhere_in_the_stage() {
        // No space around the operator, and a word after the target: bash reads
        // both as arguments to the command.
        let (command, redirects) = split_redirects("echo a>b c").unwrap();
        assert_eq!(command, "echo a c");
        assert_eq!(redirects[0].target, file("b", false));

        // A digit that is not the whole word is an argument, not a descriptor.
        let (command, _) = split_redirects("echo x2> f").unwrap();
        assert_eq!(command, "echo x2");
    }

    #[test]
    fn operators_inside_quotes_are_literal_and_targets_are_left_unexpanded() {
        assert_eq!(
            split_redirects(r#"echo "a > b""#).unwrap(),
            (r#"echo "a > b""#.to_string(), vec![])
        );
        assert_eq!(
            split_redirects(r"echo a\> b").unwrap(),
            (r"echo a\> b".to_string(), vec![])
        );

        // The target keeps its quoting and `$VAR` for the caller to expand.
        let (_, redirects) = split_redirects(r#"echo hi > "$HOME/my file""#).unwrap();
        assert_eq!(redirects[0].target, file(r#""$HOME/my file""#, false));
    }

    #[test]
    fn backslashes_inside_double_quotes_survive_to_the_command() {
        // Only `$`, backtick, `"` and `\` are escapable inside double quotes.
        assert_eq!(tokenize(r#""a\tb\nc""#), vec![r"a\tb\nc"]);
        assert_eq!(tokenize(r#""a\"b\\c""#), vec![r#"a"b\c"#]);
        assert_eq!(tokenize(r#""cost: \$5""#), vec!["cost: $5"]);
        // Unquoted and single-quoted behaviour is unchanged.
        assert_eq!(tokenize(r"a\tb"), vec!["atb"]);
        assert_eq!(tokenize(r"one\ word"), vec!["one word"]);
        assert_eq!(tokenize(r"'a\tb'"), vec![r"a\tb"]);
    }

    #[test]
    fn rejects_a_missing_target_or_unknown_descriptor() {
        assert!(split_redirects("echo hi >")
            .unwrap_err()
            .contains("syntax error near unexpected token `newline'"));
        assert!(split_redirects("echo hi > ")
            .unwrap_err()
            .contains("syntax error"));
        assert!(split_redirects("echo hi 2>&3")
            .unwrap_err()
            .contains("3: Bad file descriptor"));
    }
}
