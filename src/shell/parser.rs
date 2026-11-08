//! Minimal POSIX-ish command-line tokenizer.
//!
//! Splits a line into argument words, honouring single quotes, double quotes,
//! and backslash escaping, cuts a `#` comment off a line, splits a compound
//! line on `;`, `&&`, and `||`, a segment into pipeline stages on `|`, and a
//! stage's output redirections off its command text. This is deliberately
//! small: heredocs are intentionally unsupported. Variable expansion — and the
//! command substitution the splitters below skip over — happens *before*
//! tokenization in [`crate::shell::Shell`].

const MISSING_REDIRECT_TARGET: &str = "-bash: syntax error near unexpected token `newline'\n";

#[derive(Default)]
struct Quotes {
    single: bool,
    double: bool,
    escaped: bool,
}

impl Quotes {
    fn is_quoted(&self) -> bool {
        self.single || self.double
    }

    fn take_escaped(&mut self) -> bool {
        std::mem::take(&mut self.escaped)
    }

    fn toggle(&mut self, c: char) -> bool {
        match c {
            '\\' if !self.single => self.escaped = true,
            '\'' if !self.double => self.single = !self.single,
            '"' if !self.single => self.double = !self.double,
            _ => return false,
        }
        true
    }

    fn substitution_end(&self, line: &str, i: usize) -> Option<usize> {
        if self.single {
            return None;
        }
        substitution_at(line, i).map(|subst| subst.end)
    }
}

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
        b'`' => backtick_at(bytes, i),
        b'$' if bytes.get(i + 1) == Some(&b'(') => dollar_paren_at(bytes, i),
        _ => None,
    }
}

fn backtick_at(bytes: &[u8], start: usize) -> Option<Substitution> {
    let mut j = start + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 1,
            b'`' => {
                return Some(Substitution {
                    end: j + 1,
                    body: (start + 1, j),
                    arithmetic: false,
                })
            }
            _ => {}
        }
        j += 1;
    }
    None
}

fn dollar_paren_at(bytes: &[u8], start: usize) -> Option<Substitution> {
    // `$((` is read as arithmetic, as bash's own ambiguity resolves it
    // for everything but a subshell written `$( (cmd) )`.
    let arithmetic = bytes.get(start + 2) == Some(&b'(');
    let mut depth = 0usize;
    let mut quotes = Quotes::default();

    for (j, &c) in bytes.iter().enumerate().skip(start + 1) {
        if quotes.take_escaped() || quotes.toggle(char::from(c)) || quotes.is_quoted() {
            continue;
        }
        match c {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    // Closing an arithmetic region takes two `)`, so
                    // the body never runs past its own start.
                    let body = if arithmetic {
                        (start + 3, j - 1)
                    } else {
                        (start + 2, j)
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
    }
    None
}

/// A here-document a line opened: what ends the body, and how it is treated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    /// The word that ends the body when a line holds it and nothing else.
    pub delimiter: String,
    /// `<<-`: leading tabs come off every body line and off the terminator, so
    /// a heredoc inside an indented block can be indented with it.
    pub strip_tabs: bool,
    /// Whether `$VAR` and `$(…)` expand in the body. A quoted delimiter
    /// (`<< 'EOF'`) turns expansion off and the body is taken literally.
    pub expand: bool,
}

/// Find a here-document operator on `line`, returning it together with the line
/// that remains once the operator and its delimiter are removed — the command
/// that runs when the body has been collected.
///
/// Runs on the raw line, before expansion and before segment splitting, because
/// `<<` is lexical: a `<<` arriving in a variable's value is data, and one
/// inside `$((1 << 2))` is a shift. Only the first is taken — bash allows
/// several per line, and one covers every payload seen in the wild.
pub fn split_heredoc(line: &str) -> Option<(Heredoc, String)> {
    let bytes = line.as_bytes();
    let mut quotes = Quotes::default();
    let mut i = 0;

    while i < bytes.len() {
        if quotes.take_escaped() {
            i += 1;
            continue;
        }
        // `$((1 << 2))` is a shift, and a `<<` inside `$(…)` belongs to the
        // command being substituted.
        if let Some(end) = quotes.substitution_end(line, i) {
            i = end;
            continue;
        }
        if quotes.toggle(char::from(bytes[i])) || quotes.is_quoted() {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"<<<") {
            // `<<<` is a here-string, which takes its word from the line
            // itself rather than opening a body.
            i += 3;
            continue;
        }
        if bytes[i..].starts_with(b"<<") {
            return heredoc_operator(line, i);
        }
        i += 1;
    }
    None
}

fn heredoc_operator(line: &str, start: usize) -> Option<(Heredoc, String)> {
    let bytes = line.as_bytes();
    let strip_tabs = bytes.get(start + 2) == Some(&b'-');
    let word_start = skip_whitespace(bytes, start + 2 + usize::from(strip_tabs));
    let end = word_end(line, word_start);
    if end == word_start {
        // `cat <<` with nothing after it is a syntax error, and
        // treating it as a plain argument is closer to the truth
        // than inventing an empty delimiter.
        return None;
    }
    let raw = &line[word_start..end];
    let quoted = raw.starts_with('\'') || raw.starts_with('"') || raw.contains('\\');
    let rest = format!("{}{}", &line[..start], &line[end..]);
    let doc = Heredoc {
        delimiter: unquote(raw),
        strip_tabs,
        expand: !quoted,
    };
    Some((doc, rest))
}

/// Strip the quoting from a here-document delimiter word. The delimiter is
/// matched against a body line as plain text, so `'EOF'`, `"EOF"` and `\EOF`
/// all end a body at `EOF`.
fn unquote(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut quotes = Quotes::default();
    for c in word.chars() {
        if quotes.take_escaped() || !quotes.toggle(c) {
            out.push(c);
        }
    }
    out
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
    let mut quotes = Quotes::default();
    // A `#` only opens a comment at the start of a word: at the start of the
    // line, after whitespace, or after an operator character that ended one.
    let mut word_start = true;

    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if quotes.take_escaped() {
            word_start = false;
            i += 1;
            continue;
        }
        // A `#` inside `$(…)` comments out the rest of *that* command, which is
        // the substitution's business, not this line's.
        if let Some(end) = quotes.substitution_end(line, i) {
            i = end;
            word_start = false;
            continue;
        }
        let quoting = quotes.toggle(char::from(c)) || quotes.is_quoted();
        if !quoting && word_start && c == b'#' {
            return &line[..i];
        }
        word_start = !quoting && (matches!(c, b';' | b'&' | b'|') || c.is_ascii_whitespace());
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

impl Separator {
    pub fn permits(self, previous_status: i32) -> bool {
        match self {
            Separator::Always => true,
            Separator::AndIf => previous_status == 0,
            Separator::OrIf => previous_status != 0,
        }
    }

    fn at(bytes: &[u8], i: usize) -> Option<(usize, Separator)> {
        match (bytes[i], bytes.get(i + 1)) {
            (b';', _) => Some((1, Separator::Always)),
            (b'&', Some(b'&')) => Some((2, Separator::AndIf)),
            (b'|', Some(b'|')) => Some((2, Separator::OrIf)),
            // A single `&` or `|` is not a separator here: background
            // jobs and pipes are not emulated, so they stay literal.
            _ => None,
        }
    }
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
    let mut quotes = Quotes::default();

    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if quotes.take_escaped() {
            i += 1;
            continue;
        }
        if let Some(end) = quotes.substitution_end(line, i) {
            i = end;
            continue;
        }
        if quotes.toggle(char::from(bytes[i])) || quotes.is_quoted() {
            i += 1;
            continue;
        }
        let Some((width, next)) = Separator::at(bytes, i) else {
            i += 1;
            continue;
        };
        segments.push(Segment {
            run_if,
            text: &line[start..i],
        });
        run_if = next;
        i += width;
        start = i;
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
    let mut quotes = Quotes::default();

    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if quotes.take_escaped() {
            i += 1;
            continue;
        }
        if let Some(end) = quotes.substitution_end(segment, i) {
            i = end;
            continue;
        }
        let quoting = quotes.toggle(char::from(bytes[i])) || quotes.is_quoted();
        if !quoting && bytes[i] == b'|' {
            stages.push(&segment[start..i]);
            start = i + 1;
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

impl Stream {
    fn from_descriptor_prefix(prefix: &str) -> Option<Stream> {
        match prefix {
            "1" => Some(Stream::Stdout),
            "2" => Some(Stream::Stderr),
            "&" => Some(Stream::Both),
            _ => None,
        }
    }
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
    let mut quotes = Quotes::default();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i];
        if quotes.take_escaped() {
            i += 1;
            continue;
        }
        // `$((3>2))` is one word, not a redirect, and a `>` inside `$(…)`
        // belongs to the command being substituted.
        if let Some(end) = quotes.substitution_end(stage, i) {
            i = end;
            plain_word = false;
            continue;
        }
        if quotes.toggle(char::from(c)) {
            plain_word = false;
            i += 1;
            continue;
        }
        if quotes.is_quoted() {
            i += 1;
            continue;
        }
        if c == b'>' {
            let prefix = if plain_word {
                &stage[word_start..i]
            } else {
                ""
            };
            // `echo a>b` redirects and keeps `a` as an argument; only an
            // exact `1`, `2`, or `&` is consumed as the descriptor.
            let (stream, op_start) = match Stream::from_descriptor_prefix(prefix) {
                Some(stream) => (stream, word_start),
                None => (Stream::Stdout, i),
            };
            let (target, end) = redirect_target(stage, i + 1)?;
            command.push_str(&stage[copy_from..op_start]);
            redirects.push(Redirect { stream, target });
            copy_from = end;
            i = end;
            word_start = end;
            plain_word = true;
            continue;
        }
        if c.is_ascii_whitespace() {
            word_start = i + 1;
            plain_word = true;
        }
        i += 1;
    }

    command.push_str(&stage[copy_from..]);
    Ok((command, redirects))
}

fn redirect_target(stage: &str, after_operator: usize) -> Result<(Target, usize), String> {
    let bytes = stage.as_bytes();
    let append = bytes.get(after_operator) == Some(&b'>');
    let start = after_operator + usize::from(append);
    if !append && bytes.get(start) == Some(&b'&') {
        return descriptor_target(stage, start + 1);
    }
    let word_start = skip_whitespace(bytes, start);
    let end = word_end(stage, word_start);
    if end == word_start {
        return Err(MISSING_REDIRECT_TARGET.to_string());
    }
    let path = stage[word_start..end].to_string();
    Ok((Target::File { path, append }, end))
}

fn descriptor_target(stage: &str, start: usize) -> Result<(Target, usize), String> {
    let digits = stage.as_bytes()[start..]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .count();
    let end = start + digits;
    match &stage[start..end] {
        "1" => Ok((Target::Dup(Stream::Stdout), end)),
        "2" => Ok((Target::Dup(Stream::Stderr), end)),
        fd => Err(format!("-bash: {fd}: Bad file descriptor\n")),
    }
}

fn skip_whitespace(bytes: &[u8], start: usize) -> usize {
    start
        + bytes[start.min(bytes.len())..]
            .iter()
            .take_while(|c| c.is_ascii_whitespace())
            .count()
}

/// Index one past the end of the word starting at `start`, stopping at unquoted
/// whitespace or the start of another redirection.
fn word_end(s: &str, start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut quotes = Quotes::default();
    let mut i = start;

    while i < bytes.len() {
        let c = bytes[i];
        if quotes.take_escaped() {
            i += 1;
            continue;
        }
        // `> $(echo f)` names one target word, spaces and all.
        if let Some(end) = quotes.substitution_end(s, i) {
            i = end;
            continue;
        }
        let quoting = quotes.toggle(char::from(c)) || quotes.is_quoted();
        if !quoting && (matches!(c, b'>' | b'<') || c.is_ascii_whitespace()) {
            break;
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
