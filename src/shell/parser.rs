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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    pub end: usize,

    pub body: (usize, usize),

    pub arithmetic: bool,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    pub delimiter: String,

    pub strip_tabs: bool,

    pub expand: bool,
}

pub fn split_heredoc(line: &str) -> Option<(Heredoc, String)> {
    let bytes = line.as_bytes();
    let mut quotes = Quotes::default();
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
        if bytes[i..].starts_with(b"<<<") {
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

pub fn strip_comment(line: &str) -> &str {
    let mut quotes = Quotes::default();

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separator {
    Always,

    AndIf,

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

            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub run_if: Separator,

    pub text: &'a str,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,

    Stderr,

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    File { path: String, append: bool },

    Dup(Stream),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub stream: Stream,

    pub target: Target,
}

pub fn split_redirects(stage: &str) -> Result<(String, Vec<Redirect>), String> {
    let bytes = stage.as_bytes();
    let mut command = String::new();
    let mut redirects = Vec::new();
    let mut copy_from = 0;

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
                Some(&next) if !in_double || matches!(next, '$' | '`' | '"' | '\\') => {
                    cur.push(next);
                    chars.next();
                    has_token = true;
                }
                Some(_) => {
                    cur.push('\\');
                    has_token = true;
                }

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

        assert_eq!(split_pipeline("echo `a | b` c"), vec!["echo `a | b` c"]);
        assert_eq!(
            split_pipeline("echo $(a ')' | b)"),
            vec!["echo $(a ')' | b)"]
        );
        assert_eq!(split_pipeline("echo '$(a | b)'"), vec!["echo '$(a | b)'"]);

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

        assert_eq!(strip_comment("echo a # b; echo c"), "echo a ");
        assert_eq!(strip_comment("echo a;# b && echo c"), "echo a;");
        assert_eq!(strip_comment("echo a |# b"), "echo a |");
    }

    #[test]
    fn a_hash_that_does_not_start_a_word_is_data() {
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
        let (command, redirects) = split_redirects("echo a>b c").unwrap();
        assert_eq!(command, "echo a c");
        assert_eq!(redirects[0].target, file("b", false));

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

        let (_, redirects) = split_redirects(r#"echo hi > "$HOME/my file""#).unwrap();
        assert_eq!(redirects[0].target, file(r#""$HOME/my file""#, false));
    }

    #[test]
    fn backslashes_inside_double_quotes_survive_to_the_command() {
        assert_eq!(tokenize(r#""a\tb\nc""#), vec![r"a\tb\nc"]);
        assert_eq!(tokenize(r#""a\"b\\c""#), vec![r#"a"b\c"#]);
        assert_eq!(tokenize(r#""cost: \$5""#), vec!["cost: $5"]);

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
