#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    pub end: usize,

    pub body: (usize, usize),

    pub arithmetic: bool,
}

pub fn substitution_at(line: &str, i: usize) -> Option<Substitution> {
    let bytes = line.as_bytes();
    match bytes.get(i)? {
        b'`' => backtick_substitution(bytes, i),
        b'$' if bytes.get(i + 1) == Some(&b'(') => dollar_paren_substitution(bytes, i),
        _ => None,
    }
}

fn backtick_substitution(bytes: &[u8], open: usize) -> Option<Substitution> {
    let mut j = open + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 1,
            b'`' => {
                return Some(Substitution {
                    end: j + 1,
                    body: (open + 1, j),
                    arithmetic: false,
                })
            }
            _ => {}
        }
        j += 1;
    }
    None
}

fn dollar_paren_substitution(bytes: &[u8], dollar: usize) -> Option<Substitution> {
    let arithmetic = bytes.get(dollar + 2) == Some(&b'(');
    let close = matching_paren(bytes, dollar + 1)?;
    let body = if arithmetic {
        (dollar + 3, close - 1)
    } else {
        (dollar + 2, close)
    };
    Some(Substitution {
        end: close + 1,
        body,
        arithmetic,
    })
}

fn matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut j = open;
    while j < bytes.len() {
        let quoted = in_single || in_double;
        match bytes[j] {
            b'\\' if !in_single => j += 1,
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'(' if !quoted => depth += 1,
            b')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lexeme {
    Escape,
    Substitution,
    Quote,
    Quoted,
    Unquoted(u8),
}

struct Scanner<'a> {
    line: &'a str,
    pos: usize,
    in_single: bool,
    in_double: bool,
}

impl<'a> Scanner<'a> {
    fn new(line: &'a str) -> Self {
        Self::starting_at(line, 0)
    }

    fn starting_at(line: &'a str, pos: usize) -> Self {
        Self {
            line,
            pos,
            in_single: false,
            in_double: false,
        }
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }
}

impl Iterator for Scanner<'_> {
    type Item = (usize, Lexeme);

    fn next(&mut self) -> Option<Self::Item> {
        let i = self.pos;
        let &byte = self.line.as_bytes().get(i)?;
        if !self.in_single {
            if let Some(subst) = substitution_at(self.line, i) {
                self.pos = subst.end;
                return Some((i, Lexeme::Substitution));
            }
        }
        self.pos = i + 1;
        let lexeme = match byte {
            b'\\' if !self.in_single => {
                self.pos += 1;
                Lexeme::Escape
            }
            b'\'' if !self.in_double => {
                self.in_single = !self.in_single;
                Lexeme::Quote
            }
            b'"' if !self.in_single => {
                self.in_double = !self.in_double;
                Lexeme::Quote
            }
            _ if self.in_single || self.in_double => Lexeme::Quoted,
            _ => Lexeme::Unquoted(byte),
        };
        Some((i, lexeme))
    }
}

fn skip_whitespace(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map_or(bytes.len(), |offset| from + offset)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    pub delimiter: String,

    pub strip_tabs: bool,

    pub expand: bool,
}

const HEREDOC_OPERATOR: &str = "<<";

const HERE_STRING_OPERATOR: &str = "<<<";

pub fn split_heredoc(line: &str) -> Option<(Heredoc, String)> {
    let mut scanner = Scanner::new(line);
    while let Some((i, lexeme)) = scanner.next() {
        if lexeme != Lexeme::Unquoted(b'<') || !line[i..].starts_with(HEREDOC_OPERATOR) {
            continue;
        }
        if line[i..].starts_with(HERE_STRING_OPERATOR) {
            scanner.seek(i + HERE_STRING_OPERATOR.len());
            continue;
        }
        return heredoc_at(line, i);
    }
    None
}

fn heredoc_at(line: &str, operator: usize) -> Option<(Heredoc, String)> {
    let bytes = line.as_bytes();
    let mut after_operator = operator + HEREDOC_OPERATOR.len();
    let strip_tabs = bytes.get(after_operator) == Some(&b'-');
    if strip_tabs {
        after_operator += 1;
    }
    let start = skip_whitespace(bytes, after_operator);
    let end = word_end(line, start);
    if end == start {
        return None;
    }
    let raw = &line[start..end];
    let quoted = raw.starts_with('\'') || raw.starts_with('"') || raw.contains('\\');
    let rest = format!("{}{}", &line[..operator], &line[end..]);
    Some((
        Heredoc {
            delimiter: unquote(raw),
            strip_tabs,
            expand: !quoted,
        },
        rest,
    ))
}

fn unquote(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for c in word.chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if !in_single => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            _ => out.push(c),
        }
    }
    out
}

fn ends_word(byte: u8) -> bool {
    matches!(byte, b';' | b'&' | b'|') || byte.is_ascii_whitespace()
}

pub fn strip_comment(line: &str) -> &str {
    let mut word_start = true;
    for (i, lexeme) in Scanner::new(line) {
        word_start = match lexeme {
            Lexeme::Unquoted(b'#') if word_start => return &line[..i],
            Lexeme::Unquoted(byte) => ends_word(byte),
            _ => false,
        };
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
    pub fn admits(self, previous_status: i32) -> bool {
        match self {
            Separator::Always => true,
            Separator::AndIf => previous_status == 0,
            Separator::OrIf => previous_status != 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub run_if: Separator,

    pub text: &'a str,
}

pub fn split_segments(line: &str) -> Vec<Segment<'_>> {
    let bytes = line.as_bytes();
    let mut segments = Vec::new();
    let mut run_if = Separator::Always;
    let mut start = 0;
    let mut scanner = Scanner::new(line);

    while let Some((i, lexeme)) = scanner.next() {
        let Lexeme::Unquoted(byte) = lexeme else {
            continue;
        };
        let (width, next) = match (byte, bytes.get(i + 1)) {
            (b';', _) => (1, Separator::Always),
            (b'&', Some(b'&')) => (2, Separator::AndIf),
            (b'|', Some(b'|')) => (2, Separator::OrIf),
            _ => continue,
        };
        segments.push(Segment {
            run_if,
            text: &line[start..i],
        });
        run_if = next;
        start = i + width;
        scanner.seek(start);
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
    for (i, lexeme) in Scanner::new(segment) {
        if lexeme == Lexeme::Unquoted(b'|') {
            stages.push(&segment[start..i]);
            start = i + 1;
        }
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
    let mut command = String::new();
    let mut redirects = Vec::new();
    let mut copy_from = 0;
    let mut word_start = 0;
    let mut plain_word = true;
    let mut scanner = Scanner::new(stage);

    while let Some((i, lexeme)) = scanner.next() {
        match lexeme {
            Lexeme::Escape | Lexeme::Substitution | Lexeme::Quote => plain_word = false,
            Lexeme::Unquoted(b'>') => {
                let named_stream = if plain_word {
                    descriptor_stream(&stage[word_start..i])
                } else {
                    None
                };
                let (stream, operator_start) = match named_stream {
                    Some(stream) => (stream, word_start),
                    None => (Stream::Stdout, i),
                };
                let (target, end) = redirect_target(stage, i + 1)?;

                command.push_str(&stage[copy_from..operator_start]);
                redirects.push(Redirect { stream, target });
                copy_from = end;
                word_start = end;
                plain_word = true;
                scanner.seek(end);
            }
            Lexeme::Unquoted(byte) if byte.is_ascii_whitespace() => {
                word_start = i + 1;
                plain_word = true;
            }
            _ => {}
        }
    }

    command.push_str(&stage[copy_from..]);
    Ok((command, redirects))
}

fn descriptor_stream(prefix: &str) -> Option<Stream> {
    match prefix {
        "1" => Some(Stream::Stdout),
        "2" => Some(Stream::Stderr),
        "&" => Some(Stream::Both),
        _ => None,
    }
}

fn redirect_target(stage: &str, after_operator: usize) -> Result<(Target, usize), String> {
    let bytes = stage.as_bytes();
    let append = bytes.get(after_operator) == Some(&b'>');
    if !append && bytes.get(after_operator) == Some(&b'&') {
        return duplicated_descriptor(stage, after_operator + 1);
    }
    let start = skip_whitespace(bytes, after_operator + usize::from(append));
    let end = word_end(stage, start);
    if end == start {
        return Err("-bash: syntax error near unexpected token `newline'\n".to_string());
    }
    let path = stage[start..end].to_string();
    Ok((Target::File { path, append }, end))
}

fn duplicated_descriptor(stage: &str, start: usize) -> Result<(Target, usize), String> {
    let digits = stage.as_bytes()[start..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let end = start + digits;
    match &stage[start..end] {
        "1" => Ok((Target::Dup(Stream::Stdout), end)),
        "2" => Ok((Target::Dup(Stream::Stderr), end)),
        fd => Err(format!("-bash: {fd}: Bad file descriptor\n")),
    }
}

fn word_end(s: &str, start: usize) -> usize {
    for (i, lexeme) in Scanner::starting_at(s, start) {
        if let Lexeme::Unquoted(byte) = lexeme {
            if matches!(byte, b'>' | b'<') || byte.is_ascii_whitespace() {
                return i;
            }
        }
    }
    s.len()
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
