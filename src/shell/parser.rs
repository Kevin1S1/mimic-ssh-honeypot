//! Minimal POSIX-ish command-line tokenizer.
//!
//! Splits a line into argument words, honouring single quotes, double quotes,
//! and backslash escaping, and splits a compound line on `;`, `&&`, and `||`.
//! This is deliberately small: pipes, redirects, and command substitution are
//! intentionally unsupported. Variable expansion happens *before* tokenization
//! in [`crate::shell::Shell`].

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

/// Split `line` into argument words. Quotes group whitespace; backslash escapes
/// the next character (outside single quotes).
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
            '\\' if !in_single => {
                if let Some(&next) = chars.peek() {
                    cur.push(next);
                    chars.next();
                    has_token = true;
                }
            }
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
}
