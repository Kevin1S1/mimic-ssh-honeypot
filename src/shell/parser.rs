//! Minimal POSIX-ish command-line tokenizer.
//!
//! Splits a line into argument words, honouring single quotes, double quotes,
//! and backslash escaping. This is deliberately small: pipes, redirects, and
//! command substitution are intentionally unsupported. Variable expansion
//! happens *before* tokenization in [`crate::shell::Shell`].

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
