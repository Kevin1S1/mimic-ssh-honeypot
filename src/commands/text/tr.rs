use super::{has_flag_letter, missing_operand, split_args, stdin_text};
use crate::commands::CommandResult;
use crate::shell::Shell;

/// The widest `tr` set that will be expanded.
///
/// A range is two characters on the wire and up to 1.1 million after expansion
/// (`tr '\x01-\u{10FFFF}' x`), and every input character is then matched
/// against the set linearly — so an unbounded set is both an allocation and a
/// quadratic-time vector for a few bytes of argument. Real `tr` works over
/// bytes, so 256 entries is already more than it can express; the margin is for
/// the multi-byte sets a shell one-liner writes literally.
const MAX_TR_SET: usize = 1024;

const POSIX_CLASSES: [&str; 5] = [
    "[:upper:]",
    "[:lower:]",
    "[:digit:]",
    "[:space:]",
    "[:alpha:]",
];

struct Translation {
    from: Vec<char>,
    to: Vec<char>,
    delete: bool,
    squeeze: bool,
}

/// `tr [-d] [-s] SET1 [SET2]`
pub fn tr(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let Some(from) = operands.first() else {
        return missing_operand("tr");
    };
    let translation = Translation {
        from: expand_set(from),
        to: operands.get(1).map(|s| expand_set(s)).unwrap_or_default(),
        delete: has_flag_letter(&flags, 'd'),
        squeeze: has_flag_letter(&flags, 's'),
    };
    CommandResult::ok(translation.apply(&stdin_text(shell)))
}

impl Translation {
    fn apply(&self, text: &str) -> String {
        let mut out = String::new();
        let mut last: Option<char> = None;
        for c in text.chars() {
            let Some(pos) = self.from.iter().position(|s| *s == c) else {
                out.push(c);
                last = Some(c);
                continue;
            };
            if self.delete {
                continue;
            }
            // Real tr pads a short SET2 with its final character.
            let mapped = self
                .to
                .get(pos)
                .or_else(|| self.to.last())
                .copied()
                .unwrap_or(c);
            if self.squeeze && last == Some(mapped) {
                continue;
            }
            out.push(mapped);
            last = Some(mapped);
        }
        out
    }
}

/// Expand `a-z` ranges and the common escapes in a `tr` set, up to
/// [`MAX_TR_SET`] characters.
fn expand_set(spec: &str) -> Vec<char> {
    let chars: Vec<char> = spec.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() && out.len() < MAX_TR_SET {
        let rest = &chars[i..];
        i += if let Some(escaped) = escape_at(rest) {
            out.push(escaped);
            2
        } else if let Some((lo, hi)) = range_at(rest) {
            out.extend((lo..=hi).take(MAX_TR_SET - out.len()));
            3
        } else if let Some(class) = posix_class_at(rest) {
            out.extend(posix_class_members(class));
            class.len()
        } else {
            out.push(rest[0]);
            1
        };
    }
    out
}

fn escape_at(rest: &[char]) -> Option<char> {
    let ['\\', escaped, ..] = rest else {
        return None;
    };
    Some(match escaped {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        '0' => '\0',
        other => *other,
    })
}

fn range_at(rest: &[char]) -> Option<(char, char)> {
    match rest {
        [lo, '-', hi, ..] if hi >= lo => Some((*lo, *hi)),
        _ => None,
    }
}

fn posix_class_at(rest: &[char]) -> Option<&'static str> {
    POSIX_CLASSES
        .into_iter()
        .find(|class| rest.iter().copied().take(class.len()).eq(class.chars()))
}

fn posix_class_members(class: &str) -> Vec<char> {
    match class {
        "[:upper:]" => ('A'..='Z').collect(),
        "[:lower:]" => ('a'..='z').collect(),
        "[:digit:]" => ('0'..='9').collect(),
        "[:space:]" => vec![' ', '\t', '\n', '\r'],
        _ => ('A'..='Z').chain('a'..='z').collect(),
    }
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    /// Two characters of argument must not become a million characters of set,
    /// which every input byte would then be matched against linearly.
    #[test]
    fn tr_bounds_a_hostile_range() {
        let set = super::expand_set("\u{1}-\u{10FFFE}");
        assert!(
            set.len() <= super::MAX_TR_SET,
            "expanded to {} chars",
            set.len()
        );
        // The ranges a one-liner actually writes are unaffected.
        assert_eq!(super::expand_set("a-z").len(), 26);
        let mut shell = Shell::new("root", "debian");
        assert_eq!(shell.execute("echo abc | tr a-z A-Z").text, "ABC\n");
    }
}
