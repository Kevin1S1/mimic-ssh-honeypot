use super::{newline_terminated, with_input};
use crate::commands::CommandResult;
use crate::shell::Shell;

const DEFAULT_DELIMITER: char = '\t';

type Range = (usize, usize);

/// `cut -d DELIM -f LIST [FILE]...` / `cut -c LIST [FILE]...`
pub fn cut(shell: &Shell, args: &[String]) -> CommandResult {
    let mut delim = DEFAULT_DELIMITER;
    let mut fields: Option<String> = None;
    let mut chars: Option<String> = None;
    let mut files: Vec<&str> = Vec::new();
    let mut iter = args.iter();

    while let Some(a) = iter.next() {
        match a.as_str() {
            "-d" => delim = first_char_or_default(iter.next().map(String::as_str)),
            "-f" => fields = iter.next().cloned(),
            "-c" => chars = iter.next().cloned(),
            s if s.starts_with("-d") && s.len() > 2 => delim = first_char_or_default(Some(&s[2..])),
            s if s.starts_with("-f") && s.len() > 2 => fields = Some(s[2..].to_string()),
            s if s.starts_with("-c") && s.len() > 2 => chars = Some(s[2..].to_string()),
            s if s.starts_with('-') && s.len() > 1 => {}
            other => files.push(other),
        }
    }

    if fields.is_none() && chars.is_none() {
        return CommandResult::err(
            "cut: you must specify a list of bytes, characters, or fields\n\
             Try 'cut --help' for more information.\n",
            1,
        );
    }

    let wanted = parse_ranges(fields.as_deref().or(chars.as_deref()).unwrap_or(""));
    let by_chars = chars.is_some();
    with_input(shell, "cut", &files, |text| {
        let picked = text.lines().map(|line| {
            if by_chars {
                pick_chars(line, &wanted)
            } else {
                pick_fields(line, delim, &wanted)
            }
        });
        CommandResult::ok(newline_terminated(picked))
    })
}

fn first_char_or_default(value: Option<&str>) -> char {
    value
        .and_then(|v| v.chars().next())
        .unwrap_or(DEFAULT_DELIMITER)
}

fn is_selected(wanted: &[Range], index: usize) -> bool {
    let position = index + 1;
    wanted
        .iter()
        .any(|(lo, hi)| *lo <= position && position <= *hi)
}

fn pick_chars(line: &str, wanted: &[Range]) -> String {
    line.chars()
        .enumerate()
        .filter(|(i, _)| is_selected(wanted, *i))
        .map(|(_, c)| c)
        .collect()
}

fn pick_fields(line: &str, delim: char, wanted: &[Range]) -> String {
    let parts: Vec<&str> = line.split(delim).collect();
    // A line with no delimiter is passed through whole, like real cut.
    if parts.len() == 1 {
        return line.to_string();
    }
    let picked: Vec<&str> = parts
        .iter()
        .enumerate()
        .filter(|(i, _)| is_selected(wanted, *i))
        .map(|(_, p)| *p)
        .collect();
    picked.join(&delim.to_string())
}

/// Parse a `cut`-style list such as `1,3-5,7-` into inclusive 1-based ranges.
fn parse_ranges(spec: &str) -> Vec<Range> {
    let mut out = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let lo = a.parse().unwrap_or(1);
            out.push((lo, b.parse().unwrap_or(usize::MAX)));
        } else if let Ok(n) = part.parse() {
            out.push((n, n));
        }
    }
    out
}
