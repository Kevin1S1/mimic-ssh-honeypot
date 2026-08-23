//! Text-processing commands: the plumbing shell one-liners are made of.
//!
//! These exist because of what they unblock rather than what they do on their
//! own. An automated intrusion almost never runs a bare command — it runs a
//! pipeline, and a pipeline dies at its first `command not found`. The single
//! most common payload-delivery idiom in SSH botnets is
//! `echo <base64> | base64 -d | sh`, which needs exactly one of these to work
//! before anything downstream of it can be observed.
//!
//! Purely in-memory, like every other command module: input comes from the VFS
//! or the pipeline, never from a real file.

use super::{CommandResult, MAX_COMMAND_OUTPUT_BYTES};
use crate::shell::Shell;
use crate::vfs::NodeKind;

/// Read the operands as files, or fall back to the pipeline's stdin when there
/// are none — the convention every filter here follows, and what real
/// coreutils does.
///
/// The text is capped at [`MAX_COMMAND_OUTPUT_BYTES`] before any filter sees
/// it. Every command in this module is a transform whose result is capped at
/// that same figure anyway, and several of them *inflate* their input
/// (`base64` by 4/3, `sed` by the length of a replacement) — so bounding the
/// input is what keeps the peak allocation bounded, not just the result.
///
/// Returns the concatenated text plus any per-file errors and an exit status.
fn input_text(shell: &Shell, tool: &str, files: &[&str]) -> (String, String, i32) {
    let mut text = String::new();
    let mut errs = String::new();
    let mut status = 0;

    if files.is_empty() || files == ["-"] {
        text = shell.stdin.clone().unwrap_or_default();
        cap(&mut text);
        return (text, errs, status);
    }
    for f in files {
        if *f == "-" {
            text.push_str(shell.stdin.as_deref().unwrap_or_default());
        } else {
            match shell.vfs.resolve(shell.cwd, f) {
                Some(id) => match &shell.vfs.node(id).kind {
                    NodeKind::File { contents } => {
                        text.push_str(&String::from_utf8_lossy(contents));
                    }
                    _ => {
                        errs.push_str(&format!("{tool}: {f}: Is a directory\n"));
                        status = 1;
                    }
                },
                None => {
                    errs.push_str(&format!("{tool}: {f}: No such file or directory\n"));
                    status = 1;
                }
            }
        }
        if text.len() >= MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    cap(&mut text);
    (text, errs, status)
}

/// Cut `text` to [`MAX_COMMAND_OUTPUT_BYTES`] on a char boundary, silently —
/// unlike the dispatch cap this is an *input* bound, so it must not inject a
/// truncation notice into data a filter is about to transform.
fn cap(text: &mut String) {
    if text.len() <= MAX_COMMAND_OUTPUT_BYTES {
        return;
    }
    let mut cut = MAX_COMMAND_OUTPUT_BYTES;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
}

/// Split argv into flags and operands, treating everything after `--` as an
/// operand.
fn split_args(args: &[String]) -> (Vec<&str>, Vec<&str>) {
    let mut flags = Vec::new();
    let mut operands = Vec::new();
    let mut only_operands = false;
    for a in args {
        if only_operands {
            operands.push(a.as_str());
        } else if a == "--" {
            only_operands = true;
        } else if a.starts_with('-') && a.len() > 1 {
            flags.push(a.as_str());
        } else {
            operands.push(a.as_str());
        }
    }
    (flags, operands)
}

// --- base64 ---------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in text.chars() {
        // Real `base64 -d` skips newlines; anything else invalid is an error.
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == '=' {
            break;
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// `base64 [-d] [FILE]`
///
/// The one command in this module that is load-bearing on its own: staged
/// payloads arrive base64-encoded far more often than any other way, so
/// without it the interesting half of an intrusion never runs.
pub fn base64(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let decode = flags
        .iter()
        .any(|f| *f == "-d" || *f == "--decode" || (f.starts_with('-') && f.contains('d')));
    let wrap_zero = flags.iter().any(|f| *f == "-w0" || *f == "--wrap=0");

    let (text, errs, status) = input_text(shell, "base64", &operands);
    if status != 0 {
        return CommandResult::err(errs, status);
    }

    if decode {
        match b64_decode(&text) {
            Some(bytes) => CommandResult::ok(String::from_utf8_lossy(&bytes).into_owned()),
            None => CommandResult::err("base64: invalid input\n", 1),
        }
    } else {
        let encoded = b64_encode(text.as_bytes());
        if wrap_zero {
            return CommandResult::ok(format!("{encoded}\n"));
        }
        // Real `base64` wraps at 76 columns.
        let mut out = String::new();
        for chunk in encoded.as_bytes().chunks(76) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        CommandResult::ok(out)
    }
}

// --- hashes ---------------------------------------------------------------

/// `sha256sum [FILE]...`
pub fn sha256sum(shell: &Shell, args: &[String]) -> CommandResult {
    shasum(shell, args, 256)
}

/// `sha512sum [FILE]...`
pub fn sha512sum(shell: &Shell, args: &[String]) -> CommandResult {
    shasum(shell, args, 512)
}

/// The shared implementation behind both digest commands.
///
/// ponytail: `md5sum` and `sha1sum` are absent — both would need a digest crate
/// this tree does not carry, while `sha2` is already here for the quarantine
/// store. Upgrade if captured scripts are seen verifying payloads with the
/// legacy pair.
fn shasum(shell: &Shell, args: &[String], bits: u16) -> CommandResult {
    use sha2::{Digest, Sha256, Sha512};
    let tool = format!("sha{bits}sum");
    let (_, operands) = split_args(args);

    let hash = |data: &[u8]| -> String {
        if bits == 512 {
            let mut h = Sha512::new();
            h.update(data);
            h.finalize().iter().map(|b| format!("{b:02x}")).collect()
        } else {
            let mut h = Sha256::new();
            h.update(data);
            h.finalize().iter().map(|b| format!("{b:02x}")).collect()
        }
    };

    if operands.is_empty() {
        let text = shell.stdin.clone().unwrap_or_default();
        return CommandResult::ok(format!("{}  -\n", hash(text.as_bytes())));
    }

    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    for f in operands {
        match shell.vfs.resolve(shell.cwd, f) {
            Some(id) => match &shell.vfs.node(id).kind {
                NodeKind::File { contents } => {
                    out.push_str(&format!("{}  {f}\n", hash(contents)));
                }
                _ => {
                    errs.push_str(&format!("{tool}: {f}: Is a directory\n"));
                    status = 1;
                }
            },
            None => {
                errs.push_str(&format!("{tool}: {f}: No such file or directory\n"));
                status = 1;
            }
        }
    }
    CommandResult::streams(out, errs, status)
}

// --- sed ------------------------------------------------------------------

/// `sed [-n] [-e SCRIPT] [SCRIPT] [FILE]...`
///
/// ponytail: supports the substitution (`s/a/b/[g][i]`), delete (`d`) and
/// print (`p`) commands over literal patterns — no regular expressions,
/// address ranges, hold space, or `-i`. That covers the config-editing and
/// line-filtering one-liners droppers use; upgrade when captured scripts need
/// real regex.
pub fn sed(shell: &Shell, args: &[String]) -> CommandResult {
    let mut quiet = false;
    let mut scripts: Vec<String> = Vec::new();
    let mut files: Vec<&str> = Vec::new();
    let mut expect_script = false;
    let mut have_script = false;

    for a in args {
        if expect_script {
            scripts.push(a.clone());
            have_script = true;
            expect_script = false;
            continue;
        }
        match a.as_str() {
            "-n" | "--quiet" | "--silent" => quiet = true,
            "-e" | "--expression" => expect_script = true,
            // `-i` without a real filesystem write would be a lie; refuse the
            // way sed does when it cannot edit in place.
            "-i" | "--in-place" => {
                return CommandResult::err("sed: no input files while in-place editing\n", 1)
            }
            "-r" | "-E" | "--regexp-extended" | "-s" | "-u" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                if other.contains('n') {
                    quiet = true;
                }
            }
            other => {
                if have_script {
                    files.push(other);
                } else {
                    scripts.push(other.to_string());
                    have_script = true;
                }
            }
        }
    }

    if !have_script {
        return CommandResult::err(
            "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...\n",
            1,
        );
    }

    let (text, errs, status) = input_text(shell, "sed", &files);
    if status != 0 {
        return CommandResult::err(errs, status);
    }

    let mut out = String::new();
    for line in text.lines() {
        let mut current = line.to_string();
        let mut deleted = false;
        let mut explicit_print = false;

        for script in &scripts {
            match apply_sed_script(script, &current) {
                SedOutcome::Unchanged => {}
                SedOutcome::Replaced(next) => current = next,
                SedOutcome::Deleted => {
                    deleted = true;
                    break;
                }
                SedOutcome::Print => explicit_print = true,
                SedOutcome::Error(msg) => return CommandResult::err(msg, 1),
            }
        }

        if deleted {
            continue;
        }
        if !quiet {
            out.push_str(&current);
            out.push('\n');
        }
        if explicit_print {
            out.push_str(&current);
            out.push('\n');
        }
        // A substitution is the one transform here that grows its input without
        // limit — `s/a/<4096 bytes>/g` over a megabyte of `a` is a gigabyte —
        // so the accumulator is checked as it is built rather than trimmed
        // afterwards by dispatch, which would already have paid for it.
        if out.len() >= MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    CommandResult::ok(out)
}

enum SedOutcome {
    Unchanged,
    Replaced(String),
    Deleted,
    Print,
    Error(String),
}

fn apply_sed_script(script: &str, line: &str) -> SedOutcome {
    let script = script.trim();
    match script {
        "d" => return SedOutcome::Deleted,
        "p" => return SedOutcome::Print,
        _ => {}
    }
    if !script.starts_with('s') || script.len() < 4 {
        return SedOutcome::Error(format!(
            "sed: -e expression #1, char 1: unknown command: `{}'\n",
            script.chars().next().unwrap_or(' ')
        ));
    }
    // The delimiter is whatever follows `s`, so `s|a|b|` works like `s/a/b/`.
    let delim = script.as_bytes()[1] as char;
    let body: Vec<&str> = script[2..].split(delim).collect();
    if body.len() < 2 {
        return SedOutcome::Error(
            "sed: -e expression #1, char 3: unterminated `s' command\n".to_string(),
        );
    }
    let (pattern, replacement) = (body[0], body[1]);
    let flags = body.get(2).copied().unwrap_or("");
    let global = flags.contains('g');

    if pattern.is_empty() {
        return SedOutcome::Unchanged;
    }
    if !line.contains(pattern) {
        return SedOutcome::Unchanged;
    }
    let replaced = if global {
        // One line can be the whole input, so a global substitution that grows
        // what it matches has to be bounded here too and not only across lines:
        // `s/a/<4 KiB>/g` over a megabyte of `a` would otherwise build a
        // gigabyte before anything downstream could cap it.
        let grow = replacement.len().saturating_sub(pattern.len());
        let limit = MAX_COMMAND_OUTPUT_BYTES
            .checked_div(grow)
            .map_or(usize::MAX, |n| n + 1);
        line.replacen(pattern, replacement, limit)
    } else {
        line.replacen(pattern, replacement, 1)
    };
    SedOutcome::Replaced(replaced)
}

// --- cut ------------------------------------------------------------------

/// `cut -d DELIM -f LIST [FILE]...` / `cut -c LIST [FILE]...`
pub fn cut(shell: &Shell, args: &[String]) -> CommandResult {
    let mut delim = '\t';
    let mut fields: Option<String> = None;
    let mut chars: Option<String> = None;
    let mut files: Vec<&str> = Vec::new();
    let mut iter = args.iter().peekable();

    while let Some(a) = iter.next() {
        match a.as_str() {
            "-d" => {
                delim = iter.next().and_then(|d| d.chars().next()).unwrap_or('\t');
            }
            "-f" => fields = iter.next().cloned(),
            "-c" => chars = iter.next().cloned(),
            s if s.starts_with("-d") && s.len() > 2 => {
                delim = s[2..].chars().next().unwrap_or('\t');
            }
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

    let (text, errs, status) = input_text(shell, "cut", &files);
    if status != 0 {
        return CommandResult::err(errs, status);
    }

    let wanted = parse_ranges(fields.as_deref().or(chars.as_deref()).unwrap_or(""));
    let mut out = String::new();
    for line in text.lines() {
        if chars.is_some() {
            let picked: String = line
                .chars()
                .enumerate()
                .filter(|(i, _)| wanted.iter().any(|(lo, hi)| *lo <= i + 1 && i < hi))
                .map(|(_, c)| c)
                .collect();
            out.push_str(&picked);
        } else {
            let parts: Vec<&str> = line.split(delim).collect();
            // A line with no delimiter is passed through whole, like real cut.
            if parts.len() == 1 {
                out.push_str(line);
            } else {
                let picked: Vec<&str> = parts
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| wanted.iter().any(|(lo, hi)| *lo <= i + 1 && i < hi))
                    .map(|(_, p)| *p)
                    .collect();
                out.push_str(&picked.join(&delim.to_string()));
            }
        }
        out.push('\n');
    }
    CommandResult::ok(out)
}

/// Parse a `cut`-style list such as `1,3-5,7-` into inclusive 1-based ranges.
fn parse_ranges(spec: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo = a.parse().unwrap_or(1);
            let hi = if b.is_empty() {
                usize::MAX
            } else {
                b.parse().unwrap_or(usize::MAX)
            };
            out.push((lo, hi));
        } else if let Ok(n) = part.parse() {
            out.push((n, n));
        }
    }
    out
}

// --- tr -------------------------------------------------------------------

/// `tr [-d] [-s] SET1 [SET2]`
pub fn tr(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let delete = flags.iter().any(|f| f.contains('d'));
    let squeeze = flags.iter().any(|f| f.contains('s'));

    if operands.is_empty() {
        return CommandResult::err(
            "tr: missing operand\nTry 'tr --help' for more information.\n",
            1,
        );
    }
    let set1 = expand_set(operands[0]);
    let set2 = operands.get(1).map(|s| expand_set(s)).unwrap_or_default();
    let text = shell.stdin.clone().unwrap_or_default();

    let mut out = String::new();
    let mut last: Option<char> = None;
    for c in text.chars() {
        if let Some(pos) = set1.iter().position(|s| *s == c) {
            if delete {
                continue;
            }
            // Real tr pads a short SET2 with its final character.
            let mapped = set2.get(pos).or_else(|| set2.last()).copied().unwrap_or(c);
            if squeeze && last == Some(mapped) {
                continue;
            }
            out.push(mapped);
            last = Some(mapped);
        } else {
            out.push(c);
            last = Some(c);
        }
    }
    CommandResult::ok(out)
}

/// The widest `tr` set that will be expanded.
///
/// A range is two characters on the wire and up to 1.1 million after expansion
/// (`tr '\x01-\u{10FFFF}' x`), and every input character is then matched
/// against the set linearly — so an unbounded set is both an allocation and a
/// quadratic-time vector for a few bytes of argument. Real `tr` works over
/// bytes, so 256 entries is already more than it can express; the margin is for
/// the multi-byte sets a shell one-liner writes literally.
const MAX_TR_SET: usize = 1024;

/// Expand `a-z` ranges and the common escapes in a `tr` set, up to
/// [`MAX_TR_SET`] characters.
fn expand_set(spec: &str) -> Vec<char> {
    let chars: Vec<char> = spec.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() && out.len() < MAX_TR_SET {
        if chars[i] == '\\' && i + 1 < chars.len() {
            out.push(match chars[i + 1] {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '0' => '\0',
                other => other,
            });
            i += 2;
            continue;
        }
        if i + 2 < chars.len() && chars[i + 1] == '-' && chars[i + 2] >= chars[i] {
            for c in chars[i]..=chars[i + 2] {
                if out.len() >= MAX_TR_SET {
                    break;
                }
                out.push(c);
            }
            i += 3;
            continue;
        }
        // The POSIX classes that actually turn up in shell one-liners.
        if chars[i] == '[' {
            let rest: String = chars[i..].iter().collect();
            let class = [
                "[:upper:]",
                "[:lower:]",
                "[:digit:]",
                "[:space:]",
                "[:alpha:]",
            ]
            .iter()
            .find(|c| rest.starts_with(**c));
            if let Some(class) = class {
                match *class {
                    "[:upper:]" => out.extend('A'..='Z'),
                    "[:lower:]" => out.extend('a'..='z'),
                    "[:digit:]" => out.extend('0'..='9'),
                    "[:space:]" => out.extend([' ', '\t', '\n', '\r']),
                    _ => {
                        out.extend('A'..='Z');
                        out.extend('a'..='z');
                    }
                }
                i += class.len();
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

// --- sort / uniq ----------------------------------------------------------

/// `sort [-r] [-n] [-u] [FILE]...`
pub fn sort(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let reverse = flags.iter().any(|f| f.contains('r'));
    let numeric = flags.iter().any(|f| f.contains('n'));
    let unique = flags.iter().any(|f| f.contains('u'));

    let (text, errs, status) = input_text(shell, "sort", &operands);
    if status != 0 {
        return CommandResult::err(errs, status);
    }

    let mut lines: Vec<&str> = text.lines().collect();
    if numeric {
        lines.sort_by(|a, b| {
            let na: f64 = a.trim().parse().unwrap_or(f64::MIN);
            let nb: f64 = b.trim().parse().unwrap_or(f64::MIN);
            na.partial_cmp(&nb).unwrap_or(std::cmp::Ordering::Equal)
        });
    } else {
        lines.sort_unstable();
    }
    if reverse {
        lines.reverse();
    }
    if unique {
        lines.dedup();
    }
    let mut out = String::new();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    CommandResult::ok(out)
}

/// `uniq [-c] [-d] [-u] [FILE]`
pub fn uniq(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let count = flags.iter().any(|f| f.contains('c'));
    let only_dupes = flags.iter().any(|f| f.contains('d'));
    let only_unique = flags.iter().any(|f| f.contains('u'));

    let (text, errs, status) = input_text(shell, "uniq", &operands);
    if status != 0 {
        return CommandResult::err(errs, status);
    }

    let mut out = String::new();
    let mut runs: Vec<(&str, usize)> = Vec::new();
    for line in text.lines() {
        match runs.last_mut() {
            Some((prev, n)) if *prev == line => *n += 1,
            _ => runs.push((line, 1)),
        }
    }
    for (line, n) in runs {
        if only_dupes && n < 2 {
            continue;
        }
        if only_unique && n > 1 {
            continue;
        }
        if count {
            out.push_str(&format!("{n:>7} {line}\n"));
        } else {
            out.push_str(&format!("{line}\n"));
        }
    }
    CommandResult::ok(out)
}

// --- small path and stream tools -----------------------------------------

/// `basename PATH [SUFFIX]`
pub fn basename(_shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    let Some(path) = operands.first() else {
        return CommandResult::err(
            "basename: missing operand\nTry 'basename --help' for more information.\n",
            1,
        );
    };
    let trimmed = path.trim_end_matches('/');
    let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let base = match operands.get(1) {
        Some(suffix) if base != *suffix => base.strip_suffix(*suffix).unwrap_or(base),
        _ => base,
    };
    let base = if base.is_empty() { "/" } else { base };
    CommandResult::ok(format!("{base}\n"))
}

/// `dirname PATH`
pub fn dirname(_shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    let Some(path) = operands.first() else {
        return CommandResult::err(
            "dirname: missing operand\nTry 'dirname --help' for more information.\n",
            1,
        );
    };
    let trimmed = path.trim_end_matches('/');
    let out = match trimmed.rsplit_once('/') {
        Some(("", _)) => "/".to_string(),
        Some((dir, _)) => dir.to_string(),
        None => ".".to_string(),
    };
    CommandResult::ok(format!("{out}\n"))
}

/// `tee [-a] FILE...` — copies stdin onward and into each named VFS file.
pub fn tee(shell: &mut Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let append = flags.iter().any(|f| f.contains('a'));
    let text = shell.stdin.clone().unwrap_or_default();

    let mut errs = String::new();
    let mut status = 0;
    let (uid, gid) = (shell.uid, shell.gid);
    for path in &operands {
        let Some((parent, name)) = super::fs::resolve_parent(shell, path) else {
            errs.push_str(&format!("tee: {path}: No such file or directory\n"));
            status = 1;
            continue;
        };
        let existing = shell.vfs.child(parent, &name);
        match existing {
            Some(id) if !shell.vfs.write_file(id, text.as_bytes(), append) => {
                errs.push_str(&format!("tee: {path}: No space left on device\n"));
                status = 1;
            }
            Some(_) => {}
            None => {
                if shell.vfs.is_full() {
                    errs.push_str(&format!("tee: {path}: No space left on device\n"));
                    status = 1;
                } else {
                    shell
                        .vfs
                        .add_file(parent, &name, text.as_bytes().to_vec(), 0o644, uid, gid);
                }
            }
        }
    }
    CommandResult::streams(text, errs, status)
}

/// `rev [FILE]...`
pub fn rev(shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    let (text, errs, status) = input_text(shell, "rev", &operands);
    if status != 0 {
        return CommandResult::err(errs, status);
    }
    let mut out = String::new();
    for line in text.lines() {
        out.extend(line.chars().rev());
        out.push('\n');
    }
    CommandResult::ok(out)
}

/// `nl [FILE]...` — number non-empty lines, as GNU `nl` does by default.
pub fn nl(shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    let (text, errs, status) = input_text(shell, "nl", &operands);
    if status != 0 {
        return CommandResult::err(errs, status);
    }
    let mut out = String::new();
    let mut n = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            out.push('\n');
        } else {
            n += 1;
            out.push_str(&format!("{n:>6}\t{line}\n"));
        }
    }
    CommandResult::ok(out)
}

/// `seq [FIRST [INCREMENT]] LAST`
pub fn seq(_shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    let nums: Vec<i64> = operands.iter().filter_map(|a| a.parse().ok()).collect();
    let (first, step, last) = match nums.len() {
        1 => (1, 1, nums[0]),
        2 => (nums[0], 1, nums[1]),
        3 => (nums[0], nums[1], nums[2]),
        _ => {
            return CommandResult::err(
                "seq: missing operand\nTry 'seq --help' for more information.\n",
                1,
            )
        }
    };
    if step == 0 {
        return CommandResult::err("seq: invalid Zero increment value: '0'\n", 1);
    }
    let mut out = String::new();
    let mut i = first;
    // Bounded like every other generated stream: `seq 1 100000000` must not
    // become an unbounded allocation just because the arithmetic allows it.
    while (step > 0 && i <= last) || (step < 0 && i >= last) {
        out.push_str(&format!("{i}\n"));
        if out.len() > MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
        i += step;
    }
    CommandResult::ok(out)
}

/// `xargs [-n N] [COMMAND [ARG]...]`
///
/// Runs `COMMAND` with the whitespace-separated words of stdin appended, which
/// is the shape every `find ... | xargs rm`-style one-liner takes.
pub fn xargs(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut per_call: Option<usize> = None;
    let mut command: Vec<String> = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-n" => per_call = iter.next().and_then(|v| v.parse().ok()),
            s if s.starts_with("-n") && s.len() > 2 => per_call = s[2..].parse().ok(),
            "-r" | "--no-run-if-empty" | "-0" | "--null" => {}
            other => {
                command.push(other.to_string());
                command.extend(iter.map(|s| s.to_string()));
                break;
            }
        }
    }
    if command.is_empty() {
        command.push("echo".to_string());
    }

    let input = shell.stdin.clone().unwrap_or_default();
    let words: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
    if words.is_empty() {
        return CommandResult::empty();
    }

    let chunk = per_call.unwrap_or(words.len()).max(1);
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    for group in words.chunks(chunk) {
        let mut argv = command.clone();
        argv.extend(group.iter().cloned());
        // Goes through `dispatch`, so the nesting cap bounds recursion here the
        // same way it bounds `sudo` and `sh -c`.
        let result = super::dispatch(shell, &argv);
        out.push_str(&result.output);
        errs.push_str(&result.stderr);
        if result.status != 0 {
            status = result.status;
        }
        if out.len() > MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    CommandResult::streams(out, errs, status)
}

/// `awk [-F SEP] [-v VAR=VAL] PROGRAM [FILE...]`
///
/// A deliberately small subset: `[pattern] { print ... }` rules, plus a bare
/// pattern (which prints the line). That covers the shape awk actually takes in
/// an attack script — `awk '{print $2}'`, `awk -F: '$3==0 {print $1}'`,
/// `awk '/root/'` — which is pipeline plumbing, not programming. A pipeline
/// dies at its first `command not found`, so awk's absence hid everything
/// downstream of it; that is what this is here to stop.
///
/// Anything outside the subset is a syntax error rather than a wrong answer.
/// Silently printing nothing for a program it did not understand would make
/// awk look like it ran and found no matches, which is worse than admitting it
/// could not parse the program.
///
// ponytail: no user functions, arrays, loops, or BEGIN/END bodies beyond
// `print`. Upgrade when captured `command` events show programs being rejected
// here — `status: 2` on an `awk` line is the signal.
pub fn awk(shell: &Shell, args: &[String]) -> CommandResult {
    let mut sep: Option<String> = None;
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut program: Option<String> = None;
    let mut files: Vec<&str> = Vec::new();
    let mut iter = args.iter();

    while let Some(a) = iter.next() {
        match a.as_str() {
            "-F" => sep = iter.next().cloned(),
            "-v" => {
                if let Some((k, v)) = iter.next().and_then(|s| s.split_once('=')) {
                    vars.push((k.to_string(), v.to_string()));
                }
            }
            "-f" => {
                // `awk -f prog.awk` reads the program from a file. Attackers
                // drop the program alongside the payload, so it is worth
                // reading out of the VFS rather than refusing.
                let Some(path) = iter.next() else { continue };
                match shell.vfs.resolve(shell.cwd, path) {
                    Some(id) => match &shell.vfs.node(id).kind {
                        NodeKind::File { contents } => {
                            program = Some(String::from_utf8_lossy(contents).into_owned())
                        }
                        _ => {
                            return CommandResult::err(format!("awk: can't open file {path}\n"), 2)
                        }
                    },
                    None => return CommandResult::err(format!("awk: can't open file {path}\n"), 2),
                }
            }
            s if s.starts_with("-F") && s.len() > 2 => sep = Some(s[2..].to_string()),
            s if s.starts_with("-v") && s.len() > 2 => {
                if let Some((k, v)) = s[2..].split_once('=') {
                    vars.push((k.to_string(), v.to_string()));
                }
            }
            s if s.starts_with('-') && s.len() > 1 => {}
            other if program.is_none() => program = Some(other.to_string()),
            other => files.push(other),
        }
    }

    let Some(program) = program else {
        return CommandResult::err(
            "usage: awk [-F fs][-v var=value][prog | -f progfile][file ...]\n",
            2,
        );
    };

    // `-v FS=:` is the other way to set the separator, and scripts use both.
    let sep = vars
        .iter()
        .find(|(k, _)| k == "FS")
        .map(|(_, v)| v.clone())
        .or(sep);

    let rules = match parse_awk(&program) {
        Some(rules) => rules,
        None => {
            return CommandResult::err(
                format!("awk: syntax error at source line 1\n context is\n\t{program}\n"),
                2,
            )
        }
    };

    let (text, errs, status) = input_text(shell, "awk", &files);
    if status != 0 {
        return CommandResult::err(errs, status);
    }

    let mut out = String::new();
    for (i, line) in text.lines().enumerate() {
        let fields = split_fields(line, sep.as_deref());
        for rule in &rules {
            if !awk_matches(&rule.pattern, line, &fields, i as u64 + 1) {
                continue;
            }
            match &rule.action {
                // A bare pattern prints the whole line, like `awk '/root/'`.
                None => {
                    out.push_str(line);
                    out.push('\n');
                }
                Some(items) => {
                    let rendered: Vec<String> = items
                        .iter()
                        .map(|it| awk_value(it, line, &fields, i as u64 + 1))
                        .collect();
                    out.push_str(&rendered.join(" "));
                    out.push('\n');
                }
            }
        }
        // Dispatch caps the result afterwards, but awk can emit more than it
        // read (`{print $0 $0}`), so stop at the cap rather than inflating
        // first and trimming after.
        if out.len() >= MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    cap(&mut out);
    CommandResult::ok(out)
}

/// One `pattern { action }` rule. `action: None` is a bare pattern.
struct AwkRule {
    pattern: AwkPattern,
    action: Option<Vec<String>>,
}

enum AwkPattern {
    /// No pattern: the rule runs on every line.
    Always,
    /// `/regex/` — substring matching only; see `parse_awk`.
    Contains(String),
    /// `$N == "value"` / `$N != "value"`.
    FieldEq {
        field: usize,
        value: String,
        negate: bool,
    },
    /// `NR == N`.
    LineIs(u64),
}

/// Parse the supported subset. Returns `None` for anything else, which the
/// caller turns into a syntax error.
fn parse_awk(program: &str) -> Option<Vec<AwkRule>> {
    let mut rules = Vec::new();
    for chunk in split_awk_rules(program) {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        let (pattern_src, action_src) = match chunk.split_once('{') {
            Some((p, rest)) => (p.trim(), Some(rest.trim_end().trim_end_matches('}').trim())),
            None => (chunk, None),
        };
        // BEGIN/END need a program state this subset does not model, and
        // guessing at them would produce output a real awk never printed.
        if pattern_src.starts_with("BEGIN") || pattern_src.starts_with("END") {
            return None;
        }
        let pattern = parse_awk_pattern(pattern_src)?;
        let action = match action_src {
            None => None,
            Some(body) => Some(parse_awk_print(body)?),
        };
        rules.push(AwkRule { pattern, action });
    }
    if rules.is_empty() {
        return None;
    }
    Some(rules)
}

/// Split a program into rules on top-level `}`, so `'/a/{print} /b/{print}'`
/// parses as two rules and a `}` inside a string does not split anything.
fn split_awk_rules(program: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut in_regex = false;
    for c in program.chars() {
        match c {
            '"' if !in_regex => in_string = !in_string,
            '/' if !in_string => in_regex = !in_regex,
            _ => {}
        }
        current.push(c);
        if c == '}' && !in_string && !in_regex {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

fn parse_awk_pattern(src: &str) -> Option<AwkPattern> {
    let src = src.trim();
    if src.is_empty() {
        return Some(AwkPattern::Always);
    }
    // `/text/` — treated as a substring, not a regex. Anything with regex
    // metacharacters is refused rather than silently matched as a literal,
    // because a wrong match set is worse than an honest syntax error.
    if let Some(body) = src.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
        if body.contains(['*', '+', '?', '[', ']', '(', ')', '|', '\\', '{', '}']) {
            return None;
        }
        return Some(AwkPattern::Contains(
            body.trim_start_matches('^')
                .trim_end_matches('$')
                .to_string(),
        ));
    }
    if let Some(rest) = src.strip_prefix("NR") {
        let rest = rest.trim().strip_prefix("==")?.trim();
        return rest.parse().ok().map(AwkPattern::LineIs);
    }
    if let Some(rest) = src.strip_prefix('$') {
        let (negate, split) = if rest.contains("!=") {
            (true, "!=")
        } else {
            (false, "==")
        };
        let (idx, value) = rest.split_once(split)?;
        let field = idx.trim().parse().ok()?;
        let value = value.trim().trim_matches('"').to_string();
        return Some(AwkPattern::FieldEq {
            field,
            value,
            negate,
        });
    }
    None
}

/// Parse a `{ print a, b }` body into the items to print. Only `print` is
/// supported; `printf`, assignments and control flow are refused.
fn parse_awk_print(body: &str) -> Option<Vec<String>> {
    let body = body.trim().trim_end_matches(';').trim();
    if body.is_empty() || body == "print" {
        return Some(vec!["$0".to_string()]);
    }
    let rest = body.strip_prefix("print ")?;
    Some(
        rest.split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect(),
    )
}

fn awk_matches(pattern: &AwkPattern, line: &str, fields: &[String], nr: u64) -> bool {
    match pattern {
        AwkPattern::Always => true,
        AwkPattern::Contains(needle) => line.contains(needle.as_str()),
        AwkPattern::LineIs(n) => *n == nr,
        AwkPattern::FieldEq {
            field,
            value,
            negate,
        } => {
            let actual = awk_field(*field, line, fields);
            (actual == *value) != *negate
        }
    }
}

/// Resolve one `print` item: a field reference, `NR`/`NF`, a quoted string, or
/// a literal passed through as awk would print an unset variable's name-free
/// empty value only for bare identifiers.
fn awk_value(item: &str, line: &str, fields: &[String], nr: u64) -> String {
    if let Some(idx) = item.strip_prefix('$') {
        if let Ok(n) = idx.trim().parse::<usize>() {
            return awk_field(n, line, fields);
        }
    }
    match item {
        "NR" => nr.to_string(),
        "NF" => fields.len().to_string(),
        s if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 => {
            s[1..s.len() - 1].to_string()
        }
        // An unset variable is the empty string in awk, and every bare
        // identifier here is unset — this subset has no assignment.
        _ => String::new(),
    }
}

fn awk_field(n: usize, line: &str, fields: &[String]) -> String {
    if n == 0 {
        return line.to_string();
    }
    fields.get(n - 1).cloned().unwrap_or_default()
}

/// Split a line the way awk does: on runs of whitespace by default, or on each
/// occurrence of an explicit `-F` separator.
fn split_fields(line: &str, sep: Option<&str>) -> Vec<String> {
    match sep {
        None => line.split_whitespace().map(str::to_string).collect(),
        Some(s) if s.is_empty() || s == " " => {
            line.split_whitespace().map(str::to_string).collect()
        }
        // `-F '\t'` arrives as a two-character string from the shell.
        Some("\\t") => line.split('\t').map(str::to_string).collect(),
        Some(s) => line.split(s).map(str::to_string).collect(),
    }
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        let out = shell.execute(line);
        format!("{}{}", out.stdout, out.stderr)
    }

    #[test]
    fn base64_round_trips_through_a_pipeline() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo hello | base64"), "aGVsbG8K\n");
        assert_eq!(run(&mut shell, "echo aGVsbG8K | base64 -d"), "hello\n");
    }

    /// The idiom this module exists for: a staged payload arriving encoded and
    /// piped straight into a shell.
    #[test]
    fn the_base64_dropper_idiom_runs_end_to_end() {
        let mut shell = Shell::new("root", "debian");
        // `echo whoami` encoded.
        let out = run(&mut shell, "echo d2hvYW1pCg== | base64 -d | sh");
        assert_eq!(out, "root\n", "the decoded command must actually run");
    }

    #[test]
    fn base64_rejects_invalid_input() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("echo '!!!!' | base64 -d");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("invalid input"), "{}", out.stderr);
    }

    #[test]
    fn sha256sum_matches_a_known_vector() {
        let mut shell = Shell::new("root", "debian");
        // Well-known: sha256 of "abc".
        let out = run(&mut shell, "echo -n abc | sha256sum");
        assert!(
            out.starts_with("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            "{out}"
        );
        assert!(out.trim_end().ends_with("  -"), "{out}");
    }

    #[test]
    fn sed_substitutes_globally_and_once() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo aaa | sed 's/a/b/'"), "baa\n");
        assert_eq!(run(&mut shell, "echo aaa | sed 's/a/b/g'"), "bbb\n");
        // Any delimiter, which is what path substitutions use.
        assert_eq!(run(&mut shell, "echo /x/y | sed 's|/x|/z|'"), "/z/y\n");
    }

    #[test]
    fn sed_deletes_and_prints() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "printf 'a\\nb\\n' | sed 'd'"), "");
        assert_eq!(run(&mut shell, "echo hi | sed -n 'p'"), "hi\n");
    }

    #[test]
    fn cut_selects_fields_and_characters() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo a:b:c | cut -d: -f2"), "b\n");
        assert_eq!(run(&mut shell, "echo a:b:c | cut -d: -f1,3"), "a:c\n");
        assert_eq!(run(&mut shell, "echo abcdef | cut -c2-4"), "bcd\n");
    }

    /// The reconnaissance one-liner this unblocks.
    #[test]
    fn cut_reads_passwd_fields() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "cat /etc/passwd | cut -d: -f1");
        assert!(out.starts_with("root\n"), "{out}");
        assert!(out.contains("\nuser\n"), "{out}");
    }

    #[test]
    fn tr_translates_deletes_and_squeezes() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo abc | tr a-z A-Z"), "ABC\n");
        assert_eq!(run(&mut shell, "echo hello | tr -d l"), "heo\n");
        assert_eq!(run(&mut shell, "echo aabbcc | tr -s abc"), "abc\n");
        assert_eq!(
            run(&mut shell, "echo abc | tr '[:lower:]' '[:upper:]'"),
            "ABC\n"
        );
    }

    #[test]
    fn sort_and_uniq_cooperate() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "printf 'b\\na\\nb\\n' | sort"), "a\nb\nb\n");
        assert_eq!(
            run(&mut shell, "printf 'b\\na\\nb\\n' | sort | uniq"),
            "a\nb\n"
        );
        assert_eq!(
            run(&mut shell, "printf 'b\\na\\nb\\n' | sort | uniq -c"),
            "      1 a\n      2 b\n"
        );
        assert_eq!(run(&mut shell, "printf '10\\n9\\n' | sort -n"), "9\n10\n");
    }

    #[test]
    fn basename_and_dirname_split_paths() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "basename /usr/bin/wget"), "wget\n");
        assert_eq!(run(&mut shell, "basename /tmp/x.sh .sh"), "x\n");
        assert_eq!(run(&mut shell, "dirname /usr/bin/wget"), "/usr/bin\n");
        assert_eq!(run(&mut shell, "dirname wget"), ".\n");
    }

    #[test]
    fn tee_writes_the_vfs_and_passes_through() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo saved | tee /tmp/t.txt"), "saved\n");
        assert_eq!(run(&mut shell, "cat /tmp/t.txt"), "saved\n");
    }

    #[test]
    fn seq_counts_and_stays_bounded() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "seq 3"), "1\n2\n3\n");
        assert_eq!(run(&mut shell, "seq 2 4"), "2\n3\n4\n");
        // A generated stream is capped like every other command's output.
        let huge = run(&mut shell, "seq 1 100000000");
        assert!(
            huge.len() < super::MAX_COMMAND_OUTPUT_BYTES + 4096,
            "unbounded seq"
        );
    }

    #[test]
    fn xargs_feeds_words_to_a_command() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo a b c | xargs echo"), "a b c\n");
        assert_eq!(run(&mut shell, "echo a b | xargs -n1 echo"), "a\nb\n");
    }

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
        assert_eq!(run(&mut shell, "echo abc | tr a-z A-Z"), "ABC\n");
    }

    /// A substitution is the one transform here that grows what it matches, and
    /// a single line can be the whole input.
    #[test]
    fn sed_bounds_a_growing_substitution() {
        let mut shell = Shell::new("root", "debian");
        let long: String = "y".repeat(2000);
        let line = format!("echo {} | sed 's/a/{long}/g'", "a".repeat(2000));
        let out = shell.execute(&line);
        assert!(
            out.stdout.len() < super::MAX_COMMAND_OUTPUT_BYTES + 4096,
            "unbounded substitution: {} bytes",
            out.stdout.len()
        );
    }

    #[test]
    fn rev_and_nl_render() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo abc | rev"), "cba\n");
        assert_eq!(run(&mut shell, "echo hi | nl"), "     1\thi\n");
    }
    #[test]
    fn awk_handles_the_pipeline_shapes_attackers_use() {
        let mut shell = Shell::new("root", "debian");

        // The single most common form, and the reason awk's absence mattered:
        // a pipeline dies at its first `command not found`, so everything
        // downstream of awk used to be invisible.
        assert_eq!(
            shell.execute("echo 'a b c' | awk '{print $2}'").stdout,
            "b\n"
        );
        assert_eq!(
            shell.execute("echo 'a b c' | awk '{print $3, $1}'").stdout,
            "c a\n"
        );
        assert_eq!(
            shell.execute("echo 'a b' | awk '{print $0}'").stdout,
            "a b\n"
        );

        // Finding uid-0 accounts is textbook post-exploitation recon.
        let roots = shell.execute("awk -F: '$3 == 0 {print $1}' /etc/passwd");
        assert_eq!(roots.stdout, "root\n");

        // A bare pattern prints the whole line.
        assert!(shell
            .execute("awk '/root/' /etc/passwd")
            .stdout
            .starts_with("root:x:0:0:"));

        // NR and NF are the other two names worth supporting.
        assert_eq!(
            shell
                .execute("printf 'x\\ny\\n' | awk 'NR == 2 {print $1}'")
                .stdout,
            "y\n"
        );
        assert_eq!(
            shell.execute("echo 'a b c' | awk '{print NF}'").stdout,
            "3\n"
        );
    }

    #[test]
    fn awk_admits_what_it_cannot_parse() {
        let mut shell = Shell::new("root", "debian");
        // Printing nothing would make awk look like it ran and matched no
        // lines, which is a worse lie than an honest syntax error — and
        // `status: 2` on an awk line is the signal for what to implement next.
        for program in [
            "BEGIN {x = 1} {print x}",
            "{for (i = 1; i <= NF; i++) print $i}",
            "{printf \"%s\\n\", $1}",
        ] {
            let result = shell.execute(&format!("echo a | awk '{program}'"));
            assert_eq!(result.status, 2, "{program}");
            assert!(result.stderr.contains("syntax error"), "{program}");
        }
    }
}
