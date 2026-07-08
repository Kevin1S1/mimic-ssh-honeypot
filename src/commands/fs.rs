//! Filesystem read commands: `ls`, `cd`, `pwd`, `cat`.
//!
//! All operate exclusively on the in-memory [`Vfs`]; no real path is touched.

use super::CommandResult;
use crate::shell::Shell;
use crate::vfs::nodes::{NodeKind, S_IFDIR, S_IFLNK, S_IFMT};
use crate::vfs::{NodeId, Vfs};

/// Flags parsed from a leading run of `-xyz` arguments.
#[derive(Default)]
struct LsFlags {
    all: bool,        // -a: include entries starting with '.'
    almost_all: bool, // -A: like -a but skip '.' and '..'
    long: bool,       // -l: long listing format
    human: bool,      // -h: human-readable sizes (with -l)
    one: bool,        // -1: one entry per line
}

/// `ls [OPTION]... [FILE]...`
pub fn ls(shell: &Shell, args: &[String]) -> CommandResult {
    let mut flags = LsFlags::default();
    let mut paths: Vec<&str> = Vec::new();

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for ch in arg[1..].chars() {
                match ch {
                    'a' => flags.all = true,
                    'A' => flags.almost_all = true,
                    'l' => flags.long = true,
                    'h' => flags.human = true,
                    '1' => flags.one = true,
                    'F' | 'C' | 'r' | 't' | 'R' | 'S' => {} // accepted, no-op
                    other => {
                        return CommandResult::err(
                            format!(
                                "ls: invalid option -- '{other}'\nTry 'ls --help' for more information.\n"
                            ),
                            2,
                        );
                    }
                }
            }
        } else if arg == "--all" {
            flags.all = true;
        } else if arg == "--almost-all" {
            flags.almost_all = true;
        } else {
            paths.push(arg);
        }
    }

    if paths.is_empty() {
        paths.push(".");
    }

    let multiple = paths.len() > 1;
    let mut out = String::new();
    let mut status = 0;

    for (idx, path) in paths.iter().enumerate() {
        let Some(target) = shell.vfs.resolve(shell.cwd, path) else {
            out.push_str(&format!(
                "ls: cannot access '{path}': No such file or directory\n"
            ));
            status = 2;
            continue;
        };

        let node = shell.vfs.node(target);
        if !node.meta.is_dir() {
            // A file operand: list the operand itself.
            out.push_str(&format_single(&shell.vfs, target, path, &flags));
            continue;
        }

        if multiple {
            if idx > 0 {
                out.push('\n');
            }
            out.push_str(&format!("{path}:\n"));
        }
        out.push_str(&list_dir(&shell.vfs, target, &flags));
    }

    if status == 0 {
        CommandResult::ok(out)
    } else {
        CommandResult::err(out, status)
    }
}

/// Render the listing for one directory's contents.
fn list_dir(vfs: &Vfs, dir: NodeId, flags: &LsFlags) -> String {
    let mut names: Vec<(String, NodeId)> = Vec::new();

    if flags.all {
        names.push((".".to_string(), dir));
        let parent = vfs.node(dir).parent.unwrap_or(dir);
        names.push(("..".to_string(), parent));
    }
    for (name, id) in vfs.entries(dir).unwrap_or_default() {
        if name.starts_with('.') && !flags.all && !flags.almost_all {
            continue;
        }
        names.push((name, id));
    }

    if flags.long {
        let mut out = String::new();
        if flags.all || flags.almost_all {
            // GNU ls prints a "total" line for long listings.
            out.push_str("total 8\n");
        }
        for (name, id) in &names {
            out.push_str(&long_entry(vfs, *id, name, flags));
            out.push('\n');
        }
        out
    } else if flags.one {
        names
            .iter()
            .map(|(n, _)| format!("{n}\n"))
            .collect::<String>()
    } else {
        let line = names
            .iter()
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
            .join("  ");
        if line.is_empty() {
            String::new()
        } else {
            format!("{line}\n")
        }
    }
}

/// Render a listing for a single non-directory operand.
fn format_single(vfs: &Vfs, id: NodeId, display: &str, flags: &LsFlags) -> String {
    if flags.long {
        format!("{}\n", long_entry(vfs, id, display, flags))
    } else {
        format!("{display}\n")
    }
}

/// One `ls -l` line for the node `id`, labelled `name`.
fn long_entry(vfs: &Vfs, id: NodeId, name: &str, flags: &LsFlags) -> String {
    let node = vfs.node(id);
    let mode = mode_string(node.meta.mode);
    let nlink = match &node.kind {
        NodeKind::Directory { children } => children.len() + 2,
        _ => 1,
    };
    let owner = uid_name(node.meta.uid);
    let group = gid_name(node.meta.gid);
    let size = node_size(node);
    let size = if flags.human {
        human_size(size)
    } else {
        size.to_string()
    };
    let date = format_time(node.meta.mtime);

    let suffix = if node.meta.is_symlink() {
        if let NodeKind::Symlink { target } = &node.kind {
            format!(" -> {target}")
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    format!("{mode} {nlink:>2} {owner:<8} {group:<8} {size:>6} {date} {name}{suffix}")
}

/// Apparent size of a node, as `ls -l` reports it.
fn node_size(node: &crate::vfs::Node) -> u64 {
    match &node.kind {
        NodeKind::File { contents } => contents.len() as u64,
        NodeKind::Symlink { target } => target.len() as u64,
        NodeKind::Directory { .. } => 4096,
    }
}

/// Render a numeric mode as a `drwxr-xr-x`-style string.
fn mode_string(mode: u32) -> String {
    let type_char = match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        _ => '-',
    };
    let mut s = String::with_capacity(10);
    s.push(type_char);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    s
}

/// Format a unix timestamp the way `ls -l` does (`May  3 00:00`), in UTC.
fn format_time(ts: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (_, month, day) = civil_from_days(days);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let mon = MONTHS[(month - 1) as usize];
    format!("{mon} {day:>2} {hour:02}:{minute:02}")
}

/// Convert days since the Unix epoch to `(year, month, day)` (UTC).
///
/// Howard Hinnant's `civil_from_days` algorithm — exact for all valid dates,
/// no leap-second/leap-year special cases needed.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Human-readable size for `ls -lh`.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["", "K", "M", "G", "T", "P"];
    if bytes < 1024 {
        return bytes.to_string();
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1}{}", UNITS[unit])
}

/// Map a uid to a Debian account name.
fn uid_name(uid: u32) -> String {
    match uid {
        0 => "root".into(),
        1 => "daemon".into(),
        2 => "bin".into(),
        3 => "sys".into(),
        8 => "mail".into(),
        33 => "www-data".into(),
        34 => "backup".into(),
        100 => "sshd".into(),
        1000 => "user".into(),
        65534 => "nobody".into(),
        other => other.to_string(),
    }
}

/// Map a gid to a Debian group name.
fn gid_name(gid: u32) -> String {
    match gid {
        0 => "root".into(),
        4 => "adm".into(),
        8 => "mail".into(),
        27 => "sudo".into(),
        33 => "www-data".into(),
        34 => "backup".into(),
        42 => "shadow".into(),
        43 => "utmp".into(),
        1000 => "user".into(),
        65534 => "nogroup".into(),
        other => other.to_string(),
    }
}

/// `cd [DIR]`
pub fn cd(shell: &mut Shell, args: &[String]) -> CommandResult {
    let target_path = match args.first().map(String::as_str) {
        None | Some("~") => shell.vfs.path_of(shell.home),
        Some("-") => {
            let prev = shell.vfs.path_of(shell.prev_cwd);
            // `cd -` swaps to the previous directory and prints where it landed.
            std::mem::swap(&mut shell.prev_cwd, &mut shell.cwd);
            shell.env.set("PWD", &prev);
            return CommandResult::ok(format!("{prev}\n"));
        }
        Some(path) if path.starts_with("~/") => {
            format!("{}/{}", shell.vfs.path_of(shell.home), &path[2..])
        }
        Some(path) => path.to_string(),
    };

    let Some(target) = shell.vfs.resolve(shell.cwd, &target_path) else {
        return CommandResult::err(
            format!("-bash: cd: {target_path}: No such file or directory\n"),
            1,
        );
    };

    if !shell.vfs.node(target).meta.is_dir() {
        return CommandResult::err(format!("-bash: cd: {target_path}: Not a directory\n"), 1);
    }

    shell.prev_cwd = shell.cwd;
    shell.cwd = target;
    let pwd = shell.vfs.path_of(target);
    shell.env.set("PWD", &pwd);
    CommandResult::empty()
}

/// `pwd`
pub fn pwd(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.cwd_path()))
}

/// `cat [FILE]...`
pub fn cat(shell: &Shell, args: &[String]) -> CommandResult {
    if args.is_empty() {
        // Real `cat` with no args reads stdin; over a non-interactive exec we
        // just succeed silently.
        return CommandResult::empty();
    }

    let mut out = String::new();
    let mut status = 0;

    for arg in args {
        let Some(id) = shell.vfs.resolve(shell.cwd, arg) else {
            out.push_str(&format!("cat: {arg}: No such file or directory\n"));
            status = 1;
            continue;
        };
        let node = shell.vfs.node(id);
        if !node.meta.readable_by(shell.uid, shell.gid) {
            out.push_str(&format!("cat: {arg}: Permission denied\n"));
            status = 1;
            continue;
        }
        match &node.kind {
            NodeKind::Directory { .. } => {
                out.push_str(&format!("cat: {arg}: Is a directory\n"));
                status = 1;
            }
            NodeKind::File { contents } => {
                out.push_str(&String::from_utf8_lossy(contents));
            }
            NodeKind::Symlink { .. } => {
                // resolve() already follows symlinks, so this is unreachable in
                // practice; treat as empty to be safe.
            }
        }
    }

    if status == 0 {
        CommandResult::ok(out)
    } else {
        CommandResult::err(out, status)
    }
}

/// Parse a numeric count operand for `head`/`tail` (`-n`/`-c`). Rejects
/// negatives and non-digits, matching coreutils' basic validation.
fn parse_count(s: &str) -> Option<usize> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `head [-n N] [-c N] [FILE]...` — first N lines (default 10) of each file.
///
/// ponytail: supports `-n`/`-c` (and the legacy `-N` form) only; no `-q`/`-v`
/// header control. Upgrade if captured tooling depends on those.
pub fn head(shell: &Shell, args: &[String]) -> CommandResult {
    head_tail(shell, args, false)
}

/// `tail [-n N] [-c N] [FILE]...` — last N lines (default 10) of each file.
pub fn tail(shell: &Shell, args: &[String]) -> CommandResult {
    head_tail(shell, args, true)
}

/// Shared body for [`head`] and [`tail`]. `from_end` selects the tail variant.
fn head_tail(shell: &Shell, args: &[String], from_end: bool) -> CommandResult {
    let cmd = if from_end { "tail" } else { "head" };
    let mut count: usize = 10;
    let mut by_bytes = false;
    let mut files: Vec<&str> = Vec::new();
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        let a = arg.as_str();
        if a == "-n" || a == "-c" {
            by_bytes = a == "-c";
            let Some(val) = iter.next() else {
                return CommandResult::err(
                    format!("{cmd}: option requires an argument -- '{}'\n", &a[1..]),
                    1,
                );
            };
            let Some(n) = parse_count(val) else {
                return invalid_count(cmd, by_bytes, val);
            };
            count = n;
        } else if let Some(rest) = a.strip_prefix("-n").filter(|_| a.len() > 2) {
            let Some(n) = parse_count(rest) else {
                return invalid_count(cmd, false, rest);
            };
            by_bytes = false;
            count = n;
        } else if let Some(rest) = a.strip_prefix("-c").filter(|_| a.len() > 2) {
            let Some(n) = parse_count(rest) else {
                return invalid_count(cmd, true, rest);
            };
            by_bytes = true;
            count = n;
        } else if a.len() > 1 && a.starts_with('-') && a[1..].bytes().all(|b| b.is_ascii_digit()) {
            // Legacy `head -20` form.
            count = a[1..].parse().unwrap_or(10);
            by_bytes = false;
        } else if a.starts_with('-') && a.len() > 1 {
            return CommandResult::err(format!("{cmd}: invalid option -- '{}'\n", &a[1..]), 1);
        } else {
            files.push(a);
        }
    }

    if files.is_empty() {
        // Real head/tail read stdin, which is empty over a non-interactive exec.
        return CommandResult::empty();
    }

    let show_headers = files.len() > 1;
    let mut out = String::new();
    let mut status = 0;
    for (i, path) in files.iter().enumerate() {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            out.push_str(&format!(
                "{cmd}: cannot open '{path}' for reading: No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        let node = shell.vfs.node(id);
        if !node.meta.readable_by(shell.uid, shell.gid) {
            out.push_str(&format!(
                "{cmd}: cannot open '{path}' for reading: Permission denied\n"
            ));
            status = 1;
            continue;
        }
        let NodeKind::File { contents } = &node.kind else {
            out.push_str(&format!("{cmd}: error reading '{path}': Is a directory\n"));
            status = 1;
            continue;
        };
        if show_headers {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&format!("==> {path} <==\n"));
        }
        out.push_str(&select_slice(contents, count, by_bytes, from_end));
    }

    if status == 0 {
        CommandResult::ok(out)
    } else {
        CommandResult::err(out, status)
    }
}

/// The "invalid number of lines/bytes" error shared by `head`/`tail`.
fn invalid_count(cmd: &str, by_bytes: bool, val: &str) -> CommandResult {
    let unit = if by_bytes { "bytes" } else { "lines" };
    CommandResult::err(format!("{cmd}: invalid number of {unit}: '{val}'\n"), 1)
}

/// Take the first/last `count` lines (or bytes) of `contents` as a string.
fn select_slice(contents: &[u8], count: usize, by_bytes: bool, from_end: bool) -> String {
    if by_bytes {
        let slice = if from_end {
            &contents[contents.len().saturating_sub(count)..]
        } else {
            &contents[..count.min(contents.len())]
        };
        return String::from_utf8_lossy(slice).into_owned();
    }
    let text = String::from_utf8_lossy(contents);
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let selected = if from_end {
        &lines[lines.len().saturating_sub(count)..]
    } else {
        &lines[..count.min(lines.len())]
    };
    selected.concat()
}

/// `wc [-l] [-w] [-c|-m] [FILE]...` — line, word and byte counts.
///
/// ponytail: `-m` (chars) is treated as `-c` (bytes); the fake VFS is ASCII in
/// practice, so the distinction never shows. Upgrade if that changes.
pub fn wc(shell: &Shell, args: &[String]) -> CommandResult {
    let mut show_l = false;
    let mut show_w = false;
    let mut show_c = false;
    let mut files: Vec<&str> = Vec::new();

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for ch in arg[1..].chars() {
                match ch {
                    'l' => show_l = true,
                    'w' => show_w = true,
                    'c' | 'm' => show_c = true,
                    other => {
                        return CommandResult::err(
                            format!(
                                "wc: invalid option -- '{other}'\nUsage: wc [OPTION]... [FILE]...\n"
                            ),
                            1,
                        );
                    }
                }
            }
        } else {
            files.push(arg.as_str());
        }
    }
    // Default with no selectors: lines, words, bytes.
    if !(show_l || show_w || show_c) {
        show_l = true;
        show_w = true;
        show_c = true;
    }
    if files.is_empty() {
        return CommandResult::empty();
    }

    let mut out = String::new();
    let mut status = 0;
    let (mut tl, mut tw, mut tc) = (0usize, 0usize, 0usize);
    let mut counted = 0;

    for path in &files {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            out.push_str(&format!("wc: {path}: No such file or directory\n"));
            status = 1;
            continue;
        };
        let node = shell.vfs.node(id);
        if !node.meta.readable_by(shell.uid, shell.gid) {
            out.push_str(&format!("wc: {path}: Permission denied\n"));
            status = 1;
            continue;
        }
        let NodeKind::File { contents } = &node.kind else {
            out.push_str(&format!("wc: {path}: Is a directory\n"));
            status = 1;
            continue;
        };
        let text = String::from_utf8_lossy(contents);
        let lines = text.bytes().filter(|&b| b == b'\n').count();
        let words = text.split_whitespace().count();
        let bytes = contents.len();
        tl += lines;
        tw += words;
        tc += bytes;
        counted += 1;
        out.push_str(&format_wc(lines, words, bytes, show_l, show_w, show_c));
        out.push_str(&format!(" {path}\n"));
    }

    if counted > 1 {
        out.push_str(&format_wc(tl, tw, tc, show_l, show_w, show_c));
        out.push_str(" total\n");
    }

    if status == 0 {
        CommandResult::ok(out)
    } else {
        CommandResult::err(out, status)
    }
}

/// Format the selected `wc` counts as coreutils does: each count right-aligned
/// in a width-7 field, space-separated.
fn format_wc(
    lines: usize,
    words: usize,
    bytes: usize,
    show_l: bool,
    show_w: bool,
    show_c: bool,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if show_l {
        parts.push(format!("{lines:>7}"));
    }
    if show_w {
        parts.push(format!("{words:>7}"));
    }
    if show_c {
        parts.push(format!("{bytes:>7}"));
    }
    parts.join(" ")
}

/// Flags shared by `grep`'s file/directory search helpers.
#[derive(Default, Clone, Copy)]
struct GrepFlags {
    ignore_case: bool,
    invert: bool,
    line_numbers: bool,
    count_only: bool,
    show_filename: bool,
}

/// `grep [OPTION]... PATTERN [FILE]...`
///
/// A literal (non-regex) substring search — `-i` case-insensitive, `-v`
/// invert, `-n` line numbers, `-c` count only, `-r`/`-R` recurse into
/// directories.
///
/// ponytail: literal substring match only, not real BRE/ERE regex; upgrade if
/// attacker tooling depends on regex features.
pub fn grep(shell: &Shell, args: &[String]) -> CommandResult {
    let mut flags = GrepFlags::default();
    let mut recursive = false;
    let mut pattern: Option<&str> = None;
    let mut paths: Vec<&str> = Vec::new();

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for ch in arg[1..].chars() {
                match ch {
                    'i' => flags.ignore_case = true,
                    'v' => flags.invert = true,
                    'n' => flags.line_numbers = true,
                    'c' => flags.count_only = true,
                    'r' | 'R' => recursive = true,
                    other => {
                        return CommandResult::err(
                            format!(
                                "grep: invalid option -- '{other}'\nUsage: grep [OPTION]... PATTERNS [FILE]...\n"
                            ),
                            2,
                        );
                    }
                }
            }
        } else if pattern.is_none() {
            pattern = Some(arg);
        } else {
            paths.push(arg);
        }
    }

    let Some(pattern) = pattern else {
        return CommandResult::err("Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2);
    };
    if paths.is_empty() {
        // No file operand: real grep reads stdin, which is empty here.
        return CommandResult::err("", 1);
    }

    let needle = if flags.ignore_case {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };
    flags.show_filename = paths.len() > 1 || recursive;

    let mut out = String::new();
    let mut any_match = false;
    for path in &paths {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            out.push_str(&format!("grep: {path}: No such file or directory\n"));
            continue;
        };
        if shell.vfs.node(id).meta.is_dir() {
            if recursive {
                grep_dir(
                    &shell.vfs,
                    id,
                    path,
                    &needle,
                    flags,
                    shell.uid,
                    shell.gid,
                    &mut out,
                    &mut any_match,
                );
            } else {
                out.push_str(&format!("grep: {path}: Is a directory\n"));
            }
        } else if !shell.vfs.node(id).meta.readable_by(shell.uid, shell.gid) {
            out.push_str(&format!("grep: {path}: Permission denied\n"));
        } else {
            grep_file(
                &shell.vfs,
                id,
                path,
                &needle,
                flags,
                &mut out,
                &mut any_match,
            );
        }
    }

    if any_match {
        CommandResult::ok(out)
    } else {
        CommandResult::err(out, 1)
    }
}

/// Search a single file's contents for `needle`, appending matching lines.
fn grep_file(
    vfs: &Vfs,
    id: NodeId,
    path: &str,
    needle: &str,
    flags: GrepFlags,
    out: &mut String,
    any_match: &mut bool,
) {
    let NodeKind::File { contents } = &vfs.node(id).kind else {
        return;
    };
    let text = String::from_utf8_lossy(contents);
    let mut count = 0usize;
    for (i, line) in text.lines().enumerate() {
        let hay = if flags.ignore_case {
            line.to_lowercase()
        } else {
            line.to_string()
        };
        if hay.contains(needle) != flags.invert {
            count += 1;
            *any_match = true;
            if !flags.count_only {
                if flags.show_filename {
                    out.push_str(path);
                    out.push(':');
                }
                if flags.line_numbers {
                    out.push_str(&(i + 1).to_string());
                    out.push(':');
                }
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if flags.count_only {
        if flags.show_filename {
            out.push_str(path);
            out.push(':');
        }
        out.push_str(&count.to_string());
        out.push('\n');
    }
}

/// Recurse into a directory for `grep -r`, always showing filenames. Files
/// unreadable by `uid`/`gid` are silently skipped, matching real `grep -r`
/// behaviour (it reports a permission error per file but does not abort).
#[allow(clippy::too_many_arguments)]
fn grep_dir(
    vfs: &Vfs,
    dir: NodeId,
    path: &str,
    needle: &str,
    flags: GrepFlags,
    uid: u32,
    gid: u32,
    out: &mut String,
    any_match: &mut bool,
) {
    let Some(entries) = vfs.entries(dir) else {
        return;
    };
    let flags = GrepFlags {
        show_filename: true,
        ..flags
    };
    for (name, id) in entries {
        let child_path = format!("{}/{}", path.trim_end_matches('/'), name);
        if vfs.node(id).meta.is_dir() {
            grep_dir(
                vfs,
                id,
                &child_path,
                needle,
                flags,
                uid,
                gid,
                out,
                any_match,
            );
        } else if vfs.node(id).meta.readable_by(uid, gid) {
            grep_file(vfs, id, &child_path, needle, flags, out, any_match);
        } else {
            out.push_str(&format!("grep: {child_path}: Permission denied\n"));
        }
    }
}

/// `find [PATH] [-name PATTERN] [-type f|d]`
///
/// Recursively lists VFS paths under `PATH` (default `.`), optionally
/// filtered by a glob `-name` pattern (`*`/`?` wildcards) and/or `-type`.
///
/// ponytail: a small wildcard matcher, not the full GNU find expression
/// language (`-perm`, `-mtime`, boolean operators, ...); other predicates are
/// accepted and ignored rather than rejected outright.
pub fn find(shell: &Shell, args: &[String]) -> CommandResult {
    let mut start_path = ".";
    let mut name_pattern: Option<&str> = None;
    let mut type_filter: Option<char> = None;
    let mut first_operand = true;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-name" | "-iname" => name_pattern = iter.next().map(String::as_str),
            "-type" => type_filter = iter.next().and_then(|s| s.chars().next()),
            "-maxdepth" | "-mindepth" => {
                iter.next(); // accepted, ignored
            }
            other if first_operand && !other.starts_with('-') => {
                start_path = other;
                first_operand = false;
            }
            _ => {} // other predicates/flags (-print, -perm, ...): ignored
        }
    }

    let Some(root) = shell.vfs.resolve(shell.cwd, start_path) else {
        return CommandResult::err(
            format!("find: '{start_path}': No such file or directory\n"),
            1,
        );
    };

    let mut out = String::new();
    find_walk(
        &shell.vfs,
        root,
        start_path,
        name_pattern,
        type_filter,
        &mut out,
    );
    CommandResult::ok(out)
}

/// Depth-first walk collecting paths that match the `-name`/`-type` filters.
fn find_walk(
    vfs: &Vfs,
    id: NodeId,
    path: &str,
    name: Option<&str>,
    type_filter: Option<char>,
    out: &mut String,
) {
    let node = vfs.node(id);
    let is_dir = node.meta.is_dir();
    let base = if node.name.is_empty() {
        path
    } else {
        node.name.as_str()
    };
    let type_ok = match type_filter {
        Some('d') => is_dir,
        Some('f') => !is_dir,
        _ => true,
    };
    let name_ok = name.map(|p| glob_match(p, base)).unwrap_or(true);
    if type_ok && name_ok {
        out.push_str(path);
        out.push('\n');
    }

    if is_dir {
        if let Some(entries) = vfs.entries(id) {
            for (child_name, child_id) in entries {
                let child_path = format!("{}/{}", path.trim_end_matches('/'), child_name);
                find_walk(vfs, child_id, &child_path, name, type_filter, out);
            }
        }
    }
}

/// Minimal glob matcher supporting `*` and `?` wildcards (no character
/// classes) — enough for typical `find -name` usage.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn helper(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => helper(&p[1..], t) || (!t.is_empty() && helper(p, &t[1..])),
            (Some(b'?'), Some(_)) => helper(&p[1..], &t[1..]),
            (Some(pc), Some(tc)) if pc == tc => helper(&p[1..], &t[1..]),
            _ => false,
        }
    }
    helper(pattern.as_bytes(), text.as_bytes())
}

/// Apply a run of `tar` flag characters (from either a `-xyz` argument or
/// GNU tar's dashless historical form), returning the first unrecognised
/// character, if any.
fn apply_tar_flags(
    chars: &str,
    create: &mut bool,
    extract: &mut bool,
    list: &mut bool,
    verbose: &mut bool,
    expect_file: &mut bool,
) -> Option<char> {
    for ch in chars.chars() {
        match ch {
            'c' => *create = true,
            'x' => *extract = true,
            't' => *list = true,
            'v' => *verbose = true,
            'f' => *expect_file = true,
            'z' | 'j' | 'J' | 'p' | 'k' | 'm' => {} // compression/misc flags, no-op
            other => return Some(other),
        }
    }
    None
}

/// Non-empty, non-identifying placeholder bytes written by `tar -c`. Starts
/// with the real gzip magic (`1f 8b 08 00`) so the file "looks" like a gzip
/// stream at a glance, followed by random bytes — never a plaintext marker
/// string, since an attacker who creates and then `cat`s the archive would
/// otherwise read it directly (unlike the honest corrupt-archive errors
/// `tar`'s own extract/list paths already give).
const FAKE_ARCHIVE_BYTES: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x56, 0xc7, 0xb6, 0xee, 0x0d, 0xa0,
    0xf8, 0x4b, 0xaf, 0x0c, 0xab, 0xea, 0xd2, 0x59, 0x3d, 0x8f, 0xc1, 0x3d, 0x59, 0x5f, 0x67, 0x2c,
    0x22, 0x44,
];

/// `tar [OPTION]... [-f ARCHIVE] [FILE]...`
///
/// Only creation (`-c`) is emulated meaningfully: it writes a small non-empty
/// placeholder archive into the VFS. Extraction (`-x`) and listing (`-t`)
/// always report a corrupt/empty archive — which is honest, since every file
/// an attacker can get onto this honeypot (faked `wget`/`curl` downloads, the
/// VFS mirror of an SCP upload) is either a zero-byte placeholder or has no
/// real archive structure. A real host fails identically on a 0-byte or
/// garbage "archive".
///
/// ponytail: no real (de)compression; upgrade only if genuinely round-tripping
/// a created archive's contents is needed.
pub fn tar(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut create = false;
    let mut extract = false;
    let mut list = false;
    let mut verbose = false;
    let mut archive: Option<&str> = None;
    let mut members: Vec<&str> = Vec::new();
    let mut expect_file = false;
    let mut first = true;

    for arg in args {
        if expect_file {
            archive = Some(arg);
            expect_file = false;
            first = false;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--file=") {
            archive = Some(rest);
        } else if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            if let Some(bad) = apply_tar_flags(
                &arg[1..],
                &mut create,
                &mut extract,
                &mut list,
                &mut verbose,
                &mut expect_file,
            ) {
                return CommandResult::err(
                    format!(
                        "tar: invalid option -- '{bad}'\nTry 'tar --help' or 'tar --usage' for more information.\n"
                    ),
                    2,
                );
            }
        } else if first && !arg.is_empty() && arg.bytes().all(|b| b"cxtvzjJpkfm".contains(&b)) {
            // Old-style bundled flags without a leading dash (GNU tar's
            // historical BSD compatibility), e.g. `tar czf archive.tar.gz file`.
            apply_tar_flags(
                arg,
                &mut create,
                &mut extract,
                &mut list,
                &mut verbose,
                &mut expect_file,
            );
        } else {
            members.push(arg);
        }
        first = false;
    }

    let Some(archive_path) = archive.or_else(|| members.first().copied()) else {
        return CommandResult::err(
            "tar: refusing to read archive contents from terminal (missing -f option?)\ntar: Error is not recoverable: exiting now\n",
            2,
        );
    };
    if archive.is_none() && !members.is_empty() {
        members.remove(0);
    }

    if create {
        let Some((parent, name)) = resolve_parent(shell, archive_path) else {
            return CommandResult::err(
                format!("tar: {archive_path}: Cannot open: Not a directory\n"),
                2,
            );
        };
        let (uid, gid) = (shell.uid, shell.gid);
        shell
            .vfs
            .add_file(parent, &name, FAKE_ARCHIVE_BYTES, 0o644, uid, gid);
        let mut out = String::new();
        if verbose {
            for m in &members {
                out.push_str(m);
                out.push('\n');
            }
        }
        return CommandResult::ok(out);
    }

    if extract || list {
        let Some(id) = shell.vfs.resolve(shell.cwd, archive_path) else {
            return CommandResult::err(
                format!(
                    "tar: {archive_path}: Cannot open: No such file or directory\ntar: Error is not recoverable: exiting now\n"
                ),
                2,
            );
        };
        match &shell.vfs.node(id).kind {
            NodeKind::Directory { .. } => {
                return CommandResult::err(
                    format!(
                        "tar: {archive_path}: Cannot open: Is a directory\ntar: Error is not recoverable: exiting now\n"
                    ),
                    2,
                );
            }
            NodeKind::File { contents } if contents.is_empty() => {
                return CommandResult::err(
                    "gzip: stdin: unexpected end of file\ntar: Child returned status 1\ntar: Error is not recoverable: exiting now\n",
                    2,
                );
            }
            _ => {}
        }
        return CommandResult::err(
            "tar: This does not look like a tar archive\ntar: Exiting with failure status due to previous errors\n",
            2,
        );
    }

    CommandResult::err(
        "tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\nTry 'tar --help' or 'tar --usage' for more information.\n",
        2,
    )
}

// --- Mutating file operations ---------------------------------------------
//
// Every operand resolves through the VFS only; the helpers below never touch a
// real path. Destructive ops act on the per-session VFS copy, which is bounded
// by the arena node cap, so `rm -rf /` and friends cannot harm the host.

/// Strip trailing `/` from a path operand (keeping a lone `/`).
fn strip_trailing_slashes(p: &str) -> &str {
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        "/"
    } else {
        trimmed
    }
}

/// Resolve `path` to the `(parent_directory, final_name)` pair used when
/// creating, removing, or renaming an entry. Returns `None` if the parent
/// directory does not exist or is not a directory, or the final component is
/// empty/`.`/`..`.
fn resolve_parent(shell: &Shell, path: &str) -> Option<(NodeId, String)> {
    let path = strip_trailing_slashes(path);
    let (dir, name) = Vfs::split_path(path);
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    let parent = shell.vfs.resolve(shell.cwd, dir)?;
    if !shell.vfs.node(parent).meta.is_dir() {
        return None;
    }
    Some((parent, name.to_string()))
}

/// The basename of a path operand (final non-empty component).
fn basename(path: &str) -> &str {
    Vfs::split_path(strip_trailing_slashes(path)).1
}

/// Build a [`CommandResult`] from accumulated output and an exit status.
fn finish(out: String, status: i32) -> CommandResult {
    if status == 0 {
        CommandResult::ok(out)
    } else {
        CommandResult::err(out, status)
    }
}

/// `touch [OPTION]... FILE...`
pub fn touch(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut no_create = false;
    let mut operands: Vec<&str> = Vec::new();
    let mut skip_value = false;

    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        match arg.as_str() {
            "-c" | "--no-create" => no_create = true,
            // Options that take a following value we accept but ignore.
            "-r" | "--reference" | "-d" | "--date" | "-t" => skip_value = true,
            "-a" | "-m" | "--time" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                // Bundled short flags like -am; ignore unknown ones quietly.
            }
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        return CommandResult::err(
            "touch: missing file operand\nTry 'touch --help' for more information.\n",
            1,
        );
    }

    let (uid, gid) = (shell.uid, shell.gid);
    let mut out = String::new();
    let mut status = 0;
    for path in operands {
        match resolve_parent(shell, path) {
            // `vfs.touch` creates the file or refreshes mtime if it exists.
            Some((parent, name)) => {
                if no_create && shell.vfs.child(parent, &name).is_none() {
                    continue;
                }
                shell.vfs.touch(parent, &name, uid, gid);
            }
            None => {
                out.push_str(&format!(
                    "touch: cannot touch '{path}': No such file or directory\n"
                ));
                status = 1;
            }
        }
    }
    finish(out, status)
}

/// `mkdir [OPTION]... DIRECTORY...`
pub fn mkdir(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut parents = false;
    let mut operands: Vec<&str> = Vec::new();
    let mut skip_value = false;

    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        match arg.as_str() {
            "-p" | "--parents" => parents = true,
            "-v" | "--verbose" => {}
            "-m" | "--mode" => skip_value = true,
            other if other.starts_with("-m") && other.len() > 2 => {} // -m755
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                if other.contains('p') {
                    parents = true;
                }
            }
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        return CommandResult::err(
            "mkdir: missing operand\nTry 'mkdir --help' for more information.\n",
            1,
        );
    }

    let (uid, gid) = (shell.uid, shell.gid);
    let mut out = String::new();
    let mut status = 0;
    for path in operands {
        if parents {
            // Walk component by component, creating directories as needed.
            let mut current = if path.starts_with('/') {
                shell.vfs.root()
            } else {
                shell.cwd
            };
            for comp in strip_trailing_slashes(path).split('/') {
                match comp {
                    "" | "." => continue,
                    ".." => current = shell.vfs.node(current).parent.unwrap_or(current),
                    name => {
                        if let Some(child) = shell.vfs.child(current, name) {
                            if !shell.vfs.node(child).meta.is_dir() {
                                out.push_str(&format!(
                                    "mkdir: cannot create directory '{path}': Not a directory\n"
                                ));
                                status = 1;
                                break;
                            }
                            current = child;
                        } else {
                            current = shell.vfs.mkdir(current, name, 0o755, uid, gid);
                        }
                    }
                }
            }
            continue;
        }

        match resolve_parent(shell, path) {
            Some((parent, name)) => {
                if shell.vfs.child(parent, &name).is_some() {
                    out.push_str(&format!(
                        "mkdir: cannot create directory '{path}': File exists\n"
                    ));
                    status = 1;
                } else {
                    shell.vfs.mkdir(parent, &name, 0o755, uid, gid);
                }
            }
            None => {
                out.push_str(&format!(
                    "mkdir: cannot create directory '{path}': No such file or directory\n"
                ));
                status = 1;
            }
        }
    }
    finish(out, status)
}

/// `rmdir [OPTION]... DIRECTORY...`
pub fn rmdir(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut parents = false;
    let mut operands: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-p" | "--parents" => parents = true,
            "-v" | "--verbose" | "--ignore-fail-on-non-empty" => {}
            other if other.starts_with('-') && other.len() > 1 => {}
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        return CommandResult::err(
            "rmdir: missing operand\nTry 'rmdir --help' for more information.\n",
            1,
        );
    }

    let mut out = String::new();
    let mut status = 0;
    for path in operands {
        let mut p = strip_trailing_slashes(path).to_string();
        loop {
            let Some((parent, name)) = resolve_parent(shell, &p) else {
                out.push_str(&format!(
                    "rmdir: failed to remove '{p}': No such file or directory\n"
                ));
                status = 1;
                break;
            };
            let Some(target) = shell.vfs.child(parent, &name) else {
                out.push_str(&format!(
                    "rmdir: failed to remove '{p}': No such file or directory\n"
                ));
                status = 1;
                break;
            };
            if !shell.vfs.node(target).meta.is_dir() {
                out.push_str(&format!("rmdir: failed to remove '{p}': Not a directory\n"));
                status = 1;
                break;
            }
            let empty = shell
                .vfs
                .entries(target)
                .map(|e| e.is_empty())
                .unwrap_or(true);
            if !empty {
                out.push_str(&format!(
                    "rmdir: failed to remove '{p}': Directory not empty\n"
                ));
                status = 1;
                break;
            }
            shell.vfs.unlink(parent, &name);
            if !parents {
                break;
            }
            // `-p`: ascend and remove now-empty parents.
            let (dir, _) = Vfs::split_path(&p);
            if dir == "." || dir == "/" || dir.is_empty() {
                break;
            }
            p = dir.to_string();
        }
    }
    finish(out, status)
}

/// `rm [OPTION]... FILE...`
pub fn rm(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut recursive = false;
    let mut force = false;
    let mut dir_ok = false;
    let mut operands: Vec<&str> = Vec::new();

    for arg in args {
        match arg.as_str() {
            "-r" | "-R" | "--recursive" => recursive = true,
            "-f" | "--force" => force = true,
            "-d" | "--dir" => dir_ok = true,
            "-v" | "--verbose" | "-i" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                for ch in other[1..].chars() {
                    match ch {
                        'r' | 'R' => recursive = true,
                        'f' => force = true,
                        'd' => dir_ok = true,
                        _ => {}
                    }
                }
            }
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        if force {
            return CommandResult::empty();
        }
        return CommandResult::err(
            "rm: missing operand\nTry 'rm --help' for more information.\n",
            1,
        );
    }

    let mut out = String::new();
    let mut status = 0;
    for path in operands {
        let base = basename(path);
        if base == "." || base == ".." {
            out.push_str(&format!(
                "rm: refusing to remove '.' or '..' directory: skipping '{path}'\n"
            ));
            status = 1;
            continue;
        }

        let Some((parent, name)) = resolve_parent(shell, path) else {
            if !force {
                out.push_str(&format!(
                    "rm: cannot remove '{path}': No such file or directory\n"
                ));
                status = 1;
            }
            continue;
        };
        let Some(target) = shell.vfs.child(parent, &name) else {
            if !force {
                out.push_str(&format!(
                    "rm: cannot remove '{path}': No such file or directory\n"
                ));
                status = 1;
            }
            continue;
        };

        if shell.vfs.node(target).meta.is_dir() {
            let empty = shell
                .vfs
                .entries(target)
                .map(|e| e.is_empty())
                .unwrap_or(true);
            if !recursive {
                if !dir_ok {
                    out.push_str(&format!("rm: cannot remove '{path}': Is a directory\n"));
                    status = 1;
                    continue;
                }
                if !empty {
                    out.push_str(&format!(
                        "rm: cannot remove '{path}': Directory not empty\n"
                    ));
                    status = 1;
                    continue;
                }
            }
        }
        shell.vfs.unlink(parent, &name);
    }
    finish(out, status)
}

/// `cp [OPTION]... SOURCE... DEST`
pub fn cp(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut recursive = false;
    let mut operands: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-r" | "-R" | "--recursive" | "-a" | "--archive" => recursive = true,
            "-v" | "--verbose" | "-f" | "-p" | "-i" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                for ch in other[1..].chars() {
                    if ch == 'r' || ch == 'R' || ch == 'a' {
                        recursive = true;
                    }
                }
            }
            other => operands.push(other),
        }
    }

    if operands.len() < 2 {
        let missing = if operands.is_empty() {
            "missing file operand"
        } else {
            "missing destination file operand"
        };
        return CommandResult::err(
            format!("cp: {missing}\nTry 'cp --help' for more information.\n"),
            1,
        );
    }

    let dest = operands.pop().unwrap();
    let dest_dir = shell
        .vfs
        .resolve(shell.cwd, dest)
        .filter(|&id| shell.vfs.node(id).meta.is_dir());

    if operands.len() > 1 && dest_dir.is_none() {
        return CommandResult::err(format!("cp: target '{dest}' is not a directory\n"), 1);
    }

    let mut out = String::new();
    let mut status = 0;
    for src in operands {
        let Some(src_id) = shell.vfs.resolve(shell.cwd, src) else {
            out.push_str(&format!(
                "cp: cannot stat '{src}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        if shell.vfs.node(src_id).meta.is_dir() && !recursive {
            out.push_str(&format!(
                "cp: -r not specified; omitting directory '{src}'\n"
            ));
            status = 1;
            continue;
        }

        let (parent, name) = if let Some(dir) = dest_dir {
            (dir, basename(src).to_string())
        } else {
            match resolve_parent(shell, dest) {
                Some(pn) => pn,
                None => {
                    out.push_str(&format!(
                        "cp: cannot create regular file '{dest}': No such file or directory\n"
                    ));
                    status = 1;
                    continue;
                }
            }
        };
        shell.vfs.deep_copy(src_id, parent, &name);
    }
    finish(out, status)
}

/// `mv [OPTION]... SOURCE... DEST`
pub fn mv(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut operands: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-v" | "--verbose" | "-f" | "-i" | "-n" | "--no-clobber" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {}
            other => operands.push(other),
        }
    }

    if operands.len() < 2 {
        let missing = if operands.is_empty() {
            "missing file operand"
        } else {
            "missing destination file operand"
        };
        return CommandResult::err(
            format!("mv: {missing}\nTry 'mv --help' for more information.\n"),
            1,
        );
    }

    let dest = operands.pop().unwrap();
    let dest_dir = shell
        .vfs
        .resolve(shell.cwd, dest)
        .filter(|&id| shell.vfs.node(id).meta.is_dir());

    if operands.len() > 1 && dest_dir.is_none() {
        return CommandResult::err(format!("mv: target '{dest}' is not a directory\n"), 1);
    }

    let mut out = String::new();
    let mut status = 0;
    for src in operands {
        let Some((src_parent, src_name)) = resolve_parent(shell, src) else {
            out.push_str(&format!(
                "mv: cannot stat '{src}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        let Some(src_id) = shell.vfs.child(src_parent, &src_name) else {
            out.push_str(&format!(
                "mv: cannot stat '{src}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };

        let (parent, name) = if let Some(dir) = dest_dir {
            (dir, basename(src).to_string())
        } else {
            match resolve_parent(shell, dest) {
                Some(pn) => pn,
                None => {
                    out.push_str(&format!(
                        "mv: cannot move '{src}' to '{dest}': No such file or directory\n"
                    ));
                    status = 1;
                    continue;
                }
            }
        };
        shell.vfs.rename(src_id, parent, &name);
    }
    finish(out, status)
}

/// `chmod [OPTION]... MODE FILE...`
pub fn chmod(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut recursive = false;
    let mut rest: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-R" | "--recursive" => recursive = true,
            "-v" | "--verbose" | "-c" | "-f" => {}
            other => rest.push(other),
        }
    }

    if rest.len() < 2 {
        return CommandResult::err(
            "chmod: missing operand\nTry 'chmod --help' for more information.\n",
            1,
        );
    }

    let mode_spec = rest.remove(0);
    let mut out = String::new();
    let mut status = 0;
    for path in rest {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            out.push_str(&format!(
                "chmod: cannot access '{path}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        match compute_mode(mode_spec, shell.vfs.node(id).meta.mode & 0o7777) {
            Some(new_perms) => apply_chmod(shell, id, new_perms, mode_spec, recursive),
            None => {
                return CommandResult::err(format!("chmod: invalid mode: '{mode_spec}'\n"), 1);
            }
        }
    }
    finish(out, status)
}

/// Apply a chmod to `id`, recursing into directories when requested.
fn apply_chmod(shell: &mut Shell, id: NodeId, perms: u32, spec: &str, recursive: bool) {
    shell.vfs.chmod(id, perms);
    if recursive && shell.vfs.node(id).meta.is_dir() {
        for (_, child) in shell.vfs.entries(id).unwrap_or_default() {
            let child_perms =
                compute_mode(spec, shell.vfs.node(child).meta.mode & 0o7777).unwrap_or(perms);
            apply_chmod(shell, child, child_perms, spec, recursive);
        }
    }
}

/// Resolve a chmod mode spec (octal like `755`/`0644` or symbolic like
/// `u+x`,`go-w`,`a=r`) against the current permission bits. Returns `None` for
/// a malformed spec.
fn compute_mode(spec: &str, current: u32) -> Option<u32> {
    if !spec.is_empty() && spec.bytes().all(|b| b.is_ascii_digit()) {
        return u32::from_str_radix(spec, 8).ok().map(|m| m & 0o7777);
    }

    let mut mode = current;
    for clause in spec.split(',') {
        let pos = clause.find(['+', '-', '='])?;
        let (who, rest) = clause.split_at(pos);
        let op = rest.chars().next()?;
        let perms = &rest[1..];

        let mut who_mask = 0u32;
        if who.is_empty() || who.contains('a') {
            who_mask = 0o7777;
        } else {
            for c in who.chars() {
                match c {
                    'u' => who_mask |= 0o4700,
                    'g' => who_mask |= 0o2070,
                    'o' => who_mask |= 0o1007,
                    _ => return None,
                }
            }
        }

        let mut perm_bits = 0u32;
        for c in perms.chars() {
            match c {
                'r' => perm_bits |= 0o444,
                'w' => perm_bits |= 0o222,
                'x' | 'X' => perm_bits |= 0o111,
                's' => perm_bits |= 0o6000,
                't' => perm_bits |= 0o1000,
                _ => return None,
            }
        }
        let effective = perm_bits & who_mask;

        match op {
            '+' => mode |= effective,
            '-' => mode &= !effective,
            '=' => mode = (mode & !who_mask) | effective,
            _ => return None,
        }
    }
    Some(mode & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn format_time_matches_default_mtime() {
        // DEFAULT_MTIME = 1_714_694_400 = 2024-05-03 00:00:00 UTC.
        assert_eq!(format_time(1_714_694_400), "May  3 00:00");
        // A timestamp with non-zero time-of-day and a two-digit day.
        assert_eq!(
            format_time(1_734_652_800 + 13 * 3600 + 7 * 60),
            "Dec 20 13:07"
        );
    }

    #[test]
    fn pwd_and_cd_navigate() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "pwd"), "/root\n");
        assert_eq!(run(&mut shell, "cd /etc"), "");
        assert_eq!(run(&mut shell, "pwd"), "/etc\n");
        // `cd -` returns to the previous directory.
        assert_eq!(run(&mut shell, "cd -"), "/root\n");
        assert_eq!(run(&mut shell, "pwd"), "/root\n");
    }

    #[test]
    fn cd_rejects_missing_and_non_dir() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "cd /nope").contains("No such file or directory"));
        assert!(run(&mut shell, "cd /etc/hostname").contains("Not a directory"));
    }

    #[test]
    fn ls_lists_and_hides_dotfiles() {
        let mut shell = Shell::new("root", "debian");
        let plain = run(&mut shell, "ls /");
        assert!(plain.contains("etc"));
        assert!(plain.contains("root"));
        // Home dotfiles are hidden without -a.
        assert!(!run(&mut shell, "ls").contains(".bashrc"));
        assert!(run(&mut shell, "ls -a").contains(".bashrc"));
    }

    #[test]
    fn ls_missing_path_errors() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "ls /nope");
        assert!(out.contains("cannot access '/nope': No such file or directory"));
    }

    #[test]
    fn cat_reads_files_and_reports_errors() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "cat /etc/hostname").contains("debian"));
        assert!(run(&mut shell, "cat /nope").contains("No such file or directory"));
        assert!(run(&mut shell, "cat /etc").contains("Is a directory"));
    }

    #[test]
    fn cat_enforces_read_permissions() {
        // /etc/shadow is 0640, owned by root:42 — an unprivileged uid/gid
        // 1000 session must be denied, matching real Debian.
        let mut unprivileged = Shell::new("user", "debian");
        assert!(run(&mut unprivileged, "cat /etc/shadow").contains("Permission denied"));

        // Root always bypasses permission checks.
        let mut root = Shell::new("root", "debian");
        assert!(run(&mut root, "cat /etc/shadow").contains("root:!:"));
    }

    #[test]
    fn grep_enforces_read_permissions() {
        let mut unprivileged = Shell::new("user", "debian");
        assert!(run(&mut unprivileged, "grep root /etc/shadow").contains("Permission denied"));
        assert!(run(&mut unprivileged, "grep -r root /etc").contains("Permission denied"));

        let mut root = Shell::new("root", "debian");
        assert!(run(&mut root, "grep root /etc/shadow").contains("root:!:"));
    }

    #[test]
    fn head_and_tail_select_lines() {
        let mut shell = Shell::new("root", "debian");
        let cwd = shell.cwd;
        shell
            .vfs
            .add_file(cwd, "nums", "1\n2\n3\n4\n5\n", 0o644, 0, 0);
        // Default is 10 lines: the whole 5-line file.
        assert_eq!(run(&mut shell, "head nums"), "1\n2\n3\n4\n5\n");
        // -n limits; both `-n N` and `-N` forms work.
        assert_eq!(run(&mut shell, "head -n 2 nums"), "1\n2\n");
        assert_eq!(run(&mut shell, "head -2 nums"), "1\n2\n");
        assert_eq!(run(&mut shell, "tail -n 2 nums"), "4\n5\n");
        // -c counts bytes.
        assert_eq!(run(&mut shell, "head -c 3 nums"), "1\n2");
        assert_eq!(run(&mut shell, "tail -c 2 nums"), "5\n");
    }

    #[test]
    fn head_multi_file_prints_headers_and_errors() {
        let mut shell = Shell::new("root", "debian");
        let cwd = shell.cwd;
        shell.vfs.add_file(cwd, "a", "A\n", 0o644, 0, 0);
        shell.vfs.add_file(cwd, "b", "B\n", 0o644, 0, 0);
        let out = run(&mut shell, "head a b");
        assert!(out.contains("==> a <==\n"));
        assert!(out.contains("==> b <==\n"));
        assert!(run(&mut shell, "head /nope").contains("No such file or directory"));
        assert!(run(&mut shell, "head /etc").contains("Is a directory"));
    }

    #[test]
    fn wc_counts_lines_words_bytes() {
        let mut shell = Shell::new("root", "debian");
        let cwd = shell.cwd;
        shell
            .vfs
            .add_file(cwd, "f", "one two\nthree\n", 0o644, 0, 0);
        // Default: lines, words, bytes, then the filename.
        assert_eq!(run(&mut shell, "wc f"), "      2       3      14 f\n");
        // Single selectors.
        assert_eq!(run(&mut shell, "wc -l f"), "      2 f\n");
        assert_eq!(run(&mut shell, "wc -w f"), "      3 f\n");
        assert_eq!(run(&mut shell, "wc -c f"), "     14 f\n");
    }

    #[test]
    fn head_tail_wc_enforce_read_permissions() {
        let mut unprivileged = Shell::new("user", "debian");
        assert!(run(&mut unprivileged, "head /etc/shadow").contains("Permission denied"));
        assert!(run(&mut unprivileged, "tail /etc/shadow").contains("Permission denied"));
        assert!(run(&mut unprivileged, "wc /etc/shadow").contains("Permission denied"));
    }

    #[test]
    fn touch_mkdir_and_cat_roundtrip() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "mkdir /tmp/d"), "");
        assert_eq!(run(&mut shell, "touch /tmp/d/f"), "");
        // The new file shows up and reads back empty.
        assert!(run(&mut shell, "ls /tmp/d").contains("f"));
        assert_eq!(run(&mut shell, "cat /tmp/d/f"), "");
        // mkdir on an existing entry fails; -p is idempotent.
        assert!(run(&mut shell, "mkdir /tmp/d").contains("File exists"));
        assert_eq!(run(&mut shell, "mkdir -p /tmp/d/e/f"), "");
        assert!(run(&mut shell, "ls /tmp/d/e").contains("f"));
    }

    #[test]
    fn rm_and_rmdir_enforce_directory_rules() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir /tmp/x");
        run(&mut shell, "touch /tmp/x/f");
        // rm on a non-empty dir without -r fails.
        assert!(run(&mut shell, "rm /tmp/x").contains("Is a directory"));
        assert!(run(&mut shell, "rmdir /tmp/x").contains("Directory not empty"));
        // -r removes the whole tree.
        assert_eq!(run(&mut shell, "rm -rf /tmp/x"), "");
        assert!(run(&mut shell, "ls /tmp/x").contains("No such file or directory"));
        // rm -f on a missing path is silent.
        assert_eq!(run(&mut shell, "rm -f /tmp/gone"), "");
    }

    #[test]
    fn cp_and_mv_move_content() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir /tmp/src");
        run(&mut shell, "touch /tmp/a");
        assert_eq!(run(&mut shell, "cp /tmp/a /tmp/b"), "");
        assert!(run(&mut shell, "ls /tmp").contains("b"));
        // mv renames: source gone, dest present.
        assert_eq!(run(&mut shell, "mv /tmp/a /tmp/src/c"), "");
        assert!(run(&mut shell, "ls /tmp").contains("b"));
        assert!(run(&mut shell, "cat /tmp/a").contains("No such file or directory"));
        assert!(run(&mut shell, "ls /tmp/src").contains("c"));
        // cp without -r refuses a directory.
        assert!(run(&mut shell, "cp /tmp/src /tmp/d").contains("omitting directory"));
    }

    #[test]
    fn chmod_octal_and_symbolic() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "touch /tmp/f");
        assert_eq!(run(&mut shell, "chmod 600 /tmp/f"), "");
        assert!(run(&mut shell, "ls -l /tmp/f").contains("-rw-------"));
        assert_eq!(run(&mut shell, "chmod u+x /tmp/f"), "");
        assert!(run(&mut shell, "ls -l /tmp/f").contains("-rwx------"));
        assert!(run(&mut shell, "chmod 9z9 /tmp/f").contains("invalid mode"));
    }

    #[test]
    fn grep_finds_and_filters_lines() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "grep root /etc/passwd").contains("root:x:0:0"));
        // Case-insensitive.
        assert!(run(&mut shell, "grep -i ROOT /etc/passwd").contains("root:x:0:0"));
        // No match: empty output, non-zero exit captured via execute().
        let out = shell.execute("grep nope-at-all /etc/passwd");
        assert_eq!(out.text, "");
        // Missing file.
        assert!(run(&mut shell, "grep root /nope").contains("No such file or directory"));
    }

    #[test]
    fn find_walks_and_filters_by_name_and_type() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/d/sub");
        run(&mut shell, "touch /tmp/d/a.txt");
        run(&mut shell, "touch /tmp/d/sub/b.txt");
        let out = run(&mut shell, "find /tmp/d -name *.txt");
        assert!(out.contains("/tmp/d/a.txt"));
        assert!(out.contains("/tmp/d/sub/b.txt"));
        let dirs_only = run(&mut shell, "find /tmp/d -type d");
        assert!(dirs_only.contains("/tmp/d/sub"));
        assert!(!dirs_only.contains("a.txt"));
    }

    #[test]
    fn tar_create_writes_placeholder_and_extract_reports_corrupt() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "touch /tmp/a");
        assert_eq!(run(&mut shell, "tar czf /tmp/out.tar.gz /tmp/a"), "");
        assert!(run(&mut shell, "ls /tmp").contains("out.tar.gz"));
        // Extracting our own fake (non-gzip) archive reports a corrupt archive.
        assert!(
            run(&mut shell, "tar xzf /tmp/out.tar.gz").contains("does not look like a tar archive")
        );
        // Extracting a genuinely empty file reports the gzip EOF error real
        // tools give on a 0-byte "download".
        run(&mut shell, "touch /tmp/empty.tar.gz");
        assert!(run(&mut shell, "tar xzf /tmp/empty.tar.gz").contains("unexpected end of file"));
        // Missing archive.
        assert!(run(&mut shell, "tar xzf /tmp/nope.tar.gz").contains("No such file or directory"));
    }

    #[test]
    fn tar_archive_content_is_not_self_identifying() {
        // The created archive must look like inert binary data, never a
        // plaintext product-name marker an attacker could `cat` and read.
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "touch /tmp/a");
        run(&mut shell, "tar czf /tmp/out.tar.gz /tmp/a");
        let content = run(&mut shell, "cat /tmp/out.tar.gz");
        let lower = content.to_lowercase();
        for tell in ["mimic", "honeypot", "fake", "placeholder"] {
            assert!(
                !lower.contains(tell),
                "tar archive content must not contain the identifying word {tell:?}"
            );
        }
    }
}
