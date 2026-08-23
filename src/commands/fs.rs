//! Filesystem operations: `ls`, `cd`, `pwd`, `cat`, `touch`, `mkdir`, `rm`, `cp`, `mv`, `chmod`, `tar`, `grep`, `find`, `head`, `tail`, `wc`, `rmdir`.
//!
//! All operate exclusively on the in-memory [`Vfs`]; no real path is touched.

use super::CommandResult;
use crate::shell::Shell;
use crate::vfs::nodes::{Metadata, NodeKind, S_IFDIR, S_IFLNK, S_IFMT};
use crate::vfs::{NodeId, Vfs};

/// Flags parsed from a leading run of `-xyz` arguments.
#[derive(Default)]
struct LsFlags {
    all: bool,        // -a: include entries starting with '.'
    almost_all: bool, // -A: like -a but skip '.' and '..'
    directory: bool,  // -d: list directories themselves, not their contents
    long: bool,       // -l: long listing format
    human: bool,      // -h: human-readable sizes (with -l)
    one: bool,        // -1: one entry per line
}

/// `ls [OPTION]... [FILE]...`
pub fn ls(shell: &Shell, args: &[String]) -> CommandResult {
    let mut flags = LsFlags::default();
    let mut paths: Vec<&str> = Vec::new();

    // GNU ls drops the column layout when stdout is not a terminal, so
    // `ls | head -n 2` sees two names rather than one long line.
    if !shell.stdout_is_tty {
        flags.one = true;
    }

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for ch in arg[1..].chars() {
                match ch {
                    'a' => flags.all = true,
                    'A' => flags.almost_all = true,
                    'd' => flags.directory = true,
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
        } else if arg == "--directory" {
            flags.directory = true;
        } else {
            paths.push(arg);
        }
    }

    if paths.is_empty() {
        paths.push(".");
    }

    let multiple = paths.len() > 1;
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;

    for path in paths.iter() {
        let Some(target) = shell.vfs.resolve(shell.cwd, path) else {
            errs.push_str(&format!(
                "ls: cannot access '{path}': No such file or directory\n"
            ));
            status = 2;
            continue;
        };

        let node = shell.vfs.node(target);
        if flags.directory || !node.meta.is_dir() {
            // A file operand or -d directory: list the operand itself.
            out.push_str(&format_single(&shell.vfs, target, path, &flags));
            continue;
        }

        // Listing a directory's entries requires read permission on it, just
        // like real `ls` — otherwise a non-root user reading e.g. /root would
        // be an obvious honeypot tell.
        if !node.meta.readable_by(shell.uid, shell.gid) {
            errs.push_str(&format!(
                "ls: cannot open directory '{path}': Permission denied\n"
            ));
            status = 2;
            continue;
        }

        if multiple {
            // The blank line separates one listing from the next, so it
            // depends on what actually reached stdout — an operand that failed
            // wrote to stderr and does not earn one.
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("{path}:\n"));
        }
        out.push_str(&list_dir(&shell.vfs, target, &flags));
    }

    CommandResult::streams(out, errs, status)
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
        // GNU ls heads every long directory listing with the disk usage of the
        // entries it is about to print — including an empty one, as `total 0`.
        let total: u64 = names.iter().map(|(_, id)| allocated_kib(vfs, *id)).sum();
        out.push_str(&format!("total {total}\n"));
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

/// Disk space a node occupies in 1 KiB units, the unit `ls -l` sums into its
/// `total` line. Modelled on ext4 with 4 KiB blocks: a file rounds up to whole
/// blocks and an empty one occupies none, a directory is one block, and a short
/// symlink is stored inside its inode and so occupies none either.
///
/// ext4 is the right model for every path in the snapshot because `mount`
/// reports one real filesystem, `/dev/sda1 on / type ext4`, with no separate
/// `/tmp`; a tmpfs would give directories no blocks at all and the two would
/// disagree. The one-block directory also matches the 4096 `ls -l` prints as a
/// directory's size.
fn allocated_kib(vfs: &Vfs, id: NodeId) -> u64 {
    match &vfs.node(id).kind {
        NodeKind::File { contents } => (contents.len() as u64).div_ceil(4096) * 4,
        NodeKind::Directory { .. } => 4,
        NodeKind::Symlink { .. } => 0,
    }
}

/// Apparent size of a node, as `ls -l` reports it.
pub(crate) fn node_size(node: &crate::vfs::Node) -> u64 {
    match &node.kind {
        NodeKind::File { contents } => contents.len() as u64,
        NodeKind::Symlink { target } => target.len() as u64,
        NodeKind::Directory { .. } => 4096,
    }
}

/// Render a numeric mode as a `drwxr-xr-x`-style string.
pub(crate) fn mode_string(mode: u32) -> String {
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
pub(crate) fn format_time(ts: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    /// Half a mean year, the window coreutils calls "recent".
    const SIX_MONTHS: i64 = 15_778_800;

    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let mon = MONTHS[(month - 1) as usize];

    // Real `ls -l` shows the clock only for a recent mtime, and the year for
    // anything older than six months or dated in the future. Reachable here
    // because the snapshot's install date is fixed at startup while the clock
    // keeps moving: a process left running for months would otherwise report
    // `/etc` with a time of day where a real box reports a year.
    let now = crate::clock::now();
    if ts > now + 3_600 || ts < now - SIX_MONTHS {
        format!("{mon} {day:>2}  {year}")
    } else {
        format!("{mon} {day:>2} {hour:02}:{minute:02}")
    }
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
pub(crate) fn uid_name(uid: u32) -> String {
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
pub(crate) fn gid_name(gid: u32) -> String {
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
    // `cd -` goes back to the previous directory and prints where it landed;
    // every other form is silent. It resolves and is permission-checked like
    // any other destination, since the directory may have become unreachable
    // since the shell was last in it.
    let mut announce = false;
    let target_path = match args.first().map(String::as_str) {
        None | Some("~") => shell.vfs.path_of(shell.home),
        Some("-") => {
            announce = true;
            shell.vfs.path_of(shell.prev_cwd)
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

    let meta = &shell.vfs.node(target).meta;
    if !meta.is_dir() {
        return CommandResult::err(format!("-bash: cd: {target_path}: Not a directory\n"), 1);
    }
    // Entering a directory needs its execute (search) bit. Without this an
    // unprivileged session could `cd /root` and watch the prompt change while
    // `ls /root` in the same directory said `Permission denied`.
    if !meta.executable_by(shell.uid, shell.gid) {
        return CommandResult::err(format!("-bash: cd: {target_path}: Permission denied\n"), 1);
    }

    shell.prev_cwd = shell.cwd;
    shell.cwd = target;
    let pwd = shell.vfs.path_of(target);
    shell.env.set("PWD", &pwd);
    if announce {
        CommandResult::ok(format!("{pwd}\n"))
    } else {
        CommandResult::empty()
    }
}

/// `pwd`
pub fn pwd(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.cwd_path()))
}

/// `cat [FILE]...`
pub fn cat(shell: &Shell, args: &[String]) -> CommandResult {
    if args.is_empty() {
        // Real `cat` with no args reads stdin: piped input if there is any,
        // and over a non-interactive exec nothing at all.
        return CommandResult::ok(shell.stdin.clone().unwrap_or_default());
    }

    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;

    for arg in args {
        let Some(id) = shell.vfs.resolve(shell.cwd, arg) else {
            errs.push_str(&format!("cat: {arg}: No such file or directory\n"));
            status = 1;
            continue;
        };
        let node = shell.vfs.node(id);
        if !node.meta.readable_by(shell.uid, shell.gid) {
            errs.push_str(&format!("cat: {arg}: Permission denied\n"));
            status = 1;
            continue;
        }
        match &node.kind {
            NodeKind::Directory { .. } => {
                errs.push_str(&format!("cat: {arg}: Is a directory\n"));
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

    CommandResult::streams(out, errs, status)
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
        // Real head/tail read stdin: piped input if there is any, and nothing
        // over a non-interactive exec.
        let Some(input) = &shell.stdin else {
            return CommandResult::empty();
        };
        return CommandResult::ok(select_slice(input.as_bytes(), count, by_bytes, from_end));
    }

    let show_headers = files.len() > 1;
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    for (i, path) in files.iter().enumerate() {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            errs.push_str(&format!(
                "{cmd}: cannot open '{path}' for reading: No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        let node = shell.vfs.node(id);
        if !node.meta.readable_by(shell.uid, shell.gid) {
            errs.push_str(&format!(
                "{cmd}: cannot open '{path}' for reading: Permission denied\n"
            ));
            status = 1;
            continue;
        }
        let NodeKind::File { contents } = &node.kind else {
            errs.push_str(&format!("{cmd}: error reading '{path}': Is a directory\n"));
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

    CommandResult::streams(out, errs, status)
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
        // Counting stdin prints no filename, and a single count is unpadded —
        // `wc -l` on a pipe gives "15", not GNU's column-aligned form.
        let Some(input) = &shell.stdin else {
            return CommandResult::empty();
        };
        let (lines, words, bytes) = (
            input.bytes().filter(|&b| b == b'\n').count(),
            input.split_whitespace().count(),
            input.len(),
        );
        if [show_l, show_w, show_c].iter().filter(|on| **on).count() == 1 {
            let single = if show_l {
                lines
            } else if show_w {
                words
            } else {
                bytes
            };
            return CommandResult::ok(format!("{single}\n"));
        }
        let counts = format_wc(lines, words, bytes, show_l, show_w, show_c);
        return CommandResult::ok(format!("{counts}\n"));
    }

    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    let (mut tl, mut tw, mut tc) = (0usize, 0usize, 0usize);
    let mut counted = 0;

    for path in &files {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            errs.push_str(&format!("wc: {path}: No such file or directory\n"));
            status = 1;
            continue;
        };
        let node = shell.vfs.node(id);
        if !node.meta.readable_by(shell.uid, shell.gid) {
            errs.push_str(&format!("wc: {path}: Permission denied\n"));
            status = 1;
            continue;
        }
        let NodeKind::File { contents } = &node.kind else {
            errs.push_str(&format!("wc: {path}: Is a directory\n"));
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

    CommandResult::streams(out, errs, status)
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
        // No file operand: real grep reads stdin — piped input if there is any,
        // and nothing over a non-interactive exec.
        let Some(input) = &shell.stdin else {
            return CommandResult::err("", 1);
        };
        let needle = if flags.ignore_case {
            pattern.to_lowercase()
        } else {
            pattern.to_string()
        };
        let mut out = String::new();
        let mut any_match = false;
        grep_text(input, "", &needle, flags, &mut out, &mut any_match);
        return if any_match {
            CommandResult::ok(out)
        } else {
            CommandResult::err(out, 1)
        };
    }

    let needle = if flags.ignore_case {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };
    flags.show_filename = paths.len() > 1 || recursive;

    let mut out = String::new();
    let mut errs = String::new();
    let mut any_match = false;
    for path in &paths {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            errs.push_str(&format!("grep: {path}: No such file or directory\n"));
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
                    &mut errs,
                    &mut any_match,
                );
            } else {
                errs.push_str(&format!("grep: {path}: Is a directory\n"));
            }
        } else if !shell.vfs.node(id).meta.readable_by(shell.uid, shell.gid) {
            errs.push_str(&format!("grep: {path}: Permission denied\n"));
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

    CommandResult::streams(out, errs, i32::from(!any_match))
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
    grep_text(
        &String::from_utf8_lossy(contents),
        path,
        needle,
        flags,
        out,
        any_match,
    );
}

/// Search `text` for `needle`, appending matching lines. Shared by the file,
/// recursive, and stdin (pipeline) paths.
fn grep_text(
    text: &str,
    path: &str,
    needle: &str,
    flags: GrepFlags,
    out: &mut String,
    any_match: &mut bool,
) {
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
    errs: &mut String,
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
                errs,
                any_match,
            );
        } else if vfs.node(id).meta.readable_by(uid, gid) {
            grep_file(vfs, id, &child_path, needle, flags, out, any_match);
        } else {
            errs.push_str(&format!("grep: {child_path}: Permission denied\n"));
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
///
/// Iterative single-backtrack algorithm rather than the natural recursive one.
/// The recursive form branches on every `*` and is exponential on patterns like
/// `*a*a*a*a*b`; since both the pattern and the filename come from the attacker
/// (bounded only by the 4096-byte command line) and `find` runs synchronously
/// inside the async handler, that would peg a worker thread with no timeout able
/// to fire on it. Remembering just the most recent `*` keeps this linear in
/// practice while matching the same language.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    // Position of the last `*` seen, and how much of `text` it had consumed.
    let mut star: Option<usize> = None;
    let mut resume = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            resume = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Mismatch: let the last `*` swallow one more byte and retry.
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }

    // Trailing `*`s may match the empty remainder.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
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

/// One ustar record. Everything in an archive — headers, file contents, the
/// end-of-archive marker — is a whole number of these.
const TAR_BLOCK: usize = 512;

/// GNU tar's default blocking factor: it pads the finished archive to a
/// multiple of 20 records, which is why a real `.tar`'s size is always a
/// multiple of 10240.
const TAR_BLOCKING: usize = 20 * TAR_BLOCK;

/// Copy `bytes` into a header field, truncating to the field width. Fields are
/// NUL-padded, and the header starts zeroed, so short values need no padding.
fn tar_put(header: &mut [u8; TAR_BLOCK], at: usize, width: usize, bytes: &[u8]) {
    let n = bytes.len().min(width);
    header[at..at + n].copy_from_slice(&bytes[..n]);
}

/// Write a ustar numeric field: zero-padded octal with a trailing NUL.
fn tar_put_octal(header: &mut [u8; TAR_BLOCK], at: usize, width: usize, value: u64) {
    let digits = format!("{value:0>width$o}", width = width - 1);
    tar_put(header, at, width - 1, digits.as_bytes());
}

/// Read a ustar numeric field (octal, NUL- or space-terminated).
fn tar_read_octal(field: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(field);
    u64::from_str_radix(text.trim_matches(['\0', ' ']), 8).unwrap_or(0)
}

/// Read a NUL-terminated ustar text field.
fn tar_read_str(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Split a member name across the ustar `prefix`/`name` fields, which hold 155
/// and 100 bytes. Names that fit go in `name` alone; longer ones split at a
/// `/`. A name too long to split either way is left for [`tar_put`] to
/// truncate rather than rejected, since nothing here can act on the error.
fn tar_split_name(name: &str) -> (&str, &str) {
    if name.len() <= 100 {
        return ("", name);
    }
    for (i, _) in name.match_indices('/') {
        let (prefix, rest) = (&name[..i], &name[i + 1..]);
        if prefix.len() <= 155 && rest.len() <= 100 {
            return (prefix, rest);
        }
    }
    ("", name)
}

/// Append one ustar header record describing `name`.
fn tar_write_header(
    name: &str,
    link: &str,
    meta: &Metadata,
    typeflag: u8,
    size: usize,
    out: &mut Vec<u8>,
) {
    let mut h = [0u8; TAR_BLOCK];
    let (prefix, stem) = tar_split_name(name);
    tar_put(&mut h, 0, 100, stem.as_bytes());
    tar_put_octal(&mut h, 100, 8, (meta.mode & 0o7777) as u64);
    tar_put_octal(&mut h, 108, 8, meta.uid as u64);
    tar_put_octal(&mut h, 116, 8, meta.gid as u64);
    tar_put_octal(&mut h, 124, 12, size as u64);
    tar_put_octal(&mut h, 136, 12, meta.mtime.max(0) as u64);
    // The checksum is computed with its own field read as spaces.
    h[148..156].fill(b' ');
    h[156] = typeflag;
    tar_put(&mut h, 157, 100, link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    tar_put(&mut h, 265, 32, uid_name(meta.uid).as_bytes());
    tar_put(&mut h, 297, 32, gid_name(meta.gid).as_bytes());
    tar_put(&mut h, 345, 155, prefix.as_bytes());
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    out.extend_from_slice(&h);
}

/// The archive `tar -c` is building, plus what it has to say about it.
struct TarBuild {
    bytes: Vec<u8>,
    /// Under `-v`, the member names as they are added. GNU tar puts these on
    /// stdout whenever the archive itself is not going there, which it never
    /// is here — only the `tar: …` diagnostics below go to stderr.
    log: String,
    /// Warnings and errors about members that could not be archived.
    errs: String,
    status: i32,
    verbose: bool,
    /// The archive's own node, when it already exists: a tree containing it
    /// must skip it rather than read its own growing output.
    archive: Option<NodeId>,
}

/// Depth-first walk appending `id` and everything under it to the archive,
/// storing each member as `name`.
///
/// Permission checks mirror real `tar`: a directory it cannot read and a file
/// it cannot open are both reported and skipped, so an unprivileged session
/// cannot archive `/root` to read it back.
fn tar_walk(shell: &Shell, id: NodeId, name: &str, build: &mut TarBuild) {
    if build.archive == Some(id) {
        build
            .errs
            .push_str(&format!("tar: {name}: file is the archive; not dumped\n"));
        return;
    }
    let node = shell.vfs.node(id);
    match &node.kind {
        NodeKind::Symlink { target } => {
            tar_write_header(name, target, &node.meta, b'2', 0, &mut build.bytes);
            if build.verbose {
                build.log.push_str(&format!("{name}\n"));
            }
        }
        NodeKind::File { contents } => {
            if !node.meta.readable_by(shell.uid, shell.gid) {
                build
                    .errs
                    .push_str(&format!("tar: {name}: Cannot open: Permission denied\n"));
                build.status = 2;
                return;
            }
            tar_write_header(name, "", &node.meta, b'0', contents.len(), &mut build.bytes);
            build.bytes.extend_from_slice(contents);
            let pad = contents.len().next_multiple_of(TAR_BLOCK) - contents.len();
            build.bytes.resize(build.bytes.len() + pad, 0);
            if build.verbose {
                build.log.push_str(&format!("{name}\n"));
            }
        }
        NodeKind::Directory { .. } => {
            let dir_name = format!("{}/", name.trim_end_matches('/'));
            tar_write_header(&dir_name, "", &node.meta, b'5', 0, &mut build.bytes);
            if build.verbose {
                build.log.push_str(&format!("{dir_name}\n"));
            }
            if !node.meta.readable_by(shell.uid, shell.gid) {
                build
                    .errs
                    .push_str(&format!("tar: {name}: Cannot open: Permission denied\n"));
                build.status = 2;
                return;
            }
            for (child, child_id) in shell.vfs.entries(id).unwrap_or_default() {
                tar_walk(shell, child_id, &format!("{dir_name}{child}"), build);
            }
        }
    }
}

/// One member read out of an archive.
struct TarEntry {
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    size: usize,
    mtime: i64,
    typeflag: u8,
    link: String,
    /// Offset of the member's contents within the archive bytes.
    offset: usize,
}

/// Parse `data` as a ustar stream, or return `None` if it is not one — which
/// is what a gzip-compressed or otherwise foreign upload looks like here.
fn tar_parse(data: &[u8]) -> Option<Vec<TarEntry>> {
    if data.len() < TAR_BLOCK || &data[257..262] != b"ustar" {
        return None;
    }
    let mut entries = Vec::new();
    let mut at = 0;
    while at + TAR_BLOCK <= data.len() {
        let h = &data[at..at + TAR_BLOCK];
        // Two zero records end the stream; the blocking-factor padding after
        // them is zeros too, so the first one is enough to stop on.
        if h.iter().all(|b| *b == 0) || &h[257..262] != b"ustar" {
            break;
        }
        let prefix = tar_read_str(&h[345..500]);
        let stem = tar_read_str(&h[0..100]);
        let size = tar_read_octal(&h[124..136]) as usize;
        entries.push(TarEntry {
            name: if prefix.is_empty() {
                stem
            } else {
                format!("{prefix}/{stem}")
            },
            mode: tar_read_octal(&h[100..108]) as u32 & 0o7777,
            uid: tar_read_octal(&h[108..116]) as u32,
            gid: tar_read_octal(&h[116..124]) as u32,
            size,
            mtime: tar_read_octal(&h[136..148]) as i64,
            typeflag: h[156],
            link: tar_read_str(&h[157..257]),
            offset: at + TAR_BLOCK,
        });
        at = at.saturating_add(TAR_BLOCK + size.next_multiple_of(TAR_BLOCK));
    }
    Some(entries)
}

/// Whether a listed/extracted member is selected by the operands given after
/// the archive (`tar xf a.tar dir/one`). No operands selects everything.
fn tar_selected(name: &str, members: &[&str]) -> bool {
    if members.is_empty() {
        return true;
    }
    let name = name.trim_end_matches('/');
    members.iter().any(|m| {
        let m = strip_trailing_slashes(m).trim_start_matches('/');
        name == m || name.starts_with(&format!("{m}/"))
    })
}

/// Minimum width GNU tar gives the joined `owner/group` and size columns of a
/// `-tv` listing. It widens to fit a long name or size — and, because tar
/// keeps the widened value for the rest of the run, only from that member on.
const TAR_UGSWIDTH: usize = 18;

/// One `tar -tv` line: `ls -l`-shaped, but with `owner/group` joined and a
/// full `YYYY-MM-DD HH:MM` date. `ugswidth` carries GNU tar's column width
/// across the listing.
fn tar_long_entry(entry: &TarEntry, ugswidth: &mut usize) -> String {
    let type_bits = match entry.typeflag {
        b'5' => S_IFDIR,
        b'2' => S_IFLNK,
        _ => 0,
    };
    let mode = mode_string(type_bits | entry.mode);
    let owner = format!("{}/{}", uid_name(entry.uid), gid_name(entry.gid));
    let size = entry.size.to_string();
    *ugswidth = (*ugswidth).max(owner.len() + size.len());
    let width = *ugswidth - owner.len();
    let link = if entry.typeflag == b'2' {
        format!(" -> {}", entry.link)
    } else {
        String::new()
    };
    let date = tar_date(entry.mtime);
    format!(
        "{mode} {owner} {size:>width$} {date} {}{link}\n",
        entry.name
    )
}

/// Format a member's mtime the way `tar -tv` does (`2024-05-03 00:00`, UTC).
fn tar_date(ts: i64) -> String {
    let (year, month, day) = civil_from_days(ts.div_euclid(86_400));
    let secs = ts.rem_euclid(86_400);
    let (hour, minute) = (secs / 3_600, (secs % 3_600) / 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
}

/// Whether any component of a member name is `..`. Real tar refuses to
/// extract such a member outright rather than letting an uploaded archive
/// pick where in the tree it lands.
fn tar_has_dot_dot(name: &str) -> bool {
    name.split('/').any(|c| c == "..")
}

/// Strip the leading run GNU tar drops from a member name — every component up
/// to and including the last `..`, plus the slashes after it — warning the
/// first time each distinct prefix is dropped, exactly as tar does. `warned`
/// carries the last prefix warned about across the members of one run, and the
/// warning itself goes to `errs` — it is a `tar:` diagnostic, not part of the
/// listing.
fn tar_strip_leading<'a>(name: &'a str, warned: &mut String, errs: &mut String) -> &'a str {
    let b = name.as_bytes();
    let mut prefix = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"..") && (i + 2 == b.len() || b[i + 2] == b'/') {
            prefix = i + 2;
        }
        while i < b.len() && b[i] != b'/' {
            i += 1;
        }
        while i < b.len() && b[i] == b'/' {
            i += 1;
        }
    }
    while prefix < b.len() && b[prefix] == b'/' {
        prefix += 1;
    }
    if prefix > 0 && warned.as_str() != &name[..prefix] {
        warned.clear();
        warned.push_str(&name[..prefix]);
        errs.push_str(&format!(
            "tar: Removing leading `{warned}' from member names\n"
        ));
    }
    &name[prefix..]
}

/// Create the directory chain leading to an extracted member, returning the
/// parent directory and final name. Returns `None` if a component collides
/// with a non-directory or the arena node cap refuses the `mkdir`.
fn tar_dest(shell: &mut Shell, name: &str) -> Option<(NodeId, String)> {
    // `..` never reaches here — the caller refuses those members — and `.` is
    // a no-op component, as it is in any path.
    if tar_has_dot_dot(name) {
        return None;
    }
    let mut parts: Vec<&str> = name
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let last = parts.pop()?;
    let (uid, gid) = (shell.uid, shell.gid);
    let mut dir = shell.cwd;
    for comp in parts {
        let next = match shell.vfs.child(dir, comp) {
            Some(existing) if shell.vfs.node(existing).meta.is_dir() => existing,
            Some(_) => return None,
            None => shell.vfs.mkdir(dir, comp, 0o755, uid, gid),
        };
        if next == dir {
            return None; // node cap: `mkdir` dropped the insert
        }
        dir = next;
    }
    Some((dir, last.to_string()))
}

/// `tar [OPTION]... [-f ARCHIVE] [FILE]...`
///
/// Creation (`-c`), listing (`-t`) and extraction (`-x`) all speak real POSIX
/// ustar, so an archive created here round-trips through the emulator's own
/// reader the way a scripted `tar czf … && tar xzf …` on a real box does.
/// Anything that is not a ustar stream — a zero-byte `wget` placeholder, a
/// genuinely gzip-compressed upload — still gets the honest errors real tools
/// give.
///
/// ponytail: `-z`/`-j`/`-J` are accepted but nothing is ever compressed. That
/// is unobservable from inside the box (no `file`, `gzip` or `gunzip` command,
/// and the SSH layer refuses `scp -f` downloads); upgrade when any of those
/// would let an attacker see the missing gzip container.
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
        if members.is_empty() {
            return CommandResult::err(
                "tar: Cowardly refusing to create an empty archive\nTry 'tar --help' or 'tar --usage' for more information.\n",
                2,
            );
        }
        let Some((parent, name)) = resolve_parent(shell, archive_path) else {
            return CommandResult::err(
                format!("tar: {archive_path}: Cannot open: Not a directory\n"),
                2,
            );
        };
        if !shell
            .vfs
            .node(parent)
            .meta
            .writable_by(shell.uid, shell.gid)
        {
            return CommandResult::err(
                format!(
                    "tar: {archive_path}: Cannot open: Permission denied\ntar: Error is not recoverable: exiting now\n"
                ),
                2,
            );
        }
        let mut build = TarBuild {
            bytes: Vec::new(),
            log: String::new(),
            errs: String::new(),
            status: 0,
            verbose,
            archive: shell.vfs.child(parent, &name),
        };
        let mut warned = String::new();
        for member in &members {
            let Some(id) = shell.vfs.resolve(shell.cwd, member) else {
                build.errs.push_str(&format!(
                    "tar: {member}: Cannot stat: No such file or directory\n"
                ));
                build.status = 2;
                continue;
            };
            // An operand is stored relative, without the leading `/` or `../`
            // run tar refuses to put in an archive.
            let stored =
                tar_strip_leading(strip_trailing_slashes(member), &mut warned, &mut build.errs);
            let stored = if stored.is_empty() { "." } else { stored };
            tar_walk(shell, id, stored, &mut build);
        }
        // Two zero records end the stream, then GNU tar pads to its blocking
        // factor — which is what makes a real archive's size a round 10240.
        let TarBuild {
            mut bytes,
            log,
            mut errs,
            status,
            ..
        } = build;
        bytes.resize(bytes.len() + 2 * TAR_BLOCK, 0);
        bytes.resize(bytes.len().next_multiple_of(TAR_BLOCKING), 0);

        let (uid, gid) = (shell.uid, shell.gid);
        let written = bytes.len();
        let id = shell.vfs.add_file(parent, &name, bytes, 0o644, uid, gid);
        // The arena's byte cap drops an oversized write silently; a real box
        // fills up too, so report it the way a full disk does rather than
        // claiming an archive that is not there.
        let stored_ok = matches!(
            &shell.vfs.node(id).kind,
            NodeKind::File { contents } if contents.len() == written
        );
        if !stored_ok {
            // A full disk stops tar dead, before it can summarise anything else.
            errs.push_str(&format!(
                "tar: {archive_path}: Cannot write: No space left on device\ntar: Error is not recoverable: exiting now\n"
            ));
            return CommandResult::streams(log, errs, 2);
        }
        if status != 0 {
            errs.push_str("tar: Exiting with failure status due to previous errors\n");
        }
        return CommandResult::streams(log, errs, status);
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
        let node = shell.vfs.node(id);
        if node.meta.is_dir() {
            return CommandResult::err(
                format!(
                    "tar: {archive_path}: Cannot open: Is a directory\ntar: Error is not recoverable: exiting now\n"
                ),
                2,
            );
        }
        if !node.meta.readable_by(shell.uid, shell.gid) {
            return CommandResult::err(
                format!(
                    "tar: {archive_path}: Cannot open: Permission denied\ntar: Error is not recoverable: exiting now\n"
                ),
                2,
            );
        }
        let NodeKind::File { contents } = &node.kind else {
            return CommandResult::err(
                "tar: This does not look like a tar archive\ntar: Exiting with failure status due to previous errors\n",
                2,
            );
        };
        if contents.is_empty() {
            return CommandResult::err(
                "gzip: stdin: unexpected end of file\ntar: Child returned status 1\ntar: Error is not recoverable: exiting now\n",
                2,
            );
        }
        let Some(entries) = tar_parse(contents) else {
            return CommandResult::err(
                "tar: This does not look like a tar archive\ntar: Exiting with failure status due to previous errors\n",
                2,
            );
        };

        if list {
            let mut out = String::new();
            let mut errs = String::new();
            let mut ugswidth = TAR_UGSWIDTH;
            let mut warned = String::new();
            for entry in entries.iter().filter(|e| tar_selected(&e.name, &members)) {
                // A listing warns about the prefix it would strip on the way
                // out, but prints the name the archive actually stores.
                tar_strip_leading(&entry.name, &mut warned, &mut errs);
                if verbose {
                    out.push_str(&tar_long_entry(entry, &mut ugswidth));
                } else {
                    out.push_str(&format!("{}\n", entry.name));
                }
            }
            return CommandResult::streams(out, errs, 0);
        }

        // Extraction mutates the VFS, so take a copy of the archive bytes and
        // let go of the borrow on it.
        let data = contents.clone();
        let (uid, gid) = (shell.uid, shell.gid);
        let mut out = String::new();
        let mut errs = String::new();
        let mut status = 0;
        let mut warned = String::new();
        for entry in entries {
            if !tar_selected(&entry.name, &members) {
                continue;
            }
            let member = tar_strip_leading(&entry.name, &mut warned, &mut errs).to_string();
            // A `..` left anywhere in the name is refused outright: an archive
            // does not get to choose a path outside the one being extracted to.
            if tar_has_dot_dot(&entry.name) {
                errs.push_str(&format!("tar: {}: Member name contains '..'\n", entry.name));
                status = 2;
                continue;
            }
            if verbose {
                out.push_str(&format!("{member}\n"));
            }
            let Some((parent, name)) = tar_dest(shell, &member) else {
                errs.push_str(&format!(
                    "tar: {member}: Cannot open: No such file or directory\n"
                ));
                status = 2;
                continue;
            };
            if !shell.vfs.node(parent).meta.writable_by(uid, gid) {
                errs.push_str(&format!("tar: {member}: Cannot open: Permission denied\n"));
                status = 2;
                continue;
            }
            // Only root restores the archived ownership; for anyone else the
            // extracted copy belongs to them, as it does on a real box.
            let (owner, group) = if uid == 0 {
                (entry.uid, entry.gid)
            } else {
                (uid, gid)
            };
            match entry.typeflag {
                b'5' => {
                    shell.vfs.mkdir(parent, &name, entry.mode, owner, group);
                }
                b'2' => {
                    shell.vfs.add_symlink(parent, &name, &entry.link);
                }
                b'0' | 0 => {
                    let end = entry.offset.saturating_add(entry.size).min(data.len());
                    let body = &data[entry.offset.min(end)..end];
                    let id = shell
                        .vfs
                        .add_file(parent, &name, body, entry.mode, owner, group);
                    let stored_ok = matches!(
                        &shell.vfs.node(id).kind,
                        NodeKind::File { contents } if contents.len() == body.len()
                    );
                    if !stored_ok {
                        errs.push_str(&format!(
                            "tar: {member}: Cannot write: No space left on device\n"
                        ));
                        status = 2;
                    }
                }
                // Hard links, devices and FIFOs are not modelled; real tar
                // skips what it cannot create and carries on.
                _ => {}
            }
        }
        if status != 0 {
            errs.push_str("tar: Exiting with failure status due to previous errors\n");
        }
        return CommandResult::streams(out, errs, status);
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
pub(crate) fn resolve_parent(shell: &Shell, path: &str) -> Option<(NodeId, String)> {
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

/// Build a [`CommandResult`] from the diagnostics a mutating operation
/// accumulated and its exit status. These commands say nothing on success, so
/// everything they collected is stderr.
fn finish(errs: String, status: i32) -> CommandResult {
    CommandResult::err(errs, status)
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
                if shell.vfs.child(parent, &name).is_none() && shell.vfs.is_full() {
                    out.push_str(&format!(
                        "touch: cannot touch '{path}': No space left on device
"
                    ));
                    status = 1;
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
                } else if shell.vfs.is_full() {
                    // A real kernel reports the failure; silently exiting 0 on
                    // a directory that never appears is a honeypot tell.
                    out.push_str(&format!(
                        "mkdir: cannot create directory '{path}': No space left on device
"
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

    // The length check above refused anything shorter than two operands.
    let dest = operands.pop().expect("at least two operands");
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

    // The length check above refused anything shorter than two operands.
    let dest = operands.pop().expect("at least two operands");
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
        if !shell.vfs.rename(src_id, parent, &name) {
            // The destination sits inside the source's own subtree. Real `mv`
            // refuses this rather than corrupting the tree.
            out.push_str(&format!(
                "mv: cannot move '{src}' to a subdirectory of itself, '{dest}/{name}'\n"
            ));
            status = 1;
        }
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
    fn format_time_shows_the_clock_only_for_a_recent_mtime() {
        let now = crate::clock::now();
        // Recent: month, day, and the time of day.
        assert_eq!(
            format_time(now - 86_400),
            crate::clock::format(now - 86_400, "%b %e %H:%M")
        );
        // Older than six months, or dated in the future: the year instead,
        // which is what a real `ls -l` switches to.
        for ts in [now - 200 * 86_400, now + 7_200] {
            assert_eq!(
                format_time(ts),
                crate::clock::format(ts, "%b %e  %Y"),
                "expected the year form for {ts}"
            );
        }
        // The snapshot's install date is inside the recent window, so `ls -l`
        // on `/etc` shows a time of day like a freshly installed box.
        let install = crate::clock::install_time();
        assert_eq!(
            format_time(install),
            crate::clock::format(install, "%b %e %H:%M")
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
    fn cd_needs_the_directorys_search_bit() {
        let mut user = Shell::new("attacker", "debian");

        // `/root` is 0700: entering it has to fail the way `ls /root` already
        // does, and leave the session where it was.
        assert_eq!(
            run(&mut user, "cd /root"),
            "-bash: cd: /root: Permission denied\n"
        );
        assert_eq!(user.last_status, 1);
        assert_eq!(run(&mut user, "pwd"), "/home/attacker\n");

        // Their own directories are still theirs to enter.
        run(&mut user, "mkdir /tmp/mine && cd /tmp/mine");
        assert_eq!(run(&mut user, "pwd"), "/tmp/mine\n");

        // Root goes anywhere, as it does everywhere else in the VFS.
        let mut root = Shell::new("root", "debian");
        assert_eq!(run(&mut root, "cd /root"), "");
        assert_eq!(run(&mut root, "pwd"), "/root\n");

        // `cd -` is checked too: it is a destination like any other, and the
        // directory may have become unreachable since the shell left it.
        let mut user = Shell::new("attacker", "debian");
        run(&mut user, "mkdir /tmp/locked && cd /tmp/locked");
        assert_eq!(run(&mut user, "pwd"), "/tmp/locked\n");
        run(&mut user, "cd /tmp");
        run(&mut user, "chmod 600 /tmp/locked");
        assert_eq!(
            run(&mut user, "cd -"),
            "-bash: cd: /tmp/locked: Permission denied\n"
        );
        assert_eq!(run(&mut user, "pwd"), "/tmp\n");
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
    fn ls_long_totals_the_entries_it_prints() {
        let mut shell = Shell::new("root", "debian");
        // Every long directory listing is headed by a total, -a or not.
        assert!(run(&mut shell, "ls -l /").starts_with("total "));
        assert!(run(&mut shell, "ls -la /").starts_with("total "));
        // A single file operand is not a directory listing, so it has none.
        assert!(!run(&mut shell, "ls -l /etc/hostname").contains("total"));

        run(&mut shell, "mkdir /tmp/t && cd /tmp/t");
        assert_eq!(run(&mut shell, "ls -l"), "total 0\n");
        // An empty file occupies no blocks; a written one takes a 4 KiB block,
        // and `.`/`..` add a block each.
        run(&mut shell, "touch empty");
        assert!(run(&mut shell, "ls -l").starts_with("total 0\n"));
        run(&mut shell, "echo hello > small");
        assert!(run(&mut shell, "ls -l").starts_with("total 4\n"));
        assert!(run(&mut shell, "ls -la").starts_with("total 12\n"));
    }

    #[test]
    fn ls_missing_path_errors() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "ls /nope");
        assert!(out.contains("cannot access '/nope': No such file or directory"));
    }

    #[test]
    fn ls_directory_flag_lists_dirs_without_descending() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "ls -d /tmp"), "/tmp\n");
        assert_eq!(run(&mut shell, "ls --directory /tmp"), "/tmp\n");
        assert_eq!(run(&mut shell, "ls -d"), ".\n");

        // -ld lists the directory itself in long form without descending or printing total
        let ld_tmp = run(&mut shell, "ls -ld /tmp");
        assert!(ld_tmp.starts_with("drwxrwxrwx") || ld_tmp.starts_with("drwxrwxrwt"));
        assert!(ld_tmp.ends_with("/tmp\n"));
        assert!(!ld_tmp.contains("total"));

        // -ld on unreadable directory lists the directory itself without permission error
        let mut user = Shell::new("attacker", "debian");
        let ld_root = run(&mut user, "ls -ld /root");
        assert!(ld_root.starts_with("drwx------"));
        assert!(ld_root.ends_with("/root\n"));
        assert!(!ld_root.contains("Permission denied"));
    }

    #[test]
    fn ls_enforces_directory_read_permissions() {
        // /root is 0700, owned by root. An unprivileged user cannot list it.
        let mut user = Shell::new("attacker", "debian");
        let out = user.execute("ls -la /root");
        assert!(
            out.text
                .contains("ls: cannot open directory '/root': Permission denied"),
            "unprivileged ls of /root must be denied, got: {out:?}",
            out = out.text
        );
        assert!(!user.execute("ls -la /root").text.contains(".bashrc"));
        // Root can still list it.
        let mut root = Shell::new("root", "debian");
        assert!(root.execute("ls -la /root").text.contains(".bashrc"));
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
    fn glob_match_semantics_and_pathological_pattern() {
        use super::glob_match;

        assert!(glob_match("*.txt", "a.txt"));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("*", ""));
        assert!(glob_match("**b", "ab"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("*.txt", "a.txtx"));
        assert!(glob_match("a*b*c", "axxbyyc"));

        // The recursive matcher this replaced was exponential here: a pattern of
        // many `*a` groups against a run of `a`s that never satisfies the final
        // literal. If this ever regresses, the test hangs rather than fails.
        let pattern = "*a".repeat(24) + "b";
        let text = "a".repeat(2048);
        assert!(!glob_match(&pattern, &text));
    }

    #[test]
    fn mv_refuses_move_into_own_subdirectory() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/a/b");
        let out = run(&mut shell, "mv /tmp/a /tmp/a/b");
        assert!(
            out.contains("cannot move '/tmp/a' to a subdirectory of itself"),
            "unexpected output: {out}"
        );

        // The tree survived: /tmp/a is still where it was, and rendering paths
        // through it terminates (a cycle here would hang the whole process).
        assert!(run(&mut shell, "ls /tmp").contains('a'));
        run(&mut shell, "cd /tmp/a/b");
        assert_eq!(run(&mut shell, "pwd"), "/tmp/a/b\n");
    }

    #[test]
    fn tar_round_trips_a_created_archive() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/d/sub");
        let cwd = shell.vfs.resolve(shell.cwd, "/tmp/d").unwrap();
        shell.vfs.add_file(cwd, "one", "hello\n", 0o644, 0, 0);
        let sub = shell.vfs.resolve(shell.cwd, "/tmp/d/sub").unwrap();
        shell.vfs.add_file(sub, "two", "world\n", 0o600, 0, 0);

        assert_eq!(run(&mut shell, "cd /tmp && tar czf out.tgz d"), "");
        // A real archive is a whole number of 20-record blocks.
        let size = match &shell
            .vfs
            .node(shell.vfs.resolve(shell.cwd, "out.tgz").unwrap())
            .kind
        {
            NodeKind::File { contents } => contents.len(),
            other => panic!("archive is not a file: {other:?}"),
        };
        assert_eq!(size % TAR_BLOCKING, 0);

        // Listing shows every member, directories with a trailing slash.
        let listed = run(&mut shell, "tar tzf out.tgz");
        assert_eq!(listed, "d/\nd/one\nd/sub/\nd/sub/two\n");

        // Extracting elsewhere reproduces the tree, contents and modes intact.
        run(&mut shell, "mkdir /tmp/back && cd /tmp/back");
        assert_eq!(run(&mut shell, "tar xzf /tmp/out.tgz"), "");
        assert_eq!(run(&mut shell, "cat d/one"), "hello\n");
        assert_eq!(run(&mut shell, "cat d/sub/two"), "world\n");
        assert!(run(&mut shell, "ls -l d/sub").contains("-rw-------"));
    }

    #[test]
    fn tar_lists_verbosely_and_selects_members() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/d/sub");
        let cwd = shell.vfs.resolve(shell.cwd, "/tmp/d").unwrap();
        shell.vfs.add_file(cwd, "one", "hello\n", 0o644, 0, 0);
        run(&mut shell, "cd /tmp && tar cf out.tar d");

        // Byte-for-byte the shape GNU tar 1.35 prints: the joined owner/group
        // and the size share an 18-column field, then a UTC `YYYY-MM-DD HH:MM`.
        // The members were created during this session, so they carry the
        // current time — not the install date the snapshot carries.
        let now = crate::clock::format(crate::clock::now(), "%F %H:%M");
        let long = run(&mut shell, "tar tvf out.tar");
        assert!(
            long.contains(&format!("drwxr-xr-x root/root         0 {now} d/\n")),
            "unexpected listing: {long}"
        );
        assert!(
            long.contains(&format!("-rw-r--r-- root/root         6 {now} d/one\n")),
            "unexpected listing: {long}"
        );

        // An operand after the archive selects a subtree.
        assert_eq!(run(&mut shell, "tar tf out.tar d/sub"), "d/sub/\n");

        // Extracting a single member leaves the rest behind.
        run(&mut shell, "mkdir /tmp/back && cd /tmp/back");
        run(&mut shell, "tar xf /tmp/out.tar d/one");
        assert_eq!(run(&mut shell, "cat d/one"), "hello\n");
        assert!(!run(&mut shell, "ls d").contains("sub"));
    }

    #[test]
    fn tar_symlinks_survive_the_round_trip() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir /tmp/d");
        let d = shell.vfs.resolve(shell.cwd, "/tmp/d").unwrap();
        shell.vfs.add_file(d, "real", "x\n", 0o644, 0, 0);
        shell.vfs.add_symlink(d, "link", "real");

        run(&mut shell, "cd /tmp && tar cf out.tar d");
        assert!(run(&mut shell, "tar tvf out.tar").contains("link -> real"));

        run(&mut shell, "mkdir /tmp/back && cd /tmp/back");
        run(&mut shell, "tar xf /tmp/out.tar");
        assert_eq!(run(&mut shell, "cat d/link"), "x\n");
    }

    #[test]
    fn tar_reports_what_it_cannot_read_or_write() {
        // An unprivileged session cannot use `tar -c` to read a tree `ls` and
        // `cd` already refuse it.
        let mut user = Shell::new("attacker", "debian");
        let out = run(&mut user, "cd /tmp && tar cf mine.tar /root");
        assert!(
            out.contains("tar: root: Cannot open: Permission denied"),
            "{out}"
        );
        assert!(out.contains("Exiting with failure status"));
        assert_eq!(user.last_status, 2);
        // The archive still exists — real tar writes what it could read — but
        // nothing from /root is in it.
        assert_eq!(run(&mut user, "tar tf mine.tar"), "root/\n");

        // Reading an archive needs read permission on the archive itself —
        // checked before its contents, so an unreadable file cannot be probed
        // by the shape of the "not a tar archive" reply.
        assert!(run(&mut user, "tar tf /etc/shadow").contains("Cannot open: Permission denied"));

        // Missing operands and missing archives report the same way real tar does.
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "tar cf /tmp/a.tar /nope").contains("Cannot stat"));
        assert!(run(&mut shell, "tar cf /tmp/a.tar").contains("Cowardly refusing"));
        assert!(run(&mut shell, "tar xf /tmp/nope.tar").contains("No such file or directory"));
        assert!(run(&mut shell, "tar xf /etc").contains("Is a directory"));
    }

    #[test]
    fn tar_cannot_grow_the_vfs_past_its_byte_cap() {
        // `tar -c` copies member contents, so repeatedly archiving an archive
        // would double the arena's bytes each round if nothing stopped it. The
        // VFS cap does; the point of the test is that the refusal is reported
        // rather than leaving a truncated archive that lies about its contents.
        let mut shell = Shell::new("root", "debian");
        let cwd = shell.cwd;
        shell
            .vfs
            .add_file(cwd, "big", vec![b'x'; 5 * 1024 * 1024], 0o644, 0, 0);
        let out = run(&mut shell, "tar cf big.tar big");
        assert!(out.contains("No space left on device"), "{out}");
        assert_eq!(shell.last_status, 2);
        assert!(!run(&mut shell, "ls").contains("big.tar"));
    }

    #[test]
    fn tar_rejects_what_is_not_a_ustar_stream() {
        let mut shell = Shell::new("root", "debian");
        // A genuinely gzip-compressed upload: the magic is right for a `.tgz`,
        // but there is no ustar header to read, and inventing one would be the
        // lie. Real tar fails here too when the payload is not an archive.
        let cwd = shell.cwd;
        let gzip = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        shell.vfs.add_file(cwd, "up.tgz", &gzip[..], 0o644, 0, 0);
        assert!(run(&mut shell, "tar tzf up.tgz").contains("does not look like a tar archive"));

        // A zero-byte "download" gets the gzip EOF error real tools give.
        run(&mut shell, "touch empty.tar.gz");
        assert!(run(&mut shell, "tar xzf empty.tar.gz").contains("unexpected end of file"));
    }

    #[test]
    fn tar_refuses_a_traversal_member() {
        // An uploaded archive whose members climb out of the extraction
        // directory: real tar strips the leading run, refuses any name that
        // still holds a `..`, and extracts the rest.
        let mut shell = Shell::new("root", "debian");
        let meta = Metadata::new(crate::vfs::nodes::S_IFREG, 0o644, 0, 0);
        let mut bytes = Vec::new();
        for name in ["../evil", "a/../../etc/passwd", "/abs", "ok"] {
            tar_write_header(name, "", &meta, b'0', 4, &mut bytes);
            bytes.extend_from_slice(b"pwn\n");
            bytes.resize(bytes.len() + TAR_BLOCK - 4, 0);
        }
        bytes.resize(bytes.len() + 2 * TAR_BLOCK, 0);
        let cwd = shell.cwd;
        shell.vfs.add_file(cwd, "trav.tar", bytes, 0o644, 0, 0);

        // Listing is the asymmetric half: it warns about the prefix it would
        // strip, prints every stored name unchanged, and succeeds — the `..`
        // refusal belongs to extraction alone. The listing is stdout and every
        // `tar:` warning is stderr, so `tar tf … 2>/dev/null` is just names.
        let listed = shell.execute("tar tf trav.tar");
        assert_eq!(
            listed.stdout,
            "../evil\n\
             a/../../etc/passwd\n\
             /abs\n\
             ok\n"
        );
        assert_eq!(
            listed.stderr,
            "tar: Removing leading `../' from member names\n\
             tar: Removing leading `a/../../' from member names\n\
             tar: Removing leading `/' from member names\n"
        );
        assert_eq!(shell.last_status, 0);

        run(&mut shell, "mkdir /tmp/out && cd /tmp/out");
        let out = run(&mut shell, "tar xf /root/trav.tar");
        assert_eq!(
            out,
            "tar: Removing leading `../' from member names\n\
             tar: ../evil: Member name contains '..'\n\
             tar: Removing leading `a/../../' from member names\n\
             tar: a/../../etc/passwd: Member name contains '..'\n\
             tar: Removing leading `/' from member names\n\
             tar: Exiting with failure status due to previous errors\n"
        );
        assert_eq!(shell.last_status, 2);
        // The two traversal members landed nowhere; the others extracted here.
        assert_eq!(run(&mut shell, "ls"), "abs  ok\n");
        assert_eq!(
            run(&mut shell, "cat /etc/passwd | head -n 1"),
            "root:x:0:0:root:/root:/bin/bash\n"
        );
    }

    #[test]
    fn tar_does_not_archive_itself() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir /tmp/d");
        let d = shell.vfs.resolve(shell.cwd, "/tmp/d").unwrap();
        shell.vfs.add_file(d, "f", "data\n", 0o644, 0, 0);
        // The archive lives inside the tree being archived: real tar warns and
        // skips it instead of reading its own growing output.
        run(&mut shell, "cd /tmp/d && tar cf inner.tar .");
        let out = run(&mut shell, "tar cf inner.tar .");
        assert!(out.contains("file is the archive; not dumped"), "{out}");
        assert_eq!(run(&mut shell, "tar tf inner.tar"), "./\n./f\n");
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
