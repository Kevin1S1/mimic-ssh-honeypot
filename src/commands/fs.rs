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
        match &shell.vfs.node(id).kind {
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
}
