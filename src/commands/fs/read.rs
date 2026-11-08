use crate::commands::CommandResult;
use crate::shell::Shell;

pub fn cat(shell: &Shell, args: &[String]) -> CommandResult {
    if args.is_empty() {
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
        if let Some(bytes) = node.file_bytes() {
            out.push_str(&String::from_utf8_lossy(&bytes));
        } else if node.meta.is_dir() {
            errs.push_str(&format!("cat: {arg}: Is a directory\n"));
            status = 1;
        }
    }

    CommandResult::streams(out, errs, status)
}

fn parse_count(s: &str) -> Option<usize> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub fn head(shell: &Shell, args: &[String]) -> CommandResult {
    head_tail(shell, args, false)
}

pub fn tail(shell: &Shell, args: &[String]) -> CommandResult {
    head_tail(shell, args, true)
}

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
            count = a[1..].parse().unwrap_or(10);
            by_bytes = false;
        } else if a.starts_with('-') && a.len() > 1 {
            return CommandResult::err(format!("{cmd}: invalid option -- '{}'\n", &a[1..]), 1);
        } else {
            files.push(a);
        }
    }

    if files.is_empty() {
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
        let Some(bytes) = node.file_bytes() else {
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
        out.push_str(&select_slice(&bytes, count, by_bytes, from_end));
    }

    CommandResult::streams(out, errs, status)
}

fn invalid_count(cmd: &str, by_bytes: bool, val: &str) -> CommandResult {
    let unit = if by_bytes { "bytes" } else { "lines" };
    CommandResult::err(format!("{cmd}: invalid number of {unit}: '{val}'\n"), 1)
}

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

    if !(show_l || show_w || show_c) {
        show_l = true;
        show_w = true;
        show_c = true;
    }
    if files.is_empty() {
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
        let Some(bytes) = node.file_bytes() else {
            errs.push_str(&format!("wc: {path}: Is a directory\n"));
            status = 1;
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let lines = text.bytes().filter(|&b| b == b'\n').count();
        let words = text.split_whitespace().count();
        let byte_count = bytes.len();
        tl += lines;
        tw += words;
        tc += byte_count;
        counted += 1;
        out.push_str(&format_wc(lines, words, byte_count, show_l, show_w, show_c));
        out.push_str(&format!(" {path}\n"));
    }

    if counted > 1 {
        out.push_str(&format_wc(tl, tw, tc, show_l, show_w, show_c));
        out.push_str(" total\n");
    }

    CommandResult::streams(out, errs, status)
}

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

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
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
        let mut unprivileged = Shell::new("user", "debian");
        assert!(run(&mut unprivileged, "cat /etc/shadow").contains("Permission denied"));

        let mut root = Shell::new("root", "debian");
        assert!(run(&mut root, "cat /etc/shadow").contains("root:!:"));
    }

    #[test]
    fn head_and_tail_select_lines() {
        let mut shell = Shell::new("root", "debian");
        let cwd = shell.cwd;
        shell
            .vfs
            .add_file(cwd, "nums", "1\n2\n3\n4\n5\n", 0o644, 0, 0);

        assert_eq!(run(&mut shell, "head nums"), "1\n2\n3\n4\n5\n");

        assert_eq!(run(&mut shell, "head -n 2 nums"), "1\n2\n");
        assert_eq!(run(&mut shell, "head -2 nums"), "1\n2\n");
        assert_eq!(run(&mut shell, "tail -n 2 nums"), "4\n5\n");

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

        assert_eq!(run(&mut shell, "wc f"), "      2       3      14 f\n");

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
}
