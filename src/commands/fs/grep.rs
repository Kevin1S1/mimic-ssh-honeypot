use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::{NodeId, Vfs};

#[derive(Default, Clone, Copy)]
struct GrepFlags {
    ignore_case: bool,
    invert: bool,
    line_numbers: bool,
    count_only: bool,
    show_filename: bool,

    quiet: bool,

    files_with_matches: bool,

    word_regexp: bool,

    only_matching: bool,
}

pub fn grep(shell: &Shell, args: &[String]) -> CommandResult {
    let mut flags = GrepFlags::default();
    let mut recursive = false;
    let mut suppress_errors = false;
    let mut force_filename = false;
    let mut no_filename = false;
    let mut pattern: Option<&str> = None;
    let mut paths: Vec<&str> = Vec::new();
    let mut expect_pattern = false;

    for arg in args {
        if expect_pattern {
            pattern = Some(arg);
            expect_pattern = false;
            continue;
        }
        if arg.starts_with("--") {
            match arg.as_str() {
                "--ignore-case" => flags.ignore_case = true,
                "--invert-match" => flags.invert = true,
                "--line-number" => flags.line_numbers = true,
                "--count" => flags.count_only = true,
                "--quiet" | "--silent" => flags.quiet = true,
                "--files-with-matches" => flags.files_with_matches = true,
                "--word-regexp" => flags.word_regexp = true,
                "--only-matching" => flags.only_matching = true,
                "--recursive" | "--dereference-recursive" => recursive = true,
                "--no-messages" => suppress_errors = true,
                "--with-filename" => force_filename = true,
                "--no-filename" => no_filename = true,

                _ => {}
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            for ch in arg[1..].chars() {
                match ch {
                    'i' | 'y' => flags.ignore_case = true,
                    'v' => flags.invert = true,
                    'n' => flags.line_numbers = true,
                    'c' => flags.count_only = true,
                    'r' | 'R' => recursive = true,
                    'q' => flags.quiet = true,
                    'l' => flags.files_with_matches = true,
                    'w' => flags.word_regexp = true,
                    'o' => flags.only_matching = true,
                    's' => suppress_errors = true,
                    'H' => force_filename = true,
                    'h' => no_filename = true,

                    'e' => expect_pattern = true,

                    'E' | 'F' | 'G' | 'P' | 'a' | 'I' | 'U' | 'z' => {}

                    _ => {}
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
        grep_text(
            input,
            "(standard input)",
            &needle,
            flags,
            &mut out,
            &mut any_match,
        );
        if flags.quiet {
            out.clear();
        }
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
    flags.show_filename = force_filename
        || (!no_filename && (paths.len() > 1 || recursive || flags.files_with_matches));

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

    if flags.quiet {
        out.clear();
        errs.clear();
    }
    if suppress_errors {
        errs.clear();
    }
    CommandResult::streams(out, errs, i32::from(!any_match))
}

fn grep_file(
    vfs: &Vfs,
    id: NodeId,
    path: &str,
    needle: &str,
    flags: GrepFlags,
    out: &mut String,
    any_match: &mut bool,
) {
    let Some(bytes) = vfs.node(id).file_bytes() else {
        return;
    };
    grep_text(
        &String::from_utf8_lossy(&bytes),
        path,
        needle,
        flags,
        out,
        any_match,
    );
}

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
        let hit = if flags.word_regexp {
            word_match(&hay, needle)
        } else {
            hay.contains(needle)
        };
        if hit != flags.invert {
            count += 1;
            *any_match = true;

            if flags.files_with_matches {
                out.push_str(path);
                out.push('\n');
                return;
            }
            if flags.quiet {
                return;
            }
            if !flags.count_only {
                if flags.show_filename {
                    out.push_str(path);
                    out.push(':');
                }
                if flags.line_numbers {
                    out.push_str(&(i + 1).to_string());
                    out.push(':');
                }

                if flags.only_matching && !flags.invert {
                    for (i, m) in hay.match_indices(needle) {
                        out.push_str(line.get(i..i + m.len()).unwrap_or(needle));
                        out.push('\n');
                    }
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
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
fn word_match(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    hay.match_indices(needle).any(|(i, m)| {
        let before = hay[..i].chars().next_back().is_none_or(|c| !is_word(c));
        let after = hay[i + m.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_word(c));
        before && after
    })
}

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

#[cfg(test)]
mod grep_flag_tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> crate::shell::Output {
        shell.execute(line)
    }

    #[test]
    fn grep_accepts_the_flags_scripts_actually_pass() {
        let mut shell = Shell::new("root", "debian");

        let hit = run(&mut shell, "grep -q root /etc/passwd");
        assert_eq!(hit.status, 0);
        assert_eq!(hit.text, "", "-q must print nothing");
        let miss = run(&mut shell, "grep -q nosuchstring /etc/passwd");
        assert_eq!(miss.status, 1);

        assert_eq!(run(&mut shell, "grep -E root /etc/passwd").status, 0);
        assert_eq!(run(&mut shell, "grep -F root /etc/passwd").status, 0);

        assert_eq!(
            run(&mut shell, "grep -l root /etc/passwd").stdout,
            "/etc/passwd\n"
        );
        assert_eq!(run(&mut shell, "echo aXbXc | grep -o X").stdout, "X\nX\n");

        assert_eq!(run(&mut shell, "echo aXbXc | grep -io x").stdout, "X\nX\n");

        let quiet_err = run(&mut shell, "grep -s root /nosuchfile");
        assert_eq!(quiet_err.status, 1);
        assert_eq!(quiet_err.stderr, "");
    }

    #[test]
    fn grep_w_matches_whole_words_only() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "echo rooted | grep -w root").status, 1);
        assert_eq!(run(&mut shell, "echo 'a root b' | grep -w root").status, 0);
    }

    #[test]
    fn grep_dash_e_takes_its_pattern_from_the_next_operand() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "grep -e root /etc/passwd");
        assert_eq!(out.status, 0);
        assert!(out.stdout.starts_with("root:x:0:0:"), "{:?}", out.stdout);
    }
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
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
    fn grep_finds_and_filters_lines() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "grep root /etc/passwd").contains("root:x:0:0"));

        assert!(run(&mut shell, "grep -i ROOT /etc/passwd").contains("root:x:0:0"));

        let out = shell.execute("grep nope-at-all /etc/passwd");
        assert_eq!(out.text, "");

        assert!(run(&mut shell, "grep root /nope").contains("No such file or directory"));
    }
}
