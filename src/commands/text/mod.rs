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

use std::borrow::Cow;

use super::{CommandResult, MAX_COMMAND_OUTPUT_BYTES};
use crate::shell::Shell;

mod awk;
mod base64;
mod cut;
mod digest;
mod editor;
mod lines;
mod path;
mod pipe;
mod sed;
mod tr;

pub use awk::awk;
pub use base64::base64;
pub use cut::cut;
pub use digest::{md5sum, sha1sum, sha256sum, sha512sum};
pub use editor::{nano, vi, EditorKind, EditorScreen};
pub use lines::{nl, rev, sort, uniq};
pub use path::{basename, dirname};
pub use pipe::{seq, tee, xargs};
pub use sed::sed;
pub use tr::tr;

fn vfs_file<'a>(shell: &'a Shell, tool: &str, path: &str) -> Result<Cow<'a, [u8]>, String> {
    let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
        return Err(format!("{tool}: {path}: No such file or directory\n"));
    };
    shell
        .vfs
        .node(id)
        .file_bytes()
        .ok_or_else(|| format!("{tool}: {path}: Is a directory\n"))
}

fn stdin_text(shell: &Shell) -> String {
    shell.stdin.clone().unwrap_or_default()
}

/// Read the operands as files, or fall back to the pipeline's stdin when there
/// are none — the convention every filter here follows, and what real
/// coreutils does.
///
/// The text is capped at [`MAX_COMMAND_OUTPUT_BYTES`] before any filter sees
/// it. Every command in this module is a transform whose result is capped at
/// that same figure anyway, and several of them *inflate* their input
/// (`base64` by 4/3, `sed` by the length of a replacement) — so bounding the
/// input is what keeps the peak allocation bounded, not just the result.
fn read_input(shell: &Shell, tool: &str, files: &[&str]) -> Result<String, CommandResult> {
    if files.is_empty() || files == ["-"] {
        let mut text = stdin_text(shell);
        cap(&mut text);
        return Ok(text);
    }
    let mut text = String::new();
    let mut errs = String::new();
    for file in files {
        if *file == "-" {
            text.push_str(shell.stdin.as_deref().unwrap_or_default());
        } else {
            match vfs_file(shell, tool, file) {
                Ok(bytes) => text.push_str(&String::from_utf8_lossy(&bytes)),
                Err(message) => errs.push_str(&message),
            }
        }
        if text.len() >= MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    if !errs.is_empty() {
        return Err(CommandResult::err(errs, 1));
    }
    cap(&mut text);
    Ok(text)
}

fn with_input(
    shell: &Shell,
    tool: &str,
    files: &[&str],
    filter: impl FnOnce(&str) -> CommandResult,
) -> CommandResult {
    match read_input(shell, tool, files) {
        Ok(text) => filter(&text),
        Err(failure) => failure,
    }
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

fn has_flag_letter(flags: &[&str], letter: char) -> bool {
    flags.iter().any(|f| f.contains(letter))
}

fn failure_status(errs: &str) -> i32 {
    i32::from(!errs.is_empty())
}

fn missing_operand(tool: &str) -> CommandResult {
    CommandResult::err(
        format!("{tool}: missing operand\nTry '{tool} --help' for more information.\n"),
        1,
    )
}

fn newline_terminated<S: AsRef<str>>(lines: impl IntoIterator<Item = S>) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line.as_ref());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::shell::{Screen, Shell};

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
    fn md5sum_matches_a_known_vector() {
        let mut shell = Shell::new("root", "debian");
        // Well-known: md5 of "abc" is 900150983cd24fb0d6963f7d28e17f72.
        let out = run(&mut shell, "echo -n abc | md5sum");
        assert!(out.starts_with("900150983cd24fb0d6963f7d28e17f72"), "{out}");
        assert!(out.trim_end().ends_with("  -"), "{out}");
    }

    #[test]
    fn sha1sum_matches_a_known_vector() {
        let mut shell = Shell::new("root", "debian");
        // Well-known: sha1 of "abc" is a9993e364706816aba3e25717850c26c9cd0d89d.
        let out = run(&mut shell, "echo -n abc | sha1sum");
        assert!(
            out.starts_with("a9993e364706816aba3e25717850c26c9cd0d89d"),
            "{out}"
        );
        assert!(out.trim_end().ends_with("  -"), "{out}");
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

    #[test]
    fn vi_and_nano_take_the_screen_only_on_an_interactive_tty() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("echo hi > /tmp/f");

        for cmd in ["vi /tmp/f", "nano /tmp/f"] {
            let out = run(&mut shell, cmd);
            assert_eq!(out, "", "{cmd} should write nothing itself");
            assert!(
                shell.screen.take().is_some(),
                "{cmd} should hold the screen"
            );
        }

        // A pipe, a redirect, and a one-shot `exec` are not a terminal: real
        // vi/nano have no full-screen behaviour to fall back to there, so
        // they get nothing, exactly like any other listed-but-unimplemented
        // binary rather than an invented dump.
        assert_eq!(run(&mut shell, "vi /tmp/f | wc -l"), "0\n");
        assert!(shell.screen.is_none(), "a pipe should not hold the screen");
        run(&mut shell, "nano /tmp/f > /tmp/out");
        assert!(
            shell.screen.is_none(),
            "a redirect should not hold the screen"
        );
        assert_eq!(shell.execute("cat /tmp/out").stdout, "");

        shell.interactive = false;
        assert_eq!(run(&mut shell, "vi /tmp/f"), "");
        assert!(shell.screen.is_none(), "exec should not hold the screen");
        shell.interactive = true;

        // A substitution runs in a subshell with no terminal of its own.
        assert_eq!(shell.execute("echo [$(vi /tmp/f)]").text, "[]\n");
        assert!(
            shell.screen.is_none(),
            "a substitution should not hold the screen"
        );
    }

    #[test]
    fn vi_renders_a_read_only_view_of_the_target() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("printf 'one\\ntwo\\n' > /tmp/f");

        run(&mut shell, "vi /tmp/f");
        let Screen::Editor(editor) = shell.screen.take().expect("vi should hold the screen") else {
            panic!("vi should hold a Screen::Editor");
        };
        let rendered = editor.render();
        assert!(rendered.contains("one\ntwo\n"));
        assert!(rendered.contains("~\n"), "unused rows should show as ~");
        assert!(rendered.contains("\"/tmp/f\" 2L,"));

        // A path that does not exist yet is a new buffer, like real vi.
        run(&mut shell, "vi /tmp/nope");
        let Screen::Editor(editor) = shell.screen.take().unwrap() else {
            panic!("vi should hold a Screen::Editor");
        };
        assert!(editor.render().contains("\"/tmp/nope\" [New File]"));

        // A bare invocation is an unnamed, empty buffer with no status line.
        run(&mut shell, "vi");
        let Screen::Editor(editor) = shell.screen.take().unwrap() else {
            panic!("vi should hold a Screen::Editor");
        };
        assert!(!editor.render().contains('"'));
    }

    #[test]
    fn nano_renders_a_title_bar_and_shortcuts() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("echo hi > /tmp/f");
        run(&mut shell, "nano /tmp/f");
        let Screen::Editor(editor) = shell.screen.take().expect("nano should hold the screen")
        else {
            panic!("nano should hold a Screen::Editor");
        };
        let rendered = editor.render();
        assert!(rendered.contains("GNU nano"));
        assert!(rendered.contains("/tmp/f"));
        assert!(rendered.contains("^X Exit"));
        assert!(rendered.contains("hi\n"));
    }
}
