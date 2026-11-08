use super::with_input;
use crate::commands::{CommandResult, MAX_COMMAND_OUTPUT_BYTES};
use crate::shell::Shell;

struct SedInvocation<'a> {
    quiet: bool,
    scripts: Vec<&'a str>,
    files: Vec<&'a str>,
}

struct EditedLine {
    text: String,
    explicit_print: bool,
}

enum SedOutcome {
    Unchanged,
    Replaced(String),
    Deleted,
    Print,
    Error(String),
}

/// `sed [-n] [-e SCRIPT] [SCRIPT] [FILE]...`
///
/// ponytail: supports the substitution (`s/a/b/[g][i]`), delete (`d`) and
/// print (`p`) commands over literal patterns — no regular expressions,
/// address ranges, hold space, or `-i`. That covers the config-editing and
/// line-filtering one-liners droppers use; upgrade when captured scripts need
/// real regex.
pub fn sed(shell: &Shell, args: &[String]) -> CommandResult {
    let invocation = match parse_args(args) {
        Ok(invocation) => invocation,
        Err(failure) => return failure,
    };
    with_input(shell, "sed", &invocation.files, |text| {
        run(&invocation, text)
    })
}

fn parse_args(args: &[String]) -> Result<SedInvocation<'_>, CommandResult> {
    let mut invocation = SedInvocation {
        quiet: false,
        scripts: Vec::new(),
        files: Vec::new(),
    };
    let mut expect_script = false;

    for a in args {
        if expect_script {
            invocation.scripts.push(a);
            expect_script = false;
            continue;
        }
        match a.as_str() {
            "-n" | "--quiet" | "--silent" => invocation.quiet = true,
            "-e" | "--expression" => expect_script = true,
            // `-i` without a real filesystem write would be a lie; refuse the
            // way sed does when it cannot edit in place.
            "-i" | "--in-place" => {
                return Err(CommandResult::err(
                    "sed: no input files while in-place editing\n",
                    1,
                ))
            }
            "-r" | "-E" | "--regexp-extended" | "-s" | "-u" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                if other.contains('n') {
                    invocation.quiet = true;
                }
            }
            other if invocation.scripts.is_empty() => invocation.scripts.push(other),
            other => invocation.files.push(other),
        }
    }

    if invocation.scripts.is_empty() {
        return Err(CommandResult::err(
            "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...\n",
            1,
        ));
    }
    Ok(invocation)
}

fn run(invocation: &SedInvocation, text: &str) -> CommandResult {
    let mut out = String::new();
    for line in text.lines() {
        let edited = match edit_line(&invocation.scripts, line) {
            Ok(edited) => edited,
            Err(message) => return CommandResult::err(message, 1),
        };
        let Some(edited) = edited else {
            continue;
        };
        let copies = usize::from(!invocation.quiet) + usize::from(edited.explicit_print);
        for _ in 0..copies {
            out.push_str(&edited.text);
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

fn edit_line(scripts: &[&str], line: &str) -> Result<Option<EditedLine>, String> {
    let mut edited = EditedLine {
        text: line.to_string(),
        explicit_print: false,
    };
    for script in scripts {
        match apply_script(script, &edited.text) {
            SedOutcome::Unchanged => {}
            SedOutcome::Replaced(next) => edited.text = next,
            SedOutcome::Deleted => return Ok(None),
            SedOutcome::Print => edited.explicit_print = true,
            SedOutcome::Error(message) => return Err(message),
        }
    }
    Ok(Some(edited))
}

fn apply_script(script: &str, line: &str) -> SedOutcome {
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
    let global = body.get(2).is_some_and(|flags| flags.contains('g'));

    if pattern.is_empty() || !line.contains(pattern) {
        return SedOutcome::Unchanged;
    }
    let limit = if global {
        global_replacement_limit(pattern, replacement)
    } else {
        1
    };
    SedOutcome::Replaced(line.replacen(pattern, replacement, limit))
}

/// One line can be the whole input, so a global substitution that grows what
/// it matches has to be bounded here too and not only across lines:
/// `s/a/<4 KiB>/g` over a megabyte of `a` would otherwise build a gigabyte
/// before anything downstream could cap it.
fn global_replacement_limit(pattern: &str, replacement: &str) -> usize {
    let growth = replacement.len().saturating_sub(pattern.len());
    MAX_COMMAND_OUTPUT_BYTES
        .checked_div(growth)
        .map_or(usize::MAX, |n| n + 1)
}
