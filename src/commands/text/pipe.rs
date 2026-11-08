use super::{failure_status, has_flag_letter, missing_operand, split_args, stdin_text};
use crate::commands::{fs::resolve_parent, CommandResult, MAX_COMMAND_OUTPUT_BYTES};
use crate::shell::Shell;

const NEW_FILE_MODE: u32 = 0o644;
const NO_SUCH_FILE: &str = "No such file or directory";
const NO_SPACE: &str = "No space left on device";

pub fn tee(shell: &mut Shell, args: &[String]) -> CommandResult {
    let (flags, operands) = split_args(args);
    let append = has_flag_letter(&flags, 'a');
    let text = stdin_text(shell);

    let mut errs = String::new();
    for path in &operands {
        if let Err(reason) = write_copy(shell, path, text.as_bytes(), append) {
            errs.push_str(&format!("tee: {path}: {reason}\n"));
        }
    }
    let status = failure_status(&errs);
    CommandResult::streams(text, errs, status)
}

fn write_copy(
    shell: &mut Shell,
    path: &str,
    data: &[u8],
    append: bool,
) -> Result<(), &'static str> {
    let Some((parent, name)) = resolve_parent(shell, path) else {
        return Err(NO_SUCH_FILE);
    };
    match shell.vfs.child(parent, &name) {
        Some(id) if shell.vfs.write_file(id, data, append) => Ok(()),
        Some(_) => Err(NO_SPACE),
        None if shell.vfs.is_full(parent) => Err(NO_SPACE),
        None => {
            let (uid, gid) = (shell.uid, shell.gid);
            shell
                .vfs
                .add_file(parent, &name, data.to_vec(), NEW_FILE_MODE, uid, gid);
            Ok(())
        }
    }
}

pub fn seq(_shell: &Shell, args: &[String]) -> CommandResult {
    let (_, operands) = split_args(args);
    let nums: Vec<i64> = operands.iter().filter_map(|a| a.parse().ok()).collect();
    let (first, step, last) = match nums[..] {
        [last] => (1, 1, last),
        [first, last] => (first, 1, last),
        [first, step, last] => (first, step, last),
        _ => return missing_operand("seq"),
    };
    if step == 0 {
        return CommandResult::err("seq: invalid Zero increment value: '0'\n", 1);
    }
    let mut out = String::new();
    let mut i = first;

    while (step > 0 && i <= last) || (step < 0 && i >= last) {
        out.push_str(&format!("{i}\n"));
        if out.len() > MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
        i += step;
    }
    CommandResult::ok(out)
}

pub fn xargs(shell: &mut Shell, args: &[String]) -> CommandResult {
    let (per_call, command) = parse_xargs_args(args);

    let input = stdin_text(shell);
    let words: Vec<String> = input.split_whitespace().map(str::to_string).collect();
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

        let result = crate::commands::dispatch(shell, &argv);
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

fn parse_xargs_args(args: &[String]) -> (Option<usize>, Vec<String>) {
    let mut per_call: Option<usize> = None;
    let mut command: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-n" => per_call = iter.next().and_then(|v| v.parse().ok()),
            s if s.starts_with("-n") && s.len() > 2 => per_call = s[2..].parse().ok(),
            "-r" | "--no-run-if-empty" | "-0" | "--null" => {}
            _ => {
                command.push(a.clone());
                command.extend(iter.cloned());
                break;
            }
        }
    }
    if command.is_empty() {
        command.push("echo".to_string());
    }
    (per_call, command)
}
