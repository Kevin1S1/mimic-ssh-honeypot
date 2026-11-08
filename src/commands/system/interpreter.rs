use crate::commands::{dispatch, CommandResult, MAX_COMMAND_OUTPUT_BYTES};
use crate::shell::{Capture, Shell};

pub(super) const MAX_SCRIPT_LINES: usize = 4096;

const SSH_PORT: u16 = 22;

pub fn shell_cmd(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" => {
                let Some(line) = iter.next() else {
                    return CommandResult::err("bash: -c: option requires an argument\n", 2);
                };
                return run_command_line(shell, line);
            }

            other if other.starts_with('-') => {}
            script => return run_script_file(shell, script),
        }
    }

    match shell.stdin.clone() {
        Some(text) if !text.trim().is_empty() => run_script(shell, &text),
        _ => CommandResult::ok(""),
    }
}

fn run_command_line(shell: &mut Shell, line: &str) -> CommandResult {
    let argv = shell.parse_line(line);
    if argv.is_empty() {
        return CommandResult::ok("");
    }
    dispatch(shell, &argv)
}

fn run_script_file(shell: &mut Shell, path: &str) -> CommandResult {
    let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
        return CommandResult::err(format!("bash: {path}: No such file or directory\n"), 127);
    };
    let Some(bytes) = shell.vfs.node(id).file_bytes() else {
        return CommandResult::err(format!("bash: {path}: Is a directory\n"), 126);
    };
    let text = String::from_utf8_lossy(&bytes).into_owned();
    run_script(shell, &text)
}

fn run_script(shell: &mut Shell, text: &str) -> CommandResult {
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;

    let mut collected = std::mem::take(&mut shell.captures);

    for line in text.lines().take(MAX_SCRIPT_LINES).map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let result = shell.execute(line);

        collected.push(Capture::ScriptCommand {
            line: line.to_string(),
            status: result.status,
        });
        collected.append(&mut shell.captures);

        out.push_str(&result.stdout);
        errs.push_str(&result.stderr);
        status = result.status;

        if result.exit || out.len() + errs.len() > MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    shell.captures = collected;
    CommandResult::streams(out, errs, status)
}

pub fn scp(shell: &mut Shell, args: &[String]) -> CommandResult {
    let operands: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if operands.len() < 2 {
        return CommandResult::err(
            "usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n           \
             [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n           \
             [-P port] [-S program] [-X sftp_option] source ... target\n",
            1,
        );
    }

    if let Some(host) = operands.iter().find_map(|op| remote_host(op)) {
        return CommandResult::err(
            format!(
                "ssh: connect to host {host} port {SSH_PORT}: Connection refused\nlost connection\n"
            ),
            1,
        );
    }

    let argv: Vec<String> = std::iter::once("cp".to_string())
        .chain(operands.into_iter().cloned())
        .collect();
    dispatch(shell, &argv)
}

fn remote_host(operand: &str) -> Option<&str> {
    let (user_at_host, _) = operand.split_once(':')?;
    let host = user_at_host.rsplit('@').next().unwrap_or(user_at_host);
    (!host.is_empty()).then_some(host)
}
