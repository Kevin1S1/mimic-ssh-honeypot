use crate::commands::{dispatch, CommandResult, MAX_COMMAND_OUTPUT_BYTES};
use crate::shell::{Capture, Shell};

/// How many lines of a script or of piped stdin `sh` will run.
///
/// The output cap alone does not bound this: a script of a million `true` lines
/// produces nothing to truncate and still costs a parse per line. A VFS file
/// can hold 8 MiB, so without a line cap an attacker buys arbitrary CPU for one
/// upload.
pub(super) const MAX_SCRIPT_LINES: usize = 4096;

const SSH_PORT: u16 = 22;

/// `bash`/`sh` — the shell this session already claims to be.
///
/// Three ways a payload arrives, all of which now run:
///
/// - `-c LINE`, the classic `sh -c "cd /tmp; wget ...; ./x"`;
/// - piped stdin, which is what `... | base64 -d | sh` and `curl ... | sh`
///   produce — the single most common staging idiom there is;
/// - a script operand, read back out of the VFS, which is what the
///   `wget`-then-`chmod +x`-then-run sequence ends in.
///
/// Each line of a script or of stdin is run through the same shell that would
/// have run it interactively, so the nesting cap and the output cap apply
/// exactly as they do everywhere else.
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
            // Interactive/login flags change nothing here.
            other if other.starts_with('-') => {}
            script => return run_script_file(shell, script),
        }
    }

    // No `-c` and no operand: a real shell reads its stdin. Over a pipe that is
    // the payload; with no pipe there is nothing to read and it exits.
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

/// Run each line of `text` as a shell command, accumulating both streams.
///
/// This is what makes a dropped script observable: the download was already
/// captured, but until the body actually ran, nothing downstream of it — the
/// second-stage fetch, the persistence attempt, the credential change — was
/// ever seen.
fn run_script(shell: &mut Shell, text: &str) -> CommandResult {
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    // `Shell::execute` clears `captures` on entry, so each line would otherwise
    // wipe the one before it — a script that fetched two payloads would log
    // only the second. Accumulate across the whole body and hand the lot back,
    // the way command substitution already does for its subshell.
    let mut collected = std::mem::take(&mut shell.captures);

    for line in text.lines().take(MAX_SCRIPT_LINES).map(str::trim) {
        // Shebangs and comments are not commands.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let result = shell.execute(line);
        // The network layer logs a `command` event per line the *client*
        // submits, and these lines came from a file. Capturing each one is what
        // makes a dropped script observable rather than just its side effects.
        collected.push(Capture::ScriptCommand {
            line: line.to_string(),
            status: result.status,
        });
        collected.append(&mut shell.captures);
        // `stdout` is the pipe view and `text` the terminal-combined one; a
        // script's output is going onward as a stream, so only the former.
        out.push_str(&result.stdout);
        errs.push_str(&result.stderr);
        status = result.status;
        // Bounded like every other accumulated stream.
        if result.exit || out.len() + errs.len() > MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    shell.captures = collected;
    CommandResult::streams(out, errs, status)
}

/// `scp` run as an interactive command.
///
/// The binary has to exist — uploads to this host succeed, which means the
/// server side runs `scp -t` — but an interactive copy would need a real
/// network, so it fails as a refused connection — a "timed out" that returns
/// instantly would be a tell in itself. Transfer mode (`-t`/`-f`) never reaches
/// this handler: the SSH layer intercepts it before the shell sees it.
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

    // A `host:path` operand means a real connection, which this host will never
    // make. It fails as a refused connection rather than a timeout: a timeout
    // that returns instantly is itself a tell.
    if let Some(host) = operands.iter().find_map(|op| remote_host(op)) {
        return CommandResult::err(
            format!(
                "ssh: connect to host {host} port {SSH_PORT}: Connection refused\nlost connection\n"
            ),
            1,
        );
    }

    // Purely local operands: real scp just copies, so let `cp` do it.
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
