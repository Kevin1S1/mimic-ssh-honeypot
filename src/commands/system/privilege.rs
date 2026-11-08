use super::is_root;
use crate::commands::{dispatch, CommandResult};
use crate::shell::{Pending, Shell};

const ROOT: &str = "root";

const SUDO_USAGE: &str = "usage: sudo -h | -K | -k | -V\n\
     usage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]\n\
     usage: sudo -l [-ABkNnS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\n\
     usage: sudo [-ABbEHknPS] [-r role] [-t type] [-C fd] [-D directory] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] [VAR=value] [-i | -s] [<command>]\n";

enum SudoRequest {
    List,
    Run {
        login_shell: bool,
        keep_cwd: bool,
        command: Vec<String>,
    },
}

fn parse_sudo(args: &[String]) -> SudoRequest {
    let mut login_shell = false;
    let mut keep_cwd = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.peek() {
        match arg.as_str() {
            "-i" | "--login" => login_shell = true,
            "-s" | "--shell" => {
                login_shell = true;
                keep_cwd = true;
            }
            "-l" | "--list" => return SudoRequest::List,
            "-u" => {
                iter.next();
            }
            other if other.starts_with('-') => {}
            _ => break,
        }
        iter.next();
    }
    SudoRequest::Run {
        login_shell,
        keep_cwd,
        command: iter.cloned().collect(),
    }
}

pub fn sudo(shell: &mut Shell, args: &[String]) -> CommandResult {
    match parse_sudo(args) {
        SudoRequest::List => sudo_list(shell),
        SudoRequest::Run {
            login_shell: true,
            keep_cwd,
            command,
        } if command.is_empty() => {
            become_root(shell, keep_cwd);
            CommandResult::empty()
        }
        SudoRequest::Run { command, .. } if command.is_empty() => CommandResult::err(SUDO_USAGE, 1),
        SudoRequest::Run { command, .. } => run_as_root(shell, &command),
    }
}

fn sudo_list(shell: &Shell) -> CommandResult {
    CommandResult::ok(format!(
        "Matching Defaults entries for {user} on {host}:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\nUser {user} may run the following commands on {host}:\n    (ALL : ALL) ALL\n",
        user = shell.username,
        host = shell.hostname,
    ))
}

fn become_root(shell: &mut Shell, keep_cwd: bool) {
    let (cwd, home) = (shell.cwd, shell.home);
    shell.switch_user(ROOT);
    if !keep_cwd {
        return;
    }
    shell.cwd = cwd;
    shell.prev_cwd = cwd;
    shell.home = home;
    let (pwd, home) = (shell.vfs.path_of(cwd), shell.vfs.path_of(home));
    shell.env.set("PWD", &pwd);
    shell.env.set("HOME", &home);
}

fn run_as_root(shell: &mut Shell, command: &[String]) -> CommandResult {
    let (uid, gid) = (shell.uid, shell.gid);
    shell.uid = 0;
    shell.gid = 0;
    let result = dispatch(shell, command);
    shell.uid = uid;
    shell.gid = gid;
    result
}

pub fn su(shell: &mut Shell, args: &[String]) -> CommandResult {
    let target = su_target(args).to_string();

    if is_root(shell) {
        shell.switch_user(&target);
        return CommandResult::empty();
    }

    shell.pending = Some(Pending::SuPassword { target });
    CommandResult::ok("Password: ")
}

fn su_target(args: &[String]) -> &str {
    let mut target = ROOT;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--command" | "-s" | "--shell" | "-g" | "--group" => {
                iter.next();
            }
            other if other.starts_with('-') => {}
            other => target = other,
        }
    }
    target
}
