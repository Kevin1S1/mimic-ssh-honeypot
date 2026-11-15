use super::host::KERNEL_RELEASE;
use super::is_root;
use super::process::{CLOCK_TIME_FORMAT, SESSION_TTY};
use crate::clock;
use crate::commands::CommandResult;
use crate::shell::Shell;

pub fn whoami(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.username))
}

pub fn id(shell: &Shell, _args: &[String]) -> CommandResult {
    let line = if is_root(shell) {
        "uid=0(root) gid=0(root) groups=0(root)\n".to_string()
    } else {
        format!(
            "uid={uid}({user}) gid={gid}({user}) groups={gid}({user}),27(sudo)\n",
            uid = shell.uid,
            gid = shell.gid,
            user = shell.username,
        )
    };
    CommandResult::ok(line)
}

const USER_COLUMN_WIDTH: usize = 8;

const W_COLUMNS: &str = "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n";

const LAST_TIME_FORMAT: &str = "%a %b %e %H:%M";

pub fn w(shell: &Shell, _args: &[String]) -> CommandResult {
    let header = format!(" {}\n", clock::uptime_banner());
    let row = format!(
        "{user:<8} {SESSION_TTY:<8} {from:<16} {login}    0.00s  0.02s  0.00s w\n",
        user = truncate(&shell.username, USER_COLUMN_WIDTH),
        from = clock::PREV_LOGIN_FROM,
        login = clock::format(shell.login, CLOCK_TIME_FORMAT),
    );
    CommandResult::ok(format!("{header}{W_COLUMNS}{row}"))
}

pub fn last(shell: &Shell, _args: &[String]) -> CommandResult {
    let (prev, prev_end) = clock::prev_login();
    let boot = clock::boot_time();
    let user = truncate(&shell.username, USER_COLUMN_WIDTH);
    let from = clock::PREV_LOGIN_FROM;
    let span = prev_end - prev;
    let out = format!(
        "{user:<8} {SESSION_TTY:<12} {from:<16} {this}   still logged in\n\
         {user:<8} {SESSION_TTY:<12} {from:<16} {prev} - {prev_end} ({hours:02}:{mins:02})\n\
         reboot   system boot  {KERNEL_RELEASE:<16} {boot}   still running\n\
         \n\
         wtmp begins {wtmp}\n",
        this = clock::format(shell.login, LAST_TIME_FORMAT),
        prev = clock::format(prev, LAST_TIME_FORMAT),
        prev_end = clock::format(prev_end, CLOCK_TIME_FORMAT),
        hours = span / 3600,
        mins = (span % 3600) / 60,
        boot = clock::format(boot, LAST_TIME_FORMAT),
        wtmp = clock::format(boot, "%a %b %e %H:%M:%S %Y"),
    );
    CommandResult::ok(out)
}

pub fn crontab(shell: &Shell, args: &[String]) -> CommandResult {
    if args.iter().any(|a| a == "-l") {
        return CommandResult::err(format!("no crontab for {}\n", shell.username), 1);
    }
    if args.iter().any(|a| a == "-r" || a == "-e") {
        return CommandResult::empty();
    }
    CommandResult::err(
        "usage:  crontab [-u user] file\n\
         \tcrontab [ -u user ] [ -i ] { -e | -l | -r }\n",
        1,
    )
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn groups(shell: &Shell, _args: &[String]) -> CommandResult {
    let line = if is_root(shell) {
        "root".to_string()
    } else {
        format!("{} sudo", shell.username)
    };
    CommandResult::ok(format!("{line}\n"))
}

pub fn tty(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("/dev/{SESSION_TTY}\n"))
}
