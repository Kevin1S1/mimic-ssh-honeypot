use crate::shell::Shell;

mod builtins;
mod host;
mod identity;
mod interpreter;
mod privilege;
mod process;
mod resources;
mod top;

pub use builtins::{clear, echo, env, export, history, printf, unset, which, BUILTINS};
pub use host::{arch, date, dmesg, hostname, lsb_release, lscpu, nproc, uname, uptime};
pub use identity::{crontab, groups, id, last, tty, w, whoami};
pub use interpreter::{scp, shell_cmd};
pub use privilege::{su, sudo};
pub use process::{kill, pkill, process_name, process_pid, process_table, ps};
pub use resources::{df, free, mount};
pub use top::{top, TopScreen};

fn is_root(shell: &Shell) -> bool {
    shell.uid == 0
}

#[cfg(test)]
mod tests;
