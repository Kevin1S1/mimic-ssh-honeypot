use super::process::{invocation, session_table, Proc, IDLE_CPU_PERCENT};
use crate::clock;
use crate::commands::CommandResult;
use crate::shell::{Screen, Shell};

const RESOURCE_SUMMARY: &str = "\
%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.4 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st\n\
MiB Mem :   1993.4 total,   1468.3 free,    179.0 used,    346.0 buff/cache\n\
MiB Swap:      0.0 total,      0.0 free,      0.0 used.   1723.6 avail Mem\n\
\n    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n";

#[derive(Clone)]
pub struct TopScreen {
    rows: Vec<String>,
    total: usize,
    running: usize,
}

impl TopScreen {
    fn new(table: &[Proc]) -> Self {
        Self {
            rows: table.iter().map(top_row).collect(),
            total: table.len(),
            running: table.iter().filter(|p| p.stat.starts_with('R')).count(),
        }
    }

    pub fn render(&self) -> String {
        let mut out = format!("top - {}\n", clock::uptime_banner());
        out.push_str(&format!(
            "Tasks: {:>3} total,   {} running, {:>3} sleeping,   0 stopped,   0 zombie\n",
            self.total,
            self.running,
            self.total - self.running
        ));
        out.push_str(RESOURCE_SUMMARY);
        out.extend(self.rows.iter().map(String::as_str));
        out
    }
}

fn top_row(p: &Proc) -> String {
    format!(
        "{:>7} {:<8}  20   0 {:>7} {:>6} {:>6} {} {:>5} {:>5}   {:>7} {}\n",
        p.pid,
        p.user,
        p.vsz,
        p.rss,
        p.rss / 2,
        &p.stat[..1],
        IDLE_CPU_PERCENT,
        p.mem,
        p.time,
        p.command_word()
    )
}

fn is_one_shot(args: &[String]) -> bool {
    args.iter()
        .any(|a| a == "-b" || a == "--batch" || (a.starts_with('-') && a.contains('n')))
}

pub fn top(shell: &mut Shell, args: &[String]) -> CommandResult {
    let screen = TopScreen::new(&session_table(shell, &invocation("top", args)));
    if !is_one_shot(args) && shell.interactive && shell.stdout_is_tty {
        shell.screen = Some(Screen::Top(screen));
        return CommandResult::empty();
    }
    CommandResult::ok(screen.render())
}
