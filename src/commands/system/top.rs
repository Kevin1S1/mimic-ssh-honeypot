use super::process::{invocation, session_table, Proc, IDLE_CPU_PERCENT};
use crate::clock;
use crate::commands::CommandResult;
use crate::persona::MemStats;
use crate::shell::{Screen, Shell};

const CPU_SUMMARY: &str =
    "%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.4 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st
";
const COLUMN_HEADER: &str = "
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
";

fn mib(kb: u64) -> f64 {
    kb as f64 / 1024.0
}

#[derive(Clone)]
pub struct TopScreen {
    rows: Vec<String>,
    total: usize,
    running: usize,
    mem: MemStats,
}

impl TopScreen {
    fn new(table: &[Proc], mem: MemStats) -> Self {
        Self {
            rows: table.iter().map(top_row).collect(),
            total: table.len(),
            running: table.iter().filter(|p| p.stat.starts_with('R')).count(),
            mem,
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
        out.push_str(CPU_SUMMARY);
        let m = &self.mem;
        out.push_str(&format!(
            "MiB Mem : {:>8.1} total, {:>8.1} free, {:>8.1} used, {:>8.1} buff/cache
",
            mib(m.total),
            mib(m.free),
            mib(m.used),
            mib(m.buff_cache)
        ));
        out.push_str(&format!(
            "MiB Swap: {:>8.1} total, {:>8.1} free, {:>8.1} used. {:>8.1} avail Mem
",
            0.0,
            0.0,
            0.0,
            mib(m.available)
        ));
        out.push_str(COLUMN_HEADER);
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
    let screen = TopScreen::new(
        &session_table(shell, &invocation("top", args)),
        shell.persona.memory(),
    );
    if !is_one_shot(args) && shell.interactive && shell.stdout_is_tty {
        shell.screen = Some(Screen::Top(screen));
        return CommandResult::empty();
    }
    CommandResult::ok(screen.render())
}
