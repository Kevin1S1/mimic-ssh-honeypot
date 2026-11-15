use crate::commands::system::{process_pid, process_table};
use crate::commands::CommandResult;
use crate::shell::Shell;

const DEFAULT_SSH_PORT: u16 = 22;
const FALLBACK_PEER_IP: &str = "10.0.0.1";
const FALLBACK_PEER_PORT: u16 = 51394;
const FALLBACK_LISTENER_PID: u32 = 604;
const SESSION_TTY_COLUMN: &str = "pt";

struct Sockets {
    local_ip: String,
    port: u16,
    peer_ip: String,
    peer_port: u16,
    listener_pid: u32,
    session_pid: u32,
    user: String,
}

impl Sockets {
    fn from_shell(shell: &Shell) -> Self {
        let mut fields = shell
            .env
            .get("SSH_CONNECTION")
            .unwrap_or_default()
            .split_whitespace();
        let peer_ip = fields.next();
        let peer_port = fields.next().and_then(|p| p.parse().ok());
        let port = fields.nth(1).and_then(|p| p.parse().ok());
        let (peer_ip, peer_port) = match (peer_ip, peer_port) {
            (Some(ip), Some(port)) => (ip.to_string(), port),
            _ => (FALLBACK_PEER_IP.to_string(), FALLBACK_PEER_PORT),
        };
        let listener_pid = process_pid(shell, "sshd").unwrap_or(FALLBACK_LISTENER_PID);
        let session_pid = process_table(shell)
            .into_iter()
            .find(|(pid, cmd)| *pid != listener_pid && cmd.starts_with("sshd: "))
            .map_or(listener_pid, |(pid, _)| pid);
        Self {
            local_ip: shell.persona.ipv4.clone(),
            port: port.unwrap_or(DEFAULT_SSH_PORT),
            peer_ip,
            peer_port,
            listener_pid,
            session_pid,
            user: shell.username.clone(),
        }
    }

    fn named_port(&self, numeric: bool) -> String {
        if numeric || self.port != DEFAULT_SSH_PORT {
            self.port.to_string()
        } else {
            "ssh".to_string()
        }
    }

    fn peer(&self) -> String {
        format!("{}:{}", self.peer_ip, self.peer_port)
    }
}

fn flag_letters(args: &[String]) -> String {
    args.iter()
        .filter(|a| a.starts_with('-'))
        .map(String::as_str)
        .collect()
}

fn if_shown(show: bool, text: String) -> String {
    if show {
        text
    } else {
        String::new()
    }
}

pub fn netstat(shell: &Shell, args: &[String]) -> CommandResult {
    let sockets = Sockets::from_shell(shell);
    let flags = flag_letters(args);
    let listening = flags.contains('l');
    let numeric = flags.contains('n');
    let show_prog = flags.contains('p');

    let mut out = String::from("Active Internet connections (");
    out.push_str(if listening {
        "only servers)\n"
    } else {
        "w/o servers)\n"
    });
    out.push_str("Proto Recv-Q Send-Q Local Address           Foreign Address         State      ");
    out.push_str(if show_prog {
        "PID/Program name\n"
    } else {
        "\n"
    });

    let named_port = sockets.named_port(numeric);
    if listening {
        let listener = if_shown(show_prog, format!("{}/sshd: /usr/sb", sockets.listener_pid));
        out.push_str(&format!(
            "tcp        0      0 {:<23} 0.0.0.0:*               LISTEN      {listener}\n",
            format!("0.0.0.0:{named_port}"),
        ));
        out.push_str(&format!(
            "tcp6       0      0 {:<23} :::*                    LISTEN      {listener}\n",
            format!(":::{named_port}"),
        ));
    } else {
        let local = if numeric {
            sockets.local_ip.as_str()
        } else {
            "debian"
        };
        let session = if_shown(
            show_prog,
            format!(
                "{}/sshd: {}@{SESSION_TTY_COLUMN}",
                sockets.session_pid, sockets.user
            ),
        );
        out.push_str(&format!(
            "tcp        0      0 {:<23} {:<23} ESTABLISHED {session}\n",
            format!("{local}:{named_port}"),
            sockets.peer(),
        ));
    }
    CommandResult::ok(out)
}

pub fn ss(shell: &Shell, args: &[String]) -> CommandResult {
    let sockets = Sockets::from_shell(shell);
    let flags = flag_letters(args);
    let listening = flags.contains('l');
    let show_prog = flags.contains('p');

    let mut out =
        String::from("State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port   ");
    out.push_str(if show_prog { "Process\n" } else { "\n" });

    let port = sockets.port;
    let users =
        |pid: u32, fd: u32| if_shown(show_prog, format!("users:((\"sshd\",pid={pid},fd={fd}))"));
    if listening {
        out.push_str(&format!(
            "LISTEN   0        128{:>24}{:>22}          {}\n",
            format!("0.0.0.0:{port}"),
            "0.0.0.0:*",
            users(sockets.listener_pid, 3)
        ));
        out.push_str(&format!(
            "LISTEN   0        128{:>24}{:>22}          {}\n",
            format!("[::]:{port}"),
            "[::]:*",
            users(sockets.listener_pid, 4)
        ));
    } else {
        out.push_str(&format!(
            "ESTAB    0        0{:>26}{:>25}      {}\n",
            format!("{}:{port}", sockets.local_ip),
            sockets.peer(),
            users(sockets.session_pid, 4)
        ));
    }
    CommandResult::ok(out)
}
