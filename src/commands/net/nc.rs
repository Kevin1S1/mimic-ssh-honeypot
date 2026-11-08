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
            s if VALUE_FLAGS.contains(&s) => {
                iter.next();
            }
            s if s.starts_with('-') && s.len() > 1 && !s.starts_with("--") => {
                let letters = &s[1..];
                for c in letters.chars() {
                    options.set_letter(c);
                }

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
    if options.port_flag {
        return CommandResult::err("nc: cannot use -p and -l\n", 1);
    }

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

        if options.verbose || options.scan {
            errs.push_str(&format!(
                "nc: connect to {host} port {port} ({proto}) failed: Connection refused\n"
            ));
        }
    }
    CommandResult::err(errs, 1)
}
