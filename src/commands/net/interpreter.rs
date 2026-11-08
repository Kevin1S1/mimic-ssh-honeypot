use super::capture_connection;
use crate::commands::CommandResult;
use crate::shell::Shell;

const USAGE_FAILURE: i32 = 2;
const MAX_HOSTNAME_LEN: usize = 253;
const NETWORK_HINTS: [&str; 3] = ["socket", "connect", "Socket"];

const PYTHON_VERSION: &str = "Python 3.11.2";

const PERL_VERSION: &str = "\nThis is perl 5, version 36, subversion 0 (v5.36.0) built for \
    x86_64-linux-gnu-thread-multi\n\n\
    Copyright 1987-2022, Larry Wall\n\n\
    Perl may be copied only under the terms of either the Artistic License or the\n\
    GNU General Public License, which may be found in the Perl 5 source kit.\n\n\
    Complete documentation for Perl, including FAQ lists, should be found on\n\
    this system using \"man perl\" or \"perldoc perl\".  If you have access to the\n\
    Internet, point your browser at https://www.perl.org/, the Perl Home Page.\n\n";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Interpreter {
    Python3,
    Perl,
}

pub fn python3(shell: &mut Shell, args: &[String]) -> CommandResult {
    run(shell, Interpreter::Python3, args)
}

pub fn perl(shell: &mut Shell, args: &[String]) -> CommandResult {
    run(shell, Interpreter::Perl, args)
}

impl Interpreter {
    fn name(self) -> &'static str {
        match self {
            Interpreter::Python3 => "python3",
            Interpreter::Perl => "perl",
        }
    }

    fn version(self) -> String {
        match self {
            Interpreter::Python3 => format!("{PYTHON_VERSION}\n"),
            Interpreter::Perl => PERL_VERSION.to_string(),
        }
    }

    fn is_version_flag(self, flag: &str) -> bool {
        matches!(flag, "--version" | "-V") || (self == Interpreter::Perl && flag == "-v")
    }

    fn missing_code_message(self) -> &'static str {
        match self {
            Interpreter::Python3 => {
                "Argument expected for the -c option\nusage: python3 [option] ... \n"
            }
            Interpreter::Perl => "Missing argument to -e.\n",
        }
    }

    fn connection_refused(self) -> CommandResult {
        match self {
            Interpreter::Python3 => CommandResult::err(
                "Traceback (most recent call last):\n  \
                 File \"<string>\", line 1, in <module>\n\
                 ConnectionRefusedError: [Errno 111] Connection refused\n",
                1,
            ),
            Interpreter::Perl => CommandResult::err("Connection refused at -e line 1.\n", 255),
        }
    }
}

fn run(shell: &mut Shell, interpreter: Interpreter, args: &[String]) -> CommandResult {
    let perl = interpreter == Interpreter::Perl;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            flag if interpreter.is_version_flag(flag) => {
                return CommandResult::ok(interpreter.version())
            }
            "-c" | "-e" => {
                let Some(code) = iter.next() else {
                    return CommandResult::err(interpreter.missing_code_message(), USAGE_FAILURE);
                };
                return run_inline(shell, interpreter, code);
            }

            "-m" | "-W" | "-X" | "-I" if !perl => {
                iter.next();
                return CommandResult::empty();
            }
            s if s.starts_with('-') && s.len() > 1 => {}
            script => return run_script(shell, interpreter, script),
        }
    }

    if shell.stdin.is_some() || perl {
        return CommandResult::empty();
    }
    CommandResult::ok(format!(
        "{}\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n",
        python_banner()
    ))
}

fn run_inline(shell: &mut Shell, interpreter: Interpreter, code: &str) -> CommandResult {
    let Some((host, port)) = inline_endpoint(code) else {
        return CommandResult::empty();
    };

    capture_connection(shell, interpreter.name(), format!("tcp://{host}:{port}"));
    interpreter.connection_refused()
}

fn run_script(shell: &mut Shell, interpreter: Interpreter, script: &str) -> CommandResult {
    let name = interpreter.name();
    let message = match (shell.vfs.resolve(shell.cwd, script), interpreter) {
        (Some(id), _) if !shell.vfs.node(id).meta.is_dir() => return CommandResult::empty(),
        (Some(_), Interpreter::Perl) => {
            format!("Can't open perl script \"{script}\": Is a directory\n")
        }
        (Some(_), Interpreter::Python3) => {
            format!("{name}: can't open file '{script}': [Errno 21] Is a directory\n")
        }
        (None, Interpreter::Perl) => {
            format!("Can't open perl script \"{script}\": No such file or directory\n")
        }
        (None, Interpreter::Python3) => format!(
            "{name}: can't open file '{}': [Errno 2] No such file or directory\n",
            abs_operand(shell, script)
        ),
    };
    CommandResult::err(message, USAGE_FAILURE)
}

fn abs_operand(shell: &Shell, script: &str) -> String {
    if script.starts_with('/') {
        return script.to_string();
    }
    let cwd = shell.vfs.path_of(shell.cwd);
    format!("{}/{script}", cwd.trim_end_matches('/'))
}

fn inline_endpoint(code: &str) -> Option<(String, u16)> {
    if !NETWORK_HINTS.iter().any(|hint| code.contains(hint)) {
        return None;
    }
    let chars: Vec<char> = code.chars().collect();
    let ports = port_literals(&chars);

    let mut i = 0;
    while i < chars.len() {
        let quote = chars[i];
        if quote != '"' && quote != '\'' {
            i += 1;
            continue;
        }
        let Some(len) = chars[i + 1..].iter().position(|c| *c == quote) else {
            break;
        };
        let host: String = chars[i + 1..i + 1 + len].iter().collect();
        if is_host_shaped(&host) {
            if let Some(port) = nearest_port(&ports, i, i + len + 1) {
                return Some((host, port));
            }
        }
        i += len + 2;
    }
    None
}

fn is_host_shaped(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOSTNAME_LEN
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
}

fn nearest_port(ports: &[(usize, u16)], start: usize, end: usize) -> Option<u16> {
    ports
        .iter()
        .min_by_key(|(at, _)| {
            if *at > end {
                at - end
            } else {
                start.saturating_sub(*at)
            }
        })
        .map(|(_, port)| *port)
}

fn port_literals(chars: &[char]) -> Vec<(usize, u16)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
        let dotted = (start > 0 && chars[start - 1] == '.') || chars.get(i) == Some(&'.');
        if dotted {
            continue;
        }
        let digits: String = chars[start..i].iter().collect();
        if let Some(port) = digits.parse::<u16>().ok().filter(|port| *port > 0) {
            out.push((start, port));
        }
    }
    out
}

fn python_banner() -> String {
    format!("{PYTHON_VERSION} (main, Mar 13 2023, 09:44:40) [GCC 12.2.0] on linux")
}
