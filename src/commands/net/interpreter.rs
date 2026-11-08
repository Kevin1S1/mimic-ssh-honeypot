use super::capture_connection;
use crate::commands::CommandResult;
use crate::shell::Shell;

const USAGE_FAILURE: i32 = 2;
const MAX_HOSTNAME_LEN: usize = 253;
const NETWORK_HINTS: [&str; 3] = ["socket", "connect", "Socket"];

/// Kept in one place so `python3 --version`, the REPL banner and the
/// `python3` entry in the package database cannot drift apart.
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

/// `python3` — see the note below; `perl` is [`perl`].
///
/// No interpreter is emulated, and none should be: running attacker code is the
/// one thing this box exists not to do. What matters is the *invocation* — the
/// `-c` payload is the intelligence, and the `command` event already records
/// the whole line verbatim, including the one-liner. Before this existed the
/// same line came back `command not found`, which both lost the interaction and
/// told a scanner the box has no Python while `dpkg -l` lists python3 as
/// installed. That contradiction was the real cost.
///
/// The one-liner attackers reach for is a reverse shell, and the outcome a real
/// box gives it most of the time is a connect that fails — their listener is
/// usually already gone. So a payload that tries to reach the network gets the
/// traceback that failure produces, and anything else exits quietly.
pub fn python3(shell: &mut Shell, args: &[String]) -> CommandResult {
    run(shell, Interpreter::Python3, args)
}

/// `perl` — see [`python3`].
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

    /// The `--version` text each interpreter prints.
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
            // Flags that take a value; consumed so the value is not mistaken
            // for a script path.
            "-m" | "-W" | "-X" | "-I" if !perl => {
                iter.next();
                return CommandResult::empty();
            }
            s if s.starts_with('-') && s.len() > 1 => {}
            script => return run_script(shell, interpreter, script),
        }
    }

    // No script and no `-c`: the interpreter reads its program from stdin,
    // which is how `curl … | python3` and `python3 < payload` arrive.
    // With no stdin either, python prints its banner and exits at EOF. Perl
    // waits for input and then exits silently.
    if shell.stdin.is_some() || perl {
        return CommandResult::empty();
    }
    CommandResult::ok(format!(
        "{}\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n",
        python_banner()
    ))
}

/// Run a `-c`/`-e` one-liner. Nothing is executed; the payload is already in the
/// `command` event, so all this decides is what the attacker sees back.
fn run_inline(shell: &mut Shell, interpreter: Interpreter, code: &str) -> CommandResult {
    let Some((host, port)) = inline_endpoint(code) else {
        // A non-network one-liner: most of these really do exit 0 with no
        // output, and guessing at output for code that was never run would be
        // a fabrication, not an emulation.
        return CommandResult::empty();
    };

    // The endpoint is worth as much as a `wget` URL, and lands in the same
    // event so one query finds every remote host a session named.
    capture_connection(shell, interpreter.name(), format!("tcp://{host}:{port}"));
    interpreter.connection_refused()
}

/// Run a script operand. The file has to exist in the VFS — a dropper that
/// `wget`s a payload and then runs it should see it run, and one that names a
/// path that was never written should see the real error.
fn run_script(shell: &mut Shell, interpreter: Interpreter, script: &str) -> CommandResult {
    let name = interpreter.name();
    let message = match (shell.vfs.resolve(shell.cwd, script), interpreter) {
        // ponytail: the body is not interpreted, so a script that would
        // have printed something prints nothing. `sh` runs its operands
        // line by line because those lines are shell commands this box
        // already emulates; there is no equivalent for Python. Upgrade only
        // if captured payloads show scripts whose output attackers check.
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

/// Python reports the absolute path it tried to open, not the operand.
fn abs_operand(shell: &Shell, script: &str) -> String {
    if script.starts_with('/') {
        return script.to_string();
    }
    let cwd = shell.vfs.path_of(shell.cwd);
    format!("{}/{script}", cwd.trim_end_matches('/'))
}

/// The host and port a one-liner tries to reach, if it looks like it does.
///
/// Deliberately shallow: a quoted host-shaped string plus the integer literal
/// nearest to it. Python writes the pair one way round
/// (`s.connect(("1.2.3.4",4444))`) and Perl the other
/// (`sockaddr_in(4444,inet_aton("1.2.3.4"))`), so "nearest" is what covers both
/// without parsing either language. Missing an exotic payload costs a
/// traceback, not a capture — the whole command line is logged regardless.
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

/// A host is an address or a name, never empty and never a sentence.
fn is_host_shaped(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOSTNAME_LEN
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
}

/// The port literal closest to the quoted host spanning `start..=end`, on
/// either side.
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

/// Every integer literal in `code` that could be a port, with where it starts.
/// Dotted-quad octets are excluded by requiring the run not to sit between two
/// dots, so `1.2.3.4` never contributes a "port".
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

/// The banner the interactive interpreter prints before its first prompt.
fn python_banner() -> String {
    format!("{PYTHON_VERSION} (main, Mar 13 2023, 09:44:40) [GCC 12.2.0] on linux")
}
