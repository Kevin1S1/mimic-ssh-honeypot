use crate::commands::{CommandResult, MAX_COMMAND_OUTPUT_BYTES};
use crate::shell::Shell;
use crate::vfs::snapshot::{USR_BIN, USR_SBIN};

pub fn printf(_shell: &Shell, args: &[String]) -> CommandResult {
    let Some(format) = args.first() else {
        return CommandResult::err("printf: usage: printf [-v var] format [arguments]\n", 2);
    };
    let mut operands = args[1..].iter();
    let mut out = String::new();
    let mut chars = format.chars();

    while let Some(c) = chars.next() {
        match c {
            '\\' | '%' => match chars.next() {
                Some(code) if c == '\\' => push_printf_escape(&mut out, code),
                Some(spec) => push_printf_conversion(&mut out, spec, &mut operands),
                None => out.push(c),
            },
            c => out.push(c),
        }
        if out.len() > MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    CommandResult::ok(out)
}

fn push_printf_escape(out: &mut String, code: char) {
    let decoded = match code {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        '0' => '\0',
        '\\' => '\\',
        other => {
            out.push('\\');
            other
        }
    };
    out.push(decoded);
}

fn push_printf_conversion(
    out: &mut String,
    spec: char,
    operands: &mut std::slice::Iter<'_, String>,
) {
    match spec {
        '%' => out.push('%'),
        's' => out.push_str(operands.next().map(String::as_str).unwrap_or("")),
        'd' | 'i' => {
            let value: i64 = operands
                .next()
                .and_then(|a| a.trim().parse().ok())
                .unwrap_or(0);
            out.push_str(&value.to_string());
        }
        other => {
            out.push('%');
            out.push(other);
        }
    }
}

pub fn echo(_shell: &Shell, args: &[String]) -> CommandResult {
    let flag_count = args.iter().take_while(|arg| is_echo_flag(arg)).count();
    let (flags, words) = args.split_at(flag_count);
    let no_newline = flags.iter().any(|flag| flag.contains('n'));
    let interpret = flags.iter().any(|flag| flag.contains('e'));

    let mut text = words.join(" ");
    let mut stopped = false;
    if interpret {
        (text, stopped) = interpret_escapes(&text);
    }
    if !no_newline && !stopped {
        text.push('\n');
    }
    CommandResult::ok(text)
}

fn is_echo_flag(arg: &str) -> bool {
    arg.strip_prefix('-')
        .is_some_and(|letters| !letters.is_empty() && letters.chars().all(|c| c == 'n' || c == 'e'))
}

fn interpret_escapes(s: &str) -> (String, bool) {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('a') => out.push('\x07'),
            Some('b') => out.push('\x08'),
            Some('e') | Some('E') => out.push('\x1b'),
            Some('f') => out.push('\x0c'),
            Some('v') => out.push('\x0b'),

            Some('0') => out.push(take_code(&mut chars, 8, 3).unwrap_or('\0')),
            Some('x') => match take_code(&mut chars, 16, 2) {
                Some(c) => out.push(c),
                None => out.push_str("\\x"),
            },

            Some('c') => return (out, true),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    (out, false)
}

fn take_code(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    max: usize,
) -> Option<char> {
    let mut value = 0u32;
    let mut digits = 0;
    while digits < max {
        let Some(d) = chars.peek().and_then(|c| c.to_digit(radix)) else {
            break;
        };
        value = value * radix + d;
        chars.next();
        digits += 1;
    }

    (digits > 0).then(|| char::from(value as u8))
}

pub fn env(shell: &Shell, _args: &[String]) -> CommandResult {
    let out: String = shell
        .env
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect();
    CommandResult::ok(out)
}

pub fn export(shell: &mut Shell, args: &[String]) -> CommandResult {
    for arg in args {
        if let Some((name, value)) = arg.split_once('=') {
            shell.env.set(name, value);
        }
    }
    CommandResult::empty()
}

pub fn unset(shell: &mut Shell, args: &[String]) -> CommandResult {
    for arg in args {
        shell.env.unset(arg);
    }
    CommandResult::empty()
}

pub fn clear(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok("\x1b[H\x1b[2J\x1b[3J")
}

pub const BUILTINS: &[&str] = &[
    "cd", "export", "unset", "history", "exit", "logout", "alias", "source",
];

pub fn history(shell: &mut Shell, args: &[String]) -> CommandResult {
    if args.iter().any(|a| a == "-c") {
        shell.history.clear();
        return CommandResult::empty();
    }
    let mut out = String::new();
    for (i, cmd) in shell.history.iter().enumerate() {
        out.push_str(&format!("{:5}  {}\n", i + 1, cmd));
    }
    CommandResult::ok(out)
}

pub fn which(_shell: &Shell, args: &[String]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::empty();
    }
    let mut out = String::new();
    let mut status = 0;
    for name in args {
        match binary_path(name) {
            Some(path) => out.push_str(&format!("{path}\n")),
            None => status = 1,
        }
    }
    CommandResult::streams(out, "", status)
}

fn binary_path(name: &str) -> Option<String> {
    if BUILTINS.contains(&name) {
        return None;
    }
    if USR_BIN.contains(&name) {
        Some(format!("/usr/bin/{name}"))
    } else if USR_SBIN.contains(&name) {
        Some(format!("/usr/sbin/{name}"))
    } else {
        None
    }
}
