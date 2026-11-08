use super::{cap, vfs_file, with_input};
use crate::commands::{CommandResult, MAX_COMMAND_OUTPUT_BYTES};
use crate::shell::Shell;

const AWK_FAILURE: i32 = 2;
const REGEX_METACHARACTERS: [char; 11] = ['*', '+', '?', '[', ']', '(', ')', '|', '\\', '{', '}'];

struct AwkInvocation<'a> {
    separator: Option<String>,
    program: String,
    files: Vec<&'a str>,
}

struct AwkRule {
    pattern: AwkPattern,
    print_items: Vec<String>,
}

enum AwkPattern {
    Always,

    Contains(String),

    FieldEq {
        field: usize,
        value: String,
        negate: bool,
    },

    LineIs(u64),
}

struct Record<'a> {
    line: &'a str,
    fields: Vec<String>,
    number: u64,
}

pub fn awk(shell: &Shell, args: &[String]) -> CommandResult {
    let invocation = match parse_args(shell, args) {
        Ok(invocation) => invocation,
        Err(failure) => return failure,
    };
    let Some(rules) = parse_program(&invocation.program) else {
        return CommandResult::err(
            format!(
                "awk: syntax error at source line 1\n context is\n\t{}\n",
                invocation.program
            ),
            AWK_FAILURE,
        );
    };
    with_input(shell, "awk", &invocation.files, |text| {
        CommandResult::ok(run(&rules, text, invocation.separator.as_deref()))
    })
}

fn parse_args<'a>(shell: &Shell, args: &'a [String]) -> Result<AwkInvocation<'a>, CommandResult> {
    let mut separator: Option<String> = None;
    let mut separator_variable: Option<String> = None;
    let mut program: Option<String> = None;
    let mut files: Vec<&str> = Vec::new();
    let mut iter = args.iter();

    while let Some(a) = iter.next() {
        match a.as_str() {
            "-F" => separator = iter.next().cloned(),
            "-v" => {
                if let Some(assignment) = iter.next() {
                    note_separator_assignment(&mut separator_variable, assignment);
                }
            }
            "-f" => {
                let Some(path) = iter.next() else { continue };
                program = Some(read_program_file(shell, path)?);
            }
            s if s.starts_with("-F") && s.len() > 2 => separator = Some(s[2..].to_string()),
            s if s.starts_with("-v") && s.len() > 2 => {
                note_separator_assignment(&mut separator_variable, &s[2..]);
            }
            s if s.starts_with('-') && s.len() > 1 => {}
            other if program.is_none() => program = Some(other.to_string()),
            other => files.push(other),
        }
    }

    let Some(program) = program else {
        return Err(CommandResult::err(
            "usage: awk [-F fs][-v var=value][prog | -f progfile][file ...]\n",
            AWK_FAILURE,
        ));
    };
    Ok(AwkInvocation {
        separator: separator_variable.or(separator),
        program,
        files,
    })
}

fn note_separator_assignment(separator_variable: &mut Option<String>, assignment: &str) {
    if let Some(("FS", value)) = assignment.split_once('=') {
        separator_variable.get_or_insert_with(|| value.to_string());
    }
}

fn read_program_file(shell: &Shell, path: &str) -> Result<String, CommandResult> {
    vfs_file(shell, "awk", path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|_| CommandResult::err(format!("awk: can't open file {path}\n"), AWK_FAILURE))
}

fn run(rules: &[AwkRule], text: &str, separator: Option<&str>) -> String {
    let mut out = String::new();
    for (index, line) in text.lines().enumerate() {
        let record = Record {
            line,
            fields: split_fields(line, separator),
            number: index as u64 + 1,
        };
        for rule in rules.iter().filter(|rule| record.matches(&rule.pattern)) {
            out.push_str(&record.render(&rule.print_items));
            out.push('\n');
        }

        if out.len() >= MAX_COMMAND_OUTPUT_BYTES {
            break;
        }
    }
    cap(&mut out);
    out
}

fn parse_program(program: &str) -> Option<Vec<AwkRule>> {
    let mut rules = Vec::new();
    for chunk in split_rules(program) {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        let (pattern_src, action_src) = match chunk.split_once('{') {
            Some((p, rest)) => (p.trim(), Some(rest.trim_end().trim_end_matches('}').trim())),
            None => (chunk, None),
        };

        if pattern_src.starts_with("BEGIN") || pattern_src.starts_with("END") {
            return None;
        }
        let pattern = parse_pattern(pattern_src)?;
        let print_items = match action_src {
            None => whole_line(),
            Some(body) => parse_print(body)?,
        };
        rules.push(AwkRule {
            pattern,
            print_items,
        });
    }
    if rules.is_empty() {
        return None;
    }
    Some(rules)
}

fn whole_line() -> Vec<String> {
    vec!["$0".to_string()]
}

fn split_rules(program: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut in_regex = false;
    for c in program.chars() {
        match c {
            '"' if !in_regex => in_string = !in_string,
            '/' if !in_string => in_regex = !in_regex,
            _ => {}
        }
        current.push(c);
        if c == '}' && !in_string && !in_regex {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

fn parse_pattern(src: &str) -> Option<AwkPattern> {
    let src = src.trim();
    if src.is_empty() {
        return Some(AwkPattern::Always);
    }

    if let Some(body) = src.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
        if body.contains(REGEX_METACHARACTERS) {
            return None;
        }
        let literal = body.trim_start_matches('^').trim_end_matches('$');
        return Some(AwkPattern::Contains(literal.to_string()));
    }
    if let Some(rest) = src.strip_prefix("NR") {
        let rest = rest.trim().strip_prefix("==")?.trim();
        return rest.parse().ok().map(AwkPattern::LineIs);
    }
    let rest = src.strip_prefix('$')?;
    let (negate, operator) = if rest.contains("!=") {
        (true, "!=")
    } else {
        (false, "==")
    };
    let (idx, value) = rest.split_once(operator)?;
    Some(AwkPattern::FieldEq {
        field: idx.trim().parse().ok()?,
        value: value.trim().trim_matches('"').to_string(),
        negate,
    })
}

fn parse_print(body: &str) -> Option<Vec<String>> {
    let body = body.trim().trim_end_matches(';').trim();
    if body.is_empty() || body == "print" {
        return Some(whole_line());
    }
    let rest = body.strip_prefix("print ")?;
    Some(
        rest.split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect(),
    )
}

impl Record<'_> {
    fn matches(&self, pattern: &AwkPattern) -> bool {
        match pattern {
            AwkPattern::Always => true,
            AwkPattern::Contains(needle) => self.line.contains(needle.as_str()),
            AwkPattern::LineIs(n) => *n == self.number,
            AwkPattern::FieldEq {
                field,
                value,
                negate,
            } => (self.field(*field) == *value) != *negate,
        }
    }

    fn render(&self, items: &[String]) -> String {
        let rendered: Vec<String> = items.iter().map(|item| self.value(item)).collect();
        rendered.join(" ")
    }

    fn value(&self, item: &str) -> String {
        if let Some(n) = item
            .strip_prefix('$')
            .and_then(|idx| idx.trim().parse::<usize>().ok())
        {
            return self.field(n);
        }
        match item {
            "NR" => self.number.to_string(),
            "NF" => self.fields.len().to_string(),
            s if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 => {
                s[1..s.len() - 1].to_string()
            }

            _ => String::new(),
        }
    }

    fn field(&self, n: usize) -> String {
        if n == 0 {
            return self.line.to_string();
        }
        self.fields.get(n - 1).cloned().unwrap_or_default()
    }
}

fn split_fields(line: &str, sep: Option<&str>) -> Vec<String> {
    match sep {
        None | Some("" | " ") => line.split_whitespace().map(str::to_string).collect(),

        Some("\\t") => line.split('\t').map(str::to_string).collect(),
        Some(s) => line.split(s).map(str::to_string).collect(),
    }
}
