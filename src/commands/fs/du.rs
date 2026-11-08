use super::format::{allocated_kib, human_size};
use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::NodeId;

struct DuFlags {
    summarise: bool,
    human: bool,
    all: bool,
    unit: u64,
    max_depth: Option<usize>,
}

pub fn du(shell: &Shell, args: &[String]) -> CommandResult {
    let mut flags = DuFlags {
        summarise: false,
        human: false,
        all: false,
        unit: 1024,
        max_depth: None,
    };
    let mut operands: Vec<&str> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-d" | "--max-depth" => flags.max_depth = iter.next().and_then(|v| v.parse().ok()),
            "--summarize" => flags.summarise = true,
            "--human-readable" => flags.human = true,
            "--all" => flags.all = true,
            s if s.starts_with("--max-depth=") => {
                flags.max_depth = s["--max-depth=".len()..].parse().ok()
            }
            s if s.starts_with("--") => {}

            s if s.starts_with('-') && s.len() > 1 => {
                for c in s[1..].chars() {
                    match c {
                        's' => flags.summarise = true,
                        'h' => flags.human = true,
                        'a' => flags.all = true,
                        'k' => flags.unit = 1024,
                        'm' => flags.unit = 1024 * 1024,
                        _ => {}
                    }
                }
            }
            other => operands.push(other),
        }
    }
    if operands.is_empty() {
        operands.push(".");
    }

    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    for path in operands {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            errs.push_str(&format!(
                "du: cannot access '{path}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        du_walk(shell, id, path, 0, &flags, &mut out);
    }
    CommandResult::streams(out, errs, status)
}

fn du_walk(
    shell: &Shell,
    id: NodeId,
    path: &str,
    depth: usize,
    flags: &DuFlags,
    out: &mut String,
) -> u64 {
    let mut total = allocated_kib(&shell.vfs, id);
    let is_dir = shell.vfs.node(id).meta.is_dir();

    if is_dir {
        for (name, child) in shell.vfs.entries(id).unwrap_or_default() {
            let child_path = if path.ends_with('/') {
                format!("{path}{name}")
            } else {
                format!("{path}/{name}")
            };
            total += du_walk(shell, child, &child_path, depth + 1, flags, out);
        }
    }

    let too_deep = flags.max_depth.is_some_and(|d| depth > d);
    let visible = if flags.summarise {
        depth == 0
    } else {
        !too_deep && (is_dir || flags.all)
    };
    if visible {
        let size = if flags.human {
            human_size(total * 1024)
        } else {
            (total * 1024 / flags.unit).to_string()
        };
        out.push_str(&format!("{size}\t{path}\n"));
    }
    total
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn du_totals_match_the_ls_block_model() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/d/sub");
        run(&mut shell, "echo hello > /tmp/d/sub/f");

        let summary = run(&mut shell, "du -s /tmp/d");
        let kib: u64 = summary.split('\t').next().unwrap().parse().unwrap();
        assert_eq!(kib, 4 + 4 + 4, "two directories and one short file");
        assert!(summary.ends_with("/tmp/d\n"));

        assert!(run(&mut shell, "du -sh /tmp/d").starts_with("12.0K"));

        let full = run(&mut shell, "du /tmp/d");
        let lines: Vec<&str> = full.lines().collect();
        assert_eq!(lines.len(), 2, "{full}");
        assert!(lines[0].ends_with("/tmp/d/sub"));
        assert!(lines[1].ends_with("/tmp/d"));

        assert!(run(&mut shell, "du -a /tmp/d").contains("/tmp/d/sub/f"));
    }
}
