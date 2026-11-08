use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::{NodeId, Vfs};

pub fn find(shell: &Shell, args: &[String]) -> CommandResult {
    let mut start_path = ".";
    let mut name_pattern: Option<&str> = None;
    let mut type_filter: Option<char> = None;
    let mut first_operand = true;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-name" | "-iname" => name_pattern = iter.next().map(String::as_str),
            "-type" => type_filter = iter.next().and_then(|s| s.chars().next()),
            "-maxdepth" | "-mindepth" => {
                iter.next();
            }
            other if first_operand && !other.starts_with('-') => {
                start_path = other;
                first_operand = false;
            }
            _ => {}
        }
    }

    let Some(root) = shell.vfs.resolve(shell.cwd, start_path) else {
        return CommandResult::err(
            format!("find: '{start_path}': No such file or directory\n"),
            1,
        );
    };

    let mut out = String::new();
    find_walk(
        &shell.vfs,
        root,
        start_path,
        name_pattern,
        type_filter,
        &mut out,
    );
    CommandResult::ok(out)
}

fn find_walk(
    vfs: &Vfs,
    id: NodeId,
    path: &str,
    name: Option<&str>,
    type_filter: Option<char>,
    out: &mut String,
) {
    let node = vfs.node(id);
    let is_dir = node.meta.is_dir();
    let base = if node.name.is_empty() {
        path
    } else {
        node.name.as_str()
    };
    let type_ok = match type_filter {
        Some('d') => is_dir,
        Some('f') => !is_dir,
        _ => true,
    };
    let name_ok = name.map(|p| glob_match(p, base)).unwrap_or(true);
    if type_ok && name_ok {
        out.push_str(path);
        out.push('\n');
    }

    if is_dir {
        if let Some(entries) = vfs.entries(id) {
            for (child_name, child_id) in entries {
                let child_path = format!("{}/{}", path.trim_end_matches('/'), child_name);
                find_walk(vfs, child_id, &child_path, name, type_filter, out);
            }
        }
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);

    let mut star: Option<usize> = None;
    let mut resume = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            resume = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn find_walks_and_filters_by_name_and_type() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/d/sub");
        run(&mut shell, "touch /tmp/d/a.txt");
        run(&mut shell, "touch /tmp/d/sub/b.txt");
        let out = run(&mut shell, "find /tmp/d -name *.txt");
        assert!(out.contains("/tmp/d/a.txt"));
        assert!(out.contains("/tmp/d/sub/b.txt"));
        let dirs_only = run(&mut shell, "find /tmp/d -type d");
        assert!(dirs_only.contains("/tmp/d/sub"));
        assert!(!dirs_only.contains("a.txt"));
    }

    #[test]
    fn glob_match_semantics_and_pathological_pattern() {
        use super::glob_match;

        assert!(glob_match("*.txt", "a.txt"));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("*", ""));
        assert!(glob_match("**b", "ab"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("*.txt", "a.txtx"));
        assert!(glob_match("a*b*c", "axxbyyc"));

        let pattern = "*a".repeat(24) + "b";
        let text = "a".repeat(2048);
        assert!(!glob_match(&pattern, &text));
    }
}
