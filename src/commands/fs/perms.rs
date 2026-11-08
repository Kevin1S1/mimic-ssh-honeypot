use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::NodeId;

pub fn chmod(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut recursive = false;
    let mut rest: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-R" | "--recursive" => recursive = true,
            "-v" | "--verbose" | "-c" | "-f" => {}
            other => rest.push(other),
        }
    }

    if rest.len() < 2 {
        return CommandResult::err(
            "chmod: missing operand\nTry 'chmod --help' for more information.\n",
            1,
        );
    }

    let mode_spec = rest.remove(0);
    let mut out = String::new();
    let mut status = 0;
    for path in rest {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            out.push_str(&format!(
                "chmod: cannot access '{path}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        match compute_mode(mode_spec, shell.vfs.node(id).meta.mode & 0o7777) {
            Some(new_perms) => apply_chmod(shell, id, new_perms, mode_spec, recursive),
            None => {
                return CommandResult::err(format!("chmod: invalid mode: '{mode_spec}'\n"), 1);
            }
        }
    }
    CommandResult::err(out, status)
}

fn apply_chmod(shell: &mut Shell, id: NodeId, perms: u32, spec: &str, recursive: bool) {
    shell.vfs.chmod(id, perms);
    if recursive && shell.vfs.node(id).meta.is_dir() {
        for (_, child) in shell.vfs.entries(id).unwrap_or_default() {
            let child_perms =
                compute_mode(spec, shell.vfs.node(child).meta.mode & 0o7777).unwrap_or(perms);
            apply_chmod(shell, child, child_perms, spec, recursive);
        }
    }
}

fn compute_mode(spec: &str, current: u32) -> Option<u32> {
    if !spec.is_empty() && spec.bytes().all(|b| b.is_ascii_digit()) {
        return u32::from_str_radix(spec, 8).ok().map(|m| m & 0o7777);
    }

    let mut mode = current;
    for clause in spec.split(',') {
        let pos = clause.find(['+', '-', '='])?;
        let (who, rest) = clause.split_at(pos);
        let op = rest.chars().next()?;
        let perms = &rest[1..];

        let mut who_mask = 0u32;
        if who.is_empty() || who.contains('a') {
            who_mask = 0o7777;
        } else {
            for c in who.chars() {
                match c {
                    'u' => who_mask |= 0o4700,
                    'g' => who_mask |= 0o2070,
                    'o' => who_mask |= 0o1007,
                    _ => return None,
                }
            }
        }

        let mut perm_bits = 0u32;
        for c in perms.chars() {
            match c {
                'r' => perm_bits |= 0o444,
                'w' => perm_bits |= 0o222,
                'x' | 'X' => perm_bits |= 0o111,
                's' => perm_bits |= 0o6000,
                't' => perm_bits |= 0o1000,
                _ => return None,
            }
        }
        let effective = perm_bits & who_mask;

        match op {
            '+' => mode |= effective,
            '-' => mode &= !effective,
            '=' => mode = (mode & !who_mask) | effective,
            _ => return None,
        }
    }
    Some(mode & 0o7777)
}
pub fn chown(shell: &mut Shell, args: &[String]) -> CommandResult {
    chown_like(shell, args, "chown")
}

pub fn chgrp(shell: &mut Shell, args: &[String]) -> CommandResult {
    chown_like(shell, args, "chgrp")
}

fn chown_like(shell: &mut Shell, args: &[String], tool: &str) -> CommandResult {
    let mut recursive = false;
    let mut rest: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-R" | "--recursive" => recursive = true,
            other if other.starts_with('-') && other.len() > 1 => {}
            other => rest.push(other),
        }
    }

    if rest.len() < 2 {
        return CommandResult::err(
            format!("{tool}: missing operand\nTry '{tool} --help' for more information.\n"),
            1,
        );
    }

    let spec = rest.remove(0);
    let Some((uid, gid)) = parse_owner_spec(spec, tool) else {
        let what = if tool == "chgrp" { "group" } else { "user" };
        return CommandResult::err(format!("{tool}: invalid {what}: '{spec}'\n"), 1);
    };

    let mut errs = String::new();
    let mut status = 0;
    for path in rest {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            errs.push_str(&format!(
                "{tool}: cannot access '{path}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };

        if shell.uid != 0 {
            errs.push_str(&format!(
                "{tool}: changing ownership of '{path}': Operation not permitted\n"
            ));
            status = 1;
            continue;
        }
        apply_chown(shell, id, uid, gid, recursive);
    }
    CommandResult::err(errs, status)
}

fn apply_chown(shell: &mut Shell, id: NodeId, uid: Option<u32>, gid: Option<u32>, recursive: bool) {
    let meta = &shell.vfs.node(id).meta;
    shell
        .vfs
        .chown(id, uid.unwrap_or(meta.uid), gid.unwrap_or(meta.gid));
    if recursive && shell.vfs.node(id).meta.is_dir() {
        for (_, child) in shell.vfs.entries(id).unwrap_or_default() {
            apply_chown(shell, child, uid, gid, recursive);
        }
    }
}

fn parse_owner_spec(spec: &str, tool: &str) -> Option<(Option<u32>, Option<u32>)> {
    if tool == "chgrp" {
        return Some((None, Some(lookup_gid(spec)?)));
    }
    let (user, group) = match spec.split_once([':', '.']) {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid = if user.is_empty() {
        None
    } else {
        Some(lookup_uid(user)?)
    };
    let gid = match group {
        Some("") => uid,
        Some(g) => Some(lookup_gid(g)?),
        None => None,
    };
    Some((uid, gid))
}

fn lookup_uid(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Some(n);
    }
    match name {
        "root" => Some(0),
        "daemon" => Some(1),
        "bin" => Some(2),
        "sys" => Some(3),
        "www-data" => Some(33),
        "nobody" => Some(65534),
        "debian" => Some(1000),
        _ => None,
    }
}

fn lookup_gid(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Some(n);
    }
    match name {
        "root" => Some(0),
        "daemon" => Some(1),
        "bin" => Some(2),
        "sys" => Some(3),
        "adm" => Some(4),
        "www-data" => Some(33),
        "shadow" => Some(42),
        "nogroup" => Some(65534),
        "debian" => Some(1000),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn chmod_octal_and_symbolic() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "touch /tmp/f");
        assert_eq!(run(&mut shell, "chmod 600 /tmp/f"), "");
        assert!(run(&mut shell, "ls -l /tmp/f").contains("-rw-------"));
        assert_eq!(run(&mut shell, "chmod u+x /tmp/f"), "");
        assert!(run(&mut shell, "ls -l /tmp/f").contains("-rwx------"));
        assert!(run(&mut shell, "chmod 9z9 /tmp/f").contains("invalid mode"));
    }

    #[test]
    fn chown_changes_ownership_and_only_root_may() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "echo x > /tmp/f");
        assert_eq!(run(&mut shell, "chown www-data:adm /tmp/f"), "");

        let listing = run(&mut shell, "ls -l /tmp/f");
        assert!(listing.contains("www-data"), "{listing}");
        assert!(listing.contains("adm"), "{listing}");

        let bad = shell.execute("chown nosuchuser /tmp/f");
        assert_eq!(bad.status, 1);
        assert!(bad.stderr.contains("invalid user"));

        let mut user = Shell::new("debian", "debian");
        user.execute("echo x > /tmp/g");
        let denied = user.execute("chown root /tmp/g");
        assert_eq!(denied.status, 1);
        assert!(denied.stderr.contains("Operation not permitted"));
    }
}
