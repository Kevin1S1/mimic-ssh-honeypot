use super::{basename, resolve_parent, strip_trailing_slashes};
use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::Vfs;

pub fn touch(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut no_create = false;
    let mut operands: Vec<&str> = Vec::new();
    let mut skip_value = false;

    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        match arg.as_str() {
            "-c" | "--no-create" => no_create = true,

            "-r" | "--reference" | "-d" | "--date" | "-t" => skip_value = true,
            "-a" | "-m" | "--time" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {}
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        return CommandResult::err(
            "touch: missing file operand\nTry 'touch --help' for more information.\n",
            1,
        );
    }

    let (uid, gid) = (shell.uid, shell.gid);
    let mut out = String::new();
    let mut status = 0;
    for path in operands {
        match resolve_parent(shell, path) {
            Some((parent, name)) => {
                if no_create && shell.vfs.child(parent, &name).is_none() {
                    continue;
                }
                if shell.vfs.child(parent, &name).is_none() && shell.vfs.is_full(parent) {
                    out.push_str(&format!(
                        "touch: cannot touch '{path}': No space left on device
"
                    ));
                    status = 1;
                    continue;
                }
                shell.vfs.touch(parent, &name, uid, gid);
            }
            None => {
                out.push_str(&format!(
                    "touch: cannot touch '{path}': No such file or directory\n"
                ));
                status = 1;
            }
        }
    }
    CommandResult::err(out, status)
}

pub fn mkdir(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut parents = false;
    let mut operands: Vec<&str> = Vec::new();
    let mut skip_value = false;

    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        match arg.as_str() {
            "-p" | "--parents" => parents = true,
            "-v" | "--verbose" => {}
            "-m" | "--mode" => skip_value = true,
            other if other.starts_with("-m") && other.len() > 2 => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                if other.contains('p') {
                    parents = true;
                }
            }
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        return CommandResult::err(
            "mkdir: missing operand\nTry 'mkdir --help' for more information.\n",
            1,
        );
    }

    let (uid, gid) = (shell.uid, shell.gid);
    let mut out = String::new();
    let mut status = 0;
    for path in operands {
        if parents {
            let mut current = if path.starts_with('/') {
                shell.vfs.root()
            } else {
                shell.cwd
            };
            for comp in strip_trailing_slashes(path).split('/') {
                match comp {
                    "" | "." => continue,
                    ".." => current = shell.vfs.node(current).parent.unwrap_or(current),
                    name => {
                        if let Some(child) = shell.vfs.child(current, name) {
                            if !shell.vfs.node(child).meta.is_dir() {
                                out.push_str(&format!(
                                    "mkdir: cannot create directory '{path}': Not a directory\n"
                                ));
                                status = 1;
                                break;
                            }
                            current = child;
                        } else if shell.vfs.is_full(current) {
                            out.push_str(&format!(
                                "mkdir: cannot create directory '{path}': No space left on device\n"
                            ));
                            status = 1;
                            break;
                        } else {
                            current = shell.vfs.mkdir(current, name, 0o755, uid, gid);
                        }
                    }
                }
            }
            continue;
        }

        match resolve_parent(shell, path) {
            Some((parent, name)) => {
                if shell.vfs.child(parent, &name).is_some() {
                    out.push_str(&format!(
                        "mkdir: cannot create directory '{path}': File exists\n"
                    ));
                    status = 1;
                } else if shell.vfs.is_full(parent) {
                    out.push_str(&format!(
                        "mkdir: cannot create directory '{path}': No space left on device
"
                    ));
                    status = 1;
                } else {
                    shell.vfs.mkdir(parent, &name, 0o755, uid, gid);
                }
            }
            None => {
                out.push_str(&format!(
                    "mkdir: cannot create directory '{path}': No such file or directory\n"
                ));
                status = 1;
            }
        }
    }
    CommandResult::err(out, status)
}

pub fn rmdir(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut parents = false;
    let mut operands: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-p" | "--parents" => parents = true,
            "-v" | "--verbose" | "--ignore-fail-on-non-empty" => {}
            other if other.starts_with('-') && other.len() > 1 => {}
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        return CommandResult::err(
            "rmdir: missing operand\nTry 'rmdir --help' for more information.\n",
            1,
        );
    }

    let mut out = String::new();
    let mut status = 0;
    for path in operands {
        let mut p = strip_trailing_slashes(path).to_string();
        loop {
            let Some((parent, name)) = resolve_parent(shell, &p) else {
                out.push_str(&format!(
                    "rmdir: failed to remove '{p}': No such file or directory\n"
                ));
                status = 1;
                break;
            };
            let Some(target) = shell.vfs.child(parent, &name) else {
                out.push_str(&format!(
                    "rmdir: failed to remove '{p}': No such file or directory\n"
                ));
                status = 1;
                break;
            };
            if !shell.vfs.node(target).meta.is_dir() {
                out.push_str(&format!("rmdir: failed to remove '{p}': Not a directory\n"));
                status = 1;
                break;
            }
            let empty = shell
                .vfs
                .entries(target)
                .map(|e| e.is_empty())
                .unwrap_or(true);
            if !empty {
                out.push_str(&format!(
                    "rmdir: failed to remove '{p}': Directory not empty\n"
                ));
                status = 1;
                break;
            }
            shell.vfs.unlink(parent, &name);
            if !parents {
                break;
            }

            let (dir, _) = Vfs::split_path(&p);
            if dir == "." || dir == "/" || dir.is_empty() {
                break;
            }
            p = dir.to_string();
        }
    }
    CommandResult::err(out, status)
}

pub fn rm(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut recursive = false;
    let mut force = false;
    let mut dir_ok = false;
    let mut operands: Vec<&str> = Vec::new();

    for arg in args {
        match arg.as_str() {
            "-r" | "-R" | "--recursive" => recursive = true,
            "-f" | "--force" => force = true,
            "-d" | "--dir" => dir_ok = true,
            "-v" | "--verbose" | "-i" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                for ch in other[1..].chars() {
                    match ch {
                        'r' | 'R' => recursive = true,
                        'f' => force = true,
                        'd' => dir_ok = true,
                        _ => {}
                    }
                }
            }
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        if force {
            return CommandResult::empty();
        }
        return CommandResult::err(
            "rm: missing operand\nTry 'rm --help' for more information.\n",
            1,
        );
    }

    let mut out = String::new();
    let mut status = 0;
    for path in operands {
        let base = basename(path);
        if base == "." || base == ".." {
            out.push_str(&format!(
                "rm: refusing to remove '.' or '..' directory: skipping '{path}'\n"
            ));
            status = 1;
            continue;
        }

        let Some((parent, name)) = resolve_parent(shell, path) else {
            if !force {
                out.push_str(&format!(
                    "rm: cannot remove '{path}': No such file or directory\n"
                ));
                status = 1;
            }
            continue;
        };
        let Some(target) = shell.vfs.child(parent, &name) else {
            if !force {
                out.push_str(&format!(
                    "rm: cannot remove '{path}': No such file or directory\n"
                ));
                status = 1;
            }
            continue;
        };

        if shell.vfs.node(target).meta.is_dir() {
            let empty = shell
                .vfs
                .entries(target)
                .map(|e| e.is_empty())
                .unwrap_or(true);
            if !recursive {
                if !dir_ok {
                    out.push_str(&format!("rm: cannot remove '{path}': Is a directory\n"));
                    status = 1;
                    continue;
                }
                if !empty {
                    out.push_str(&format!(
                        "rm: cannot remove '{path}': Directory not empty\n"
                    ));
                    status = 1;
                    continue;
                }
            }
        }
        shell.vfs.unlink(parent, &name);
    }
    CommandResult::err(out, status)
}

pub fn cp(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut recursive = false;
    let mut operands: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-r" | "-R" | "--recursive" | "-a" | "--archive" => recursive = true,
            "-v" | "--verbose" | "-f" | "-p" | "-i" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {
                for ch in other[1..].chars() {
                    if ch == 'r' || ch == 'R' || ch == 'a' {
                        recursive = true;
                    }
                }
            }
            other => operands.push(other),
        }
    }

    if operands.len() < 2 {
        let missing = if operands.is_empty() {
            "missing file operand"
        } else {
            "missing destination file operand"
        };
        return CommandResult::err(
            format!("cp: {missing}\nTry 'cp --help' for more information.\n"),
            1,
        );
    }

    let dest = operands.pop().expect("at least two operands");
    let dest_dir = shell
        .vfs
        .resolve(shell.cwd, dest)
        .filter(|&id| shell.vfs.node(id).meta.is_dir());

    if operands.len() > 1 && dest_dir.is_none() {
        return CommandResult::err(format!("cp: target '{dest}' is not a directory\n"), 1);
    }

    let mut out = String::new();
    let mut status = 0;
    for src in operands {
        let Some(src_id) = shell.vfs.resolve(shell.cwd, src) else {
            out.push_str(&format!(
                "cp: cannot stat '{src}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        if shell.vfs.node(src_id).meta.is_dir() && !recursive {
            out.push_str(&format!(
                "cp: -r not specified; omitting directory '{src}'\n"
            ));
            status = 1;
            continue;
        }

        let (parent, name) = if let Some(dir) = dest_dir {
            (dir, basename(src).to_string())
        } else {
            match resolve_parent(shell, dest) {
                Some(pn) => pn,
                None => {
                    out.push_str(&format!(
                        "cp: cannot create regular file '{dest}': No such file or directory\n"
                    ));
                    status = 1;
                    continue;
                }
            }
        };

        if shell.vfs.child(parent, &name).is_none() && shell.vfs.is_full(parent) {
            out.push_str(&format!(
                "cp: cannot create regular file '{name}': No space left on device\n"
            ));
            status = 1;
            continue;
        }
        shell.vfs.deep_copy(src_id, parent, &name);
    }
    CommandResult::err(out, status)
}

pub fn mv(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut operands: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-v" | "--verbose" | "-f" | "-i" | "-n" | "--no-clobber" => {}
            other if other.starts_with('-') && other.len() > 1 && !other.starts_with("--") => {}
            other => operands.push(other),
        }
    }

    if operands.len() < 2 {
        let missing = if operands.is_empty() {
            "missing file operand"
        } else {
            "missing destination file operand"
        };
        return CommandResult::err(
            format!("mv: {missing}\nTry 'mv --help' for more information.\n"),
            1,
        );
    }

    let dest = operands.pop().expect("at least two operands");
    let dest_dir = shell
        .vfs
        .resolve(shell.cwd, dest)
        .filter(|&id| shell.vfs.node(id).meta.is_dir());

    if operands.len() > 1 && dest_dir.is_none() {
        return CommandResult::err(format!("mv: target '{dest}' is not a directory\n"), 1);
    }

    let mut out = String::new();
    let mut status = 0;
    for src in operands {
        let Some((src_parent, src_name)) = resolve_parent(shell, src) else {
            out.push_str(&format!(
                "mv: cannot stat '{src}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        let Some(src_id) = shell.vfs.child(src_parent, &src_name) else {
            out.push_str(&format!(
                "mv: cannot stat '{src}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };

        let (parent, name) = if let Some(dir) = dest_dir {
            (dir, basename(src).to_string())
        } else {
            match resolve_parent(shell, dest) {
                Some(pn) => pn,
                None => {
                    out.push_str(&format!(
                        "mv: cannot move '{src}' to '{dest}': No such file or directory\n"
                    ));
                    status = 1;
                    continue;
                }
            }
        };
        if !shell.vfs.rename(src_id, parent, &name) {
            if shell.vfs.is_ancestor_of(src_id, parent) {
                out.push_str(&format!(
                    "mv: cannot move '{src}' to a subdirectory of itself, '{dest}/{name}'\n"
                ));
            } else {
                out.push_str(&format!(
                    "mv: cannot move '{src}' to '{dest}': File name too long\n"
                ));
            }
            status = 1;
        }
    }
    CommandResult::err(out, status)
}
pub fn ln(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut symbolic = false;
    let mut force = false;
    let mut operands: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-s" | "--symbolic" => symbolic = true,
            "-f" | "--force" => force = true,
            "-sf" | "-fs" => {
                symbolic = true;
                force = true;
            }
            other if other.starts_with('-') && other.len() > 1 => {}
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        return CommandResult::err(
            "ln: missing file operand\nTry 'ln --help' for more information.\n",
            1,
        );
    }

    let target = operands[0];

    let link = operands.get(1).copied().unwrap_or_else(|| basename(target));

    if !symbolic {
        return CommandResult::err(
            format!(
                "ln: failed to create hard link '{link}' => '{target}': Invalid cross-device link\n"
            ),
            1,
        );
    }

    let (parent, name) = match shell.vfs.resolve(shell.cwd, link) {
        Some(id) if shell.vfs.node(id).meta.is_dir() => (id, basename(target).to_string()),
        _ => match resolve_parent(shell, link) {
            Some(pair) => pair,
            None => {
                return CommandResult::err(
                    format!(
                        "ln: failed to create symbolic link '{link}': No such file or directory\n"
                    ),
                    1,
                )
            }
        },
    };

    if shell.vfs.child(parent, &name).is_some() {
        if !force {
            return CommandResult::err(
                format!("ln: failed to create symbolic link '{name}': File exists\n"),
                1,
            );
        }
        shell.vfs.unlink(parent, &name);
    }

    let id = shell.vfs.add_symlink(parent, &name, target);
    if id == parent {
        return CommandResult::err(
            format!("ln: failed to create symbolic link '{name}': No space left on device\n"),
            1,
        );
    }
    CommandResult::empty()
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn touch_mkdir_and_cat_roundtrip() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "mkdir /tmp/d"), "");
        assert_eq!(run(&mut shell, "touch /tmp/d/f"), "");

        assert!(run(&mut shell, "ls /tmp/d").contains("f"));
        assert_eq!(run(&mut shell, "cat /tmp/d/f"), "");

        assert!(run(&mut shell, "mkdir /tmp/d").contains("File exists"));
        assert_eq!(run(&mut shell, "mkdir -p /tmp/d/e/f"), "");
        assert!(run(&mut shell, "ls /tmp/d/e").contains("f"));
    }

    #[test]
    fn rm_and_rmdir_enforce_directory_rules() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir /tmp/x");
        run(&mut shell, "touch /tmp/x/f");

        assert!(run(&mut shell, "rm /tmp/x").contains("Is a directory"));
        assert!(run(&mut shell, "rmdir /tmp/x").contains("Directory not empty"));

        assert_eq!(run(&mut shell, "rm -rf /tmp/x"), "");
        assert!(run(&mut shell, "ls /tmp/x").contains("No such file or directory"));

        assert_eq!(run(&mut shell, "rm -f /tmp/gone"), "");
    }

    #[test]
    fn cp_and_mv_move_content() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir /tmp/src");
        run(&mut shell, "touch /tmp/a");
        assert_eq!(run(&mut shell, "cp /tmp/a /tmp/b"), "");
        assert!(run(&mut shell, "ls /tmp").contains("b"));

        assert_eq!(run(&mut shell, "mv /tmp/a /tmp/src/c"), "");
        assert!(run(&mut shell, "ls /tmp").contains("b"));
        assert!(run(&mut shell, "cat /tmp/a").contains("No such file or directory"));
        assert!(run(&mut shell, "ls /tmp/src").contains("c"));

        assert!(run(&mut shell, "cp /tmp/src /tmp/d").contains("omitting directory"));
    }

    #[test]
    fn mv_refuses_move_into_own_subdirectory() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/a/b");
        let out = run(&mut shell, "mv /tmp/a /tmp/a/b");
        assert!(
            out.contains("cannot move '/tmp/a' to a subdirectory of itself"),
            "unexpected output: {out}"
        );

        assert!(run(&mut shell, "ls /tmp").contains('a'));
        run(&mut shell, "cd /tmp/a/b");
        assert_eq!(run(&mut shell, "pwd"), "/tmp/a/b\n");
    }

    #[test]
    fn deep_directory_chains_are_refused_not_silently_dropped() {
        let mut shell = Shell::new("root", "debian");
        let chain = "a/".repeat(200);
        let out = run(&mut shell, &format!("mkdir -p /tmp/{chain}"));
        assert!(out.contains("No space left on device"), "{out}");

        run(&mut shell, &format!("mkdir -p /tmp/x/{}", "b/".repeat(100)));
        let out = run(&mut shell, &format!("mv /tmp/x /tmp/{}a", "a/".repeat(30)));
        assert!(out.contains("File name too long"), "{out}");

        run(&mut shell, "tar cf /tmp/t.tar /tmp; find /tmp; du /tmp");
    }

    #[test]
    fn ln_creates_a_symlink_and_refuses_a_hard_one() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "echo hi > /tmp/real");
        assert_eq!(run(&mut shell, "ln -s /tmp/real /tmp/link"), "");

        assert!(run(&mut shell, "ls -l /tmp").contains("link -> /tmp/real"));

        assert_eq!(run(&mut shell, "cat /tmp/link"), "hi\n");

        let clash = shell.execute("ln -s /tmp/real /tmp/link");
        assert_eq!(clash.status, 1);
        assert!(clash.stderr.contains("File exists"));
        assert_eq!(shell.execute("ln -sf /tmp/real /tmp/link").status, 0);

        let hard = shell.execute("ln /tmp/real /tmp/hard");
        assert_eq!(hard.status, 1);
        assert!(hard.stderr.contains("Invalid cross-device link"));
    }

    #[test]
    fn ln_into_a_directory_uses_the_target_basename() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "echo x > /tmp/payload.sh");
        assert_eq!(run(&mut shell, "ln -s /tmp/payload.sh /etc"), "");
        assert!(run(&mut shell, "ls /etc").contains("payload.sh"));
    }
}
