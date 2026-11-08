use super::format::{
    allocated_kib, format_time, gid_name, human_size, mode_string, node_size, uid_name,
};
use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::nodes::NodeKind;
use crate::vfs::{NodeId, Vfs};

#[derive(Default)]
struct LsFlags {
    all: bool,
    almost_all: bool,
    directory: bool,
    long: bool,
    human: bool,
    one: bool,
}

pub fn ls(shell: &Shell, args: &[String]) -> CommandResult {
    let mut flags = LsFlags::default();
    let mut paths: Vec<&str> = Vec::new();

    if !shell.stdout_is_tty {
        flags.one = true;
    }

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for ch in arg[1..].chars() {
                match ch {
                    'a' => flags.all = true,
                    'A' => flags.almost_all = true,
                    'd' => flags.directory = true,
                    'l' => flags.long = true,
                    'h' => flags.human = true,
                    '1' => flags.one = true,
                    'F' | 'C' | 'r' | 't' | 'R' | 'S' => {}
                    other => {
                        return CommandResult::err(
                            format!(
                                "ls: invalid option -- '{other}'\nTry 'ls --help' for more information.\n"
                            ),
                            2,
                        );
                    }
                }
            }
        } else if arg == "--all" {
            flags.all = true;
        } else if arg == "--almost-all" {
            flags.almost_all = true;
        } else if arg == "--directory" {
            flags.directory = true;
        } else {
            paths.push(arg);
        }
    }

    if paths.is_empty() {
        paths.push(".");
    }

    let multiple = paths.len() > 1;
    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;

    for path in paths.iter() {
        let Some(target) = shell.vfs.resolve(shell.cwd, path) else {
            errs.push_str(&format!(
                "ls: cannot access '{path}': No such file or directory\n"
            ));
            status = 2;
            continue;
        };

        let node = shell.vfs.node(target);
        if flags.directory || !node.meta.is_dir() {
            out.push_str(&format_single(&shell.vfs, target, path, &flags));
            continue;
        }

        if !node.meta.readable_by(shell.uid, shell.gid) {
            errs.push_str(&format!(
                "ls: cannot open directory '{path}': Permission denied\n"
            ));
            status = 2;
            continue;
        }

        if multiple {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("{path}:\n"));
        }
        out.push_str(&list_dir(&shell.vfs, target, &flags));
    }

    CommandResult::streams(out, errs, status)
}

fn list_dir(vfs: &Vfs, dir: NodeId, flags: &LsFlags) -> String {
    let mut names: Vec<(String, NodeId)> = Vec::new();

    if flags.all {
        names.push((".".to_string(), dir));
        let parent = vfs.node(dir).parent.unwrap_or(dir);
        names.push(("..".to_string(), parent));
    }
    for (name, id) in vfs.entries(dir).unwrap_or_default() {
        if name.starts_with('.') && !flags.all && !flags.almost_all {
            continue;
        }
        names.push((name, id));
    }

    if flags.long {
        let mut out = String::new();

        let total: u64 = names.iter().map(|(_, id)| allocated_kib(vfs, *id)).sum();
        out.push_str(&format!("total {total}\n"));
        for (name, id) in &names {
            out.push_str(&long_entry(vfs, *id, name, flags));
            out.push('\n');
        }
        out
    } else if flags.one {
        names
            .iter()
            .map(|(n, _)| format!("{n}\n"))
            .collect::<String>()
    } else {
        let line = names
            .iter()
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
            .join("  ");
        if line.is_empty() {
            String::new()
        } else {
            format!("{line}\n")
        }
    }
}

fn format_single(vfs: &Vfs, id: NodeId, display: &str, flags: &LsFlags) -> String {
    if flags.long {
        format!("{}\n", long_entry(vfs, id, display, flags))
    } else {
        format!("{display}\n")
    }
}

fn long_entry(vfs: &Vfs, id: NodeId, name: &str, flags: &LsFlags) -> String {
    let node = vfs.node(id);
    let mode = mode_string(node.meta.mode);
    let nlink = match &node.kind {
        NodeKind::Directory { children } => children.len() + 2,
        _ => 1,
    };
    let owner = uid_name(node.meta.uid);
    let group = gid_name(node.meta.gid);
    let size = node_size(node);
    let size = if flags.human {
        human_size(size)
    } else {
        size.to_string()
    };
    let date = format_time(node.meta.mtime);

    let suffix = if node.meta.is_symlink() {
        if let NodeKind::Symlink { target } = &node.kind {
            format!(" -> {target}")
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    format!("{mode} {nlink:>2} {owner:<8} {group:<8} {size:>6} {date} {name}{suffix}")
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn ls_lists_and_hides_dotfiles() {
        let mut shell = Shell::new("root", "debian");
        let plain = run(&mut shell, "ls /");
        assert!(plain.contains("etc"));
        assert!(plain.contains("root"));

        assert!(!run(&mut shell, "ls").contains(".bashrc"));
        assert!(run(&mut shell, "ls -a").contains(".bashrc"));
    }

    #[test]
    fn ls_long_totals_the_entries_it_prints() {
        let mut shell = Shell::new("root", "debian");

        assert!(run(&mut shell, "ls -l /").starts_with("total "));
        assert!(run(&mut shell, "ls -la /").starts_with("total "));

        assert!(!run(&mut shell, "ls -l /etc/hostname").contains("total"));

        run(&mut shell, "mkdir /tmp/t && cd /tmp/t");
        assert_eq!(run(&mut shell, "ls -l"), "total 0\n");

        run(&mut shell, "touch empty");
        assert!(run(&mut shell, "ls -l").starts_with("total 0\n"));
        run(&mut shell, "echo hello > small");
        assert!(run(&mut shell, "ls -l").starts_with("total 4\n"));
        assert!(run(&mut shell, "ls -la").starts_with("total 12\n"));
    }

    #[test]
    fn ls_missing_path_errors() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "ls /nope");
        assert!(out.contains("cannot access '/nope': No such file or directory"));
    }

    #[test]
    fn ls_directory_flag_lists_dirs_without_descending() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "ls -d /tmp"), "/tmp\n");
        assert_eq!(run(&mut shell, "ls --directory /tmp"), "/tmp\n");
        assert_eq!(run(&mut shell, "ls -d"), ".\n");

        let ld_tmp = run(&mut shell, "ls -ld /tmp");
        assert!(ld_tmp.starts_with("drwxrwxrwx") || ld_tmp.starts_with("drwxrwxrwt"));
        assert!(ld_tmp.ends_with("/tmp\n"));
        assert!(!ld_tmp.contains("total"));

        let mut user = Shell::new("attacker", "debian");
        let ld_root = run(&mut user, "ls -ld /root");
        assert!(ld_root.starts_with("drwx------"));
        assert!(ld_root.ends_with("/root\n"));
        assert!(!ld_root.contains("Permission denied"));
    }

    #[test]
    fn ls_enforces_directory_read_permissions() {
        let mut user = Shell::new("attacker", "debian");
        let out = user.execute("ls -la /root");
        assert!(
            out.text
                .contains("ls: cannot open directory '/root': Permission denied"),
            "unprivileged ls of /root must be denied, got: {out:?}",
            out = out.text
        );
        assert!(!user.execute("ls -la /root").text.contains(".bashrc"));

        let mut root = Shell::new("root", "debian");
        assert!(root.execute("ls -la /root").text.contains(".bashrc"));
    }
}
