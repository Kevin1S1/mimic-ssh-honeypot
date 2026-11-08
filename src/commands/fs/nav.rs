use crate::commands::CommandResult;
use crate::shell::Shell;

pub fn cd(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut announce = false;
    let target_path = match args.first().map(String::as_str) {
        None | Some("~") => shell.vfs.path_of(shell.home),
        Some("-") => {
            announce = true;
            shell.vfs.path_of(shell.prev_cwd)
        }
        Some(path) if path.starts_with("~/") => {
            format!("{}/{}", shell.vfs.path_of(shell.home), &path[2..])
        }
        Some(path) => path.to_string(),
    };

    let Some(target) = shell.vfs.resolve(shell.cwd, &target_path) else {
        return CommandResult::err(
            format!("-bash: cd: {target_path}: No such file or directory\n"),
            1,
        );
    };

    let meta = &shell.vfs.node(target).meta;
    if !meta.is_dir() {
        return CommandResult::err(format!("-bash: cd: {target_path}: Not a directory\n"), 1);
    }

    if !meta.executable_by(shell.uid, shell.gid) {
        return CommandResult::err(format!("-bash: cd: {target_path}: Permission denied\n"), 1);
    }

    shell.prev_cwd = shell.cwd;
    shell.cwd = target;
    let pwd = shell.vfs.path_of(target);
    shell.env.set("PWD", &pwd);
    if announce {
        CommandResult::ok(format!("{pwd}\n"))
    } else {
        CommandResult::empty()
    }
}

pub fn pwd(shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::ok(format!("{}\n", shell.cwd_path()))
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn pwd_and_cd_navigate() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "pwd"), "/root\n");
        assert_eq!(run(&mut shell, "cd /etc"), "");
        assert_eq!(run(&mut shell, "pwd"), "/etc\n");

        assert_eq!(run(&mut shell, "cd -"), "/root\n");
        assert_eq!(run(&mut shell, "pwd"), "/root\n");
    }

    #[test]
    fn cd_rejects_missing_and_non_dir() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "cd /nope").contains("No such file or directory"));
        assert!(run(&mut shell, "cd /etc/hostname").contains("Not a directory"));
    }

    #[test]
    fn cd_needs_the_directorys_search_bit() {
        let mut user = Shell::new("attacker", "debian");

        assert_eq!(
            run(&mut user, "cd /root"),
            "-bash: cd: /root: Permission denied\n"
        );
        assert_eq!(user.last_status, 1);
        assert_eq!(run(&mut user, "pwd"), "/home/attacker\n");

        run(&mut user, "mkdir /tmp/mine && cd /tmp/mine");
        assert_eq!(run(&mut user, "pwd"), "/tmp/mine\n");

        let mut root = Shell::new("root", "debian");
        assert_eq!(run(&mut root, "cd /root"), "");
        assert_eq!(run(&mut root, "pwd"), "/root\n");

        let mut user = Shell::new("attacker", "debian");
        run(&mut user, "mkdir /tmp/locked && cd /tmp/locked");
        assert_eq!(run(&mut user, "pwd"), "/tmp/locked\n");
        run(&mut user, "cd /tmp");
        run(&mut user, "chmod 600 /tmp/locked");
        assert_eq!(
            run(&mut user, "cd -"),
            "-bash: cd: /tmp/locked: Permission denied\n"
        );
        assert_eq!(run(&mut user, "pwd"), "/tmp\n");
    }
}
