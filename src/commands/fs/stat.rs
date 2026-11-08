use super::format::{allocated_kib, gid_name, mode_string, node_size, uid_name};
use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::nodes::NodeKind;
use crate::vfs::{Node, NodeId};

pub fn stat(shell: &Shell, args: &[String]) -> CommandResult {
    let mut format: Option<String> = None;
    let mut terse = false;
    let mut operands: Vec<&str> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--format" | "--printf" => format = iter.next().cloned(),
            "-t" | "--terse" => terse = true,
            s if s.starts_with("-c") && s.len() > 2 => format = Some(s[2..].to_string()),
            s if s.starts_with("--format=") => format = Some(s["--format=".len()..].to_string()),
            s if s.starts_with('-') && s.len() > 1 => {}
            other => operands.push(other),
        }
    }

    if operands.is_empty() {
        return CommandResult::err(
            "stat: missing operand\nTry 'stat --help' for more information.\n",
            1,
        );
    }

    let mut out = String::new();
    let mut errs = String::new();
    let mut status = 0;
    for path in operands {
        let Some(id) = shell.vfs.resolve(shell.cwd, path) else {
            errs.push_str(&format!(
                "stat: cannot statx '{path}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        out.push_str(&match (&format, terse) {
            (Some(f), _) => format!("{}\n", stat_format(shell, id, path, f)),
            (None, true) => format!("{}\n", stat_terse(shell, id, path)),
            (None, false) => stat_long(shell, id, path),
        });
    }
    CommandResult::streams(out, errs, status)
}

fn stat_format(shell: &Shell, id: NodeId, path: &str, fmt: &str) -> String {
    let node = shell.vfs.node(id);
    let meta = &node.meta;
    let mut out = String::new();
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
            continue;
        }
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push_str(path),
            Some('N') => out.push_str(&format!("'{path}'")),
            Some('s') => out.push_str(&node_size(node).to_string()),
            Some('b') => out.push_str(&(allocated_kib(&shell.vfs, id) * 2).to_string()),
            Some('B') => out.push_str("512"),
            Some('f') => out.push_str(&format!("{:x}", meta.mode)),
            Some('a') => out.push_str(&format!("{:o}", meta.mode & 0o7777)),
            Some('A') => out.push_str(&mode_string(meta.mode)),
            Some('u') => out.push_str(&meta.uid.to_string()),
            Some('U') => out.push_str(&uid_name(meta.uid)),
            Some('g') => out.push_str(&meta.gid.to_string()),
            Some('G') => out.push_str(&gid_name(meta.gid)),
            Some('i') => out.push_str(&stat_inode(id).to_string()),
            Some('h') => out.push_str(&stat_nlink(node).to_string()),
            Some('d') => out.push_str("2049"),
            Some('D') => out.push_str("801"),
            Some('F') => out.push_str(stat_kind(node)),
            Some('X' | 'Y' | 'Z' | 'W') => out.push_str(&meta.mtime.to_string()),
            Some('x' | 'y' | 'z') => out.push_str(&stat_stamp(meta.mtime)),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

fn stat_terse(shell: &Shell, id: NodeId, path: &str) -> String {
    let node = shell.vfs.node(id);
    let meta = &node.meta;
    format!(
        "{path} {size} {blocks} {mode:x} {uid} {gid} 801 {ino} {nlink} 0 0 {t} {t} {t} 0 512",
        size = node_size(node),
        blocks = allocated_kib(&shell.vfs, id) * 2,
        mode = meta.mode,
        uid = meta.uid,
        gid = meta.gid,
        ino = stat_inode(id),
        nlink = stat_nlink(node),
        t = meta.mtime,
    )
}

fn stat_long(shell: &Shell, id: NodeId, path: &str) -> String {
    let node = shell.vfs.node(id);
    let meta = &node.meta;
    let stamp = stat_stamp(meta.mtime);
    let name = if let NodeKind::Symlink { target } = &node.kind {
        format!("'{path}' -> '{target}'")
    } else {
        format!("'{path}'")
    };
    format!(
        "  File: {name}\n  Size: {size:<15} Blocks: {blocks:<10} IO Block: 4096   {kind}\n\
         Device: 801h/2049d\tInode: {ino:<11} Links: {nlink}\n\
         Access: ({perms:04o}/{modestr})  Uid: ({uid:>5}/{uname:>8})   Gid: ({gid:>5}/{gname:>8})\n\
         Access: {stamp}\nModify: {stamp}\nChange: {stamp}\n Birth: {stamp}\n",
        size = node_size(node),
        blocks = allocated_kib(&shell.vfs, id) * 2,
        kind = stat_kind(node),
        ino = stat_inode(id),
        nlink = stat_nlink(node),
        perms = meta.mode & 0o7777,
        modestr = mode_string(meta.mode),
        uid = meta.uid,
        uname = uid_name(meta.uid),
        gid = meta.gid,
        gname = gid_name(meta.gid),
    )
}

fn stat_inode(id: NodeId) -> u64 {
    id as u64 + 2
}

fn stat_nlink(node: &Node) -> usize {
    match &node.kind {
        NodeKind::Directory { children } => children.len() + 2,
        _ => 1,
    }
}

fn stat_kind(node: &Node) -> &'static str {
    match &node.kind {
        NodeKind::Directory { .. } => "directory",
        NodeKind::Symlink { .. } => "symbolic link",
        NodeKind::File { contents } if contents.is_empty() => "regular empty file",
        NodeKind::File { .. } | NodeKind::DynamicFile { .. } => "regular file",
    }
}

fn stat_stamp(ts: i64) -> String {
    format!(
        "{} +0000",
        crate::clock::format(ts, "%Y-%m-%d %H:%M:%S.000000000")
    )
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn stat_agrees_with_ls_and_honours_a_format() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "echo hello > /tmp/f");

        let long = run(&mut shell, "stat /tmp/f");
        assert!(long.contains("File: '/tmp/f'"), "{long}");
        assert!(long.contains("regular file"), "{long}");
        assert!(long.contains("Uid: (    0/    root)"), "{long}");

        let size = run(&mut shell, "stat -c %s /tmp/f");
        assert_eq!(size.trim(), "6");
        assert!(run(&mut shell, "wc -c /tmp/f")
            .trim_start()
            .starts_with("6 "));

        let a = run(&mut shell, "stat -c %i /tmp/f");
        let b = run(&mut shell, "stat -c %i /tmp/f");
        assert_eq!(a, b);

        assert_eq!(run(&mut shell, "stat -c %F /etc").trim(), "directory");
        assert_eq!(run(&mut shell, "stat -c %a /tmp/f").trim(), "644");

        let missing = shell.execute("stat /tmp/nope");
        assert_eq!(missing.status, 1);
        assert!(missing.stderr.contains("No such file or directory"));
    }
}
