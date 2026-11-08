use crate::shell::Shell;
use crate::vfs::Vfs;

pub const COMMANDS: &[&str] = &[
    "addgroup",
    "adduser",
    "apt",
    "apt-get",
    "arch",
    "awk",
    "base64",
    "basename",
    "bash",
    "cat",
    "cd",
    "chattr",
    "chgrp",
    "chmod",
    "chown",
    "chpasswd",
    "clear",
    "cp",
    "crontab",
    "curl",
    "cut",
    "date",
    "deluser",
    "df",
    "dir",
    "dirname",
    "dmesg",
    "dpkg",
    "du",
    "echo",
    "env",
    "exit",
    "export",
    "false",
    "find",
    "free",
    "getent",
    "grep",
    "groupadd",
    "groups",
    "head",
    "history",
    "hostname",
    "id",
    "ip",
    "kill",
    "killall",
    "last",
    "ln",
    "logout",
    "ls",
    "lsattr",
    "lsb_release",
    "lscpu",
    "mawk",
    "md5sum",
    "mkdir",
    "mount",
    "mv",
    "nano",
    "nc",
    "netcat",
    "netstat",
    "nl",
    "nohup",
    "nologin",
    "nproc",
    "passwd",
    "perl",
    "pgrep",
    "pidof",
    "ping",
    "ping6",
    "pkill",
    "printenv",
    "printf",
    "ps",
    "pwd",
    "python3",
    "rev",
    "rm",
    "rmdir",
    "scp",
    "sed",
    "seq",
    "service",
    "sh",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "sleep",
    "sort",
    "ss",
    "stat",
    "su",
    "sudo",
    "sync",
    "systemctl",
    "tail",
    "tar",
    "tee",
    "top",
    "touch",
    "tr",
    "true",
    "tty",
    "uname",
    "uniq",
    "unset",
    "uptime",
    "useradd",
    "userdel",
    "vi",
    "w",
    "wc",
    "wget",
    "which",
    "whoami",
    "xargs",
];

#[derive(Debug, PartialEq, Eq)]
pub enum Completion {
    None,

    Single {
        replacement: String,
        add_space: bool,
    },

    Listing(Vec<String>),
}

pub fn complete(shell: &Shell, word: &str, is_command: bool) -> Completion {
    if is_command && !word.contains('/') {
        complete_command(shell, word)
    } else {
        complete_path(shell, word)
    }
}

fn complete_command(shell: &Shell, word: &str) -> Completion {
    let mut names: Vec<String> = Vec::new();
    for dir in ["/usr/bin", "/usr/sbin"] {
        if let Some(id) = shell.vfs.resolve(shell.vfs.root(), dir) {
            if let Some(entries) = shell.vfs.entries(id) {
                names.extend(entries.into_iter().map(|(name, _)| name));
            }
        }
    }
    names.extend(
        crate::commands::system::BUILTINS
            .iter()
            .map(|s| s.to_string()),
    );

    let mut names: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|c| c.starts_with(word))
        .collect();
    names.sort_unstable();
    names.dedup();

    match names.len() {
        0 => Completion::None,
        1 => Completion::Single {
            replacement: names[0].to_string(),
            add_space: true,
        },
        _ => {
            let lcp = longest_common_prefix(&names);
            if lcp.len() > word.len() {
                Completion::Single {
                    replacement: lcp,
                    add_space: false,
                }
            } else {
                Completion::Listing(names.into_iter().map(str::to_string).collect())
            }
        }
    }
}

fn complete_path(shell: &Shell, word: &str) -> Completion {
    let (dir_part, base) = match word.rfind('/') {
        Some(i) => (&word[..=i], &word[i + 1..]),
        None => ("", word),
    };

    let dir_id = resolve_dir(&shell.vfs, shell.cwd, dir_part);
    let dir_id = match dir_id {
        Some(id) => id,
        None => return Completion::None,
    };

    let entries = match shell.vfs.entries(dir_id) {
        Some(e) => e,
        None => return Completion::None,
    };

    let mut cands: Vec<(String, bool)> = entries
        .into_iter()
        .filter(|(name, _)| name.starts_with(base))
        .filter(|(name, _)| base.starts_with('.') || !name.starts_with('.'))
        .map(|(name, id)| {
            let is_dir = follow_is_dir(&shell.vfs, id);
            (name, is_dir)
        })
        .collect();
    cands.sort_by(|a, b| a.0.cmp(&b.0));

    match cands.len() {
        0 => Completion::None,
        1 => {
            let (name, is_dir) = &cands[0];
            let mut replacement = format!("{dir_part}{name}");
            if *is_dir {
                replacement.push('/');
            }
            Completion::Single {
                replacement,
                add_space: !is_dir,
            }
        }
        _ => {
            let names: Vec<&str> = cands.iter().map(|(n, _)| n.as_str()).collect();
            let lcp = longest_common_prefix(&names);
            if lcp.len() > base.len() {
                Completion::Single {
                    replacement: format!("{dir_part}{lcp}"),
                    add_space: false,
                }
            } else {
                let listing = cands
                    .into_iter()
                    .map(|(n, is_dir)| if is_dir { format!("{n}/") } else { n })
                    .collect();
                Completion::Listing(listing)
            }
        }
    }
}

fn resolve_dir(vfs: &Vfs, cwd: crate::vfs::NodeId, dir_part: &str) -> Option<crate::vfs::NodeId> {
    let id = if dir_part.is_empty() {
        cwd
    } else {
        vfs.resolve(cwd, dir_part)?
    };
    if vfs.node(id).meta.is_dir() {
        Some(id)
    } else {
        None
    }
}

fn follow_is_dir(vfs: &Vfs, id: crate::vfs::NodeId) -> bool {
    if vfs.node(id).meta.is_symlink() {
        let path = vfs.path_of(id);
        if let Some(target) = vfs.resolve(vfs.root(), &path) {
            return vfs.node(target).meta.is_dir();
        }
        return false;
    }
    vfs.node(id).meta.is_dir()
}

fn longest_common_prefix(items: &[&str]) -> String {
    let first = match items.first() {
        Some(s) => *s,
        None => return String::new(),
    };
    let mut end = first.len();
    for s in &items[1..] {
        end = end.min(s.len());
        while !s.as_bytes()[..end].eq(&first.as_bytes()[..end]) {
            end -= 1;
        }
        if end == 0 {
            break;
        }
    }

    while end > 0 && !first.is_char_boundary(end) {
        end -= 1;
    }
    first[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_unique_completion() {
        let shell = Shell::new("root", "debian");

        assert_eq!(
            complete(&shell, "whoam", true),
            Completion::Single {
                replacement: "whoami".to_string(),
                add_space: true
            }
        );
    }

    #[test]
    fn command_common_prefix() {
        let shell = Shell::new("root", "debian");

        match complete(&shell, "us", true) {
            Completion::Single {
                replacement,
                add_space,
            } => {
                assert_eq!(replacement, "user");
                assert!(!add_space);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn command_listing_when_ambiguous() {
        let shell = Shell::new("root", "debian");

        match complete(&shell, "c", true) {
            Completion::Listing(items) => {
                assert!(items.contains(&"cat".to_string()));
                assert!(items.contains(&"cd".to_string()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn path_completion_unique_dir_gets_slash() {
        let shell = Shell::new("root", "debian");

        assert_eq!(
            complete(&shell, "/ho", false),
            Completion::Single {
                replacement: "/home/".to_string(),
                add_space: false
            }
        );
    }

    #[test]
    fn path_completion_file_gets_space() {
        let shell = Shell::new("root", "debian");

        match complete(&shell, "/etc/os-rel", false) {
            Completion::Single {
                replacement,
                add_space,
            } => {
                assert_eq!(replacement, "/etc/os-release");
                assert!(add_space);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn hidden_entries_need_leading_dot() {
        let shell = Shell::new("root", "debian");

        if let Completion::Listing(items) = complete_path(&shell, "/root/") {
            assert!(!items.iter().any(|i| i.starts_with(".bashrc")));
        }
    }

    #[test]
    fn path_completion_over_names_sharing_a_lead_byte() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("mkdir /tmp/éa /tmp/êb");

        match complete(&shell, "/tmp/", false) {
            Completion::Listing(items) => {
                assert!(items.iter().any(|i| i.starts_with("éa")));
                assert!(items.iter().any(|i| i.starts_with("êb")));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn lcp_basic() {
        assert_eq!(longest_common_prefix(&["apt", "apt-get"]), "apt");
        assert_eq!(longest_common_prefix(&["cat", "cd"]), "c");
        assert_eq!(longest_common_prefix(&["ls", "rm"]), "");

        assert_eq!(longest_common_prefix(&["éa", "êb"]), "");
        assert_eq!(longest_common_prefix(&["éa", "éb"]), "é");
    }
}
