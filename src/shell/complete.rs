//! Tab-completion for the emulated shell.
//!
//! Real bash completes command names (first word) and filesystem paths
//! (arguments) on Tab. A honeypot that does nothing on Tab — or worse, inserts
//! a literal tab — is an easy tell. This module computes completions purely
//! from the in-memory command registry and [`Vfs`], with no real I/O.

use crate::shell::Shell;
use crate::vfs::Vfs;

/// Every command name the shell recognises, used for command-position
/// completion. Kept in sync with the command registry.
pub const COMMANDS: &[&str] = &[
    "apt", "apt-get", "cat", "cd", "chmod", "clear", "cp", "crontab", "curl", "df", "dpkg", "echo",
    "env", "exit", "export", "false", "find", "free", "grep", "history", "hostname", "id", "ip",
    "kill", "last", "logout", "ls", "lscpu", "mkdir", "mount", "mv", "netstat", "nproc", "pkill",
    "ping", "printenv", "ps", "pwd", "rm", "rmdir", "ss", "su", "sudo", "tar", "top", "touch",
    "true", "uname", "unset", "uptime", "w", "wget", "whoami", "which",
];

/// The outcome of a completion request.
#[derive(Debug, PartialEq, Eq)]
pub enum Completion {
    /// No candidates; do nothing (a real terminal would beep).
    None,
    /// A unique (or longest-common-prefix) replacement for the current word.
    /// `add_space` is set only when the completion is fully unambiguous and the
    /// result is not a directory.
    Single {
        replacement: String,
        add_space: bool,
    },
    /// Several candidates; display this listing and redraw the line.
    Listing(Vec<String>),
}

/// Compute completions for `word`. `is_command` selects command-name vs. path
/// completion.
pub fn complete(shell: &Shell, word: &str, is_command: bool) -> Completion {
    if is_command && !word.contains('/') {
        complete_command(word)
    } else {
        complete_path(shell, word)
    }
}

fn complete_command(word: &str) -> Completion {
    let mut names: Vec<&str> = COMMANDS
        .iter()
        .copied()
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
    // Split the word into the directory portion (kept verbatim in the
    // replacement) and the final base being completed.
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

    // Candidate (name, is_dir) pairs whose name starts with `base`. Hidden
    // entries are only offered when the user has typed a leading dot.
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
                // Display directory entries with a trailing slash, as bash does.
                let listing = cands
                    .into_iter()
                    .map(|(n, is_dir)| if is_dir { format!("{n}/") } else { n })
                    .collect();
                Completion::Listing(listing)
            }
        }
    }
}

/// Resolve a directory portion (e.g. `/etc/`, `sub/`, or `""`) relative to
/// `cwd`, returning the directory node if it exists and is a directory.
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

/// Whether `id`, after following a symlink, refers to a directory.
fn follow_is_dir(vfs: &Vfs, id: crate::vfs::NodeId) -> bool {
    if vfs.node(id).meta.is_symlink() {
        // Re-resolve through the parent so symlinked dirs complete with a slash.
        let path = vfs.path_of(id);
        if let Some(target) = vfs.resolve(vfs.root(), &path) {
            return vfs.node(target).meta.is_dir();
        }
        return false;
    }
    vfs.node(id).meta.is_dir()
}

/// Longest common prefix of a set of strings.
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
    first[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_unique_completion() {
        let shell = Shell::new("root", "debian");
        // "who" -> only "whoami"
        assert_eq!(
            complete(&shell, "who", true),
            Completion::Single {
                replacement: "whoami".to_string(),
                add_space: true
            }
        );
    }

    #[test]
    fn command_common_prefix() {
        let shell = Shell::new("root", "debian");
        // "ap" -> apt, apt-get : common prefix "apt"
        match complete(&shell, "ap", true) {
            Completion::Single {
                replacement,
                add_space,
            } => {
                assert_eq!(replacement, "apt");
                assert!(!add_space);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn command_listing_when_ambiguous() {
        let shell = Shell::new("root", "debian");
        // "c" -> several commands, no longer common prefix
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
        // "/ho" -> "/home" which is a directory
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
        // "/etc/os-rel" -> "/etc/os-release" (a file)
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
        // Bare "" in /root should not list ".bashrc"; "." should.
        if let Completion::Listing(items) = complete_path(&shell, "/root/") {
            assert!(!items.iter().any(|i| i.starts_with(".bashrc")));
        }
    }

    #[test]
    fn lcp_basic() {
        assert_eq!(longest_common_prefix(&["apt", "apt-get"]), "apt");
        assert_eq!(longest_common_prefix(&["cat", "cd"]), "c");
        assert_eq!(longest_common_prefix(&["ls", "rm"]), "");
    }
}
