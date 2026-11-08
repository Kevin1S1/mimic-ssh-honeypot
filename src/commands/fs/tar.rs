use super::format::{civil_from_days, gid_name, mode_string, uid_name};
use super::{resolve_parent, strip_trailing_slashes};
use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::nodes::{Metadata, NodeKind, S_IFDIR, S_IFLNK};
use crate::vfs::NodeId;

fn apply_tar_flags(
    chars: &str,
    create: &mut bool,
    extract: &mut bool,
    list: &mut bool,
    verbose: &mut bool,
    expect_file: &mut bool,
) -> Option<char> {
    for ch in chars.chars() {
        match ch {
            'c' => *create = true,
            'x' => *extract = true,
            't' => *list = true,
            'v' => *verbose = true,
            'f' => *expect_file = true,
            'z' | 'j' | 'J' | 'p' | 'k' | 'm' => {}
            other => return Some(other),
        }
    }
    None
}

const TAR_BLOCK: usize = 512;

const TAR_BLOCKING: usize = 20 * TAR_BLOCK;

fn tar_put(header: &mut [u8; TAR_BLOCK], at: usize, width: usize, bytes: &[u8]) {
    let n = bytes.len().min(width);
    header[at..at + n].copy_from_slice(&bytes[..n]);
}

fn tar_put_octal(header: &mut [u8; TAR_BLOCK], at: usize, width: usize, value: u64) {
    let digits = format!("{value:0>width$o}", width = width - 1);
    tar_put(header, at, width - 1, digits.as_bytes());
}

fn tar_read_octal(field: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(field);
    u64::from_str_radix(text.trim_matches(['\0', ' ']), 8).unwrap_or(0)
}

fn tar_read_str(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn tar_split_name(name: &str) -> (&str, &str) {
    if name.len() <= 100 {
        return ("", name);
    }
    for (i, _) in name.match_indices('/') {
        let (prefix, rest) = (&name[..i], &name[i + 1..]);
        if prefix.len() <= 155 && rest.len() <= 100 {
            return (prefix, rest);
        }
    }
    ("", name)
}

fn tar_write_header(
    name: &str,
    link: &str,
    meta: &Metadata,
    typeflag: u8,
    size: usize,
    out: &mut Vec<u8>,
) {
    let mut h = [0u8; TAR_BLOCK];
    let (prefix, stem) = tar_split_name(name);
    tar_put(&mut h, 0, 100, stem.as_bytes());
    tar_put_octal(&mut h, 100, 8, (meta.mode & 0o7777) as u64);
    tar_put_octal(&mut h, 108, 8, meta.uid as u64);
    tar_put_octal(&mut h, 116, 8, meta.gid as u64);
    tar_put_octal(&mut h, 124, 12, size as u64);
    tar_put_octal(&mut h, 136, 12, meta.mtime.max(0) as u64);

    h[148..156].fill(b' ');
    h[156] = typeflag;
    tar_put(&mut h, 157, 100, link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    tar_put(&mut h, 265, 32, uid_name(meta.uid).as_bytes());
    tar_put(&mut h, 297, 32, gid_name(meta.gid).as_bytes());
    tar_put(&mut h, 345, 155, prefix.as_bytes());
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    out.extend_from_slice(&h);
}

struct TarBuild {
    bytes: Vec<u8>,

    log: String,

    errs: String,
    status: i32,
    verbose: bool,

    archive: Option<NodeId>,
}

fn tar_walk(shell: &Shell, id: NodeId, name: &str, build: &mut TarBuild) {
    if build.archive == Some(id) {
        build
            .errs
            .push_str(&format!("tar: {name}: file is the archive; not dumped\n"));
        return;
    }
    let node = shell.vfs.node(id);
    match &node.kind {
        NodeKind::Symlink { target } => {
            tar_write_header(name, target, &node.meta, b'2', 0, &mut build.bytes);
            if build.verbose {
                build.log.push_str(&format!("{name}\n"));
            }
        }
        NodeKind::File { contents } => {
            if !node.meta.readable_by(shell.uid, shell.gid) {
                build
                    .errs
                    .push_str(&format!("tar: {name}: Cannot open: Permission denied\n"));
                build.status = 2;
                return;
            }
            tar_write_header(name, "", &node.meta, b'0', contents.len(), &mut build.bytes);
            build.bytes.extend_from_slice(contents);
            let pad = contents.len().next_multiple_of(TAR_BLOCK) - contents.len();
            build.bytes.resize(build.bytes.len() + pad, 0);
            if build.verbose {
                build.log.push_str(&format!("{name}\n"));
            }
        }
        NodeKind::DynamicFile { generator } => {
            if !node.meta.readable_by(shell.uid, shell.gid) {
                build
                    .errs
                    .push_str(&format!("tar: {name}: Cannot open: Permission denied\n"));
                build.status = 2;
                return;
            }
            let bytes = generator();
            tar_write_header(name, "", &node.meta, b'0', bytes.len(), &mut build.bytes);
            build.bytes.extend_from_slice(&bytes);
            let pad = bytes.len().next_multiple_of(TAR_BLOCK) - bytes.len();
            build.bytes.resize(build.bytes.len() + pad, 0);
            if build.verbose {
                build.log.push_str(&format!("{name}\n"));
            }
        }
        NodeKind::Directory { .. } => {
            let dir_name = format!("{}/", name.trim_end_matches('/'));
            tar_write_header(&dir_name, "", &node.meta, b'5', 0, &mut build.bytes);
            if build.verbose {
                build.log.push_str(&format!("{dir_name}\n"));
            }
            if !node.meta.readable_by(shell.uid, shell.gid) {
                build
                    .errs
                    .push_str(&format!("tar: {name}: Cannot open: Permission denied\n"));
                build.status = 2;
                return;
            }
            for (child, child_id) in shell.vfs.entries(id).unwrap_or_default() {
                tar_walk(shell, child_id, &format!("{dir_name}{child}"), build);
            }
        }
    }
}

struct TarEntry {
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    size: usize,
    mtime: i64,
    typeflag: u8,
    link: String,

    offset: usize,
}

fn tar_parse(data: &[u8]) -> Option<Vec<TarEntry>> {
    if data.len() < TAR_BLOCK || &data[257..262] != b"ustar" {
        return None;
    }
    let mut entries = Vec::new();
    let mut at = 0;
    while at + TAR_BLOCK <= data.len() {
        let h = &data[at..at + TAR_BLOCK];

        if h.iter().all(|b| *b == 0) || &h[257..262] != b"ustar" {
            break;
        }
        let prefix = tar_read_str(&h[345..500]);
        let stem = tar_read_str(&h[0..100]);
        let size = tar_read_octal(&h[124..136]) as usize;
        entries.push(TarEntry {
            name: if prefix.is_empty() {
                stem
            } else {
                format!("{prefix}/{stem}")
            },
            mode: tar_read_octal(&h[100..108]) as u32 & 0o7777,
            uid: tar_read_octal(&h[108..116]) as u32,
            gid: tar_read_octal(&h[116..124]) as u32,
            size,
            mtime: tar_read_octal(&h[136..148]) as i64,
            typeflag: h[156],
            link: tar_read_str(&h[157..257]),
            offset: at + TAR_BLOCK,
        });
        at = at.saturating_add(TAR_BLOCK + size.next_multiple_of(TAR_BLOCK));
    }
    Some(entries)
}

fn tar_selected(name: &str, members: &[&str]) -> bool {
    if members.is_empty() {
        return true;
    }
    let name = name.trim_end_matches('/');
    members.iter().any(|m| {
        let m = strip_trailing_slashes(m).trim_start_matches('/');
        name == m || name.starts_with(&format!("{m}/"))
    })
}

const TAR_UGSWIDTH: usize = 18;

fn tar_long_entry(entry: &TarEntry, ugswidth: &mut usize) -> String {
    let type_bits = match entry.typeflag {
        b'5' => S_IFDIR,
        b'2' => S_IFLNK,
        _ => 0,
    };
    let mode = mode_string(type_bits | entry.mode);
    let owner = format!("{}/{}", uid_name(entry.uid), gid_name(entry.gid));
    let size = entry.size.to_string();
    *ugswidth = (*ugswidth).max(owner.len() + size.len());
    let width = *ugswidth - owner.len();
    let link = if entry.typeflag == b'2' {
        format!(" -> {}", entry.link)
    } else {
        String::new()
    };
    let date = tar_date(entry.mtime);
    format!(
        "{mode} {owner} {size:>width$} {date} {}{link}\n",
        entry.name
    )
}

fn tar_date(ts: i64) -> String {
    let (year, month, day) = civil_from_days(ts.div_euclid(86_400));
    let secs = ts.rem_euclid(86_400);
    let (hour, minute) = (secs / 3_600, (secs % 3_600) / 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
}

fn tar_has_dot_dot(name: &str) -> bool {
    name.split('/').any(|c| c == "..")
}

fn tar_strip_leading<'a>(name: &'a str, warned: &mut String, errs: &mut String) -> &'a str {
    let b = name.as_bytes();
    let mut prefix = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"..") && (i + 2 == b.len() || b[i + 2] == b'/') {
            prefix = i + 2;
        }
        while i < b.len() && b[i] != b'/' {
            i += 1;
        }
        while i < b.len() && b[i] == b'/' {
            i += 1;
        }
    }
    while prefix < b.len() && b[prefix] == b'/' {
        prefix += 1;
    }
    if prefix > 0 && warned.as_str() != &name[..prefix] {
        warned.clear();
        warned.push_str(&name[..prefix]);
        errs.push_str(&format!(
            "tar: Removing leading `{warned}' from member names\n"
        ));
    }
    &name[prefix..]
}

fn tar_dest(shell: &mut Shell, name: &str) -> Option<(NodeId, String)> {
    if tar_has_dot_dot(name) {
        return None;
    }
    let mut parts: Vec<&str> = name
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let last = parts.pop()?;
    let (uid, gid) = (shell.uid, shell.gid);
    let mut dir = shell.cwd;
    for comp in parts {
        let next = match shell.vfs.child(dir, comp) {
            Some(existing) if shell.vfs.node(existing).meta.is_dir() => existing,
            Some(_) => return None,
            None => shell.vfs.mkdir(dir, comp, 0o755, uid, gid),
        };
        if next == dir {
            return None;
        }
        dir = next;
    }
    Some((dir, last.to_string()))
}

pub fn tar(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut create = false;
    let mut extract = false;
    let mut list = false;
    let mut verbose = false;
    let mut archive: Option<&str> = None;
    let mut members: Vec<&str> = Vec::new();
    let mut expect_file = false;
    let mut first = true;

    for arg in args {
        if expect_file {
            archive = Some(arg);
            expect_file = false;
            first = false;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--file=") {
            archive = Some(rest);
        } else if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            if let Some(bad) = apply_tar_flags(
                &arg[1..],
                &mut create,
                &mut extract,
                &mut list,
                &mut verbose,
                &mut expect_file,
            ) {
                return CommandResult::err(
                    format!(
                        "tar: invalid option -- '{bad}'\nTry 'tar --help' or 'tar --usage' for more information.\n"
                    ),
                    2,
                );
            }
        } else if first && !arg.is_empty() && arg.bytes().all(|b| b"cxtvzjJpkfm".contains(&b)) {
            apply_tar_flags(
                arg,
                &mut create,
                &mut extract,
                &mut list,
                &mut verbose,
                &mut expect_file,
            );
        } else {
            members.push(arg);
        }
        first = false;
    }

    let Some(archive_path) = archive.or_else(|| members.first().copied()) else {
        return CommandResult::err(
            "tar: refusing to read archive contents from terminal (missing -f option?)\ntar: Error is not recoverable: exiting now\n",
            2,
        );
    };
    if archive.is_none() && !members.is_empty() {
        members.remove(0);
    }

    if create {
        if members.is_empty() {
            return CommandResult::err(
                "tar: Cowardly refusing to create an empty archive\nTry 'tar --help' or 'tar --usage' for more information.\n",
                2,
            );
        }
        let Some((parent, name)) = resolve_parent(shell, archive_path) else {
            return CommandResult::err(
                format!("tar: {archive_path}: Cannot open: Not a directory\n"),
                2,
            );
        };
        if !shell
            .vfs
            .node(parent)
            .meta
            .writable_by(shell.uid, shell.gid)
        {
            return CommandResult::err(
                format!(
                    "tar: {archive_path}: Cannot open: Permission denied\ntar: Error is not recoverable: exiting now\n"
                ),
                2,
            );
        }
        let mut build = TarBuild {
            bytes: Vec::new(),
            log: String::new(),
            errs: String::new(),
            status: 0,
            verbose,
            archive: shell.vfs.child(parent, &name),
        };
        let mut warned = String::new();
        for member in &members {
            let Some(id) = shell.vfs.resolve(shell.cwd, member) else {
                build.errs.push_str(&format!(
                    "tar: {member}: Cannot stat: No such file or directory\n"
                ));
                build.status = 2;
                continue;
            };

            let stored =
                tar_strip_leading(strip_trailing_slashes(member), &mut warned, &mut build.errs);
            let stored = if stored.is_empty() { "." } else { stored };
            tar_walk(shell, id, stored, &mut build);
        }

        let TarBuild {
            mut bytes,
            log,
            mut errs,
            status,
            ..
        } = build;
        bytes.resize(bytes.len() + 2 * TAR_BLOCK, 0);
        bytes.resize(bytes.len().next_multiple_of(TAR_BLOCKING), 0);

        let (uid, gid) = (shell.uid, shell.gid);
        let written = bytes.len();
        let id = shell.vfs.add_file(parent, &name, bytes, 0o644, uid, gid);

        let stored_ok = matches!(
            &shell.vfs.node(id).kind,
            NodeKind::File { contents } if contents.len() == written
        );
        if !stored_ok {
            errs.push_str(&format!(
                "tar: {archive_path}: Cannot write: No space left on device\ntar: Error is not recoverable: exiting now\n"
            ));
            return CommandResult::streams(log, errs, 2);
        }
        if status != 0 {
            errs.push_str("tar: Exiting with failure status due to previous errors\n");
        }
        return CommandResult::streams(log, errs, status);
    }

    if extract || list {
        let Some(id) = shell.vfs.resolve(shell.cwd, archive_path) else {
            return CommandResult::err(
                format!(
                    "tar: {archive_path}: Cannot open: No such file or directory\ntar: Error is not recoverable: exiting now\n"
                ),
                2,
            );
        };
        let node = shell.vfs.node(id);
        if node.meta.is_dir() {
            return CommandResult::err(
                format!(
                    "tar: {archive_path}: Cannot open: Is a directory\ntar: Error is not recoverable: exiting now\n"
                ),
                2,
            );
        }
        if !node.meta.readable_by(shell.uid, shell.gid) {
            return CommandResult::err(
                format!(
                    "tar: {archive_path}: Cannot open: Permission denied\ntar: Error is not recoverable: exiting now\n"
                ),
                2,
            );
        }
        let NodeKind::File { contents } = &node.kind else {
            return CommandResult::err(
                "tar: This does not look like a tar archive\ntar: Exiting with failure status due to previous errors\n",
                2,
            );
        };
        if contents.is_empty() {
            return CommandResult::err(
                "gzip: stdin: unexpected end of file\ntar: Child returned status 1\ntar: Error is not recoverable: exiting now\n",
                2,
            );
        }
        let Some(entries) = tar_parse(contents) else {
            return CommandResult::err(
                "tar: This does not look like a tar archive\ntar: Exiting with failure status due to previous errors\n",
                2,
            );
        };

        if list {
            let mut out = String::new();
            let mut errs = String::new();
            let mut ugswidth = TAR_UGSWIDTH;
            let mut warned = String::new();
            for entry in entries.iter().filter(|e| tar_selected(&e.name, &members)) {
                tar_strip_leading(&entry.name, &mut warned, &mut errs);
                if verbose {
                    out.push_str(&tar_long_entry(entry, &mut ugswidth));
                } else {
                    out.push_str(&format!("{}\n", entry.name));
                }
            }
            return CommandResult::streams(out, errs, 0);
        }

        let data = contents.clone();
        let (uid, gid) = (shell.uid, shell.gid);
        let mut out = String::new();
        let mut errs = String::new();
        let mut status = 0;
        let mut warned = String::new();
        for entry in entries {
            if !tar_selected(&entry.name, &members) {
                continue;
            }
            let member = tar_strip_leading(&entry.name, &mut warned, &mut errs).to_string();

            if tar_has_dot_dot(&entry.name) {
                errs.push_str(&format!("tar: {}: Member name contains '..'\n", entry.name));
                status = 2;
                continue;
            }
            if verbose {
                out.push_str(&format!("{member}\n"));
            }
            let Some((parent, name)) = tar_dest(shell, &member) else {
                errs.push_str(&format!(
                    "tar: {member}: Cannot open: No such file or directory\n"
                ));
                status = 2;
                continue;
            };
            if !shell.vfs.node(parent).meta.writable_by(uid, gid) {
                errs.push_str(&format!("tar: {member}: Cannot open: Permission denied\n"));
                status = 2;
                continue;
            }

            let (owner, group) = if uid == 0 {
                (entry.uid, entry.gid)
            } else {
                (uid, gid)
            };
            match entry.typeflag {
                b'5' => {
                    shell.vfs.mkdir(parent, &name, entry.mode, owner, group);
                }
                b'2' => {
                    shell.vfs.add_symlink(parent, &name, &entry.link);
                }
                b'0' | 0 => {
                    let end = entry.offset.saturating_add(entry.size).min(data.len());
                    let body = &data[entry.offset.min(end)..end];
                    let id = shell
                        .vfs
                        .add_file(parent, &name, body, entry.mode, owner, group);
                    let stored_ok = matches!(
                        &shell.vfs.node(id).kind,
                        NodeKind::File { contents } if contents.len() == body.len()
                    );
                    if !stored_ok {
                        errs.push_str(&format!(
                            "tar: {member}: Cannot write: No space left on device\n"
                        ));
                        status = 2;
                    }
                }

                _ => {}
            }
        }
        if status != 0 {
            errs.push_str("tar: Exiting with failure status due to previous errors\n");
        }
        return CommandResult::streams(out, errs, status);
    }

    CommandResult::err(
        "tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\nTry 'tar --help' or 'tar --usage' for more information.\n",
        2,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn tar_round_trips_a_created_archive() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/d/sub");
        let cwd = shell.vfs.resolve(shell.cwd, "/tmp/d").unwrap();
        shell.vfs.add_file(cwd, "one", "hello\n", 0o644, 0, 0);
        let sub = shell.vfs.resolve(shell.cwd, "/tmp/d/sub").unwrap();
        shell.vfs.add_file(sub, "two", "world\n", 0o600, 0, 0);

        assert_eq!(run(&mut shell, "cd /tmp && tar czf out.tgz d"), "");

        let size = match &shell
            .vfs
            .node(shell.vfs.resolve(shell.cwd, "out.tgz").unwrap())
            .kind
        {
            NodeKind::File { contents } => contents.len(),
            other => panic!("archive is not a file: {other:?}"),
        };
        assert_eq!(size % TAR_BLOCKING, 0);

        let listed = run(&mut shell, "tar tzf out.tgz");
        assert_eq!(listed, "d/\nd/one\nd/sub/\nd/sub/two\n");

        run(&mut shell, "mkdir /tmp/back && cd /tmp/back");
        assert_eq!(run(&mut shell, "tar xzf /tmp/out.tgz"), "");
        assert_eq!(run(&mut shell, "cat d/one"), "hello\n");
        assert_eq!(run(&mut shell, "cat d/sub/two"), "world\n");
        assert!(run(&mut shell, "ls -l d/sub").contains("-rw-------"));
    }

    #[test]
    fn tar_lists_verbosely_and_selects_members() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir -p /tmp/d/sub");
        let cwd = shell.vfs.resolve(shell.cwd, "/tmp/d").unwrap();
        shell.vfs.add_file(cwd, "one", "hello\n", 0o644, 0, 0);
        run(&mut shell, "cd /tmp && tar cf out.tar d");

        let now = crate::clock::format(crate::clock::now(), "%F %H:%M");
        let long = run(&mut shell, "tar tvf out.tar");
        assert!(
            long.contains(&format!("drwxr-xr-x root/root         0 {now} d/\n")),
            "unexpected listing: {long}"
        );
        assert!(
            long.contains(&format!("-rw-r--r-- root/root         6 {now} d/one\n")),
            "unexpected listing: {long}"
        );

        assert_eq!(run(&mut shell, "tar tf out.tar d/sub"), "d/sub/\n");

        run(&mut shell, "mkdir /tmp/back && cd /tmp/back");
        run(&mut shell, "tar xf /tmp/out.tar d/one");
        assert_eq!(run(&mut shell, "cat d/one"), "hello\n");
        assert!(!run(&mut shell, "ls d").contains("sub"));
    }

    #[test]
    fn tar_symlinks_survive_the_round_trip() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir /tmp/d");
        let d = shell.vfs.resolve(shell.cwd, "/tmp/d").unwrap();
        shell.vfs.add_file(d, "real", "x\n", 0o644, 0, 0);
        shell.vfs.add_symlink(d, "link", "real");

        run(&mut shell, "cd /tmp && tar cf out.tar d");
        assert!(run(&mut shell, "tar tvf out.tar").contains("link -> real"));

        run(&mut shell, "mkdir /tmp/back && cd /tmp/back");
        run(&mut shell, "tar xf /tmp/out.tar");
        assert_eq!(run(&mut shell, "cat d/link"), "x\n");
    }

    #[test]
    fn tar_reports_what_it_cannot_read_or_write() {
        let mut user = Shell::new("attacker", "debian");
        let out = run(&mut user, "cd /tmp && tar cf mine.tar /root");
        assert!(
            out.contains("tar: root: Cannot open: Permission denied"),
            "{out}"
        );
        assert!(out.contains("Exiting with failure status"));
        assert_eq!(user.last_status, 2);

        assert_eq!(run(&mut user, "tar tf mine.tar"), "root/\n");

        assert!(run(&mut user, "tar tf /etc/shadow").contains("Cannot open: Permission denied"));

        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "tar cf /tmp/a.tar /nope").contains("Cannot stat"));
        assert!(run(&mut shell, "tar cf /tmp/a.tar").contains("Cowardly refusing"));
        assert!(run(&mut shell, "tar xf /tmp/nope.tar").contains("No such file or directory"));
        assert!(run(&mut shell, "tar xf /etc").contains("Is a directory"));
    }

    #[test]
    fn tar_cannot_grow_the_vfs_past_its_byte_cap() {
        let mut shell = Shell::new("root", "debian");
        let cwd = shell.cwd;
        shell
            .vfs
            .add_file(cwd, "big", vec![b'x'; 5 * 1024 * 1024], 0o644, 0, 0);
        let out = run(&mut shell, "tar cf big.tar big");
        assert!(out.contains("No space left on device"), "{out}");
        assert_eq!(shell.last_status, 2);
        assert!(!run(&mut shell, "ls").contains("big.tar"));
    }

    #[test]
    fn tar_rejects_what_is_not_a_ustar_stream() {
        let mut shell = Shell::new("root", "debian");

        let cwd = shell.cwd;
        let gzip = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        shell.vfs.add_file(cwd, "up.tgz", &gzip[..], 0o644, 0, 0);
        assert!(run(&mut shell, "tar tzf up.tgz").contains("does not look like a tar archive"));

        run(&mut shell, "touch empty.tar.gz");
        assert!(run(&mut shell, "tar xzf empty.tar.gz").contains("unexpected end of file"));
    }

    #[test]
    fn tar_refuses_a_traversal_member() {
        let mut shell = Shell::new("root", "debian");
        let meta = Metadata::new(crate::vfs::nodes::S_IFREG, 0o644, 0, 0);
        let mut bytes = Vec::new();
        for name in ["../evil", "a/../../etc/passwd", "/abs", "ok"] {
            tar_write_header(name, "", &meta, b'0', 4, &mut bytes);
            bytes.extend_from_slice(b"pwn\n");
            bytes.resize(bytes.len() + TAR_BLOCK - 4, 0);
        }
        bytes.resize(bytes.len() + 2 * TAR_BLOCK, 0);
        let cwd = shell.cwd;
        shell.vfs.add_file(cwd, "trav.tar", bytes, 0o644, 0, 0);

        let listed = shell.execute("tar tf trav.tar");
        assert_eq!(
            listed.stdout,
            "../evil\n\
             a/../../etc/passwd\n\
             /abs\n\
             ok\n"
        );
        assert_eq!(
            listed.stderr,
            "tar: Removing leading `../' from member names\n\
             tar: Removing leading `a/../../' from member names\n\
             tar: Removing leading `/' from member names\n"
        );
        assert_eq!(shell.last_status, 0);

        run(&mut shell, "mkdir /tmp/out && cd /tmp/out");
        let out = run(&mut shell, "tar xf /root/trav.tar");
        assert_eq!(
            out,
            "tar: Removing leading `../' from member names\n\
             tar: ../evil: Member name contains '..'\n\
             tar: Removing leading `a/../../' from member names\n\
             tar: a/../../etc/passwd: Member name contains '..'\n\
             tar: Removing leading `/' from member names\n\
             tar: Exiting with failure status due to previous errors\n"
        );
        assert_eq!(shell.last_status, 2);

        assert_eq!(run(&mut shell, "ls"), "abs  ok\n");
        assert_eq!(
            run(&mut shell, "cat /etc/passwd | head -n 1"),
            "root:x:0:0:root:/root:/bin/bash\n"
        );
    }

    #[test]
    fn tar_does_not_archive_itself() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "mkdir /tmp/d");
        let d = shell.vfs.resolve(shell.cwd, "/tmp/d").unwrap();
        shell.vfs.add_file(d, "f", "data\n", 0o644, 0, 0);

        run(&mut shell, "cd /tmp/d && tar cf inner.tar .");
        let out = run(&mut shell, "tar cf inner.tar .");
        assert!(out.contains("file is the archive; not dumped"), "{out}");
        assert_eq!(run(&mut shell, "tar tf inner.tar"), "./\n./f\n");
    }

    #[test]
    fn tar_archive_content_is_not_self_identifying() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "touch /tmp/a");
        run(&mut shell, "tar czf /tmp/out.tar.gz /tmp/a");
        let content = run(&mut shell, "cat /tmp/out.tar.gz");
        let lower = content.to_lowercase();
        for tell in ["mimic", "honeypot", "fake", "placeholder"] {
            assert!(
                !lower.contains(tell),
                "tar archive content must not contain the identifying word {tell:?}"
            );
        }
    }
}
