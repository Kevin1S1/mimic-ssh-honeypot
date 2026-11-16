use super::*;

fn read(fs: &Vfs, path: &str) -> String {
    let id = fs.resolve(fs.root(), path).expect("path should resolve");
    fs.node(id)
        .file_bytes()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_else(|| panic!("{path} is not a file"))
}

#[test]
fn runnable_commands_resolve_under_usr_bin_or_usr_sbin() {
    let fs = build("srv1", &Persona::sample());
    let runnable = crate::shell::complete::COMMANDS
        .iter()
        .copied()
        .filter(|name| !crate::commands::system::BUILTINS.contains(name));

    for name in runnable {
        let found = fs.resolve(fs.root(), &format!("/usr/bin/{name}")).is_some()
            || fs
                .resolve(fs.root(), &format!("/usr/sbin/{name}"))
                .is_some();
        assert!(
            found,
            "{name} is runnable but not listed under /usr/bin or /usr/sbin"
        );
    }
}

#[test]
fn the_box_does_not_contradict_its_own_commands() {
    let fs = build("srv1", &Persona::sample());

    assert!(
        fs.resolve(fs.root(), "/dev/pts/0").is_some(),
        "the pty `tty` reports must exist"
    );

    let sshd_config = read(&fs, "/etc/ssh/sshd_config");
    assert!(sshd_config.contains("MaxAuthTries 6"), "{sshd_config}");
    assert!(sshd_config.contains("AcceptEnv LANG LC_*"), "{sshd_config}");

    assert!(read(&fs, "/etc/apt/sources.list").contains("bookworm"));
}

#[test]
fn host_key_files_come_from_the_keys_actually_served() {
    let persona = Persona::sample().with_host_keys(vec![(
        "ssh_host_ed25519_key.pub".to_string(),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample root@srv1\n".to_string(),
    )]);
    let fs = build("srv1", &persona);
    assert_eq!(
        read(&fs, "/etc/ssh/ssh_host_ed25519_key.pub"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample root@srv1\n"
    );

    let bare = build("srv1", &Persona::sample());
    assert!(bare.resolve(bare.root(), "/etc/ssh/sshd_config").is_some());
    assert!(bare
        .resolve(bare.root(), "/etc/ssh/ssh_host_ed25519_key.pub")
        .is_none());
}

#[test]
fn hostname_is_consistent_across_files() {
    let fs = build("web-prod-01", &Persona::sample());

    assert_eq!(read(&fs, "/etc/hostname"), "web-prod-01\n");

    let hosts = read(&fs, "/etc/hosts");
    assert!(
        hosts.contains("127.0.1.1\tweb-prod-01\n"),
        "/etc/hosts should alias the configured hostname, got: {hosts:?}"
    );
    assert!(hosts.contains("127.0.0.1\tlocalhost\n"));
}

#[test]
fn proc_uptime_matches_command_banner() {
    let fs = build("srv1", &Persona::sample());
    let first = read(&fs, "/proc/uptime");
    let secs: f64 = first
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .expect("/proc/uptime first field should be a number");

    assert_eq!(
        crate::clock::uptime_phrase(secs as i64),
        crate::clock::uptime_phrase(crate::clock::uptime_secs())
    );

    let idle: f64 = first
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("/proc/uptime second field should be a number");
    assert!(idle < secs, "idle {idle} should be below uptime {secs}");
}

#[test]
fn proc_uptime_is_dynamic_and_matches_clock() {
    let fs = build("srv1", &Persona::sample());
    let read1 = read(&fs, "/proc/uptime");
    let secs1: f64 = read1
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap();
    assert_eq!(secs1.floor() as i64, crate::clock::uptime_secs());
}

#[test]
fn snapshot_files_carry_the_install_date() {
    let mut fs = build("srv1", &Persona::sample());
    let etc = fs.resolve(fs.root(), "/etc/passwd").expect("/etc/passwd");
    assert_eq!(fs.node(etc).meta.mtime, crate::clock::install_time());
    assert!(fs.node(etc).meta.mtime < crate::clock::now());

    let tmp = fs.resolve(fs.root(), "/tmp").expect("/tmp");
    let fresh = fs.mkdir(tmp, "new", 0o755, 0, 0);
    assert!(fs.node(fresh).meta.mtime >= crate::clock::install_time());
    assert!(fs.node(fresh).meta.mtime > fs.node(etc).meta.mtime);
}

#[test]
fn common_paths_exist_with_expected_content() {
    let fs = build("srv1", &Persona::sample());
    let root = fs.root();

    assert!(read(&fs, "/etc/os-release").contains("bookworm"));
    assert!(read(&fs, "/etc/passwd").contains("user:x:1000:1000:"));
    assert!(read(&fs, "/proc/cpuinfo").contains("model name\t: Intel"));

    assert!(fs.resolve(root, "/bin/ls").is_some());
}

#[test]
fn shadow_holds_no_real_credentials() {
    let fs = build("srv1", &Persona::sample());
    let shadow = read(&fs, "/etc/shadow");
    assert!(shadow.contains("root:!:"), "root must be locked");
    assert!(
        shadow.contains("$6$"),
        "user row must look like a real SHA-512 crypt hash"
    );

    let lower = shadow.to_lowercase();
    for tell in ["placeholder", "honeypot", "fake", "dummy", "mimic"] {
        assert!(
            !lower.contains(tell),
            "shadow content must not contain the identifying word {tell:?}"
        );
    }
}

#[test]
fn every_owner_and_group_ls_can_print_is_in_the_account_databases() {
    use crate::commands::fs::{gid_name, uid_name};

    let fs = build("srv1", &Persona::sample());
    let passwd = read(&fs, "/etc/passwd");
    let group = read(&fs, "/etc/group");

    let mut pending = vec![fs.root()];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let meta = &fs.node(id).meta;
        let path = fs.path_of(id);

        let owner = format!("{}:x:{}:", uid_name(meta.uid), meta.uid);
        assert!(
            passwd.lines().any(|l| l.starts_with(&owner)),
            "{path}: no /etc/passwd entry starts with {owner:?}"
        );
        let owning_group = format!("{}:x:{}:", gid_name(meta.gid), meta.gid);
        assert!(
            group.lines().any(|l| l.starts_with(&owning_group)),
            "{path}: no /etc/group entry starts with {owning_group:?}"
        );

        pending.extend(fs.entries(id).into_iter().flatten().map(|(_, child)| child));
    }
    assert!(seen.len() > 100, "the walk should cover the whole snapshot");
}

#[test]
fn every_primary_group_in_passwd_exists() {
    let fs = build("srv1", &Persona::sample());
    let group = read(&fs, "/etc/group");
    let gids: std::collections::BTreeSet<&str> =
        group.lines().filter_map(|l| l.split(':').nth(2)).collect();

    assert_eq!(gids.len(), group.lines().count(), "duplicate gid");
    for account in read(&fs, "/etc/passwd").lines() {
        let gid = account.split(':').nth(3).expect("a gid field");
        assert!(gids.contains(gid), "{account}: gid {gid} has no group");
    }
}
