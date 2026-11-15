mod bins;
mod files;
mod procfs;

use super::Vfs;
use crate::persona::Persona;
use files::{
    hosts_file, BASHRC, GROUP, OS_RELEASE, PASSWD, PROFILE, SHADOW, SOURCES_LIST, SSHD_CONFIG,
    SSH_CONFIG,
};
use procfs::{proc_loadavg, proc_uptime, VERSION};

pub(crate) use bins::{USR_BIN, USR_SBIN};
pub use procfs::{cpuinfo, meminfo};

pub fn build(hostname: &str, persona: &Persona) -> Vfs {
    let mut fs = Vfs::new();
    let root = fs.root();

    let etc = fs.mkdir(root, "etc", 0o755, 0, 0);
    let home = fs.mkdir(root, "home", 0o755, 0, 0);
    let root_home = fs.mkdir(root, "root", 0o700, 0, 0);
    let proc = fs.mkdir(root, "proc", 0o555, 0, 0);
    let var = fs.mkdir(root, "var", 0o755, 0, 0);
    let usr = fs.mkdir(root, "usr", 0o755, 0, 0);
    let tmp = fs.mkdir(root, "tmp", 0o1777, 0, 0);
    fs.mkdir(root, "boot", 0o755, 0, 0);
    let dev = fs.mkdir(root, "dev", 0o755, 0, 0);

    fs.add_file(dev, "null", Vec::new(), 0o666, 0, 0);
    fs.add_file(dev, "zero", Vec::new(), 0o666, 0, 0);
    fs.add_file(dev, "urandom", Vec::new(), 0o666, 0, 0);

    let pts = fs.mkdir(dev, "pts", 0o755, 0, 0);
    fs.add_file(pts, "0", Vec::new(), 0o620, 0, 5);
    fs.add_file(dev, "ptmx", Vec::new(), 0o666, 0, 5);
    fs.mkdir(root, "opt", 0o755, 0, 0);
    fs.mkdir(root, "run", 0o755, 0, 0);
    fs.mkdir(root, "srv", 0o755, 0, 0);
    fs.mkdir(root, "sys", 0o555, 0, 0);
    fs.mkdir(root, "mnt", 0o755, 0, 0);
    fs.mkdir(root, "media", 0o755, 0, 0);

    fs.add_symlink(root, "bin", "usr/bin");
    fs.add_symlink(root, "sbin", "usr/sbin");
    fs.add_symlink(root, "lib", "usr/lib");
    fs.add_symlink(root, "lib64", "usr/lib64");

    let usr_bin = fs.mkdir(usr, "bin", 0o755, 0, 0);
    let usr_sbin = fs.mkdir(usr, "sbin", 0o755, 0, 0);
    fs.mkdir(usr, "lib", 0o755, 0, 0);
    fs.mkdir(usr, "lib64", 0o755, 0, 0);
    fs.mkdir(usr, "local", 0o755, 0, 0);
    fs.mkdir(usr, "share", 0o755, 0, 0);
    fs.mkdir(usr, "include", 0o755, 0, 0);
    fs.mkdir(usr, "games", 0o755, 0, 0);

    for bin in USR_BIN {
        fs.add_file(usr_bin, bin, &b""[..], 0o755, 0, 0);
    }
    for bin in USR_SBIN {
        fs.add_file(usr_sbin, bin, &b""[..], 0o755, 0, 0);
    }

    fs.add_file(etc, "os-release", OS_RELEASE, 0o644, 0, 0);
    fs.add_file(etc, "debian_version", "12.5\n", 0o644, 0, 0);
    fs.add_file(etc, "hostname", format!("{hostname}\n"), 0o644, 0, 0);
    fs.add_file(etc, "hosts", hosts_file(hostname), 0o644, 0, 0);
    fs.add_file(etc, "passwd", PASSWD, 0o644, 0, 0);
    fs.add_file(etc, "group", GROUP, 0o644, 0, 0);
    fs.add_file(etc, "shadow", SHADOW, 0o640, 0, 42);
    fs.add_file(
        etc,
        "resolv.conf",
        "nameserver 127.0.0.53\noptions edns0 trust-ad\n",
        0o644,
        0,
        0,
    );
    fs.add_file(etc, "issue", "Debian GNU/Linux 12 \\n \\l\n\n", 0o644, 0, 0);

    fs.add_file(
        etc,
        "machine-id",
        format!("{}\n", persona.machine_id),
        0o444,
        0,
        0,
    );

    let etc_ssh = fs.mkdir(etc, "ssh", 0o755, 0, 0);
    fs.add_file(etc_ssh, "sshd_config", SSHD_CONFIG, 0o644, 0, 0);
    fs.add_file(etc_ssh, "ssh_config", SSH_CONFIG, 0o644, 0, 0);

    for (name, body) in &persona.host_keys {
        fs.add_file(etc_ssh, name, body.as_str(), 0o644, 0, 0);
    }

    let etc_apt = fs.mkdir(etc, "apt", 0o755, 0, 0);
    fs.add_file(etc_apt, "sources.list", SOURCES_LIST, 0o644, 0, 0);
    fs.mkdir(etc_apt, "sources.list.d", 0o755, 0, 0);
    fs.mkdir(etc_apt, "preferences.d", 0o755, 0, 0);
    fs.mkdir(etc, "systemd", 0o755, 0, 0);
    fs.mkdir(etc, "network", 0o755, 0, 0);

    fs.add_file(proc, "cpuinfo", cpuinfo(persona), 0o444, 0, 0);
    fs.add_file(proc, "meminfo", meminfo(persona), 0o444, 0, 0);
    fs.add_file(proc, "version", VERSION, 0o444, 0, 0);

    fs.add_dynamic_file(proc, "uptime", proc_uptime, 0o444, 0, 0);
    fs.add_dynamic_file(proc, "loadavg", proc_loadavg, 0o444, 0, 0);

    let var_log = fs.mkdir(var, "log", 0o755, 0, 0);
    fs.mkdir(var, "www", 0o755, 0, 0);
    fs.mkdir(var, "cache", 0o755, 0, 0);
    fs.mkdir(var, "lib", 0o755, 0, 0);
    fs.mkdir(var, "spool", 0o755, 0, 0);
    fs.mkdir(var, "tmp", 0o1777, 0, 0);
    fs.mkdir(var, "backups", 0o755, 0, 0);
    fs.add_file(var_log, "wtmp", &b""[..], 0o664, 0, 43);
    fs.add_file(var_log, "lastlog", &b""[..], 0o664, 0, 43);
    fs.add_file(var_log, "auth.log", &b""[..], 0o640, 0, 4);
    fs.add_file(var_log, "syslog", &b""[..], 0o640, 0, 4);

    let _ = tmp;

    fs.add_file(root_home, ".bashrc", BASHRC, 0o644, 0, 0);
    fs.add_file(root_home, ".profile", PROFILE, 0o644, 0, 0);
    fs.add_file(root_home, ".bash_logout", "# ~/.bash_logout\n", 0o644, 0, 0);

    let user_home = fs.mkdir(home, "user", 0o755, 1000, 1000);
    fs.add_file(user_home, ".bashrc", BASHRC, 0o644, 1000, 1000);
    fs.add_file(user_home, ".profile", PROFILE, 0o644, 1000, 1000);
    fs.add_file(
        user_home,
        ".bash_logout",
        "# ~/.bash_logout\n",
        0o644,
        1000,
        1000,
    );

    fs.set_all_mtimes(crate::clock::install_time());
    fs
}

#[cfg(test)]
mod tests;
