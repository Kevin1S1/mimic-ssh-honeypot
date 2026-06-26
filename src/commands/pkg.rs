//! Package-manager stubs: `apt`, `apt-get`, `dpkg`.
//!
//! These emulate the surface behaviour an attacker probes — update indexes,
//! "install" packages, list installed ones — without any real package work.
//! The package database is a static, read-only, in-memory table; no real
//! process is ever spawned and no real path is ever touched.

use super::CommandResult;
use crate::shell::Shell;

/// A handful of packages a base Debian 12 install ships, for `dpkg -l` and
/// `apt list --installed`.
const INSTALLED: &[(&str, &str, &str)] = &[
    (
        "base-files",
        "12.4+deb12u5",
        "Debian base system miscellaneous files",
    ),
    ("bash", "5.2.15-2+b7", "GNU Bourne Again SHell"),
    ("coreutils", "9.1-1", "GNU core utilities"),
    (
        "curl",
        "7.88.1-10+deb12u5",
        "command line tool for transferring data with URL syntax",
    ),
    ("dpkg", "1.21.22", "Debian package management system"),
    ("libc6", "2.36-9+deb12u4", "GNU C Library: Shared libraries"),
    (
        "openssh-server",
        "1:9.2p1-2+deb12u3",
        "secure shell (SSH) server, for secure access from remote machines",
    ),
    (
        "openssl",
        "3.0.11-1~deb12u2",
        "Secure Sockets Layer toolkit - cryptographic utility",
    ),
    (
        "python3",
        "3.11.2-1+b1",
        "interactive high-level object-oriented language (default python3 version)",
    ),
    (
        "sudo",
        "1.9.13p3-1+deb12u1",
        "Provide limited super user privileges to specific users",
    ),
    ("wget", "1.21.3-1+deb12u1", "retrieves files from the web"),
];

/// `apt` / `apt-get`
pub fn apt(shell: &Shell, args: &[String]) -> CommandResult {
    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    let need_root = matches!(
        sub,
        Some("update")
            | Some("upgrade")
            | Some("install")
            | Some("remove")
            | Some("purge")
            | Some("dist-upgrade")
            | Some("autoremove")
    );
    if need_root && shell.uid != 0 {
        return CommandResult::err(
            "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n\
             E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n",
            100,
        );
    }

    match sub {
        Some("update") => CommandResult::ok(
            "Hit:1 http://deb.debian.org/debian bookworm InRelease\n\
             Hit:2 http://deb.debian.org/debian bookworm-updates InRelease\n\
             Hit:3 http://security.debian.org/debian-security bookworm-security InRelease\n\
             Reading package lists... Done\n",
        ),
        Some("upgrade") | Some("dist-upgrade") => CommandResult::ok(
            "Reading package lists... Done\n\
             Building dependency tree... Done\n\
             Reading state information... Done\n\
             Calculating upgrade... Done\n\
             0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
        ),
        Some("install") => {
            let pkgs: Vec<&str> = args
                .iter()
                .skip_while(|a| a.as_str() != "install")
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .map(String::as_str)
                .collect();
            if pkgs.is_empty() {
                return CommandResult::ok(
                    "Reading package lists... Done\n\
                     Building dependency tree... Done\n\
                     Reading state information... Done\n\
                     0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
                );
            }
            let mut out = String::new();
            out.push_str("Reading package lists... Done\n");
            out.push_str("Building dependency tree... Done\n");
            out.push_str("Reading state information... Done\n");
            for pkg in &pkgs {
                if let Some((_, ver, _)) = INSTALLED.iter().find(|(n, _, _)| n == pkg) {
                    out.push_str(&format!("{pkg} is already the newest version ({ver}).\n"));
                }
            }
            let unknown: Vec<&&str> = pkgs
                .iter()
                .filter(|p| !INSTALLED.iter().any(|(n, _, _)| n == *p))
                .collect();
            if !unknown.is_empty() {
                for pkg in &unknown {
                    out.push_str(&format!("E: Unable to locate package {pkg}\n"));
                }
                return CommandResult::err(out, 100);
            }
            out.push_str("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n");
            CommandResult::ok(out)
        }
        Some("remove") | Some("purge") | Some("autoremove") => CommandResult::ok(
            "Reading package lists... Done\n\
             Building dependency tree... Done\n\
             Reading state information... Done\n\
             0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
        ),
        Some("list") => {
            let mut out = String::from("Listing... Done\n");
            for (name, ver, _) in INSTALLED {
                out.push_str(&format!("{name}/now {ver} amd64 [installed,local]\n"));
            }
            CommandResult::ok(out)
        }
        Some("show") => {
            let pkg = args
                .iter()
                .skip_while(|a| a.as_str() != "show")
                .nth(1)
                .map(String::as_str);
            match pkg.and_then(|p| INSTALLED.iter().find(|(n, _, _)| *n == p)) {
                Some((name, ver, desc)) => CommandResult::ok(format!(
                    "Package: {name}\nVersion: {ver}\nPriority: optional\nSection: misc\n\
                     Maintainer: Debian\nArchitecture: amd64\nDescription: {desc}\n\n"
                )),
                None => CommandResult::err(
                    format!("N: Unable to locate package {}\n", pkg.unwrap_or("")),
                    100,
                ),
            }
        }
        _ => CommandResult::ok(
            "apt 2.6.1 (amd64)\n\
             Usage: apt [options] command\n\n\
             apt is a commandline package manager and provides commands for\n\
             searching and managing as well as querying information about packages.\n",
        ),
    }
}

/// `dpkg`
pub fn dpkg(_shell: &Shell, args: &[String]) -> CommandResult {
    let list = args.iter().any(|a| a == "-l" || a == "--list");
    let show = args.iter().position(|a| a == "-s" || a == "--status");

    if let Some(pos) = show {
        let pkg = args.get(pos + 1).map(String::as_str);
        return match pkg.and_then(|p| INSTALLED.iter().find(|(n, _, _)| *n == p)) {
            Some((name, ver, desc)) => CommandResult::ok(format!(
                "Package: {name}\nStatus: install ok installed\nPriority: optional\n\
                 Section: misc\nInstalled-Size: 1024\nMaintainer: Debian\n\
                 Architecture: amd64\nVersion: {ver}\nDescription: {desc}\n"
            )),
            None => CommandResult::err(
                format!(
                    "dpkg-query: package '{}' is not installed and no information is available\n",
                    pkg.unwrap_or("")
                ),
                1,
            ),
        };
    }

    if list {
        let mut out = String::new();
        out.push_str("Desired=Unknown/Install/Remove/Purge/Hold\n");
        out.push_str(
            "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n",
        );
        out.push_str("|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n");
        out.push_str("||/ Name                    Version            Architecture Description\n");
        out.push_str("+++-=======================-==================-============-=================================>\n");
        for (name, ver, desc) in INSTALLED {
            out.push_str(&format!(
                "ii  {name:<23} {ver:<18} amd64        {}\n",
                trunc(desc, 50)
            ));
        }
        return CommandResult::ok(out);
    }

    CommandResult::ok(
        "Debian 'dpkg' package management program version 1.21.22 (amd64).\n\
         This is free software; see the GNU General Public License version 2 or\n\
         later for copying conditions. There is NO warranty.\n",
    )
}

/// Truncate a string to at most `max` chars (the `dpkg -l` description column).
fn trunc(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn apt_update_as_root() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "apt-get update");
        assert!(out.contains("Reading package lists... Done"));
        assert!(out.contains("bookworm"));
    }

    #[test]
    fn apt_install_requires_root() {
        let mut shell = Shell::new("attacker", "debian");
        let out = shell.execute("apt install nginx");
        assert!(out.text.contains("are you root?"));
        assert_eq!(shell.last_status, 100);
    }

    #[test]
    fn apt_install_unknown_package() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("apt install totallyfakepkg");
        assert!(out.text.contains("Unable to locate package totallyfakepkg"));
        assert_eq!(shell.last_status, 100);
    }

    #[test]
    fn apt_install_known_package_is_already_newest() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("apt install bash");
        assert!(out.text.contains("bash is already the newest version"));
        assert_eq!(shell.last_status, 0);
    }

    #[test]
    fn apt_show_and_list() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "apt show curl").contains("Package: curl"));
        assert!(run(&mut shell, "apt list").contains("openssh-server/now"));
    }

    #[test]
    fn dpkg_list_and_status() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "dpkg -l").contains("openssh-server"));
        assert!(run(&mut shell, "dpkg -s bash").contains("Status: install ok installed"));
    }

    #[test]
    fn dpkg_status_unknown_package() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("dpkg -s totallyfakepkg");
        assert!(out.text.contains("is not installed"));
        assert_eq!(shell.last_status, 1);
    }
}
