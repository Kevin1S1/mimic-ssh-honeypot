use super::CommandResult;
use crate::shell::Shell;

const INSTALLED: &[(&str, &str, &str)] = &[
    ("adduser", "3.131", "add and remove users and groups"),
    (
        "base-files",
        "12.4+deb12u5",
        "Debian base system miscellaneous files",
    ),
    ("bash", "5.2.15-2+b7", "GNU Bourne Again SHell"),
    (
        "bind9-dnsutils",
        "1:9.18.28-1~deb12u2",
        "Clients provided with BIND9",
    ),
    (
        "bzip2",
        "1.0.8-5+b1",
        "high-quality block-sorting file compressor",
    ),
    ("coreutils", "9.1-1", "GNU core utilities"),
    ("cron", "3.0pl1-184", "process scheduling daemon"),
    (
        "curl",
        "7.88.1-10+deb12u5",
        "command line tool for transferring data with URL syntax",
    ),
    (
        "debianutils",
        "5.7-0.5~deb12u1",
        "Miscellaneous utilities specific to Debian",
    ),
    ("dpkg", "1.21.22", "Debian package management system"),
    (
        "e2fsprogs",
        "1.47.0-2",
        "ext2/ext3/ext4 file system utilities",
    ),
    (
        "findutils",
        "4.9.0-4",
        "utilities for finding files--find, xargs",
    ),
    ("gzip", "1.12-1", "GNU compression utilities"),
    (
        "iproute2",
        "6.1.0-3",
        "networking and traffic control tools",
    ),
    ("less", "590-2.1~deb12u2", "pager program similar to more"),
    ("libc-bin", "2.36-9+deb12u4", "GNU C Library: Binaries"),
    ("libc6", "2.36-9+deb12u4", "GNU C Library: Shared libraries"),
    ("man-db", "2.11.2-2", "tools for reading manual pages"),
    (
        "mawk",
        "1.3.4.20200120-3.1",
        "a pattern scanning and text processing language",
    ),
    (
        "nano",
        "7.2-1",
        "small, friendly text editor inspired by Pico",
    ),
    (
        "ncurses-bin",
        "6.4-4",
        "terminal-related programs and man pages",
    ),
    ("net-tools", "2.10-0.1", "NET-3 networking toolkit"),
    ("netcat-openbsd", "1.219-1", "TCP/IP swiss army knife"),
    (
        "openssh-client",
        "1:9.2p1-2+deb12u3",
        "secure shell (SSH) client, for secure access to remote machines",
    ),
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
    ("perl-base", "5.36.0-7+deb12u1", "minimal Perl system"),
    ("procps", "2:3.3.17-7", "/proc file system utilities"),
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
    (
        "tar",
        "1.34+dfsg-1.2+deb12u1",
        "GNU version of the tar archiving utility",
    ),
    (
        "util-linux",
        "2.38.1-5+deb12u3",
        "miscellaneous system utilities",
    ),
    ("wget", "1.21.3-1+deb12u1", "retrieves files from the web"),
    ("xz-utils", "5.4.1-0.2", "XZ-format compression utilities"),
];

const APT_ERROR_STATUS: i32 = 100;

const DPKG_DESCRIPTION_WIDTH: usize = 50;

const PRIVILEGED_APT_COMMANDS: &[&str] = &[
    "update",
    "upgrade",
    "install",
    "remove",
    "purge",
    "dist-upgrade",
    "autoremove",
];

const READING_PACKAGE_STATE: &str = "Reading package lists... Done\n\
                                     Building dependency tree... Done\n\
                                     Reading state information... Done\n";

const NOTHING_CHANGED: &str = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";

fn find_package(name: &str) -> Option<&'static (&'static str, &'static str, &'static str)> {
    INSTALLED.iter().find(|(package, _, _)| *package == name)
}

fn is_installed(name: &str) -> bool {
    find_package(name).is_some()
}

fn args_after<'a>(args: &'a [String], word: &'a str) -> impl Iterator<Item = &'a String> {
    args.iter().skip_while(move |a| a.as_str() != word).skip(1)
}

fn no_change_summary() -> String {
    format!("{READING_PACKAGE_STATE}{NOTHING_CHANGED}")
}

pub fn apt(shell: &Shell, args: &[String]) -> CommandResult {
    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    let needs_root = sub.is_some_and(|s| PRIVILEGED_APT_COMMANDS.contains(&s));
    if needs_root && shell.uid != 0 {
        return CommandResult::err(
            "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n\
             E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n",
            APT_ERROR_STATUS,
        );
    }

    match sub {
        Some("update") => CommandResult::ok(
            "Hit:1 http://deb.debian.org/debian bookworm InRelease\n\
             Hit:2 http://deb.debian.org/debian bookworm-updates InRelease\n\
             Hit:3 http://security.debian.org/debian-security bookworm-security InRelease\n\
             Reading package lists... Done\n",
        ),
        Some("upgrade" | "dist-upgrade") => CommandResult::ok(format!(
            "{READING_PACKAGE_STATE}Calculating upgrade... Done\n{NOTHING_CHANGED}"
        )),
        Some("install") => apt_install(args),
        Some("remove" | "purge" | "autoremove") => CommandResult::ok(no_change_summary()),
        Some("list") => apt_list(),
        Some("show") => apt_show(args_after(args, "show").next().map(String::as_str)),
        _ => CommandResult::ok(
            "apt 2.6.1 (amd64)\n\
             Usage: apt [options] command\n\n\
             apt is a commandline package manager and provides commands for\n\
             searching and managing as well as querying information about packages.\n",
        ),
    }
}

fn apt_install(args: &[String]) -> CommandResult {
    let packages: Vec<&str> = args_after(args, "install")
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    if packages.is_empty() {
        return CommandResult::ok(no_change_summary());
    }

    let mut out = String::from(READING_PACKAGE_STATE);
    for (name, version, _) in packages.iter().filter_map(|p| find_package(p)) {
        out.push_str(&format!(
            "{name} is already the newest version ({version}).\n"
        ));
    }
    let errs: String = packages
        .iter()
        .filter(|p| !is_installed(p))
        .map(|p| format!("E: Unable to locate package {p}\n"))
        .collect();
    if !errs.is_empty() {
        return CommandResult::streams(out, errs, APT_ERROR_STATUS);
    }
    out.push_str(NOTHING_CHANGED);
    CommandResult::ok(out)
}

fn apt_list() -> CommandResult {
    let mut out = String::from("Listing... Done\n");
    for (name, version, _) in INSTALLED {
        out.push_str(&format!("{name}/now {version} amd64 [installed,local]\n"));
    }
    CommandResult::ok(out)
}

fn apt_show(package: Option<&str>) -> CommandResult {
    match package.and_then(find_package) {
        Some((name, version, description)) => CommandResult::ok(format!(
            "Package: {name}\nVersion: {version}\nPriority: optional\nSection: misc\n\
             Maintainer: Debian\nArchitecture: amd64\nDescription: {description}\n\n"
        )),
        None => CommandResult::err(
            format!(
                "N: Unable to locate package {}\n",
                package.unwrap_or_default()
            ),
            APT_ERROR_STATUS,
        ),
    }
}

pub fn dpkg(_shell: &Shell, args: &[String]) -> CommandResult {
    if let Some(pos) = args.iter().position(|a| a == "-s" || a == "--status") {
        return dpkg_status(args.get(pos + 1).map(String::as_str));
    }
    if args.iter().any(|a| a == "-l" || a == "--list") {
        return dpkg_list();
    }
    CommandResult::ok(
        "Debian 'dpkg' package management program version 1.21.22 (amd64).\n\
         This is free software; see the GNU General Public License version 2 or\n\
         later for copying conditions. There is NO warranty.\n",
    )
}

fn dpkg_status(package: Option<&str>) -> CommandResult {
    match package.and_then(find_package) {
        Some((name, version, description)) => CommandResult::ok(format!(
            "Package: {name}\nStatus: install ok installed\nPriority: optional\n\
             Section: misc\nInstalled-Size: 1024\nMaintainer: Debian\n\
             Architecture: amd64\nVersion: {version}\nDescription: {description}\n"
        )),
        None => CommandResult::err(
            format!(
                "dpkg-query: package '{}' is not installed and no information is available\n",
                package.unwrap_or_default()
            ),
            1,
        ),
    }
}

fn dpkg_list() -> CommandResult {
    let mut out = String::from(
        "Desired=Unknown/Install/Remove/Purge/Hold\n\
         | Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n\
         |/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n\
         ||/ Name                    Version            Architecture Description\n\
         +++-=======================-==================-============-=================================>\n",
    );
    for (name, version, description) in INSTALLED {
        let description: String = description.chars().take(DPKG_DESCRIPTION_WIDTH).collect();
        out.push_str(&format!(
            "ii  {name:<23} {version:<18} amd64        {description}\n"
        ));
    }
    CommandResult::ok(out)
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
