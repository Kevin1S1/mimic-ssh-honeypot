use super::CommandResult;
use crate::shell::{Capture, Pending, Shell};

const PASSWD_PATH: &str = "/etc/passwd";
const GROUP_PATH: &str = "/etc/group";
const SHADOW_PATH: &str = "/etc/shadow";

const SHADOW_AGING_FIELDS: &str = "19999:0:99999:7:::";
const CHANGED_PASSWORD_HASH: &str = "$6$mimic$changed";
const LOCKED_PASSWORD_HASH: &str = "!";

const FIRST_ADDED_ID: u32 = 1001;
const DEFAULT_LOGIN_SHELL: &str = "/bin/sh";
const ACCOUNT_FILE_MODE: u32 = 0o644;
const HOME_DIR_MODE: u32 = 0o755;

const USAGE_STATUS: i32 = 2;
const ALREADY_EXISTS_STATUS: i32 = 9;
const USERDEL_UNKNOWN_USER_STATUS: i32 = 6;
const USERADD_HOME_FAILED_STATUS: i32 = 12;
const UNIT_INACTIVE_STATUS: i32 = 3;
const UNIT_NOT_FOUND_STATUS: i32 = 4;
const GETENT_KEY_NOT_FOUND_STATUS: i32 = 2;
const NOHUP_CANNOT_RUN_STATUS: i32 = 125;

const SLEEP_UNIT_SUFFIXES: [char; 4] = ['s', 'm', 'h', 'd'];

fn read_text(shell: &Shell, path: &str) -> String {
    shell
        .vfs
        .resolve(shell.cwd, path)
        .and_then(|id| shell.vfs.node(id).file_bytes())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

fn write_text(shell: &mut Shell, path: &str, text: &str) -> bool {
    let Some((parent, name)) = super::fs::resolve_parent(shell, path) else {
        return false;
    };
    if let Some(id) = shell.vfs.child(parent, &name) {
        return shell.vfs.write_file(id, text.as_bytes(), false);
    }
    if shell.vfs.is_full(parent) {
        return false;
    }
    let (uid, gid) = (shell.uid, shell.gid);
    shell.vfs.add_file(
        parent,
        &name,
        text.as_bytes().to_vec(),
        ACCOUNT_FILE_MODE,
        uid,
        gid,
    );
    true
}

fn append_line(shell: &mut Shell, path: &str, line: &str) -> bool {
    let text = read_text(shell, path);
    write_text(shell, path, &format!("{text}{line}\n"))
}

fn is_entry_for(line: &str, name: &str) -> bool {
    line.strip_prefix(name)
        .is_some_and(|rest| rest.starts_with(':'))
}

fn has_entry(database: &str, name: &str) -> bool {
    database.lines().any(|line| is_entry_for(line, name))
}

fn user_exists(shell: &Shell, name: &str) -> bool {
    has_entry(&read_text(shell, PASSWD_PATH), name)
}

fn shadow_entry(user: &str, hash: &str) -> String {
    format!("{user}:{hash}:{SHADOW_AGING_FIELDS}")
}

fn operands(args: &[String]) -> Vec<&str> {
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect()
}

fn first_operand(args: &[String]) -> Option<&String> {
    args.iter().find(|a| !a.starts_with('-'))
}

fn permission_denied(command: &str) -> CommandResult {
    CommandResult::err(format!("{command}: Permission denied.\n"), 1)
}

fn missing_operand(command: &str) -> CommandResult {
    CommandResult::err(format!("{command}: missing operand\n"), USAGE_STATUS)
}

pub fn sleep(_shell: &Shell, args: &[String]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::err(
            "sleep: missing operand\nTry 'sleep --help' for more information.\n",
            1,
        );
    }
    let is_interval = |a: &&String| {
        a.trim_end_matches(SLEEP_UNIT_SUFFIXES)
            .parse::<f64>()
            .is_ok()
    };
    if let Some(invalid) = args.iter().find(|a| !is_interval(a)) {
        return CommandResult::err(format!("sleep: invalid time interval '{invalid}'\n"), 1);
    }
    CommandResult::empty()
}

pub fn set_shadow_entry(shell: &mut Shell, user: &str) {
    let shadow = read_text(shell, SHADOW_PATH);
    let updated: Vec<String> = shadow
        .lines()
        .map(|line| {
            if is_entry_for(line, user) {
                shadow_entry(user, CHANGED_PASSWORD_HASH)
            } else {
                line.to_string()
            }
        })
        .collect();
    write_text(shell, SHADOW_PATH, &format!("{}\n", updated.join("\n")));
}

pub fn passwd(shell: &mut Shell, args: &[String]) -> CommandResult {
    let target = first_operand(args)
        .cloned()
        .unwrap_or_else(|| shell.username.clone());
    if shell.uid != 0 && target != shell.username {
        return CommandResult::err(
            format!("passwd: You may not view or modify password information for {target}.\n"),
            1,
        );
    }
    if !user_exists(shell, &target) {
        return CommandResult::err(format!("passwd: user '{target}' does not exist\n"), 1);
    }
    let banner = format!("Changing password for {target}.\n");
    shell.pending = Some(Pending::NewPassword {
        target,
        first: None,
    });
    CommandResult::ok(format!("{banner}New password: "))
}

pub fn chpasswd(shell: &mut Shell, _args: &[String]) -> CommandResult {
    let input = shell.stdin.clone().unwrap_or_default();
    if input.trim().is_empty() {
        return CommandResult::empty();
    }
    if shell.uid != 0 {
        return permission_denied("chpasswd");
    }

    let errs: String = input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| change_password(shell, line).err())
        .collect();
    let status = i32::from(!errs.is_empty());
    CommandResult::streams(String::new(), errs, status)
}

fn change_password(shell: &mut Shell, line: &str) -> Result<(), String> {
    let Some((user, password)) = line.split_once(':') else {
        return Err(format!("chpasswd: line '{line}' is badly formatted\n"));
    };
    if !user_exists(shell, user) {
        return Err(format!(
            "chpasswd: line '{line}': user '{user}' does not exist\n"
        ));
    }
    shell.captures.push(Capture::PasswordChange {
        target: user.to_string(),
        password: password.to_string(),
    });
    set_shadow_entry(shell, user);
    Ok(())
}

struct NewAccount {
    name: String,
    uid: u32,
    login_shell: String,
    create_home: bool,
}

impl NewAccount {
    fn parse(args: &[String]) -> Option<Self> {
        let mut login_shell = DEFAULT_LOGIN_SHELL.to_string();
        let mut uid = FIRST_ADDED_ID;
        let mut create_home = false;
        let mut name = None;
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-m" | "--create-home" => create_home = true,
                "-s" | "--shell" => {
                    if let Some(value) = iter.next() {
                        login_shell = value.clone();
                    }
                }
                "-u" | "--uid" => {
                    if let Some(value) = iter.next().and_then(|v| v.parse().ok()) {
                        uid = value;
                    }
                }
                "-g" | "-G" | "-d" | "-c" | "-p" => {
                    iter.next();
                }
                other if other.starts_with('-') => {}
                other => name = Some(other.to_string()),
            }
        }
        Some(Self {
            name: name?,
            uid,
            login_shell,
            create_home,
        })
    }

    fn home(&self) -> String {
        format!("/home/{}", self.name)
    }

    fn passwd_entry(&self) -> String {
        let Self {
            name,
            uid,
            login_shell,
            ..
        } = self;
        format!("{name}:x:{uid}:{uid}::{}:{login_shell}", self.home())
    }
}

pub fn useradd(shell: &mut Shell, args: &[String]) -> CommandResult {
    if shell.uid != 0 {
        return CommandResult::err(
            "useradd: Permission denied.\nuseradd: cannot lock /etc/passwd; try again later.\n",
            1,
        );
    }
    let Some(account) = NewAccount::parse(args) else {
        return missing_operand("useradd");
    };
    let NewAccount { name, uid, .. } = &account;
    if user_exists(shell, name) {
        return CommandResult::err(
            format!("useradd: user '{name}' already exists\n"),
            ALREADY_EXISTS_STATUS,
        );
    }

    if !append_line(shell, PASSWD_PATH, &account.passwd_entry()) {
        return CommandResult::err("useradd: cannot open /etc/passwd\n", 1);
    }
    append_line(shell, GROUP_PATH, &format!("{name}:x:{uid}:"));
    append_line(
        shell,
        SHADOW_PATH,
        &shadow_entry(name, LOCKED_PASSWORD_HASH),
    );

    let home = account.home();
    if account.create_home
        && shell
            .vfs
            .mkdir_p(&home, HOME_DIR_MODE, *uid, *uid)
            .is_none()
    {
        return CommandResult::err(
            format!("useradd: cannot create directory {home}\n"),
            USERADD_HOME_FAILED_STATUS,
        );
    }
    CommandResult::empty()
}

pub fn userdel(shell: &mut Shell, args: &[String]) -> CommandResult {
    if shell.uid != 0 {
        return permission_denied("userdel");
    }
    let Some(name) = first_operand(args) else {
        return missing_operand("userdel");
    };
    let passwd_file = read_text(shell, PASSWD_PATH);
    if !has_entry(&passwd_file, name) {
        return CommandResult::err(
            format!("userdel: user '{name}' does not exist\n"),
            USERDEL_UNKNOWN_USER_STATUS,
        );
    }
    let kept: Vec<&str> = passwd_file
        .lines()
        .filter(|line| !is_entry_for(line, name))
        .collect();
    write_text(shell, PASSWD_PATH, &format!("{}\n", kept.join("\n")));
    CommandResult::empty()
}

pub fn groupadd(shell: &mut Shell, args: &[String]) -> CommandResult {
    if shell.uid != 0 {
        return permission_denied("groupadd");
    }
    let Some(name) = first_operand(args) else {
        return missing_operand("groupadd");
    };
    if has_entry(&read_text(shell, GROUP_PATH), name) {
        return CommandResult::err(
            format!("groupadd: group '{name}' already exists\n"),
            ALREADY_EXISTS_STATUS,
        );
    }
    append_line(shell, GROUP_PATH, &format!("{name}:x:{FIRST_ADDED_ID}:"));
    CommandResult::empty()
}

struct Unit {
    name: &'static str,
    description: &'static str,
}

const UNITS: &[Unit] = &[
    Unit {
        name: "ssh.service",
        description: "OpenBSD Secure Shell server",
    },
    Unit {
        name: "cron.service",
        description: "Regular background program processing daemon",
    },
    Unit {
        name: "dbus.service",
        description: "D-Bus System Message Bus",
    },
    Unit {
        name: "systemd-journald.service",
        description: "Journal Service",
    },
    Unit {
        name: "systemd-logind.service",
        description: "User Login Management",
    },
    Unit {
        name: "systemd-networkd.service",
        description: "Network Configuration",
    },
    Unit {
        name: "systemd-resolved.service",
        description: "Network Name Resolution",
    },
    Unit {
        name: "systemd-timesyncd.service",
        description: "Network Time Synchronization",
    },
    Unit {
        name: "rsyslog.service",
        description: "System Logging Service",
    },
    Unit {
        name: "getty@tty1.service",
        description: "Getty on tty1",
    },
];

const UNIT_SUB_STATE: &str = "running";

const STATE_CHANGING_VERBS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "reload",
    "enable",
    "disable",
    "daemon-reload",
    "mask",
    "unmask",
];

fn full_unit_name(unit: &str) -> String {
    if unit.contains('.') {
        unit.to_string()
    } else {
        format!("{unit}.service")
    }
}

fn find_unit(unit: &str) -> Option<&'static Unit> {
    let name = full_unit_name(unit);
    UNITS.iter().find(|u| u.name == name)
}

pub fn systemctl(shell: &Shell, args: &[String]) -> CommandResult {
    let operands = operands(args);
    let verb = operands.first().copied().unwrap_or("list-units");
    let unit = operands.get(1).copied();

    match verb {
        "list-units" | "list-unit-files" => list_units(),
        "status" => match unit {
            None => CommandResult::ok(format!(
                "â— {}\n    State: running\n     Jobs: 0 queued\n   Failed: 0 units\n",
                shell.hostname
            )),
            Some(unit) => unit_status(unit),
        },
        "is-active" => match unit.and_then(find_unit) {
            Some(_) => CommandResult::ok("active\n"),
            None => CommandResult::streams("inactive\n", "", UNIT_INACTIVE_STATUS),
        },
        "is-enabled" => match unit.and_then(find_unit) {
            Some(_) => CommandResult::ok("enabled\n"),
            None => CommandResult::streams("disabled\n", "", 1),
        },
        verb if STATE_CHANGING_VERBS.contains(&verb) => change_unit_state(shell, verb, unit),
        other => CommandResult::err(format!("Unknown command verb {other}.\n"), 1),
    }
}

fn list_units() -> CommandResult {
    let mut out = String::from("  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION\n");
    for Unit { name, description } in UNITS {
        out.push_str(&format!(
            "  {name:<27} loaded active {UNIT_SUB_STATE:<7} {description}\n"
        ));
    }
    out.push_str(&format!("\n{} loaded units listed.\n", UNITS.len()));
    CommandResult::ok(out)
}

fn unit_status(unit: &str) -> CommandResult {
    let Some(Unit { name, description }) = find_unit(unit) else {
        return CommandResult::err(
            format!(
                "Unit {}.service could not be found.\n",
                unit.trim_end_matches(".service")
            ),
            UNIT_NOT_FOUND_STATUS,
        );
    };
    CommandResult::ok(format!(
        "â— {name} - {description}\n     \
         Loaded: loaded (/lib/systemd/system/{name}; enabled; preset: enabled)\n     \
         Active: active (running) since {}; {} ago\n   \
         Main PID: 1 (systemd)\n      \
         Tasks: 1 (limit: 2273)\n     \
         Memory: 5.4M\n        \
         CPU: 142ms\n     \
         CGroup: /system.slice/{name}\n",
        crate::clock::format(crate::clock::boot_time(), "%a %Y-%m-%d %H:%M:%S %Z"),
        crate::clock::uptime_phrase(crate::clock::uptime_secs()),
    ))
}

fn change_unit_state(shell: &Shell, verb: &str, unit: Option<&str>) -> CommandResult {
    if shell.uid != 0 {
        return CommandResult::err(
            format!(
                "Failed to {verb} {}: Interactive authentication required.\n",
                unit.unwrap_or("unit")
            ),
            1,
        );
    }
    match (verb, unit) {
        ("enable", Some(unit)) => CommandResult::ok(format!(
            "Created symlink /etc/systemd/system/multi-user.target.wants/{0} â†’ /lib/systemd/system/{0}.\n",
            full_unit_name(unit)
        )),
        ("disable", Some(unit)) => CommandResult::ok(format!(
            "Removed \"/etc/systemd/system/multi-user.target.wants/{}\".\n",
            full_unit_name(unit)
        )),
        _ => CommandResult::empty(),
    }
}

pub fn service(shell: &Shell, args: &[String]) -> CommandResult {
    match operands(args).as_slice() {
        [] => {
            let out: String = UNITS
                .iter()
                .map(|u| format!(" [ + ]  {}\n", u.name.trim_end_matches(".service")))
                .collect();
            CommandResult::ok(out)
        }
        [name, action, ..] => systemctl(shell, &[action.to_string(), name.to_string()]),
        [_] => CommandResult::err(
            "Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]\n",
            1,
        ),
    }
}

fn stat_error(command: &str, path: &str) -> String {
    format!("{command}: No such file or directory while trying to stat {path}\n")
}

pub fn chattr(shell: &Shell, args: &[String]) -> CommandResult {
    let (flags, files): (Vec<&String>, Vec<&String>) =
        args.iter().partition(|a| a.starts_with(['+', '-', '=']));
    if flags.is_empty() || files.is_empty() {
        return CommandResult::err(
            "Usage: chattr [-pRVf] [-+=aAcCdDeijPsStTuFx] [-v version] files...\n",
            1,
        );
    }
    let errs: String = files
        .into_iter()
        .filter(|f| shell.vfs.resolve(shell.cwd, f).is_none())
        .map(|f| stat_error("chattr", f))
        .collect();
    let status = i32::from(!errs.is_empty());
    CommandResult::streams(String::new(), errs, status)
}

pub fn lsattr(shell: &Shell, args: &[String]) -> CommandResult {
    let files = operands(args);
    let targets: Vec<String> = if files.is_empty() {
        shell
            .vfs
            .entries(shell.cwd)
            .unwrap_or_default()
            .into_iter()
            .map(|(name, _)| format!("./{name}"))
            .collect()
    } else {
        files.into_iter().map(str::to_string).collect()
    };
    let mut out = String::new();
    let mut errs = String::new();
    for target in targets {
        if shell.vfs.resolve(shell.cwd, &target).is_some() {
            out.push_str(&format!("--------------e------- {target}\n"));
        } else {
            errs.push_str(&stat_error("lsattr", &target));
        }
    }
    let status = i32::from(!errs.is_empty());
    CommandResult::streams(out, errs, status)
}

pub fn nohup(shell: &mut Shell, args: &[String]) -> CommandResult {
    let argv: Vec<String> = args
        .iter()
        .skip_while(|a| a.starts_with('-'))
        .cloned()
        .collect();
    if argv.is_empty() {
        return CommandResult::err("nohup: missing operand\n", NOHUP_CANNOT_RUN_STATUS);
    }
    let mut result = super::dispatch(shell, &argv);
    result.stderr.insert_str(
        0,
        "nohup: ignoring input and appending output to 'nohup.out'\n",
    );
    result
}

pub fn sync(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::empty()
}

pub fn nologin(_shell: &Shell, _args: &[String]) -> CommandResult {
    CommandResult::err("This account is currently not available.\n", 1)
}

const GETENT_DATABASES: &[(&str, &str)] = &[
    ("passwd", PASSWD_PATH),
    ("group", GROUP_PATH),
    ("shadow", SHADOW_PATH),
    ("hosts", "/etc/hosts"),
];

fn matches_key(line: &str, key: &str) -> bool {
    is_entry_for(line, key) || line.split_whitespace().any(|field| field == key)
}

pub fn getent(shell: &Shell, args: &[String]) -> CommandResult {
    let operands = operands(args);
    let Some((database, keys)) = operands.split_first() else {
        return CommandResult::err("Usage: getent [OPTION...] database [key ...]\n", 1);
    };
    let Some((_, path)) = GETENT_DATABASES.iter().find(|(name, _)| name == database) else {
        return CommandResult::err(format!("Unknown database: {database}\n"), USAGE_STATUS);
    };
    let text = read_text(shell, path);
    if keys.is_empty() {
        return CommandResult::ok(text);
    }
    let mut out = String::new();
    for key in keys {
        for line in text.lines().filter(|line| matches_key(line, key)) {
            out.push_str(line);
            out.push('\n');
        }
    }
    let status = if out.is_empty() {
        GETENT_KEY_NOT_FOUND_STATUS
    } else {
        0
    };
    CommandResult::streams(out, String::new(), status)
}

pub fn killall(shell: &Shell, args: &[String]) -> CommandResult {
    let names = operands(args);
    if names.is_empty() {
        return CommandResult::err("Usage: killall [OPTION]... [--] NAME...\n", 1);
    }
    let errs: String = names
        .into_iter()
        .filter(|name| super::system::process_pid(shell, name).is_none())
        .map(|name| format!("{name}: no process found\n"))
        .collect();
    let status = i32::from(!errs.is_empty());
    CommandResult::streams(String::new(), errs, status)
}

pub fn pidof(shell: &Shell, args: &[String]) -> CommandResult {
    let pids: Vec<String> = operands(args)
        .into_iter()
        .filter_map(|name| super::system::process_pid(shell, name))
        .map(|pid| pid.to_string())
        .collect();
    if pids.is_empty() {
        return CommandResult::streams(String::new(), String::new(), 1);
    }
    CommandResult::ok(format!("{}\n", pids.join(" ")))
}

pub fn pgrep(shell: &Shell, args: &[String]) -> CommandResult {
    let long = args.iter().any(|a| a == "-l" || a == "-a");
    let Some(pattern) = first_operand(args) else {
        return CommandResult::err("pgrep: no matching criteria specified\n", USAGE_STATUS);
    };
    let out: String = super::system::process_table(shell)
        .into_iter()
        .filter(|(_, cmd)| super::system::process_name(cmd).contains(pattern.as_str()))
        .map(|(pid, cmd)| {
            if long {
                format!("{pid} {cmd}\n")
            } else {
                format!("{pid}\n")
            }
        })
        .collect();
    let status = i32::from(out.is_empty());
    CommandResult::streams(out, String::new(), status)
}

#[cfg(test)]
mod tests {
    use crate::shell::Shell;

    fn run(shell: &mut Shell, line: &str) -> String {
        let out = shell.execute(line);
        format!("{}{}", out.stdout, out.stderr)
    }

    #[test]
    fn sleep_accepts_durations_and_rejects_junk() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "sleep 5"), "");
        assert_eq!(run(&mut shell, "sleep 0.5"), "");
        assert_eq!(run(&mut shell, "sleep 2m"), "");
        assert!(run(&mut shell, "sleep abc").contains("invalid time interval"));
    }

    #[test]
    fn chpasswd_locks_out_the_owner_and_captures_the_plaintext() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("echo 'root:hunter2' | chpasswd");
        assert_eq!(out.status, 0, "{}", out.stderr);
        assert!(
            shell.captures.iter().any(
                |c| matches!(c, crate::shell::Capture::PasswordChange { target, password }
                    if target == "root" && password == "hunter2")
            ),
            "the plaintext must be captured as forensic data"
        );

        let shadow = run(&mut shell, "cat /etc/shadow");
        assert!(shadow.contains("root:$6$mimic$changed"), "{shadow}");
        assert!(
            !shadow.contains("hunter2"),
            "plaintext must not reach the VFS"
        );
    }

    #[test]
    fn chpasswd_rejects_unknown_users_and_non_root() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("echo 'nosuch:x' | chpasswd");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("does not exist"), "{}", out.stderr);

        let mut user = Shell::new("user", "debian");
        let out = user.execute("echo 'root:x' | chpasswd");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("Permission denied"), "{}", out.stderr);
    }

    #[test]
    fn useradd_creates_a_backdoor_account_visible_to_getent() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "useradd -m -s /bin/bash backdoor"), "");
        let passwd = run(&mut shell, "cat /etc/passwd");
        assert!(
            passwd.contains("backdoor:x:1001:1001::/home/backdoor:/bin/bash"),
            "{passwd}"
        );

        assert!(run(&mut shell, "getent passwd backdoor").contains("backdoor"));
        assert!(run(&mut shell, "ls /home").contains("backdoor"));

        let again = shell.execute("useradd backdoor");
        assert_eq!(again.status, 9);
    }

    #[test]
    fn useradd_is_root_only() {
        let mut shell = Shell::new("user", "debian");
        let out = shell.execute("useradd eve");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("Permission denied"), "{}", out.stderr);
    }

    #[test]
    fn systemctl_reports_a_plausible_service_state() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "systemctl is-active ssh").starts_with("active"));
        assert!(run(&mut shell, "systemctl status ssh").contains("OpenBSD Secure Shell server"));
        assert!(run(&mut shell, "systemctl list-units").contains("cron.service"));

        let missing = shell.execute("systemctl status nosuchthing");
        assert_eq!(missing.status, 4);
        assert!(
            missing.stderr.contains("could not be found"),
            "{}",
            missing.stderr
        );
    }

    #[test]
    fn systemctl_enable_is_root_only_and_reports_the_symlink() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "systemctl enable evil");
        assert!(out.contains("Created symlink"), "{out}");
        assert!(out.contains("evil.service"), "{out}");

        let mut user = Shell::new("user", "debian");
        let denied = user.execute("systemctl enable evil");
        assert_eq!(denied.status, 1);
        assert!(
            denied.stderr.contains("authentication required"),
            "{}",
            denied.stderr
        );
    }

    #[test]
    fn getent_reads_the_emulated_databases() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "getent passwd root").starts_with("root:x:0:0:"));
        assert!(run(&mut shell, "getent group sudo").contains("sudo:x:27"));
        let missing = shell.execute("getent passwd nosuchuser");
        assert_eq!(missing.status, 2);
    }

    #[test]
    fn chattr_and_lsattr_agree_about_what_exists() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "chattr +i /etc/passwd"), "");
        assert!(run(&mut shell, "lsattr /etc/passwd").contains("/etc/passwd"));
        let missing = shell.execute("chattr +i /nope");
        assert_eq!(missing.status, 1);
    }

    #[test]
    fn the_shells_etc_passwd_names_all_exist() {
        let mut shell = Shell::new("root", "debian");
        assert_eq!(run(&mut shell, "which sync"), "/usr/bin/sync\n");
        assert_eq!(run(&mut shell, "which nologin"), "/usr/sbin/nologin\n");
        assert_eq!(shell.execute("sync").status, 0);
        let out = shell.execute("nologin");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("not available"), "{}", out.stderr);
    }

    #[test]
    fn pidof_and_pgrep_agree_with_the_process_table() {
        let mut shell = Shell::new("root", "debian");

        assert!(!run(&mut shell, "pidof sshd").trim().is_empty());
        assert!(!run(&mut shell, "pgrep sshd").trim().is_empty());
        let missing = shell.execute("pidof nosuchdaemon");
        assert_eq!(missing.status, 1);
    }

    #[test]
    fn passwd_prompts_twice_and_captures_the_secret() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("passwd root");
        assert!(out.stdout.ends_with("New password: "), "{:?}", out.stdout);
        let out = shell.resume("s3cret");
        assert!(
            out.stdout.ends_with("Retype new password: "),
            "{:?}",
            out.stdout
        );
        let out = shell.resume("s3cret");
        assert!(
            out.stdout.contains("updated successfully"),
            "{:?}",
            out.stdout
        );
        assert!(shell.pending.is_none(), "the prompt must be cleared");
        assert!(shell.captures.iter().any(
            |c| matches!(c, crate::shell::Capture::PasswordChange { target, password }
                    if target == "root" && password == "s3cret")
        ));
        let shadow = run(&mut shell, "cat /etc/shadow");
        assert!(shadow.contains("root:$6$mimic$changed"), "{shadow}");
        assert!(
            !shadow.contains("s3cret"),
            "plaintext must not reach the VFS"
        );
    }

    #[test]
    fn passwd_refuses_a_mismatch_and_an_unknown_user() {
        let mut shell = Shell::new("root", "debian");
        shell.execute("passwd root");
        shell.resume("one");
        let out = shell.resume("two");
        assert_eq!(out.status, 1);
        assert!(out.stderr.contains("do not match"), "{}", out.stderr);
        assert!(shell.captures.is_empty(), "a mismatch captures nothing");

        let out = shell.execute("passwd nosuchuser");
        assert_eq!(out.status, 1);
        assert!(shell.pending.is_none(), "no prompt for a missing account");
    }

    #[test]
    fn nohup_runs_the_command_and_announces_the_redirect() {
        let mut shell = Shell::new("root", "debian");
        let out = shell.execute("nohup echo hi");
        assert_eq!(out.stdout, "hi\n");
        assert!(out.stderr.contains("nohup.out"), "{}", out.stderr);
    }
}
