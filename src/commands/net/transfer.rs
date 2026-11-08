use super::{capture_endpoint, fake_resolve, STDOUT_DESTINATION};
use crate::commands::CommandResult;
use crate::shell::Shell;
use crate::vfs::Vfs;

const NEW_FILE_MODE: u32 = 0o644;
const DEFAULT_REMOTE_NAME: &str = "index.html";
const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_64_PRIME: u64 = 0x100_0000_01b3;
const LCG_MULTIPLIER: u64 = 6364136223846793005;
const LCG_INCREMENT: u64 = 1442695040888963407;
const WGET_NAME_COLUMN: usize = 20;
const KIB: u64 = 1024;

/// Split a URL into `(host, last_path_component)`.
fn url_parts(url: &str) -> (String, String) {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (authority, path) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, ""));
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
        .unwrap_or(DEFAULT_REMOTE_NAME);
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
    let mut state = url.bytes().fold(FNV1A_64_OFFSET_BASIS, |acc, b| {
        (acc ^ b as u64).wrapping_mul(FNV1A_64_PRIME)
    }) | 1;
    (0..size)
        .map(|_| {
            state = state
                .wrapping_mul(LCG_MULTIPLIER)
                .wrapping_add(LCG_INCREMENT);
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
    if dest == STDOUT_DESTINATION {
        return (STDOUT_DESTINATION.to_string(), 0);
    }
    let (dir, name) = Vfs::split_path(dest);
    let Some(parent) = shell
        .vfs
        .resolve(shell.cwd, dir)
        .filter(|parent| shell.vfs.node(*parent).meta.is_dir())
    else {
        return (dest.to_string(), 0);
    };
    let (uid, gid) = (shell.uid, shell.gid);
    let id = shell
        .vfs
        .add_file(parent, name, contents, NEW_FILE_MODE, uid, gid);
    let written = shell
        .vfs
        .node(id)
        .file_bytes()
        .map_or(0, |b| b.len() as u64);
    (shell.vfs.path_of(parent) + "/" + name, written)
}

struct WgetOptions {
    quiet: bool,
    output: Option<String>,
    prefix: Option<String>,
    urls: Vec<String>,
}

/// `wget [OPTION]... [URL]...`
pub fn wget(shell: &mut Shell, args: &[String]) -> CommandResult {
    let options = parse_wget_args(args);
    if options.urls.is_empty() {
        return CommandResult::err(
            "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n",
            1,
        );
    }

    let mut out = String::new();
    for url in &options.urls {
        let (host, base) = url_parts(url);
        let dest = options
            .output
            .clone()
            .or_else(|| options.prefix.as_ref().map(|p| format!("{p}/{base}")))
            .unwrap_or_else(|| base.clone());
        let body = placeholder_bytes(url, fake_size(&host));
        let (written, size) = drop_file(shell, &dest, body);
        capture_endpoint(shell, "wget", url.clone(), written);

        if !options.quiet {
            out.push_str(&wget_transcript(url, &host, &base, size));
        }
    }
    CommandResult::ok(out)
}

fn parse_wget_args(args: &[String]) -> WgetOptions {
    let mut options = WgetOptions {
        quiet: false,
        output: None,
        prefix: None,
        urls: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-q" | "--quiet" => options.quiet = true,
            "-O" | "--output-document" => options.output = iter.next().cloned(),
            "-P" | "--directory-prefix" => options.prefix = iter.next().cloned(),
            "-o" | "--output-file" => {
                iter.next();
            }
            s if s.starts_with("-O") => options.output = Some(s[2..].to_string()),
            s if s.starts_with("--output-document=") => {
                options.output = Some(s["--output-document=".len()..].to_string())
            }
            s if s.starts_with('-') => {} // -c, -L, --no-check-certificate, ...
            other => options.urls.push(other.to_string()),
        }
    }
    options
}

fn wget_transcript(url: &str, host: &str, base: &str, size: u64) -> String {
    let ip = fake_resolve(host);
    let port = if url.starts_with("https://") { 443 } else { 80 };
    let stamp = crate::clock::format(crate::clock::now(), "%F %T");
    let human_size = human(size);
    let mut out = String::new();
    out.push_str(&format!("--{stamp}--  {url}\n"));
    out.push_str(&format!("Resolving {host} ({host})... {ip}\n"));
    out.push_str(&format!(
        "Connecting to {host} ({host})|{ip}|:{port}... connected.\n"
    ));
    out.push_str("HTTP request sent, awaiting response... 200 OK\n");
    out.push_str(&format!(
        "Length: {size} ({human_size}) [application/octet-stream]\n"
    ));
    out.push_str(&format!("Saving to: '{base}'\n\n"));
    out.push_str(&format!(
        "{:<WGET_NAME_COLUMN$}100%[===================>] {human_size:>8}  --.-KB/s    in 0.001s\n\n",
        truncate_chars(base, WGET_NAME_COLUMN),
    ));
    out.push_str(&format!(
        "{stamp} (12.4 MB/s) - '{base}' saved [{size}/{size}]\n\n"
    ));
    out
}

struct CurlOptions {
    output: Option<String>,
    remote_name: bool,
    silent: bool,
    show_headers: bool,
    urls: Vec<String>,
}

/// `curl [OPTION]... [URL]...`
pub fn curl(shell: &mut Shell, args: &[String]) -> CommandResult {
    let options = parse_curl_args(args);
    if options.urls.is_empty() {
        return CommandResult::err(
            "curl: try 'curl --help' or 'curl --manual' for more information\n",
            2,
        );
    }

    let mut out = String::new();
    for url in &options.urls {
        let (host, base) = url_parts(url);
        let dest = match (&options.output, options.remote_name) {
            (Some(output), _) => output.clone(),
            (None, true) => base,
            (None, false) => STDOUT_DESTINATION.to_string(),
        };
        let to_stdout = dest == STDOUT_DESTINATION;
        let (written, size) = if to_stdout {
            (STDOUT_DESTINATION.to_string(), fake_size(&host))
        } else {
            drop_file(shell, &dest, placeholder_bytes(url, fake_size(&host)))
        };
        capture_endpoint(shell, "curl", url.clone(), written);

        if options.show_headers {
            out.push_str(&curl_headers(size));
        } else if !options.silent && !to_stdout {
            out.push_str(&curl_progress(size));
        }
    }
    CommandResult::ok(out)
}

fn parse_curl_args(args: &[String]) -> CurlOptions {
    let mut options = CurlOptions {
        output: None,
        remote_name: false,
        silent: false,
        show_headers: false,
        urls: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-o" | "--output" => options.output = iter.next().cloned(),
            "-O" | "--remote-name" => options.remote_name = true,
            "-s" | "--silent" => options.silent = true,
            "-I" | "--head" => options.show_headers = true,
            "-A" | "--user-agent" | "-H" | "--header" | "-d" | "--data" | "-X" | "--request"
            | "-e" | "--referer" | "-b" | "--cookie" | "-u" | "--user" => {
                iter.next();
            }
            s if s.starts_with('-') => {} // -L, -k, -v, -f, ...
            other => options.urls.push(other.to_string()),
        }
    }
    options
}

fn curl_headers(size: u64) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         Server: nginx/1.22.1\r\n\
         Date: {}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {size}\r\n\
         Connection: keep-alive\r\n\r\n",
        crate::clock::format(crate::clock::now(), "%a, %d %b %Y %H:%M:%S GMT")
    )
}

/// Real curl always renders this table when the body goes to a file. A small
/// transfer completes instantly; curl then reports a rate in the hundreds of
/// KB/s rather than a measured one.
fn curl_progress(size: u64) -> String {
    let rate = format!("{}k", 300 + size % 500);
    let mut out = String::from(
        "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n",
    );
    out.push_str("                                 Dload  Upload   Total   Spent    Left  Speed\n");
    out.push_str(&format!(
        "100 {size:>5}  100 {size:>5}    0     0  {rate:>5}      0 --:--:-- --:--:-- --:--:-- {rate:>5}\n"
    ));
    out
}

/// Truncate a string to `max` chars for fixed-width columns.
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Human-readable byte size in wget's style (K/M/G with one decimal).
fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["", "K", "M", "G"];
    if bytes < KIB {
        return bytes.to_string();
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= KIB as f64 && unit < UNITS.len() - 1 {
        value /= KIB as f64;
        unit += 1;
    }
    format!("{value:.1}{}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::url_parts;

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
}
