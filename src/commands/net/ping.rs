use super::fake_resolve;
use crate::commands::CommandResult;
use crate::shell::Shell;

const DEFAULT_COUNT: u32 = 4;
const MAX_COUNT: u32 = 20;
const INTERVAL_MS: u32 = 1001;

pub fn ping(_shell: &Shell, args: &[String]) -> CommandResult {
    let mut count = DEFAULT_COUNT;
    let mut host: Option<&str> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" => {
                if let Some(v) = iter.next() {
                    count = v.parse().unwrap_or(DEFAULT_COUNT).min(MAX_COUNT);
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
    CommandResult::ok(transcript(host, count))
}

fn round_trip_ms(seq: u32) -> f64 {
    11.0 + ((seq as f64 * 7.3) % 4.0)
}

fn transcript(host: &str, count: u32) -> String {
    let ip = fake_resolve(host);
    let mut out = format!("PING {host} ({ip}) 56(84) bytes of data.\n");
    let mut total = 0.0f64;
    let (mut min, mut max) = (f64::MAX, 0.0f64);
    for seq in 1..=count {
        let t = round_trip_ms(seq);
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
        (count - 1) * INTERVAL_MS
    ));
    out.push_str(&format!(
        "rtt min/avg/max/mdev = {min:.3}/{avg:.3}/{max:.3}/0.412 ms\n"
    ));
    out
}
