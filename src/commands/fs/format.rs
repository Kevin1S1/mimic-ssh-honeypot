use crate::vfs::nodes::{NodeKind, S_IFDIR, S_IFLNK, S_IFMT};
use crate::vfs::{Node, NodeId, Vfs};

pub(super) fn allocated_kib(vfs: &Vfs, id: NodeId) -> u64 {
    match &vfs.node(id).kind {
        NodeKind::File { contents } => (contents.len() as u64).div_ceil(4096) * 4,
        NodeKind::DynamicFile { generator } => (generator().len() as u64).div_ceil(4096) * 4,
        NodeKind::Directory { .. } => 4,
        NodeKind::Symlink { .. } => 0,
    }
}

pub(crate) fn node_size(node: &Node) -> u64 {
    match &node.kind {
        NodeKind::File { contents } => contents.len() as u64,
        NodeKind::DynamicFile { generator } => generator().len() as u64,
        NodeKind::Symlink { target } => target.len() as u64,
        NodeKind::Directory { .. } => 4096,
    }
}

pub(crate) fn mode_string(mode: u32) -> String {
    let type_char = match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        _ => '-',
    };
    let mut s = String::with_capacity(10);
    s.push(type_char);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    s
}

pub(crate) fn format_time(ts: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    const SIX_MONTHS: i64 = 15_778_800;

    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let mon = MONTHS[(month - 1) as usize];

    let now = crate::clock::now();
    if ts > now + 3_600 || ts < now - SIX_MONTHS {
        format!("{mon} {day:>2}  {year}")
    } else {
        format!("{mon} {day:>2} {hour:02}:{minute:02}")
    }
}

pub(super) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub(super) fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["", "K", "M", "G", "T", "P"];
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

pub(crate) fn uid_name(uid: u32) -> String {
    match uid {
        0 => "root".into(),
        1 => "daemon".into(),
        2 => "bin".into(),
        3 => "sys".into(),
        8 => "mail".into(),
        33 => "www-data".into(),
        34 => "backup".into(),
        100 => "sshd".into(),
        1000 => "user".into(),
        65534 => "nobody".into(),
        other => other.to_string(),
    }
}

pub(crate) fn gid_name(gid: u32) -> String {
    match gid {
        0 => "root".into(),
        4 => "adm".into(),
        8 => "mail".into(),
        27 => "sudo".into(),
        33 => "www-data".into(),
        34 => "backup".into(),
        42 => "shadow".into(),
        43 => "utmp".into(),
        1000 => "user".into(),
        65534 => "nogroup".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_time_shows_the_clock_only_for_a_recent_mtime() {
        let now = crate::clock::now();

        assert_eq!(
            format_time(now - 86_400),
            crate::clock::format(now - 86_400, "%b %e %H:%M")
        );

        for ts in [now - 200 * 86_400, now + 7_200] {
            assert_eq!(
                format_time(ts),
                crate::clock::format(ts, "%b %e  %Y"),
                "expected the year form for {ts}"
            );
        }

        let install = crate::clock::install_time();
        assert_eq!(
            format_time(install),
            crate::clock::format(install, "%b %e %H:%M")
        );
    }
}
