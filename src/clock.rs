use std::sync::OnceLock;

const BOOT_OFFSET_SECS: i64 = 184_860;

const INSTALL_OFFSET_SECS: i64 = 95 * 86_400;

const PREV_LOGIN_OFFSET_SECS: i64 = 3_720;

const PREV_LOGIN_DURATION_SECS: i64 = 1_657;

pub const PREV_LOGIN_FROM: &str = "10.0.0.5";

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn boot_time() -> i64 {
    static BOOT: OnceLock<i64> = OnceLock::new();
    *BOOT.get_or_init(|| now() - BOOT_OFFSET_SECS)
}

pub fn uptime_secs() -> i64 {
    (now() - boot_time()).max(0)
}

pub fn install_time() -> i64 {
    static INSTALL: OnceLock<i64> = OnceLock::new();
    *INSTALL.get_or_init(|| {
        let ts = boot_time() - INSTALL_OFFSET_SECS;
        ts - ts.rem_euclid(86_400)
    })
}

pub fn prev_login() -> (i64, i64) {
    let start = boot_time() + PREV_LOGIN_OFFSET_SECS;
    (start, start + PREV_LOGIN_DURATION_SECS)
}

pub fn uptime_phrase(secs: i64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    let unit = if days == 1 { "day" } else { "days" };
    format!("{days} {unit}, {hours:2}:{mins:02}")
}

pub fn uptime_banner() -> String {
    let tm = gmtime(now());
    format!(
        "{:02}:{:02}:{:02} up {},  1 user,  load average: 0.08, 0.03, 0.01",
        tm.hour,
        tm.min,
        tm.sec,
        uptime_phrase(uptime_secs())
    )
}

pub fn format(ts: i64, fmt: &str) -> String {
    strftime(&gmtime(ts), ts, fmt)
}

pub struct Tm {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,

    pub wday: u32,

    pub yday: u32,
}

pub fn gmtime(secs: i64) -> Tm {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let min = ((rem % 3600) / 60) as u32;
    let sec = (rem % 60) as u32;

    let wday = ((days.rem_euclid(7) + 4) % 7) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if month <= 2 { y + 1 } else { y };

    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    const CUM: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut yday = CUM[(month - 1) as usize] + (day - 1);
    if leap && month > 2 {
        yday += 1;
    }

    Tm {
        year,
        month,
        day,
        hour,
        min,
        sec,
        wday,
        yday,
    }
}

pub const WDAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const WDAY_FULL: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MON: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const MON_FULL: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

pub fn strftime(tm: &Tm, epoch: i64, fmt: &str) -> String {
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&tm.year.to_string()),
            Some('y') => out.push_str(&format!("{:02}", tm.year.rem_euclid(100))),
            Some('m') => out.push_str(&format!("{:02}", tm.month)),
            Some('d') => out.push_str(&format!("{:02}", tm.day)),
            Some('e') => out.push_str(&format!("{:2}", tm.day)),
            Some('H') => out.push_str(&format!("{:02}", tm.hour)),
            Some('M') => out.push_str(&format!("{:02}", tm.min)),
            Some('S') => out.push_str(&format!("{:02}", tm.sec)),
            Some('s') => out.push_str(&epoch.to_string()),
            Some('j') => out.push_str(&format!("{:03}", tm.yday + 1)),
            Some('a') => out.push_str(WDAY[tm.wday as usize]),
            Some('A') => out.push_str(WDAY_FULL[tm.wday as usize]),
            Some('b') | Some('h') => out.push_str(MON[(tm.month - 1) as usize]),
            Some('B') => out.push_str(MON_FULL[(tm.month - 1) as usize]),
            Some('p') => out.push_str(if tm.hour < 12 { "AM" } else { "PM" }),
            Some('Z') => out.push_str("UTC"),
            Some('F') => out.push_str(&format!("{}-{:02}-{:02}", tm.year, tm.month, tm.day)),
            Some('T') => out.push_str(&format!("{:02}:{:02}:{:02}", tm.hour, tm.min, tm.sec)),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmtime_matches_known_epoch() {
        let tm = gmtime(1_714_694_400);
        assert_eq!((tm.year, tm.month, tm.day), (2024, 5, 3));
        assert_eq!((tm.hour, tm.min, tm.sec), (0, 0, 0));
        assert_eq!(WDAY[tm.wday as usize], "Fri");
        assert_eq!(
            strftime(&tm, 1_714_694_400, "%a %b %e %H:%M:%S %Z %Y"),
            "Fri May  3 00:00:00 UTC 2024"
        );
    }

    #[test]
    fn the_timeline_is_ordered_and_derived_from_the_real_clock() {
        let now = now();

        assert!(install_time() < boot_time());
        assert!(boot_time() < prev_login().0);
        assert!(prev_login().1 < now);

        assert!(install_time() > 1_714_694_400);

        assert_eq!(install_time().rem_euclid(86_400), 0);

        assert_eq!(boot_time(), boot_time());
        assert_eq!(install_time(), install_time());
    }

    #[test]
    fn uptime_phrase_matches_procps_spacing() {
        assert_eq!(uptime_phrase(184_860), "2 days,  3:21");
        assert_eq!(uptime_phrase(86_400 + 12 * 3600 + 5 * 60), "1 day, 12:05");
    }
}
