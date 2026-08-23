//! Structured JSON logging.
//!
//! All forensic events are emitted as JSON lines on stdout, which Docker and
//! systemd capture natively. When a log directory is configured, the identical
//! lines are additionally written to a daily-rotated file so log shippers
//! (Filebeat, Logstash, …) or an operator can read them straight off disk.

pub mod event;

use crate::config::LoggingConfig;
use anyhow::{Context, Result};
use tracing::Subscriber;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

/// Filename prefix and suffix of the rotated log files. Both the appender and
/// [`prune_expired`] key off these: the sweep deletes files, so it must be
/// unable to touch anything this process did not write.
const LOG_PREFIX: &str = "mimic";
const LOG_SUFFIX: &str = "jsonl";

/// How often the retention sweep re-runs. Rotation is daily, so anything under
/// a day bounds the overshoot to the tick; hourly costs one `read_dir`.
const RETENTION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Build the JSON subscriber used for the whole process.
///
/// The formatter is defined in exactly one place so the test harness exercises
/// the identical pipeline that runs in production — only the output sink
/// (`writer`) differs.
pub(crate) fn build_subscriber<W>(filter: EnvFilter, writer: W) -> impl Subscriber
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_env_filter(filter)
        .with_writer(writer)
        .finish()
}

/// Restrict the log directory to owner-only (`0700`) on Unix.
///
/// Captured passwords are written to these files in cleartext by design, so the
/// files must not be readable by other local users. `tracing-appender` creates
/// each rotated file itself and exposes no hook for its mode (0644 under a
/// normal umask), and `libc::umask` is off-limits under `#![forbid(unsafe_code)]`
/// — but a 0644 file inside a 0700 directory is still unreachable for anyone
/// else, so restricting the directory is what closes this.
#[cfg(unix)]
fn restrict_log_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

// ponytail: off Unix the log directory keeps whatever permissions it was
// created with, so the `0700` SECURITY.md T11 describes does not apply — and
// captured credentials sit in there in the clear. Windows is a development
// platform only. Upgrade if a Windows deployment is ever supported.
#[cfg(not(unix))]
fn restrict_log_dir(_dir: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Initialise the global JSON logging subscriber.
///
/// Events always go to stdout. When `config.dir` is set, they are also teed to
/// a daily-rotated `mimic.YYYY-MM-DD.jsonl` file in that directory; the returned
/// [`WorkerGuard`] must be kept alive for the process lifetime so the background
/// writer flushes on shutdown. The log level can be overridden with the
/// `RUST_LOG` environment variable; it defaults to `info`.
pub fn init(config: &LoggingConfig) -> Result<Option<WorkerGuard>> {
    use tracing_subscriber::util::SubscriberInitExt;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,mimic=info"));

    let Some(dir) = config.dir.as_deref() else {
        build_subscriber(filter, std::io::stdout).init();
        return Ok(None);
    };

    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating log directory {}", dir.display()))?;
    restrict_log_dir(dir)
        .with_context(|| format!("restricting log directory {}", dir.display()))?;

    let mut builder = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(LOG_PREFIX)
        .filename_suffix(LOG_SUFFIX);
    if let Some(days) = config.retention_days {
        // Two mechanisms, because neither covers the other. `max_log_files`
        // prunes the moment the appender rotates, but it counts *files*: they
        // only equal days while the process runs every day. The age sweep is
        // what makes the key mean what its name says; it runs once here and
        // then hourly from `spawn_retention_reaper`.
        builder = builder.max_log_files(days);
        prune_expired(dir, days);
    }
    let appender = builder
        .build(dir)
        .with_context(|| format!("initialising rolling log appender in {}", dir.display()))?;

    let (file_writer, guard) = tracing_appender::non_blocking(appender);
    build_subscriber(filter, std::io::stdout.and(file_writer)).init();
    Ok(Some(guard))
}

/// Delete rotated log files last modified more than `retention_days` days ago.
///
/// `tracing_appender`'s `max_log_files` counts files, not days, so on its own it
/// only honours `logging.retention_days` while the process runs every single
/// day — a sensor down for a week comes back holding files older than the
/// configured window. This is what closes that gap.
///
/// Failures are swallowed: losing a sweep is not a reason to refuse to start a
/// sensor. The number of files removed is returned so the caller can log it.
fn prune_expired(dir: &std::path::Path, retention_days: usize) -> usize {
    let Some(cutoff) = std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(
        retention_days as u64 * 86_400,
    )) else {
        // Only reachable with a system clock set near the epoch. Nothing can
        // predate the cutoff, so there is nothing to prune.
        return 0;
    };
    prune_before(dir, cutoff)
}

/// Delete this appender's rotated log files last modified before `cutoff`.
///
/// Scoped hard: only regular files matching this appender's own
/// `mimic.<something>.jsonl` naming are considered. This function deletes, and
/// `logging.dir` is operator-supplied — pointing it at a populated directory
/// must not make MIMIC remove someone else's data.
fn prune_before(dir: &std::path::Path, cutoff: std::time::SystemTime) -> usize {
    let (prefix, suffix) = (format!("{LOG_PREFIX}."), format!(".{LOG_SUFFIX}"));
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // The length check keeps the prefix and suffix from overlapping, so a
        // bare `mimic.jsonl` — which this appender never creates — is left
        // alone rather than matching both ends of itself.
        if name.len() < prefix.len() + suffix.len()
            || !name.starts_with(&prefix)
            || !name.ends_with(&suffix)
        {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        if meta.modified().is_ok_and(|m| m < cutoff) && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Start the background task that keeps `logging.retention_days` true for the
/// lifetime of the process, not just across restarts. No-op unless file logging
/// and a retention window are both configured; must be called from inside the
/// tokio runtime.
pub fn spawn_retention_reaper(config: &LoggingConfig) {
    let (Some(dir), Some(days)) = (config.dir.clone(), config.retention_days) else {
        return;
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
        // The first tick fires immediately, and `init` already swept.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let removed = prune_expired(&dir, days);
            if removed > 0 {
                event::log_retention_pruned(removed, days);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mimic-retention-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(dir: &std::path::Path, name: &str) {
        std::fs::write(dir.join(name), b"{}\n").unwrap();
    }

    #[test]
    fn age_is_the_criterion_not_the_file_count() {
        let dir = scratch("age");
        // Nine files: more than a seven-*file* window would keep, but all of
        // them written just now, so a seven-*day* window keeps every one. This
        // is the case `max_log_files` gets wrong once a sensor has been down.
        for day in 1..=9 {
            touch(&dir, &format!("mimic.2026-08-{day:02}.jsonl"));
        }
        assert_eq!(prune_expired(&dir, 7), 0);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 9);

        // Move the cutoff past them and the same files all go.
        assert_eq!(
            prune_before(&dir, SystemTime::now() + Duration::from_secs(60)),
            9
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn never_deletes_what_it_did_not_write() {
        let dir = scratch("scope");
        // A cutoff in the future puts everything here past retention, so the
        // only thing keeping these files is the name and file-type scoping.
        touch(&dir, "mimic.2026-01-01.jsonl");
        touch(&dir, "important.jsonl");
        touch(&dir, "mimic.2026-01-01.jsonl.gz");
        touch(&dir, "cowrie.2026-01-01.jsonl");
        touch(&dir, "mimic.jsonl");
        std::fs::create_dir(dir.join("mimic.subdir.jsonl")).unwrap();

        let cutoff = SystemTime::now() + Duration::from_secs(60);
        assert_eq!(prune_before(&dir, cutoff), 1);
        assert!(!dir.join("mimic.2026-01-01.jsonl").exists());
        assert!(dir.join("important.jsonl").exists());
        assert!(dir.join("mimic.2026-01-01.jsonl.gz").exists());
        assert!(dir.join("cowrie.2026-01-01.jsonl").exists());
        assert!(dir.join("mimic.jsonl").exists());
        assert!(dir.join("mimic.subdir.jsonl").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
