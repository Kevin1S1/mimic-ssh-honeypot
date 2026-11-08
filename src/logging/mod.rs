pub mod event;

use crate::config::LoggingConfig;
use anyhow::{Context, Result};
use tracing::Subscriber;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

const LOG_PREFIX: &str = "mimic";
const LOG_SUFFIX: &str = "jsonl";

const RETENTION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

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

#[cfg(unix)]
fn restrict_log_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_log_dir(_dir: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

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

fn prune_expired(dir: &std::path::Path, retention_days: usize) -> usize {
    let Some(cutoff) = std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(
        (retention_days as u64).saturating_mul(86_400),
    )) else {
        return 0;
    };
    prune_before(dir, cutoff)
}

fn prune_before(dir: &std::path::Path, cutoff: std::time::SystemTime) -> usize {
    let (prefix, suffix) = (format!("{LOG_PREFIX}."), format!(".{LOG_SUFFIX}"));
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };

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

pub fn spawn_retention_reaper(config: &LoggingConfig) {
    let (Some(dir), Some(days)) = (config.dir.clone(), config.retention_days) else {
        return;
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RETENTION_SWEEP_INTERVAL);

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

        for day in 1..=9 {
            touch(&dir, &format!("mimic.2026-08-{day:02}.jsonl"));
        }
        assert_eq!(prune_expired(&dir, 7), 0);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 9);

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
