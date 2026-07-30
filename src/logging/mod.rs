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
        .filename_prefix("mimic")
        .filename_suffix("jsonl");
    // `None` keeps every rotated file forever; a value caps retention to that
    // many daily files (older ones are pruned on rotation).
    if let Some(days) = config.retention_days {
        builder = builder.max_log_files(days);
    }
    let appender = builder
        .build(dir)
        .with_context(|| format!("initialising rolling log appender in {}", dir.display()))?;

    let (file_writer, guard) = tracing_appender::non_blocking(appender);
    build_subscriber(filter, std::io::stdout.and(file_writer)).init();
    Ok(Some(guard))
}
