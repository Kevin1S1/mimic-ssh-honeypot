//! Structured JSON logging.
//!
//! All forensic events are emitted as JSON lines on stdout, which Docker and
//! systemd capture natively. File and SIEM forwarding are planned for later.

pub mod event;

use tracing::Subscriber;
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

/// Initialise the global JSON logging subscriber.
///
/// The log level can be overridden with the `RUST_LOG` environment variable;
/// it defaults to `info`.
pub fn init() {
    use tracing_subscriber::util::SubscriberInitExt;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,mimic=info"));

    build_subscriber(filter, std::io::stdout).init();
}
