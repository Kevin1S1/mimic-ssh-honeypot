//! Structured JSON logging.
//!
//! All forensic events are emitted as JSON lines on stdout, which Docker and
//! systemd capture natively. File and SIEM forwarding are planned for later.

pub mod event;

use tracing_subscriber::EnvFilter;

/// Initialise the global JSON logging subscriber.
///
/// The log level can be overridden with the `RUST_LOG` environment variable;
/// it defaults to `info`.
pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,mimic=info"));

    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .init();
}
