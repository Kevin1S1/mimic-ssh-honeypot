#![forbid(unsafe_code)]
//! MIMIC honeypot binary entry point.
//!
//! Loads configuration, initialises structured JSON logging, builds the async
//! runtime, and hands control to the network listener. An optional TOML config
//! path may be passed as the first CLI argument; with none, safe compiled-in
//! defaults are used.

use anyhow::{Context, Result};
use mimic::config::Config;
use std::path::PathBuf;

fn main() -> Result<()> {
    let config_path = std::env::args().nth(1).map(PathBuf::from);
    let config = Config::load(config_path.as_deref()).context("failed to load configuration")?;

    // Kept alive for the whole process so the background log-file writer flushes
    // on shutdown; dropping it early would silently stop file logging.
    let _log_guard =
        mimic::logging::init(&config.logging).context("failed to initialise logging")?;
    mimic::logging::event::init(&config.sensor_name);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(mimic::network::run(config))
}
