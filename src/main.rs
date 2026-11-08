#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use mimic::config::Config;
use std::path::PathBuf;

fn main() -> Result<()> {
    let config_path = std::env::args().nth(1).map(PathBuf::from);
    let config = Config::load(config_path.as_deref()).context("failed to load configuration")?;

    let _log_guard =
        mimic::logging::init(&config.logging).context("failed to initialise logging")?;
    mimic::logging::event::init(&config.sensor_name);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(mimic::network::run(config))
}
