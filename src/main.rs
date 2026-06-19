#![forbid(unsafe_code)]
//! MIMIC honeypot binary entry point.
//!
//! Initialises structured JSON logging, builds the async runtime, and hands
//! control to the network listener. Configuration loading from TOML is added
//! in Phase 3; for now, all settings use safe compiled-in defaults.

use anyhow::{Context, Result};

fn main() -> Result<()> {
    mimic::logging::init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(mimic::network::run())
}
