//! Network layer: SSH listener, connection limiting, and per-connection
//! handling. This is the only module permitted to perform real I/O.

mod hostkey;
mod limiter;
mod scp;
mod sftp;
mod ssh;

use crate::config::Config;
use anyhow::Result;
use std::sync::Arc;

/// Start the SSH honeypot listener and serve connections until shutdown.
pub async fn run(config: Config) -> Result<()> {
    // Needs the runtime, so it cannot start from `logging::init`.
    crate::logging::spawn_retention_reaper(&config.logging);
    ssh::serve(Arc::new(config)).await
}
