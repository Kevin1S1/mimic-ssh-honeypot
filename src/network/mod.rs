mod hostkey;
mod limiter;
mod scp;
mod sftp;
mod ssh;

use crate::config::Config;
use anyhow::Result;
use std::sync::Arc;

pub async fn run(config: Config) -> Result<()> {
    crate::logging::spawn_retention_reaper(&config.logging);
    ssh::serve(Arc::new(config)).await
}
