//! Network layer: SSH listener, connection limiting, and per-connection
//! handling. This is the only module permitted to perform real I/O.

mod hostkey;
mod limiter;
mod ssh;

use anyhow::Result;

/// Start the SSH honeypot listener and serve connections until shutdown.
pub async fn run() -> Result<()> {
    ssh::serve().await
}
