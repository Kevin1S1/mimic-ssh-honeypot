//! Persistent SSH host keys.
//!
//! A honeypot whose host-key fingerprint changes on every restart is trivially
//! flagged by scanners that revisit the same address. We persist the keys to
//! disk (real filesystem I/O — permitted in this network layer only) and reload
//! them on subsequent starts. Both an Ed25519 and an RSA key are provided so the
//! advertised host-key algorithms resemble a stock Debian `sshd`.

use std::path::Path;

use anyhow::{Context, Result};
use rand::SeedableRng;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};

/// Load the host keys from `dir`, generating and persisting any that are
/// missing. Always returns at least the Ed25519 key; failure to produce the
/// optional RSA key is logged and skipped rather than aborting startup.
pub fn load_or_create(dir: &Path) -> Result<Vec<PrivateKey>> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating host key dir {}", dir.display()))?;

    let mut keys = Vec::new();

    // Ed25519 — always present (mirrors Debian's ssh_host_ed25519_key).
    keys.push(ensure_key(
        &dir.join("ssh_host_ed25519_key"),
        Algorithm::Ed25519,
    )?);

    // RSA — best effort; keep serving on the Ed25519 key if generation fails.
    match ensure_key(&dir.join("ssh_host_rsa_key"), Algorithm::Rsa { hash: None }) {
        Ok(key) => keys.push(key),
        Err(err) => tracing::warn!(event = "host_key_skip", algo = "rsa", error = %err),
    }

    Ok(keys)
}

/// Load a single key from `path`, or generate and persist it if absent.
fn ensure_key(path: &Path, algorithm: Algorithm) -> Result<PrivateKey> {
    if path.exists() {
        let key = PrivateKey::read_openssh_file(path)
            .with_context(|| format!("loading host key {}", path.display()))?;
        return Ok(key);
    }

    let mut rng = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng)
        .map_err(|e| anyhow::anyhow!("initializing rng: {e}"))?;
    let key = PrivateKey::random(&mut rng, algorithm)
        .map_err(|e| anyhow::anyhow!("generating host key: {e}"))?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("encoding host key: {e}"))?;
    write_key_file(path, pem.as_bytes())
        .with_context(|| format!("writing host key {}", path.display()))?;
    Ok(key)
}

/// Create and write the key file with `0600` permissions set at creation time
/// on Unix, so there is no window where the private key is world/group
/// readable between the write and a subsequent chmod.
#[cfg(unix)]
fn write_key_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

// ponytail: off Unix the key is written with default permissions — there is
// no `0600` equivalent applied. Windows is a development platform only (the
// deployment targets are Docker and systemd), and SECURITY.md T11 scopes the
// at-rest claims to Unix for the same reason. Upgrade if a Windows
// deployment is ever supported, which would need an ACL, not a mode.
#[cfg(not(unix))]
fn write_key_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_persist_across_calls() {
        let dir = std::env::temp_dir().join(format!("mimic-hostkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let first = load_or_create(&dir).expect("first load");
        assert!(!first.is_empty(), "should produce at least one host key");

        // A second load must reuse the persisted keys (stable fingerprint).
        let second = load_or_create(&dir).expect("second load");
        assert_eq!(first.len(), second.len(), "key count should be stable");

        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(
                a.public_key().to_openssh().unwrap(),
                b.public_key().to_openssh().unwrap(),
                "persisted host key fingerprint must not change across restarts",
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
