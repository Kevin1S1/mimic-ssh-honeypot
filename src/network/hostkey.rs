use std::path::Path;

use anyhow::{Context, Result};
use rand::SeedableRng;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};

pub fn load_or_create(dir: &Path) -> Result<Vec<PrivateKey>> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating host key dir {}", dir.display()))?;

    let mut keys = Vec::new();

    keys.push(ensure_key(
        &dir.join("ssh_host_ed25519_key"),
        Algorithm::Ed25519,
    )?);

    match ensure_key(&dir.join("ssh_host_rsa_key"), Algorithm::Rsa { hash: None }) {
        Ok(key) => keys.push(key),
        Err(err) => tracing::warn!(event = "host_key_skip", algo = "rsa", error = %err),
    }

    Ok(keys)
}

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
