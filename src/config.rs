//! Configuration loading and validation (TOML).
//!
//! All values have safe defaults so the honeypot runs with zero configuration.
//! A config path may be passed as the first CLI argument. Unknown keys are
//! rejected so a typo surfaces immediately instead of silently falling back to
//! a default, and every bound is range-checked on load so a misconfigured file
//! cannot turn into a resource-exhaustion vector at runtime.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

/// How many authentication attempts one connection may make before the server
/// disconnects it. Matches Debian 12 sshd's default `MaxAuthTries 6`; russh's
/// own default is 10, which is a one-connection fingerprint.
pub const MAX_AUTH_ATTEMPTS: u32 = 6;

/// Top-level runtime configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address to bind the SSH listener to.
    pub listen_addr: IpAddr,
    /// Port to listen on. Inside Docker, keep this high (e.g. 2222) and map
    /// the host's port 22 to it — the process never needs to run as root.
    pub port: u16,
    /// SSH identification string advertised in the handshake. Must begin with
    /// `SSH-2.0-`. Defaults to a Debian 12 OpenSSH banner.
    pub server_id: String,
    /// Hostname presented in the shell prompt and `uname`.
    pub hostname: String,
    /// Identifier included in every log line so operators running multiple
    /// sensors can tell their streams apart.
    pub sensor_name: String,
    /// Global cap on concurrent sessions.
    pub max_sessions: usize,
    /// Cap on concurrent connections per source IP.
    pub per_ip_connections: usize,
    /// Idle timeout in seconds before a session is dropped.
    pub idle_timeout_secs: u64,
    /// Absolute cap on a single session's lifetime in seconds, regardless of
    /// activity. Bounds the resources any one connection can hold and stops a
    /// client from keeping a session open indefinitely with periodic traffic.
    pub max_session_secs: u64,
    /// Directory where files uploaded via SCP are quarantined for analysis.
    /// Created on first upload if it does not exist.
    pub quarantine_dir: PathBuf,
    /// Maximum number of bytes stored per uploaded file. Larger uploads are
    /// consumed off the wire (to keep the SCP protocol in sync) but truncated
    /// on disk to bound memory and storage use.
    pub max_upload_bytes: u64,
    /// Directory where SSH host keys are persisted. Keys are generated on first
    /// start and reused afterwards so the server fingerprint stays stable across
    /// restarts (a changing fingerprint is a honeypot tell).
    pub host_key_dir: PathBuf,
    /// Authentication policy.
    pub auth: AuthConfig,
    /// Forensic log file output.
    pub logging: LoggingConfig,
}

/// Controls optional file-based forensic logging.
///
/// JSON event lines are always written to stdout (captured by Docker/journald).
/// When [`dir`](Self::dir) is set, the same lines are additionally written to a
/// daily-rotated file under that directory so log shippers (Filebeat, Logstash,
/// …) or an operator can read them straight off disk.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Directory to write rotated JSON log files into. When `None` (the
    /// default), logging goes to stdout only and no files are written.
    pub dir: Option<PathBuf>,
    /// How many days of rotated log files to keep. When `None` (the default),
    /// files are kept indefinitely and never deleted; set it to cap retention.
    pub retention_days: Option<usize>,
}

/// Controls how authentication attempts are accepted or rejected.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Strategy used to decide whether a login attempt succeeds.
    pub mode: AuthMode,
    /// For [`AuthMode::AcceptAfter`], which attempt succeeds: the first
    /// `accept_after - 1` are rejected and the `accept_after`th is accepted
    /// (mimics an attacker "guessing" the password).
    pub accept_after: u32,
    /// For [`AuthMode::Credentials`], the set of accepted username/password
    /// pairs.
    pub credentials: Vec<Credential>,
}

/// Authentication acceptance strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Accept every password attempt on the first try.
    AcceptAll,
    /// Reject every attempt (captures credentials without granting a shell).
    RejectAll,
    /// Accept once a session has made `accept_after` attempts.
    AcceptAfter,
    /// Accept only the configured username/password pairs.
    Credentials,
}

/// A single accepted credential pair.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 2222,
            server_id: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3".to_string(),
            hostname: "debian".to_string(),
            sensor_name: "mimic".to_string(),
            max_sessions: 32,
            per_ip_connections: 4,
            idle_timeout_secs: 300,
            max_session_secs: 1800,
            quarantine_dir: PathBuf::from("quarantine"),
            max_upload_bytes: 8 * 1024 * 1024,
            host_key_dir: PathBuf::from("host_keys"),
            auth: AuthConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::AcceptAll,
            accept_after: 2,
            credentials: Vec::new(),
        }
    }
}

impl Config {
    /// Load configuration from `path`, or return defaults when `path` is `None`.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let config = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config file {}", p.display()))?;
                toml::from_str(&raw)
                    .with_context(|| format!("parsing config file {}", p.display()))?
            }
            None => Self::default(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Range-check every bound. A misconfigured file must never widen a limit
    /// past a safe maximum, so the worst an operator can do is tighten things.
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.server_id.starts_with("SSH-2.0-"),
            "server_id must begin with \"SSH-2.0-\""
        );
        anyhow::ensure!(
            self.max_sessions > 0 && self.max_sessions <= 100_000,
            "max_sessions must be between 1 and 100000"
        );
        anyhow::ensure!(
            self.per_ip_connections > 0 && self.per_ip_connections <= self.max_sessions,
            "per_ip_connections must be between 1 and max_sessions"
        );
        anyhow::ensure!(
            self.idle_timeout_secs >= 10 && self.idle_timeout_secs <= 3600,
            "idle_timeout_secs must be between 10 and 3600 seconds"
        );
        anyhow::ensure!(
            self.max_session_secs >= self.idle_timeout_secs && self.max_session_secs <= 86_400,
            "max_session_secs must be between idle_timeout_secs and 86400 seconds"
        );
        anyhow::ensure!(
            self.max_upload_bytes > 0 && self.max_upload_bytes <= 1024 * 1024 * 1024,
            "max_upload_bytes must be between 1 and 1073741824 (1 GiB)"
        );
        // Upper bound is `max_auth_attempts` (6, matching Debian's MaxAuthTries):
        // a larger value would have the connection torn down before the
        // accepting attempt was ever reached, so the honeypot would silently
        // never grant a shell. Zero would make every attempt succeed, quietly
        // turning `accept_after` into `accept_all`.
        anyhow::ensure!(
            (1..=MAX_AUTH_ATTEMPTS).contains(&self.auth.accept_after),
            "auth.accept_after must be between 1 and {MAX_AUTH_ATTEMPTS}"
        );
        if self.auth.mode == AuthMode::Credentials {
            anyhow::ensure!(
                !self.auth.credentials.is_empty(),
                "auth.mode = \"credentials\" requires at least one credential pair"
            );
        }
        if let Some(days) = self.logging.retention_days {
            anyhow::ensure!(
                (1..=3650).contains(&days),
                "logging.retention_days must be between 1 and 3650"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write `contents` to a uniquely named temp file and return its path.
    fn temp_config(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mimic-config-{}-{}.toml",
            std::process::id(),
            // A monotonically increasing suffix keeps parallel test cases from
            // colliding on the same file.
            SUFFIX.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut file = std::fs::File::create(&path).expect("create temp config");
        file.write_all(contents.as_bytes()).expect("write config");
        path
    }

    static SUFFIX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn defaults_are_valid_with_no_file() {
        let config = Config::load(None).expect("defaults must load");
        assert_eq!(config.port, 2222);
        assert_eq!(config.auth.mode, AuthMode::AcceptAll);
        assert!(config.server_id.starts_with("SSH-2.0-"));
    }

    #[test]
    fn partial_file_falls_back_to_defaults() {
        let path = temp_config("port = 2200\nhostname = \"web-prod-01\"\n");
        let config = Config::load(Some(&path)).expect("partial config loads");
        assert_eq!(config.port, 2200);
        assert_eq!(config.hostname, "web-prod-01");
        // Untouched keys keep their safe defaults.
        assert_eq!(config.max_sessions, 32);
        assert_eq!(config.per_ip_connections, 4);
        assert_eq!(config.max_upload_bytes, 8 * 1024 * 1024);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let path = temp_config("definitely_not_a_field = true\n");
        let err = Config::load(Some(&path)).expect_err("unknown key must fail");
        assert!(err.to_string().contains("parsing config file"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_toml_fails_clearly() {
        let path = temp_config("port = = =\n");
        let err = Config::load(Some(&path)).expect_err("malformed toml must fail");
        assert!(err.to_string().contains("parsing config file"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_bad_server_id() {
        let path = temp_config("server_id = \"not-an-ssh-banner\"\n");
        let err = Config::load(Some(&path)).expect_err("bad server_id must fail");
        assert!(err.to_string().contains("SSH-2.0-"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_out_of_range_idle_timeout() {
        let path = temp_config("idle_timeout_secs = 5\n");
        assert!(Config::load(Some(&path)).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_per_ip_above_global_cap() {
        let path = temp_config("max_sessions = 10\nper_ip_connections = 50\n");
        assert!(Config::load(Some(&path)).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_out_of_range_retention_days() {
        let path = temp_config("[logging]\nretention_days = 0\n");
        assert!(Config::load(Some(&path)).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn credentials_mode_requires_at_least_one_pair() {
        let empty = temp_config("[auth]\nmode = \"credentials\"\n");
        assert!(Config::load(Some(&empty)).is_err());
        let _ = std::fs::remove_file(&empty);

        let populated = temp_config(
            "[auth]\nmode = \"credentials\"\ncredentials = [{ username = \"root\", password = \"toor\" }]\n",
        );
        let config = Config::load(Some(&populated)).expect("populated credentials load");
        assert_eq!(config.auth.credentials.len(), 1);
        let _ = std::fs::remove_file(&populated);
    }
}
