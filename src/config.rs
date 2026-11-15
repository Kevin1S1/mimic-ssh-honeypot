use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

pub const MAX_AUTH_ATTEMPTS: u32 = 6;

const SSH_BANNER_PREFIX: &str = "SSH-2.0-";
const MAX_SESSIONS_LIMIT: usize = 100_000;
const MIN_IDLE_TIMEOUT_SECS: u64 = 10;
const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;
const MAX_SESSION_SECS_LIMIT: u64 = 86_400;
const MAX_UPLOAD_BYTES_LIMIT: u64 = 1024 * 1024 * 1024;
const MAX_RETENTION_DAYS: usize = 3650;

const DEFAULT_PORT: u16 = 2222;
const DEFAULT_SERVER_ID: &str = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3";
const DEFAULT_HOSTNAME: &str = "debian";
const DEFAULT_SENSOR_NAME: &str = "mimic";
const DEFAULT_MAX_SESSIONS: usize = 32;
const DEFAULT_PER_IP_CONNECTIONS: usize = 4;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
const DEFAULT_MAX_SESSION_SECS: u64 = 1800;
const DEFAULT_QUARANTINE_DIR: &str = "quarantine";
const DEFAULT_MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_HOST_KEY_DIR: &str = "host_keys";
const DEFAULT_ACCEPT_AFTER: u32 = 2;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen_addr: IpAddr,

    pub port: u16,

    pub server_id: String,

    pub hostname: String,

    pub sensor_name: String,

    pub max_sessions: usize,

    pub per_ip_connections: usize,

    pub idle_timeout_secs: u64,

    pub max_session_secs: u64,

    pub quarantine_dir: PathBuf,

    pub max_upload_bytes: u64,

    pub quarantine_max_total_bytes: Option<u64>,

    pub host_key_dir: PathBuf,

    pub auth: AuthConfig,

    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub dir: Option<PathBuf>,

    pub retention_days: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,

    pub accept_after: u32,

    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    AcceptAll,

    RejectAll,

    AcceptAfter,

    Credentials,
}

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
            port: DEFAULT_PORT,
            server_id: DEFAULT_SERVER_ID.to_string(),
            hostname: DEFAULT_HOSTNAME.to_string(),
            sensor_name: DEFAULT_SENSOR_NAME.to_string(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            per_ip_connections: DEFAULT_PER_IP_CONNECTIONS,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            max_session_secs: DEFAULT_MAX_SESSION_SECS,
            quarantine_dir: PathBuf::from(DEFAULT_QUARANTINE_DIR),
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            quarantine_max_total_bytes: None,
            host_key_dir: PathBuf::from(DEFAULT_HOST_KEY_DIR),
            auth: AuthConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::AcceptAll,
            accept_after: DEFAULT_ACCEPT_AFTER,
            credentials: Vec::new(),
        }
    }
}

impl Config {
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

    fn validate(&self) -> Result<()> {
        self.validate_server()?;
        self.auth.validate()?;
        self.logging.validate()
    }

    fn validate_server(&self) -> Result<()> {
        anyhow::ensure!(
            self.server_id.starts_with(SSH_BANNER_PREFIX),
            "server_id must begin with \"{SSH_BANNER_PREFIX}\""
        );
        anyhow::ensure!(
            self.max_sessions > 0 && self.max_sessions <= MAX_SESSIONS_LIMIT,
            "max_sessions must be between 1 and {MAX_SESSIONS_LIMIT}"
        );
        anyhow::ensure!(
            self.per_ip_connections > 0 && self.per_ip_connections <= self.max_sessions,
            "per_ip_connections must be between 1 and max_sessions"
        );
        anyhow::ensure!(
            (MIN_IDLE_TIMEOUT_SECS..=MAX_IDLE_TIMEOUT_SECS).contains(&self.idle_timeout_secs),
            "idle_timeout_secs must be between {MIN_IDLE_TIMEOUT_SECS} and {MAX_IDLE_TIMEOUT_SECS} seconds"
        );
        anyhow::ensure!(
            (self.idle_timeout_secs..=MAX_SESSION_SECS_LIMIT).contains(&self.max_session_secs),
            "max_session_secs must be between idle_timeout_secs and {MAX_SESSION_SECS_LIMIT} seconds"
        );
        anyhow::ensure!(
            self.max_upload_bytes > 0 && self.max_upload_bytes <= MAX_UPLOAD_BYTES_LIMIT,
            "max_upload_bytes must be between 1 and {MAX_UPLOAD_BYTES_LIMIT} (1 GiB)"
        );
        Ok(())
    }
}

impl AuthConfig {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (1..=MAX_AUTH_ATTEMPTS).contains(&self.accept_after),
            "auth.accept_after must be between 1 and {MAX_AUTH_ATTEMPTS}"
        );
        if self.mode == AuthMode::Credentials {
            anyhow::ensure!(
                !self.credentials.is_empty(),
                "auth.mode = \"credentials\" requires at least one credential pair"
            );
        }
        Ok(())
    }
}

impl LoggingConfig {
    fn validate(&self) -> Result<()> {
        if let Some(days) = self.retention_days {
            anyhow::ensure!(
                (1..=MAX_RETENTION_DAYS).contains(&days),
                "logging.retention_days must be between 1 and {MAX_RETENTION_DAYS}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_config(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mimic-config-{}-{}.toml",
            std::process::id(),
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
