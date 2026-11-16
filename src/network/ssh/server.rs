use super::quarantine::measure_dir_size;
use super::MimicHandler;
use crate::config::Config;
use crate::logging::event;
use crate::network::limiter::ConnectionRegistry;
use anyhow::{Context, Result};
use russh::server::Config as ServerConfig;
use russh::{Disconnect, MethodKind, MethodSet};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

pub(super) const LOGIN_GRACE: Duration = Duration::from_secs(120);

pub async fn serve(config: Arc<Config>) -> Result<()> {
    let host_keys = crate::network::hostkey::load_or_create(&config.host_key_dir)?;

    let persona = Arc::new(
        crate::persona::Persona::from_seed(persona_seed(&host_keys, &config.sensor_name))
            .with_host_keys(host_key_files(&host_keys)),
    );
    crate::clock::set_uptime_at_start(persona.uptime_at_start_secs);
    let server_config = Arc::new(server_config(&config, host_keys));

    let registry = ConnectionRegistry::new(config.max_sessions, config.per_ip_connections);
    let session_counter = AtomicU64::new(1);
    let initial_quarantine_bytes = measure_dir_size(&config.quarantine_dir);
    let shared = SharedState {
        config: Arc::clone(&config),
        persona,
        global_quarantine_bytes: Arc::new(AtomicU64::new(initial_quarantine_bytes)),
    };

    let listener = TcpListener::bind((config.listen_addr, config.port))
        .await
        .with_context(|| format!("binding {}:{}", config.listen_addr, config.port))?;

    event::listening(
        &config.listen_addr.to_string(),
        config.port,
        config.max_sessions,
        config.per_ip_connections,
    );

    loop {
        let accepted = tokio::select! {
            () = shutdown_signal() => {
                event::shutdown();
                return Ok(());
            }
            result = listener.accept() => result,
        };

        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                event::accept_error(&err.to_string());
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };

        let guard = match registry.try_acquire(peer.ip()) {
            Ok(guard) => guard,
            Err(reason) => {
                event::connection_rejected(peer, reason.as_str());
                drop(stream);
                continue;
            }
        };

        let session_id = session_counter.fetch_add(1, Ordering::Relaxed);
        event::connection_opened(session_id, peer);

        let local = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::new(config.listen_addr, config.port));
        let handler = MimicHandler::new(&shared, session_id, peer, local, guard);
        let deadlines = SessionDeadlines::starting_now(config.max_session_secs);
        tokio::spawn(run_session(
            Arc::clone(&server_config),
            stream,
            handler,
            deadlines,
        ));
    }
}

pub(super) const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

pub(super) struct SharedState {
    pub(super) config: Arc<Config>,
    pub(super) persona: Arc<crate::persona::Persona>,
    pub(super) global_quarantine_bytes: Arc<AtomicU64>,
}

#[derive(Clone, Copy)]
pub(super) struct SessionDeadlines {
    login: Instant,
    session: Instant,
}

impl SessionDeadlines {
    fn starting_now(max_session_secs: u64) -> Self {
        let now = Instant::now();
        Self {
            login: now + LOGIN_GRACE,
            session: now + Duration::from_secs(max_session_secs),
        }
    }
}

pub(super) async fn run_session(
    server_config: Arc<ServerConfig>,
    stream: TcpStream,
    handler: MimicHandler,
    deadlines: SessionDeadlines,
) {
    let (session_id, peer) = (handler.session_id, handler.peer);
    let authenticated = Arc::clone(&handler.authenticated);
    let session = match russh::server::run_stream(server_config, stream, handler).await {
        Ok(session) => session,
        Err(err) => {
            tracing::debug!(
                event = "handshake_error",
                session_id,
                error = %err,
            );
            return;
        }
    };

    let watchdog = tokio::spawn(enforce_deadlines(
        session.handle(),
        authenticated,
        deadlines,
        session_id,
        peer,
    ));
    if let Err(err) = session.await {
        tracing::debug!(
            event = "session_error",
            session_id,
            error = %err,
        );
    }
    watchdog.abort();
}

pub(super) async fn enforce_deadlines(
    handle: russh::server::Handle,
    authenticated: Arc<AtomicBool>,
    deadlines: SessionDeadlines,
    session_id: u64,
    peer: SocketAddr,
) {
    tokio::time::sleep_until(deadlines.login.min(deadlines.session)).await;
    if authenticated.load(Ordering::Relaxed) {
        tokio::time::sleep_until(deadlines.session).await;
        event::session_timeout(session_id, peer);
    } else {
        event::login_timeout(session_id, peer);
    }
    let _ = handle
        .disconnect(Disconnect::ByApplication, String::new(), String::new())
        .await;
}

pub(super) fn server_config(
    config: &Config,
    host_keys: Vec<russh::keys::PrivateKey>,
) -> ServerConfig {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    methods.push(MethodKind::PublicKey);

    ServerConfig {
        server_id: russh::SshId::Standard(std::borrow::Cow::Owned(config.server_id.clone())),
        methods,

        preferred: debian_openssh_preferred(),
        auth_rejection_time: Duration::from_secs(2),

        auth_rejection_time_initial: Some(Duration::from_secs(0)),

        max_auth_attempts: crate::config::MAX_AUTH_ATTEMPTS as usize,
        inactivity_timeout: Some(Duration::from_secs(config.idle_timeout_secs)),
        keys: host_keys,
        ..Default::default()
    }
}

pub(super) fn host_key_files(keys: &[russh::keys::PrivateKey]) -> Vec<(String, String)> {
    keys.iter()
        .filter_map(|key| {
            let public = key.public_key();
            let stem = match public.algorithm() {
                russh::keys::Algorithm::Ed25519 => "ssh_host_ed25519_key",
                russh::keys::Algorithm::Rsa { .. } => "ssh_host_rsa_key",
                russh::keys::Algorithm::Ecdsa { .. } => "ssh_host_ecdsa_key",
                _ => return None,
            };
            let line = public.to_openssh().ok()?;
            Some((format!("{stem}.pub"), format!("{line}\n")))
        })
        .collect()
}

pub(super) fn persona_seed(keys: &[russh::keys::PrivateKey], sensor_name: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"mimic-persona-v1");
    hasher.update(sensor_name.as_bytes());
    // The ECDSA key arrived after sensors were already deployed; leaving it
    // out keeps every existing sensor's persona what it was.
    let seeding = keys
        .iter()
        .filter(|key| !matches!(key.algorithm(), russh::keys::Algorithm::Ecdsa { .. }));
    for key in seeding {
        if let Ok(blob) = key.public_key().to_openssh() {
            hasher.update(blob.as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(seed)
}

pub(super) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,

            Err(err) => {
                tracing::warn!(event = "signal_handler_error", error = %err);
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

// sshd lists host key algorithms in the order it loads its keys (RSA, ECDSA,
// Ed25519), and has not offered SHA-1 `ssh-rsa` by default since 8.8.
const HOST_KEY_ALGORITHMS: &[russh::keys::Algorithm] = &[
    russh::keys::Algorithm::Rsa {
        hash: Some(russh::keys::HashAlg::Sha512),
    },
    russh::keys::Algorithm::Rsa {
        hash: Some(russh::keys::HashAlg::Sha256),
    },
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP256,
    },
    russh::keys::Algorithm::Ed25519,
];

// The KEXINIT of `OpenSSH_9.2p1 Debian-2+deb12u3` with default sshd_config,
// in its order, less what russh cannot negotiate: the
// `sntrup761x25519-sha512@openssh.com` kex and the four `umac-*` MACs.
// `ext-info-s` is left out on purpose: sshd only started sending it in 9.6.
pub(super) fn debian_openssh_preferred() -> russh::Preferred {
    use std::borrow::Cow;
    russh::Preferred {
        kex: Cow::Borrowed(&[
            russh::kex::CURVE25519,
            russh::kex::CURVE25519_PRE_RFC_8731,
            russh::kex::ECDH_SHA2_NISTP256,
            russh::kex::ECDH_SHA2_NISTP384,
            russh::kex::ECDH_SHA2_NISTP521,
            russh::kex::DH_GEX_SHA256,
            russh::kex::DH_G16_SHA512,
            russh::kex::DH_G18_SHA512,
            russh::kex::DH_G14_SHA256,
            russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
        ]),
        key: Cow::Borrowed(HOST_KEY_ALGORITHMS),
        cipher: Cow::Borrowed(&[
            russh::cipher::CHACHA20_POLY1305,
            russh::cipher::AES_128_CTR,
            russh::cipher::AES_192_CTR,
            russh::cipher::AES_256_CTR,
            russh::cipher::AES_128_GCM,
            russh::cipher::AES_256_GCM,
        ]),
        mac: Cow::Borrowed(&[
            russh::mac::HMAC_SHA256_ETM,
            russh::mac::HMAC_SHA512_ETM,
            russh::mac::HMAC_SHA1_ETM,
            russh::mac::HMAC_SHA256,
            russh::mac::HMAC_SHA512,
            russh::mac::HMAC_SHA1,
        ]),
        compression: Cow::Borrowed(&[russh::compression::NONE, russh::compression::ZLIB_LEGACY]),
        ..russh::Preferred::DEFAULT
    }
}
