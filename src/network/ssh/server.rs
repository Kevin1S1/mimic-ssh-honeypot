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
/// Debian sshd's `LoginGraceTime`. Without it a client that never logs in holds
/// a connection slot for the whole `max_session_secs`, so a handful of sources
/// can fill every slot and blind the sensor.
pub(super) const LOGIN_GRACE: Duration = Duration::from_secs(120);

/// Build the russh server config and serve connections forever.
pub async fn serve(config: Arc<Config>) -> Result<()> {
    // Persist host keys so the server fingerprint stays stable across restarts.
    let host_keys = crate::network::hostkey::load_or_create(&config.host_key_dir)?;

    // This deployment's fabricated hardware identity, seeded from the host key
    // so it is stable across restarts (like the fingerprint) but different on
    // every sensor. Reading the key material is real I/O and belongs here; the
    // persona itself is pure data the emulation layers consume.
    let persona = Arc::new(
        crate::persona::Persona::from_seed(persona_seed(&host_keys, &config.sensor_name))
            .with_host_keys(host_key_files(&host_keys)),
    );
    let server_config = Arc::new(server_config(&config, host_keys));

    // Connection caps are enforced at accept time, before any crypto state is
    // allocated, so a connection flood is shed cheaply.
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
            // Returning on a termination signal is what lets `main` unwind and
            // drop the logging `WorkerGuard`, which is the only thing that
            // flushes the file appender's buffered lines. Without it the
            // process is killed where it stands and whatever is still in the
            // appender's channel is lost — on every `docker restart` /
            // `systemctl restart`, which `deploy/daily-reset.sh` performs
            // daily by design.
            () = shutdown_signal() => {
                event::shutdown();
                return Ok(());
            }
            result = listener.accept() => result,
        };

        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                // Transient accept errors (e.g. fd exhaustion) shouldn't kill
                // the listener; back off briefly and keep serving.
                event::accept_error(&err.to_string());
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };

        // Reserve a slot, or drop the connection if a limit is reached.
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
    // Bound the absolute session lifetime, independent of the
    // idle timeout, so no connection can be held open forever.
    // The cap has to ask the session to disconnect: a
    // `RunningSession` only wraps the session task's
    // `JoinHandle`, so dropping it (as a `timeout` would)
    // detaches that task and leaves the session — and the
    // connection slot its handler holds — running.
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
        // Algorithm ordering trimmed to resemble Debian 12 OpenSSH 9.2's
        // server offer (no sntrup761, umac, or group-exchange).
        preferred: debian_openssh_preferred(),
        auth_rejection_time: Duration::from_secs(2),
        // NOT a fingerprint, despite how it reads: russh applies this only to
        // the `none` probe every client sends first to discover auth methods
        // (see `initial_auth_until` in russh's `server::encrypted`). Real sshd
        // answers that probe immediately; password and publickey rejections
        // still take the full two seconds. Without it every connection would
        // stall 2s before the password prompt, which *would* be a tell.
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        // Debian 12 sshd defaults to `MaxAuthTries 6`; russh defaults to 10.
        // A client that keeps getting prompted past six is a one-connection
        // honeypot check.
        max_auth_attempts: crate::config::MAX_AUTH_ATTEMPTS as usize,
        inactivity_timeout: Some(Duration::from_secs(config.idle_timeout_secs)),
        keys: host_keys,
        ..Default::default()
    }
}

/// This deployment's `/etc/ssh/*.pub` files, taken from the keys actually being
/// served.
///
/// Only public halves: `to_openssh` on a `PublicKey` emits exactly the line a
/// real `.pub` file holds, which every client already receives during the key
/// exchange. Fabricating these instead would be a contradiction an attacker can
/// check with one `ssh-keygen -lf` against the fingerprint their own client
/// recorded.
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

/// Derive this deployment's persona seed from its host keys and sensor name.
///
/// The host key is already the thing that must not change between restarts, so
/// binding the emulated hardware to it gives the persona the same stability for
/// free — and two sensors never share a key, so they never share an identity.
pub(super) fn persona_seed(keys: &[russh::keys::PrivateKey], sensor_name: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"mimic-persona-v1");
    hasher.update(sensor_name.as_bytes());
    for key in keys {
        // The *public* half is enough to be unique per deployment, and keeps
        // private key material out of every derived value.
        if let Ok(blob) = key.public_key().to_openssh() {
            hasher.update(blob.as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(seed)
}

/// Resolve once the process is asked to stop.
///
/// SIGTERM is what `docker stop` and `systemctl restart` send, so it is the
/// signal that matters for a clean flush; Ctrl-C is handled too for a honeypot
/// run in the foreground. On non-Unix (a development platform only) there is no
/// SIGTERM, so Ctrl-C is the whole story.
pub(super) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            // Without a handler the default disposition still terminates the
            // process; we simply lose the clean flush. Not worth refusing to
            // serve over.
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

/// Algorithm preference list shaped to resemble a stock Debian 12 OpenSSH 9.2
/// server. Algorithms OpenSSH offers but russh does not implement
/// (`sntrup761x25519-sha512`, `diffie-hellman-group-exchange-sha256`, `umac-*`)
/// are necessarily absent; the relative ordering of what remains is preserved.
pub(super) fn debian_openssh_preferred() -> russh::Preferred {
    use std::borrow::Cow;
    russh::Preferred {
        kex: Cow::Borrowed(&[
            russh::kex::CURVE25519,
            russh::kex::CURVE25519_PRE_RFC_8731,
            russh::kex::ECDH_SHA2_NISTP256,
            russh::kex::ECDH_SHA2_NISTP384,
            russh::kex::ECDH_SHA2_NISTP521,
            russh::kex::DH_G16_SHA512,
            russh::kex::DH_G14_SHA256,
            // Server-side protocol extension markers, as real OpenSSH advertises.
            russh::kex::EXTENSION_SUPPORT_AS_SERVER,
            russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
        ]),
        cipher: Cow::Borrowed(&[
            russh::cipher::CHACHA20_POLY1305,
            russh::cipher::AES_128_CTR,
            russh::cipher::AES_192_CTR,
            russh::cipher::AES_256_CTR,
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
        ..russh::Preferred::DEFAULT
    }
}
