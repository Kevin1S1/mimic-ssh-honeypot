//! SSH protocol engine built on `russh`.
//!
//! Phase 2 scope: TCP listener, SSH handshake, credential capture, and
//! connection lifecycle. No interactive shell yet — after successful
//! authentication the server sends a brief banner and closes the channel.
//! Nothing in this file (or anywhere downstream) executes real commands or
//! touches the real filesystem beyond host-key persistence.

use crate::logging::event;
use crate::network::limiter::{ConnectionGuard, ConnectionRegistry};

use anyhow::{Context, Result};
use russh::server::{Auth, Config as ServerConfig, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Default maximum concurrent sessions.
const DEFAULT_MAX_SESSIONS: usize = 256;

/// Default maximum concurrent connections per source IP.
const DEFAULT_PER_IP: usize = 10;

/// Default port to listen on.
const DEFAULT_PORT: u16 = 2222;

/// Default idle timeout in seconds.
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// Default absolute session lifetime in seconds.
const DEFAULT_MAX_SESSION_SECS: u64 = 1800;

/// Default hostname presented in the MOTD.
const DEFAULT_HOSTNAME: &str = "debian";

/// Default SSH server identification string (Debian 12 OpenSSH 9.2).
const DEFAULT_SERVER_ID: &str = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3";

/// Default number of password attempts before accepting credentials.
const DEFAULT_ACCEPT_AFTER: u32 = 2;

/// Default directory for persisting host keys.
const DEFAULT_HOST_KEY_DIR: &str = "host_keys";

/// Build the russh server config and serve connections forever.
pub async fn serve() -> Result<()> {
    let host_keys = super::hostkey::load_or_create(std::path::Path::new(DEFAULT_HOST_KEY_DIR))?;

    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    methods.push(MethodKind::PublicKey);

    let server_config = Arc::new(ServerConfig {
        server_id: russh::SshId::Standard(std::borrow::Cow::Owned(DEFAULT_SERVER_ID.to_string())),
        methods,
        // Algorithm ordering trimmed to resemble Debian 12 OpenSSH 9.2's
        // server offer (no sntrup761, umac, or group-exchange).
        preferred: debian_openssh_preferred(),
        auth_rejection_time: Duration::from_secs(2),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        inactivity_timeout: Some(Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)),
        keys: host_keys,
        ..Default::default()
    });

    let registry = ConnectionRegistry::new(DEFAULT_MAX_SESSIONS, DEFAULT_PER_IP);
    let session_counter = Arc::new(AtomicU64::new(1));

    let listen_addr = format!("0.0.0.0:{DEFAULT_PORT}");
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("binding {listen_addr}"))?;

    tracing::info!(
        event = "listening",
        addr = "0.0.0.0",
        port = DEFAULT_PORT,
        max_sessions = DEFAULT_MAX_SESSIONS,
        per_ip = DEFAULT_PER_IP,
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // Transient accept errors (e.g. fd exhaustion) shouldn't kill
                // the listener; back off briefly and keep serving.
                tracing::warn!(event = "accept_error", error = %err);
                tokio::time::sleep(Duration::from_millis(50)).await;
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

        let handler = MimicHandler {
            session_id,
            peer,
            auth_attempts: 0,
            username: String::new(),
            _guard: guard,
        };

        let server_config = Arc::clone(&server_config);
        let max_session = Duration::from_secs(DEFAULT_MAX_SESSION_SECS);
        tokio::spawn(async move {
            match russh::server::run_stream(server_config, stream, handler).await {
                Ok(session) => {
                    // Bound the absolute session lifetime, independent of the
                    // idle timeout, so no connection can be held open forever.
                    match tokio::time::timeout(max_session, session).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            tracing::debug!(
                                event = "session_error",
                                session_id,
                                error = %err,
                            );
                        }
                        Err(_) => {
                            tracing::info!(event = "session_timeout", session_id);
                        }
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        event = "handshake_error",
                        session_id,
                        error = %err,
                    );
                }
            }
        });
    }
}

/// Algorithm preference list shaped to resemble a stock Debian 12 OpenSSH 9.2
/// server. Algorithms OpenSSH offers but russh does not implement
/// (`sntrup761x25519-sha512`, `diffie-hellman-group-exchange-sha256`, `umac-*`)
/// are necessarily absent; the relative ordering of what remains is preserved.
fn debian_openssh_preferred() -> russh::Preferred {
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

/// Per-connection handler holding connection state and credentials captured
/// during the SSH handshake.
struct MimicHandler {
    session_id: u64,
    peer: SocketAddr,
    auth_attempts: u32,
    username: String,
    /// Holds this connection's slot in the global/per-IP limiter; releasing it
    /// on drop frees the slot for the next connection.
    _guard: ConnectionGuard,
}

impl Handler for MimicHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.auth_attempts += 1;
        let accepted = self.auth_attempts >= DEFAULT_ACCEPT_AFTER;

        event::auth_attempt(
            self.session_id,
            self.peer,
            user,
            "password",
            Some(password),
            accepted,
        );

        if accepted {
            self.username = user.to_string();
            jitter().await;
            Ok(Auth::Accept)
        } else {
            jitter().await;
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_attempts += 1;
        event::auth_attempt(self.session_id, self.peer, user, "publickey", None, false);

        // Reject public-key auth so clients fall back to password, which we can
        // capture in cleartext.
        let mut proceed_with_methods = MethodSet::empty();
        proceed_with_methods.push(MethodKind::Password);
        Ok(Auth::Reject {
            proceed_with_methods: Some(proceed_with_methods),
            partial_success: false,
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Phase 2: send a Debian-style MOTD and close the channel. The full
        // interactive shell arrives in Phase 7.
        let banner = format!(
            "Linux {host} 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC \
             Debian 6.1.90-1 (2024-05-03) x86_64\r\n\
             \r\n\
             The programs included with the Debian GNU/Linux system are free software;\r\n\
             the exact distribution terms for each program are described in the\r\n\
             individual files in /usr/share/doc/*/copyright.\r\n\
             \r\n\
             Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\r\n\
             permitted by applicable law.\r\n",
            host = DEFAULT_HOSTNAME,
        );
        session.data(channel, banner.into_bytes())?;

        // No interactive shell yet — close the channel after the MOTD.
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

impl Drop for MimicHandler {
    fn drop(&mut self) {
        event::connection_closed(self.session_id, self.peer);
    }
}

/// Sleep for a small randomised interval. Real OpenSSH + bash responses carry
/// natural jitter; perfectly uniform latency is a passive honeypot tell.
async fn jitter() {
    let ms = rand::random_range(2..=18);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}
