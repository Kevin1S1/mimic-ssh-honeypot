use super::MimicHandler;
use crate::logging::event;
use crate::network::{scp, sftp};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
/// Per-session ceiling on real-disk quarantine writes, as a multiple of
/// `max_upload_bytes`. Bounds one session's disk footprint to a fixed multiple
/// of its largest single allowed upload, closing the gap where many distinct
/// small files could otherwise grow the quarantine store without limit for the
/// duration of a session.
pub(super) const QUARANTINE_SESSION_MULTIPLIER: u64 = 32;

/// Default global ceiling on real-disk quarantine writes across all sessions,
/// as a multiple of `max_upload_bytes`.
pub(super) const QUARANTINE_GLOBAL_MULTIPLIER: u64 = 64;

pub(super) fn measure_dir_size(dir: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

impl MimicHandler {
    /// Persist one SCP-uploaded file: write it into the session VFS, copy it to
    /// the quarantine store on the real filesystem, and emit an `upload` event.
    pub(super) fn store_upload(&mut self, file: scp::CompletedFile) {
        let target = self
            .scp
            .as_ref()
            .map(|s| s.target().to_string())
            .unwrap_or_else(|| "/tmp".to_string());
        let recursive = self.scp.as_ref().map(|s| s.recursive()).unwrap_or(false);
        let dest_path = self.write_to_vfs(&target, recursive, &file);
        let stored = self.quarantine(&file.data);
        event::upload(
            self.session_id,
            self.peer,
            &file.name,
            &dest_path,
            file.size,
            &file.payload_sha256,
            &stored.sha256,
            &stored.path,
            file.truncated,
        );
    }

    pub(super) fn store_sftp_upload(&mut self, upload: sftp::SftpCompletedUpload) {
        let stored = self.quarantine(&upload.data);
        event::upload(
            self.session_id,
            self.peer,
            &upload.name,
            &upload.dest_path,
            upload.size,
            &upload.payload_sha256,
            &stored.sha256,
            &stored.path,
            upload.truncated,
        );
    }

    pub(super) fn quarantine_session_cap(&self) -> u64 {
        self.config
            .max_upload_bytes
            .saturating_mul(QUARANTINE_SESSION_MULTIPLIER)
    }

    pub(super) fn quarantine_global_cap(&self) -> u64 {
        self.config.quarantine_max_total_bytes.unwrap_or_else(|| {
            self.config
                .max_upload_bytes
                .saturating_mul(QUARANTINE_GLOBAL_MULTIPLIER)
        })
    }

    pub(super) fn quarantine(&mut self, data: &[u8]) -> QuarantinedPayload {
        let sha256 = sha256_hex(data);
        let path = self.write_within_caps(&sha256, data).unwrap_or_default();
        QuarantinedPayload { sha256, path }
    }

    pub(super) fn write_within_caps(&mut self, sha256: &str, data: &[u8]) -> Option<String> {
        let (session_id, peer) = (self.session_id, self.peer);
        let len = data.len() as u64;
        if self.quarantine_bytes.saturating_add(len) > self.quarantine_session_cap() {
            event::quarantine_session_cap(session_id, peer);
            return None;
        }
        let current_global = self.global_quarantine_bytes.load(Ordering::Relaxed);
        if current_global.saturating_add(len) > self.quarantine_global_cap() {
            event::quarantine_global_cap(session_id, peer);
            return None;
        }
        match write_quarantine(&self.config.quarantine_dir, sha256, data) {
            Ok((path, written)) => {
                self.quarantine_bytes += written;
                self.global_quarantine_bytes
                    .fetch_add(written, Ordering::Relaxed);
                Some(path)
            }
            Err(err) => {
                event::quarantine_error(session_id, peer, &err.to_string());
                None
            }
        }
    }

    /// Materialise an uploaded file in the session VFS, returning its absolute
    /// path. Best-effort: failures are non-fatal for the honeypot.
    pub(super) fn write_to_vfs(
        &mut self,
        target: &str,
        recursive: bool,
        file: &scp::CompletedFile,
    ) -> String {
        let (uid, gid) = (self.shell().uid, self.shell().gid);
        let cwd = self.shell().cwd;

        // Determine the directory the file lands in and its final name.
        let (dir_path, name): (String, String) = {
            let shell = self.shell();
            let target_abs = abs_path(&shell.vfs.path_of(cwd), target);
            let mut base = target_abs.clone();
            if !file.rel_dir.is_empty() {
                base = format!("{}/{}", base.trim_end_matches('/'), file.rel_dir);
            }

            let target_is_dir = shell
                .vfs
                .resolve(cwd, &base)
                .map(|id| shell.vfs.node(id).meta.is_dir())
                .unwrap_or(false);

            if target_is_dir || target.ends_with('/') || recursive || !file.rel_dir.is_empty() {
                (base, file.name.clone())
            } else {
                // Target names the file itself.
                let (d, n) = crate::vfs::Vfs::split_path(base.trim_end_matches('/'));
                (d.to_string(), n.to_string())
            }
        };

        // The returned path is what the `upload` event records, so it must be
        // where the file actually went. Mirroring into the VFS is best-effort —
        // it has its own node and byte caps — and when either refuses, the
        // honest answer is the path the attacker asked for, not `path_of` of a
        // parent directory that happens to be what the arena handed back.
        let intended = format!("{}/{name}", dir_path.trim_end_matches('/'));
        let shell = self.shell();
        let Some(parent) = shell.vfs.mkdir_p(&dir_path, 0o755, uid, gid) else {
            return intended;
        };
        let id = shell.vfs.add_file(
            parent,
            &name,
            file.data.clone(),
            file.mode & 0o7777,
            uid,
            gid,
        );
        if id == parent {
            return intended;
        }
        shell.vfs.path_of(id)
    }
}

/// Hex-encode a byte slice.
pub(in crate::network) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(super) fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub(super) struct QuarantinedPayload {
    sha256: String,
    path: String,
}

/// Resolve `path` against `cwd` into an absolute path string (no VFS lookup).
pub(super) fn abs_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{path}")
    } else {
        format!("{cwd}/{path}")
    }
}

/// Write `data` to `<dir>/<sha256>` (deduplicating by content hash), creating
/// `dir` if needed. Returns `(stored_path, newly_written_bytes)`. Files are created
/// non-executable and owner-read/write only (`0600`) at creation time so a
/// captured payload can never be run from the quarantine store and is never
/// briefly world/group-readable between the write and a chmod.
pub(super) fn write_quarantine(
    dir: &std::path::Path,
    sha256: &str,
    data: &[u8],
) -> std::io::Result<(String, u64)> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(sha256);
    // Content-addressed store: identical payloads dedupe. `create_new` also
    // closes the exists()-then-write TOCTOU — if a concurrent session already
    // stored the same bytes, `AlreadyExists` is success, not an error.
    // Write to a scratch name and rename into place, so the store's invariant —
    // the filename is the SHA-256 of the contents — holds even if the write
    // fails partway. A direct write that dies on ENOSPC would leave a truncated
    // file under a valid hash name, and every later upload of the same payload
    // would then take the `AlreadyExists` path and report that corrupt file as
    // successfully stored. `rename` is atomic on both target platforms.
    let newly_written = if path.exists() {
        0
    } else {
        let staging = dir.join(format!("{sha256}.partial"));
        // A concurrent session storing the same payload is using the same
        // staging name; `create_new` makes exactly one of them the writer and
        // the other falls back to the dedup path below.
        match create_restricted(&staging) {
            Ok(mut file) => {
                let result = file.write_all(data).and_then(|()| file.sync_all());
                drop(file);
                if let Err(e) = result {
                    let _ = std::fs::remove_file(&staging);
                    return Err(e);
                }
                match std::fs::rename(&staging, &path) {
                    Ok(()) => data.len() as u64,
                    Err(e) => {
                        let _ = std::fs::remove_file(&staging);
                        return Err(e);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => 0,
            Err(e) => return Err(e),
        }
    };
    let stored = path.to_string_lossy().into_owned();
    // `Path::join` appends a backslash on Windows, so a forward-slash
    // `quarantine_dir` from the config yields `C:/data\ab12…` — one logged
    // path in two separator styles. Normalise so `stored_path` is a usable
    // key. Windows-only: a backslash is a legal filename byte on Unix.
    #[cfg(windows)]
    let stored = stored.replace('\\', "/");
    Ok((stored, newly_written))
}

/// Create `path` for writing with owner-only (`0600`) permissions set at
/// creation time on Unix, failing if it already exists.
#[cfg(unix)]
pub(super) fn create_restricted(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
pub(super) fn create_restricted(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}
