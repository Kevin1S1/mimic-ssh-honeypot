use super::MimicHandler;
use crate::logging::event;
use crate::network::{scp, sftp};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;

pub(super) const QUARANTINE_SESSION_MULTIPLIER: u64 = 32;

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

    pub(super) fn write_to_vfs(
        &mut self,
        target: &str,
        recursive: bool,
        file: &scp::CompletedFile,
    ) -> String {
        let (uid, gid) = (self.shell().uid, self.shell().gid);
        let cwd = self.shell().cwd;

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
                let (d, n) = crate::vfs::Vfs::split_path(base.trim_end_matches('/'));
                (d.to_string(), n.to_string())
            }
        };

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

pub(super) fn abs_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{path}")
    } else {
        format!("{cwd}/{path}")
    }
}

pub(super) fn write_quarantine(
    dir: &std::path::Path,
    sha256: &str,
    data: &[u8],
) -> std::io::Result<(String, u64)> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(sha256);

    let newly_written = if path.exists() {
        0
    } else {
        let staging = dir.join(format!("{sha256}.partial"));

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

    #[cfg(windows)]
    let stored = stored.replace('\\', "/");
    Ok((stored, newly_written))
}

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
