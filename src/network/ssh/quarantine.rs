use super::MimicHandler;
use crate::config::Config;
use crate::logging::event;
use crate::network::digest::sha256_hex;
use crate::network::{scp, sftp};
use crate::shell::Shell;
use crate::vfs::Vfs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub(super) const QUARANTINE_SESSION_MULTIPLIER: u64 = 32;

pub(super) const QUARANTINE_GLOBAL_MULTIPLIER: u64 = 64;

pub(super) struct QuarantineStore {
    dir: PathBuf,
    session_cap: u64,
    global_cap: u64,
    session_bytes: u64,
    global_bytes: Arc<AtomicU64>,
}

pub(super) enum QuarantineRefusal {
    SessionCap,
    GlobalCap,
    Io(std::io::Error),
}

impl QuarantineStore {
    pub(super) fn new(config: &Config, global_bytes: Arc<AtomicU64>) -> Self {
        let session_cap = config
            .max_upload_bytes
            .saturating_mul(QUARANTINE_SESSION_MULTIPLIER);
        let global_cap = config.quarantine_max_total_bytes.unwrap_or_else(|| {
            config
                .max_upload_bytes
                .saturating_mul(QUARANTINE_GLOBAL_MULTIPLIER)
        });
        Self {
            dir: config.quarantine_dir.clone(),
            session_cap,
            global_cap,
            session_bytes: 0,
            global_bytes,
        }
    }

    #[cfg(test)]
    pub(super) fn session_bytes(&self) -> u64 {
        self.session_bytes
    }

    pub(super) fn write(&mut self, sha256: &str, data: &[u8]) -> Result<String, QuarantineRefusal> {
        let len = data.len() as u64;
        if self.session_bytes.saturating_add(len) > self.session_cap {
            return Err(QuarantineRefusal::SessionCap);
        }
        let current_global = self.global_bytes.load(Ordering::Relaxed);
        if current_global.saturating_add(len) > self.global_cap {
            return Err(QuarantineRefusal::GlobalCap);
        }
        let (path, written) =
            write_quarantine(&self.dir, sha256, data).map_err(QuarantineRefusal::Io)?;
        self.session_bytes += written;
        self.global_bytes.fetch_add(written, Ordering::Relaxed);
        Ok(path)
    }
}

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

    pub(super) fn quarantine(&mut self, data: &[u8]) -> QuarantinedPayload {
        let sha256 = sha256_hex(data);
        let path = match self.quarantine_store.write(&sha256, data) {
            Ok(path) => path,
            Err(refusal) => {
                self.log_quarantine_refusal(refusal);
                String::new()
            }
        };
        QuarantinedPayload { sha256, path }
    }

    fn log_quarantine_refusal(&self, refusal: QuarantineRefusal) {
        let (session_id, peer) = (self.session_id, self.peer);
        match refusal {
            QuarantineRefusal::SessionCap => event::quarantine_session_cap(session_id, peer),
            QuarantineRefusal::GlobalCap => event::quarantine_global_cap(session_id, peer),
            QuarantineRefusal::Io(err) => {
                event::quarantine_error(session_id, peer, &err.to_string());
            }
        }
    }

    pub(super) fn write_to_vfs(
        &mut self,
        target: &str,
        recursive: bool,
        file: &scp::CompletedFile,
    ) -> String {
        let shell = self.shell();
        let (uid, gid) = (shell.uid, shell.gid);
        let (dir_path, name) = scp_destination(shell, target, recursive, file);
        let intended = format!("{}/{name}", dir_path.trim_end_matches('/'));
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

fn scp_destination(
    shell: &Shell,
    target: &str,
    recursive: bool,
    file: &scp::CompletedFile,
) -> (String, String) {
    let cwd = shell.cwd;
    let mut base = abs_path(&shell.vfs.path_of(cwd), target);
    if !file.rel_dir.is_empty() {
        base = format!("{}/{}", base.trim_end_matches('/'), file.rel_dir);
    }

    let target_is_dir = shell
        .vfs
        .resolve(cwd, &base)
        .is_some_and(|id| shell.vfs.node(id).meta.is_dir());

    if target_is_dir || target.ends_with('/') || recursive || !file.rel_dir.is_empty() {
        return (base, file.name.clone());
    }
    let (dir, name) = Vfs::split_path(base.trim_end_matches('/'));
    (dir.to_string(), name.to_string())
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
    std::fs::create_dir_all(dir)?;
    let path = dir.join(sha256);

    let newly_written = if path.exists() {
        0
    } else {
        stage_and_commit(dir, sha256, &path, data)?
    };
    let stored = path.to_string_lossy().into_owned();

    #[cfg(windows)]
    let stored = stored.replace('\\', "/");
    Ok((stored, newly_written))
}

fn stage_and_commit(
    dir: &std::path::Path,
    sha256: &str,
    path: &std::path::Path,
    data: &[u8],
) -> std::io::Result<u64> {
    use std::io::Write;
    let staging = dir.join(format!("{sha256}.partial"));
    let mut file = match create_restricted(&staging) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(0),
        Err(e) => return Err(e),
    };
    let written = file.write_all(data).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written.and_then(|()| std::fs::rename(&staging, path)) {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }
    Ok(data.len() as u64)
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
