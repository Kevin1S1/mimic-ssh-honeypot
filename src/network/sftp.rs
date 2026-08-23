//! SFTP subsystem (version 3) emulation for upload capture and filesystem interaction.
//!
//! This implements a state machine for the SFTP v3 wire protocol (RFC draft
//! `draft-ietf-secsh-filexfer-02`). It handles file uploads (which are captured,
//! hashed, and quarantined), file downloads from the in-memory VFS, directory
//! listings, metadata queries, and filesystem mutations (`mkdir`, `rm`, `rename`).

use crate::shell::Shell;
use crate::vfs::{Metadata, NodeKind, Vfs, S_IFDIR, S_IFREG};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// SFTP packet types (SFTP v3)
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_READLINK: u8 = 19;
const SSH_FXP_SYMLINK: u8 = 20;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;
#[allow(dead_code)]
const SSH_FXP_EXTENDED: u8 = 200;

// SFTP status codes
const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_NO_SUCH_FILE: u32 = 2;
const SSH_FX_FAILURE: u32 = 4;
const SSH_FX_BAD_MESSAGE: u32 = 5;
const SSH_FX_OP_UNSUPPORTED: u32 = 8;

// SFTP open flags
const SSH_FXF_READ: u32 = 0x00000001;
const SSH_FXF_WRITE: u32 = 0x00000002;

// Safety caps
const MAX_SFTP_PACKET_LEN: usize = 256 * 1024;
const MAX_SFTP_HANDLES: usize = 64;
/// Ceiling on bytes held across all of one session's open SFTP handles,
/// expressed as a multiple of `max_upload_bytes`. See
/// [`SftpSession::buffer_cap`].
const SFTP_SESSION_BUFFER_MULTIPLIER: u64 = 2;
/// Ceiling on the response bytes one [`SftpSession::feed`] call may accumulate
/// before it stops processing and returns. Matches the shell's own output cap:
/// unprocessed input stays in `self.buf` for the next call, so nothing is lost.
const MAX_SFTP_FEED_RESPONSE: usize = 1024 * 1024;
const MAX_READ_CHUNK: usize = 32 * 1024;
const MAX_DIR_ENTRIES_PER_READ: usize = 64;

type SftpNameEntry<'a> = (&'a str, &'a str, Option<(&'a Metadata, u64)>);

/// A file upload completed over SFTP, ready for quarantine storage and logging.
pub struct SftpCompletedUpload {
    /// Attacker-supplied file name (e.g. `bot.elf`).
    pub name: String,
    /// Absolute destination path in the emulated VFS (e.g. `/tmp/bot.elf`).
    pub dest_path: String,
    /// Unix permission bits (e.g. 0o755).
    #[allow(dead_code)]
    pub mode: u32,
    /// The (possibly truncated) file contents.
    pub data: Vec<u8>,
    /// Total byte length received off the wire.
    pub size: u64,
    /// SHA-256 of the entire payload as received over the wire.
    pub payload_sha256: String,
    /// Whether the stored data was truncated at `max_upload_bytes`.
    pub truncated: bool,
}

enum SftpHandle {
    Dir {
        entries: Vec<(String, String, Metadata, u64)>,
        offset: usize,
    },
    ReadFile {
        data: Vec<u8>,
        meta: Metadata,
    },
    WriteFile {
        dest_path: String,
        name: String,
        data: Vec<u8>,
        size: u64,
        hasher: Sha256,
        mode: u32,
        truncated: bool,
    },
}

/// The SFTP subsystem state machine.
pub struct SftpSession {
    buf: Vec<u8>,
    handles: BTreeMap<Vec<u8>, SftpHandle>,
    next_handle: u32,
    /// Bytes currently held across every open handle's buffer. Bounds one
    /// session's SFTP memory the way `quarantine_bytes` bounds its disk: without
    /// it, 64 handles each grown to `max_upload_bytes` by a single sparse write
    /// multiply the per-file cap by [`MAX_SFTP_HANDLES`].
    buffered_bytes: usize,
}

impl Default for SftpSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpSession {
    /// Create a new SFTP session handler.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            handles: BTreeMap::new(),
            next_handle: 1,
            buffered_bytes: 0,
        }
    }

    /// Per-session ceiling on bytes held across all open handles, as a multiple
    /// of `max_upload_bytes`. A legitimate client transfers files one handle at
    /// a time, so a small multiple leaves real usage untouched while capping the
    /// 64× amplification a hostile client can otherwise reach.
    fn buffer_cap(max_upload_bytes: u64) -> usize {
        max_upload_bytes
            .saturating_mul(SFTP_SESSION_BUFFER_MULTIPLIER)
            .min(usize::MAX as u64) as usize
    }

    /// Whether `extra` more bytes can be buffered without exceeding the cap.
    fn can_buffer(&self, extra: usize, max_upload_bytes: u64) -> bool {
        self.buffered_bytes.saturating_add(extra) <= Self::buffer_cap(max_upload_bytes)
    }

    /// Feed incoming channel data bytes into the SFTP state machine.
    /// Returns the bytes to send back to the client and any completed file uploads.
    pub fn feed(
        &mut self,
        data: &[u8],
        shell: &mut Shell,
        max_upload_bytes: u64,
    ) -> (Vec<u8>, Vec<SftpCompletedUpload>) {
        let mut out = Vec::new();
        let mut completed = Vec::new();

        self.buf.extend_from_slice(data);

        let mut read_pos = 0;
        while self.buf.len() - read_pos >= 4 {
            let pkt_len = u32::from_be_bytes([
                self.buf[read_pos],
                self.buf[read_pos + 1],
                self.buf[read_pos + 2],
                self.buf[read_pos + 3],
            ]) as usize;

            if pkt_len > MAX_SFTP_PACKET_LEN {
                self.buf.clear();
                return (out, completed);
            }

            if self.buf.len() - read_pos < 4 + pkt_len {
                break;
            }

            let pkt_start = read_pos + 4;
            let pkt_end = pkt_start + pkt_len;
            let pkt = self.buf[pkt_start..pkt_end].to_vec();
            self.handle_packet(&pkt, shell, max_upload_bytes, &mut out, &mut completed);
            read_pos = pkt_end;

            // Individual responses are bounded, but a pipelined burst of small
            // requests can each amplify into one. Stop once the batch reaches
            // the cap; what is left in `self.buf` is processed on the next call.
            if out.len() >= MAX_SFTP_FEED_RESPONSE {
                break;
            }
        }

        if read_pos > 0 {
            self.buf.drain(0..read_pos);
        }

        (out, completed)
    }

    /// Finalize any remaining in-flight write handles when the channel closes.
    pub fn into_pending_uploads(self, shell: &mut Shell) -> Vec<SftpCompletedUpload> {
        let mut completed = Vec::new();
        for (_, handle) in self.handles {
            if let SftpHandle::WriteFile {
                dest_path,
                name,
                data,
                size,
                hasher,
                mode,
                truncated,
            } = handle
            {
                if size > 0 || !data.is_empty() {
                    let (dir_path, _) = Vfs::split_path(&dest_path);
                    // Mirroring into the VFS is best-effort: it has its own
                    // caps, and the capture below does not depend on it. What
                    // it must never do is fall back to an ancestor directory,
                    // which would put the file somewhere other than the
                    // `dest_path` the `upload` event records.
                    if let Some(parent) = shell.vfs.mkdir_p(dir_path, 0o755, shell.uid, shell.gid) {
                        shell
                            .vfs
                            .add_file(parent, &name, data.clone(), mode, shell.uid, shell.gid);
                    }
                    let payload_sha256 = super::ssh::hex(&hasher.finalize());
                    completed.push(SftpCompletedUpload {
                        name,
                        dest_path,
                        mode,
                        data,
                        size,
                        payload_sha256,
                        truncated,
                    });
                }
            }
        }
        completed
    }

    fn alloc_handle(&mut self) -> Vec<u8> {
        let h = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        h.to_be_bytes().to_vec()
    }

    fn handle_packet(
        &mut self,
        pkt: &[u8],
        shell: &mut Shell,
        max_upload_bytes: u64,
        out: &mut Vec<u8>,
        completed: &mut Vec<SftpCompletedUpload>,
    ) {
        if pkt.is_empty() {
            return;
        }
        let msg_type = pkt[0];
        let mut cursor = &pkt[1..];

        if msg_type == SSH_FXP_INIT {
            let _version = get_u32(&mut cursor).unwrap_or(3);
            send_packet(out, SSH_FXP_VERSION, |p| {
                put_u32(p, 3);
            });
            return;
        }

        let Some(id) = get_u32(&mut cursor) else {
            return;
        };

        match msg_type {
            SSH_FXP_REALPATH => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let canonical = normalize_path(&cwd_str, path);
                put_name_pkt(out, id, &[(&canonical, &canonical, None)]);
            }
            SSH_FXP_STAT => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                if let Some(node_id) = shell.vfs.resolve(shell.cwd, &abs) {
                    let node = shell.vfs.node(node_id);
                    let size = crate::commands::fs::node_size(node);
                    put_attrs_pkt(out, id, &node.meta, size);
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            SSH_FXP_LSTAT => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                if abs == "/" {
                    let node = shell.vfs.node(shell.vfs.root());
                    let size = crate::commands::fs::node_size(node);
                    put_attrs_pkt(out, id, &node.meta, size);
                } else {
                    let (parent_path, name) = Vfs::split_path(&abs);
                    let resolved = shell
                        .vfs
                        .resolve(shell.cwd, parent_path)
                        .and_then(|p_id| shell.vfs.child(p_id, name));
                    if let Some(node_id) = resolved {
                        let node = shell.vfs.node(node_id);
                        let size = crate::commands::fs::node_size(node);
                        put_attrs_pkt(out, id, &node.meta, size);
                    } else {
                        put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                    }
                }
            }
            SSH_FXP_OPENDIR => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                let dir_node = shell.vfs.resolve(shell.cwd, &abs);
                if let Some(dir_id) = dir_node {
                    let node = shell.vfs.node(dir_id);
                    if node.meta.is_dir() {
                        if self.handles.len() >= MAX_SFTP_HANDLES {
                            put_status(out, id, SSH_FX_FAILURE, "Too many open handles");
                            return;
                        }
                        let mut entries = Vec::new();
                        // "."
                        let dir_meta = node.meta.clone();
                        let dot_long = format_dir_entry(".", &dir_meta, 4096, None);
                        entries.push((".".to_string(), dot_long, dir_meta, 4096));

                        // ".."
                        let parent_id = node.parent.unwrap_or(dir_id);
                        let parent_meta = shell.vfs.node(parent_id).meta.clone();
                        let dotdot_long = format_dir_entry("..", &parent_meta, 4096, None);
                        entries.push(("..".to_string(), dotdot_long, parent_meta, 4096));

                        // Children
                        if let Some(child_list) = shell.vfs.entries(dir_id) {
                            for (c_name, c_id) in child_list {
                                let c_node = shell.vfs.node(c_id);
                                let c_size = crate::commands::fs::node_size(c_node);
                                let c_meta = c_node.meta.clone();
                                let target = if let NodeKind::Symlink { target } = &c_node.kind {
                                    Some(target.as_str())
                                } else {
                                    None
                                };
                                let long = format_dir_entry(&c_name, &c_meta, c_size, target);
                                entries.push((c_name, long, c_meta, c_size));
                            }
                        }

                        let handle_bytes = self.alloc_handle();
                        self.handles
                            .insert(handle_bytes.clone(), SftpHandle::Dir { entries, offset: 0 });
                        put_handle(out, id, &handle_bytes);
                    } else {
                        put_status(out, id, SSH_FX_FAILURE, "Not a directory");
                    }
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            SSH_FXP_READDIR => {
                let Some(handle) = get_bytes(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                if let Some(SftpHandle::Dir { entries, offset }) = self.handles.get_mut(handle) {
                    if *offset >= entries.len() {
                        put_status(out, id, SSH_FX_EOF, "End of file");
                    } else {
                        let end = (*offset + MAX_DIR_ENTRIES_PER_READ).min(entries.len());
                        let slice = &entries[*offset..end];
                        *offset = end;
                        let formatted: Vec<SftpNameEntry> = slice
                            .iter()
                            .map(|(n, l, m, s)| (n.as_str(), l.as_str(), Some((m, *s))))
                            .collect();
                        put_name_pkt(out, id, &formatted);
                    }
                } else {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid handle");
                }
            }
            SSH_FXP_OPEN => {
                let (Some(path), Some(pflags)) = (get_str(&mut cursor), get_u32(&mut cursor))
                else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let attrs = get_attrs(&mut cursor);
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                let (_, name) = Vfs::split_path(&abs);
                if name.is_empty() {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid path");
                    return;
                }
                let name = name.to_string();

                if self.handles.len() >= MAX_SFTP_HANDLES {
                    put_status(out, id, SSH_FX_FAILURE, "Too many open handles");
                    return;
                }

                if pflags & SSH_FXF_WRITE != 0 {
                    let mode = attrs.as_ref().and_then(|a| a.permissions).unwrap_or(0o644) & 0o7777;
                    let handle_bytes = self.alloc_handle();
                    self.handles.insert(
                        handle_bytes.clone(),
                        SftpHandle::WriteFile {
                            dest_path: abs,
                            name,
                            data: Vec::new(),
                            size: 0,
                            hasher: Sha256::new(),
                            mode,
                            truncated: false,
                        },
                    );
                    put_handle(out, id, &handle_bytes);
                } else if pflags & SSH_FXF_READ != 0 {
                    if let Some(node_id) = shell.vfs.resolve(shell.cwd, &abs) {
                        let node = shell.vfs.node(node_id);
                        if let Some(data) = node.file_bytes() {
                            // Opening a read handle copies the whole file, so it
                            // is charged against the same budget writes are:
                            // 64 handles on one large file is the same
                            // amplification from the other direction.
                            if !self.can_buffer(data.len(), max_upload_bytes) {
                                put_status(out, id, SSH_FX_FAILURE, "Too many open handles");
                                return;
                            }
                            let data = data.into_owned();
                            let meta = node.meta.clone();
                            self.buffered_bytes += data.len();
                            let handle_bytes = self.alloc_handle();
                            self.handles
                                .insert(handle_bytes.clone(), SftpHandle::ReadFile { data, meta });
                            put_handle(out, id, &handle_bytes);
                        } else {
                            put_status(out, id, SSH_FX_FAILURE, "Not a regular file");
                        }
                    } else {
                        put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                    }
                } else {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid open flags");
                }
            }
            SSH_FXP_READ => {
                let (Some(handle), Some(raw_offset), Some(len)) = (
                    get_bytes(&mut cursor),
                    get_u64(&mut cursor),
                    get_u32(&mut cursor),
                ) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let len = len as usize;

                if let Some(SftpHandle::ReadFile { data, .. }) = self.handles.get(handle) {
                    if raw_offset > usize::MAX as u64 || (raw_offset as usize) >= data.len() {
                        put_status(out, id, SSH_FX_EOF, "End of file");
                    } else {
                        let offset = raw_offset as usize;
                        let read_len = len.min(MAX_READ_CHUNK).min(data.len() - offset);
                        put_data(out, id, &data[offset..offset + read_len]);
                    }
                } else {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid handle");
                }
            }
            SSH_FXP_WRITE => {
                let (Some(handle), Some(raw_offset), Some(chunk)) = (
                    get_bytes(&mut cursor),
                    get_u64(&mut cursor),
                    get_bytes(&mut cursor),
                ) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };

                // Checked before the mutable borrow below so the session-wide
                // budget is visible; `grow_to` charges what it actually adds.
                let budget_left =
                    Self::buffer_cap(max_upload_bytes).saturating_sub(self.buffered_bytes);
                let mut grew = 0usize;

                if let Some(SftpHandle::WriteFile {
                    data,
                    size,
                    hasher,
                    truncated,
                    ..
                }) = self.handles.get_mut(handle)
                {
                    hasher.update(chunk);
                    *size += chunk.len() as u64;

                    // Grow only as far as the per-file cap, the session budget,
                    // and `usize` all allow. A write past any of them is
                    // consumed and hashed (so the wire protocol and the payload
                    // hash stay correct) but not stored.
                    let mut grow_to = |data: &mut Vec<u8>, end: usize| -> bool {
                        if end <= data.len() {
                            return true;
                        }
                        let extra = end - data.len();
                        if extra > budget_left - grew {
                            return false;
                        }
                        data.resize(end, 0);
                        grew += extra;
                        true
                    };

                    let raw_end = raw_offset.saturating_add(chunk.len() as u64);
                    if raw_end <= max_upload_bytes && raw_end <= usize::MAX as u64 {
                        let offset = raw_offset as usize;
                        let end = raw_end as usize;
                        if grow_to(data, end) {
                            data[offset..end].copy_from_slice(chunk);
                        } else {
                            *truncated = true;
                        }
                    } else {
                        *truncated = true;
                        if raw_offset < max_upload_bytes && raw_offset < usize::MAX as u64 {
                            let offset = raw_offset as usize;
                            let allowed = (max_upload_bytes - raw_offset)
                                .min(usize::MAX as u64 - raw_offset)
                                as usize;
                            let take = allowed.min(chunk.len());
                            let chunk_end = offset + take;
                            if grow_to(data, chunk_end) {
                                data[offset..chunk_end].copy_from_slice(&chunk[..take]);
                            }
                        }
                    }
                    put_status(out, id, SSH_FX_OK, "OK");
                } else {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid handle");
                }
                self.buffered_bytes += grew;
            }
            SSH_FXP_CLOSE => {
                let Some(handle) = get_bytes(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                if let Some(h) = self.handles.remove(handle) {
                    // Closing a handle returns its bytes to the session budget,
                    // so a client transferring many files in sequence is never
                    // charged for more than what it holds at once.
                    self.buffered_bytes = self.buffered_bytes.saturating_sub(match &h {
                        SftpHandle::WriteFile { data, .. } | SftpHandle::ReadFile { data, .. } => {
                            data.len()
                        }
                        SftpHandle::Dir { .. } => 0,
                    });
                    if let SftpHandle::WriteFile {
                        dest_path,
                        name,
                        data,
                        size,
                        hasher,
                        mode,
                        truncated,
                    } = h
                    {
                        let (dir_path, _) = Vfs::split_path(&dest_path);
                        // Best-effort mirror; see `into_pending_uploads`.
                        if let Some(parent) =
                            shell.vfs.mkdir_p(dir_path, 0o755, shell.uid, shell.gid)
                        {
                            shell.vfs.add_file(
                                parent,
                                &name,
                                data.clone(),
                                mode,
                                shell.uid,
                                shell.gid,
                            );
                        }
                        let payload_sha256 = super::ssh::hex(&hasher.finalize());
                        completed.push(SftpCompletedUpload {
                            name,
                            dest_path,
                            mode,
                            data,
                            size,
                            payload_sha256,
                            truncated,
                        });
                    }
                    put_status(out, id, SSH_FX_OK, "OK");
                } else {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid handle");
                }
            }
            SSH_FXP_FSTAT => {
                let Some(handle) = get_bytes(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                match self.handles.get(handle) {
                    Some(SftpHandle::ReadFile { meta, data }) => {
                        put_attrs_pkt(out, id, meta, data.len() as u64);
                    }
                    Some(SftpHandle::WriteFile { mode, size, .. }) => {
                        let meta = Metadata::new(S_IFREG, *mode, shell.uid, shell.gid);
                        put_attrs_pkt(out, id, &meta, *size);
                    }
                    Some(SftpHandle::Dir { .. }) => {
                        let meta = Metadata::new(S_IFDIR, 0o755, shell.uid, shell.gid);
                        put_attrs_pkt(out, id, &meta, 4096);
                    }
                    None => {
                        put_status(out, id, SSH_FX_FAILURE, "Invalid handle");
                    }
                }
            }
            SSH_FXP_SETSTAT => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let attrs = get_attrs(&mut cursor);
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                if let Some(node_id) = shell.vfs.resolve(shell.cwd, &abs) {
                    if let Some(attrs) = attrs {
                        if let Some(perms) = attrs.permissions {
                            shell.vfs.chmod(node_id, perms);
                        }
                        if let Some((uid, gid)) = attrs.uid_gid {
                            shell.vfs.chown(node_id, uid, gid);
                        }
                        if let Some((_, mtime)) = attrs.acmodtime {
                            shell.vfs.set_mtime(node_id, mtime as i64);
                        }
                    }
                    put_status(out, id, SSH_FX_OK, "OK");
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            SSH_FXP_FSETSTAT => {
                let Some(handle) = get_bytes(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let attrs = get_attrs(&mut cursor);
                if let Some(SftpHandle::WriteFile { mode, .. }) = self.handles.get_mut(handle) {
                    if let Some(attrs) = attrs {
                        if let Some(perms) = attrs.permissions {
                            *mode = perms & 0o7777;
                        }
                    }
                    put_status(out, id, SSH_FX_OK, "OK");
                } else if self.handles.contains_key(handle) {
                    put_status(out, id, SSH_FX_OK, "OK");
                } else {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid handle");
                }
            }
            SSH_FXP_REMOVE => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                let (parent_path, name) = Vfs::split_path(&abs);
                if name.is_empty() {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid path");
                    return;
                }
                if let Some(parent_id) = shell.vfs.resolve(shell.cwd, parent_path) {
                    if shell.vfs.unlink(parent_id, name).is_some() {
                        put_status(out, id, SSH_FX_OK, "OK");
                    } else {
                        put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                    }
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            SSH_FXP_MKDIR => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let attrs = get_attrs(&mut cursor);
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                let (parent_path, name) = Vfs::split_path(&abs);
                if name.is_empty() {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid path");
                    return;
                }
                if let Some(parent_id) = shell.vfs.resolve(shell.cwd, parent_path) {
                    let perms = attrs.and_then(|a| a.permissions).unwrap_or(0o755) & 0o7777;
                    shell
                        .vfs
                        .mkdir(parent_id, name, perms, shell.uid, shell.gid);
                    put_status(out, id, SSH_FX_OK, "OK");
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            SSH_FXP_RMDIR => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                let (parent_path, name) = Vfs::split_path(&abs);
                if name.is_empty() {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid path");
                    return;
                }
                if let Some(parent_id) = shell.vfs.resolve(shell.cwd, parent_path) {
                    if let Some(child_id) = shell.vfs.child(parent_id, name) {
                        if let Some(entries) = shell.vfs.entries(child_id) {
                            if entries.is_empty() {
                                shell.vfs.unlink(parent_id, name);
                                put_status(out, id, SSH_FX_OK, "OK");
                            } else {
                                put_status(out, id, SSH_FX_FAILURE, "Directory not empty");
                            }
                        } else {
                            put_status(out, id, SSH_FX_FAILURE, "Not a directory");
                        }
                    } else {
                        put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                    }
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            SSH_FXP_RENAME => {
                let (Some(oldpath), Some(newpath)) = (get_str(&mut cursor), get_str(&mut cursor))
                else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let old_abs = normalize_path(&cwd_str, oldpath);
                let new_abs = normalize_path(&cwd_str, newpath);
                let (new_parent_path, new_name) = Vfs::split_path(&new_abs);
                if new_name.is_empty() {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid path");
                    return;
                }
                let old_node = shell.vfs.resolve(shell.cwd, &old_abs);
                let new_parent = shell.vfs.resolve(shell.cwd, new_parent_path);
                if let (Some(old_id), Some(new_p_id)) = (old_node, new_parent) {
                    if shell.vfs.rename(old_id, new_p_id, new_name) {
                        put_status(out, id, SSH_FX_OK, "OK");
                    } else {
                        put_status(out, id, SSH_FX_FAILURE, "Rename failed");
                    }
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            SSH_FXP_READLINK => {
                let Some(path) = get_str(&mut cursor) else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs = normalize_path(&cwd_str, path);
                let (parent_path, name) = Vfs::split_path(&abs);
                if name.is_empty() {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid path");
                    return;
                }
                let resolved = shell
                    .vfs
                    .resolve(shell.cwd, parent_path)
                    .and_then(|p_id| shell.vfs.child(p_id, name));
                if let Some(node_id) = resolved {
                    let node = shell.vfs.node(node_id);
                    if let NodeKind::Symlink { target } = &node.kind {
                        put_name_pkt(out, id, &[(target, target, None)]);
                    } else {
                        put_status(out, id, SSH_FX_FAILURE, "Not a symlink");
                    }
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            SSH_FXP_SYMLINK => {
                let (Some(linkpath), Some(targetpath)) =
                    (get_str(&mut cursor), get_str(&mut cursor))
                else {
                    put_status(out, id, SSH_FX_BAD_MESSAGE, "Malformed packet");
                    return;
                };
                let cwd_str = shell.vfs.path_of(shell.cwd);
                let abs_link = normalize_path(&cwd_str, linkpath);
                let (parent_path, name) = Vfs::split_path(&abs_link);
                if name.is_empty() {
                    put_status(out, id, SSH_FX_FAILURE, "Invalid path");
                    return;
                }
                let target_sanitized: String = targetpath
                    .replace('\\', "/")
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect();
                if let Some(parent_id) = shell.vfs.resolve(shell.cwd, parent_path) {
                    shell.vfs.add_symlink(parent_id, name, &target_sanitized);
                    put_status(out, id, SSH_FX_OK, "OK");
                } else {
                    put_status(out, id, SSH_FX_NO_SUCH_FILE, "No such file or directory");
                }
            }
            _ => {
                put_status(out, id, SSH_FX_OP_UNSUPPORTED, "Operation unsupported");
            }
        }
    }
}

fn normalize_path(cwd: &str, path: &str) -> String {
    let sanitized: String = path
        .replace('\\', "/")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let raw = if sanitized.starts_with('/') {
        sanitized
    } else if cwd == "/" {
        format!("/{sanitized}")
    } else {
        format!("{cwd}/{sanitized}")
    };
    let mut parts = Vec::new();
    for comp in raw.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn format_dir_entry(
    name: &str,
    meta: &Metadata,
    size: u64,
    symlink_target: Option<&str>,
) -> String {
    let mode = crate::commands::fs::mode_string(meta.mode);
    let nlink = if meta.is_dir() { 2 } else { 1 };
    let owner = crate::commands::fs::uid_name(meta.uid);
    let group = crate::commands::fs::gid_name(meta.gid);
    let date = crate::commands::fs::format_time(meta.mtime);
    let suffix = if let Some(target) = symlink_target {
        format!(" -> {target}")
    } else {
        String::new()
    };
    format!("{mode} {nlink:>2} {owner:<8} {group:<8} {size:>8} {date} {name}{suffix}")
}

// Framing helpers
fn send_packet(out: &mut Vec<u8>, pkt_type: u8, payload_fn: impl FnOnce(&mut Vec<u8>)) {
    let start = out.len();
    out.extend_from_slice(&[0, 0, 0, 0, pkt_type]);
    payload_fn(out);
    let total_len = out.len() - start;
    let pkt_len = (total_len - 4) as u32;
    out[start..start + 4].copy_from_slice(&pkt_len.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, val: u32) {
    out.extend_from_slice(&val.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, val: u64) {
    out.extend_from_slice(&val.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, data: &[u8]) {
    put_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

fn put_attrs(out: &mut Vec<u8>, meta: &Metadata, size: u64) {
    const ATTR_SIZE: u32 = 0x01;
    const ATTR_UIDGID: u32 = 0x02;
    const ATTR_PERMS: u32 = 0x04;
    const ATTR_ACMODTIME: u32 = 0x08;
    put_u32(out, ATTR_SIZE | ATTR_UIDGID | ATTR_PERMS | ATTR_ACMODTIME);
    put_u64(out, size);
    put_u32(out, meta.uid);
    put_u32(out, meta.gid);
    put_u32(out, meta.mode);
    put_u32(out, meta.mtime as u32);
    put_u32(out, meta.mtime as u32);
}

fn put_status(out: &mut Vec<u8>, id: u32, code: u32, msg: &str) {
    send_packet(out, SSH_FXP_STATUS, |p| {
        put_u32(p, id);
        put_u32(p, code);
        put_str(p, msg);
        put_str(p, "");
    });
}

fn put_handle(out: &mut Vec<u8>, id: u32, handle: &[u8]) {
    send_packet(out, SSH_FXP_HANDLE, |p| {
        put_u32(p, id);
        put_bytes(p, handle);
    });
}

fn put_data(out: &mut Vec<u8>, id: u32, data: &[u8]) {
    send_packet(out, SSH_FXP_DATA, |p| {
        put_u32(p, id);
        put_bytes(p, data);
    });
}

fn put_attrs_pkt(out: &mut Vec<u8>, id: u32, meta: &Metadata, size: u64) {
    send_packet(out, SSH_FXP_ATTRS, |p| {
        put_u32(p, id);
        put_attrs(p, meta, size);
    });
}

fn put_name_pkt(out: &mut Vec<u8>, id: u32, entries: &[SftpNameEntry]) {
    send_packet(out, SSH_FXP_NAME, |p| {
        put_u32(p, id);
        put_u32(p, entries.len() as u32);
        for (name, longname, attrs) in entries {
            put_str(p, name);
            put_str(p, longname);
            if let Some((meta, size)) = attrs {
                put_attrs(p, meta, *size);
            } else {
                put_u32(p, 0);
            }
        }
    });
}

// Decoding helpers
fn get_u32(cursor: &mut &[u8]) -> Option<u32> {
    if cursor.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Some(val)
}

fn get_u64(cursor: &mut &[u8]) -> Option<u64> {
    if cursor.len() < 8 {
        return None;
    }
    let val = u64::from_be_bytes([
        cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6], cursor[7],
    ]);
    *cursor = &cursor[8..];
    Some(val)
}

fn get_bytes<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = get_u32(cursor)? as usize;
    if cursor.len() < len {
        return None;
    }
    let slice = &cursor[..len];
    *cursor = &cursor[len..];
    Some(slice)
}

fn get_str<'a>(cursor: &mut &'a [u8]) -> Option<&'a str> {
    let bytes = get_bytes(cursor)?;
    std::str::from_utf8(bytes).ok()
}

struct ParsedAttrs {
    permissions: Option<u32>,
    uid_gid: Option<(u32, u32)>,
    acmodtime: Option<(u32, u32)>,
}

fn get_attrs(cursor: &mut &[u8]) -> Option<ParsedAttrs> {
    let flags = get_u32(cursor)?;
    if flags & 0x00000001 != 0 {
        get_u64(cursor)?; // size
    }
    let uid_gid = if flags & 0x00000002 != 0 {
        Some((get_u32(cursor)?, get_u32(cursor)?))
    } else {
        None
    };
    let permissions = if flags & 0x00000004 != 0 {
        Some(get_u32(cursor)?)
    } else {
        None
    };
    let acmodtime = if flags & 0x00000008 != 0 {
        Some((get_u32(cursor)?, get_u32(cursor)?))
    } else {
        None
    };
    if flags & 0x80000000 != 0 {
        let count = get_u32(cursor)?;
        for _ in 0..count {
            get_bytes(cursor)?;
            get_bytes(cursor)?;
        }
    }
    Some(ParsedAttrs {
        permissions,
        uid_gid,
        acmodtime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_shell() -> Shell {
        Shell::new("root", "debian")
    }

    fn make_pkt(pkt_type: u8, payload_fn: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut out = Vec::new();
        send_packet(&mut out, pkt_type, payload_fn);
        out
    }

    #[test]
    fn sftp_init_returns_version_3() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();
        let init_pkt = make_pkt(SSH_FXP_INIT, |p| put_u32(p, 3));
        let (out, completed) = session.feed(&init_pkt, &mut shell, 1024 * 1024);

        assert!(completed.is_empty());
        assert_eq!(out.len(), 9);
        assert_eq!(out[4], SSH_FXP_VERSION);
        assert_eq!(u32::from_be_bytes([out[5], out[6], out[7], out[8]]), 3);
    }

    #[test]
    fn sftp_realpath_resolves_dot_and_relative_paths() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        let realpath_pkt = make_pkt(SSH_FXP_REALPATH, |p| {
            put_u32(p, 42);
            put_str(p, ".");
        });
        let (out, _) = session.feed(&realpath_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out[4], SSH_FXP_NAME);
        let mut cur = &out[5..];
        let id = get_u32(&mut cur).unwrap();
        assert_eq!(id, 42);
        let count = get_u32(&mut cur).unwrap();
        assert_eq!(count, 1);
        let path = get_str(&mut cur).unwrap();
        assert_eq!(path, "/root");
    }

    #[test]
    fn sftp_stat_and_lstat() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        // Stat existing file
        let stat_pkt = make_pkt(SSH_FXP_STAT, |p| {
            put_u32(p, 100);
            put_str(p, "/etc/hostname");
        });
        let (out, _) = session.feed(&stat_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out[4], SSH_FXP_ATTRS);
        let mut cur = &out[5..];
        let id = get_u32(&mut cur).unwrap();
        assert_eq!(id, 100);

        // Lstat missing file
        let lstat_pkt = make_pkt(SSH_FXP_LSTAT, |p| {
            put_u32(p, 101);
            put_str(p, "/nonexistent");
        });
        let (out, _) = session.feed(&lstat_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out[4], SSH_FXP_STATUS);
        let mut cur = &out[5..];
        let id = get_u32(&mut cur).unwrap();
        assert_eq!(id, 101);
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_NO_SUCH_FILE);
    }

    #[test]
    fn sftp_file_upload_quarantine_and_vfs() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        // 1. Open for write
        let open_pkt = make_pkt(SSH_FXP_OPEN, |p| {
            put_u32(p, 1);
            put_str(p, "/tmp/malware.elf");
            put_u32(p, SSH_FXF_WRITE);
            put_u32(p, 0); // no attrs
        });
        let (out1, _) = session.feed(&open_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out1[4], SSH_FXP_HANDLE);
        let mut cur = &out1[5..];
        let _id = get_u32(&mut cur).unwrap();
        let handle = get_bytes(&mut cur).unwrap().to_vec();

        // 2. Write chunk
        let write_pkt = make_pkt(SSH_FXP_WRITE, |p| {
            put_u32(p, 2);
            put_bytes(p, &handle);
            put_u64(p, 0);
            put_bytes(p, b"\x7fELFfakebinarycontent");
        });
        let (out2, _) = session.feed(&write_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out2[4], SSH_FXP_STATUS);
        let mut cur = &out2[5..];
        let _id = get_u32(&mut cur).unwrap();
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_OK);

        // 3. Close
        let close_pkt = make_pkt(SSH_FXP_CLOSE, |p| {
            put_u32(p, 3);
            put_bytes(p, &handle);
        });
        let (out3, completed) = session.feed(&close_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out3[4], SSH_FXP_STATUS);
        assert_eq!(completed.len(), 1);

        let upload = &completed[0];
        assert_eq!(upload.name, "malware.elf");
        assert_eq!(upload.dest_path, "/tmp/malware.elf");
        assert_eq!(upload.data, b"\x7fELFfakebinarycontent");
        assert_eq!(upload.size, 21);
        assert!(!upload.truncated);

        // Verify VFS presence
        let node_id = shell.vfs.resolve(shell.cwd, "/tmp/malware.elf").unwrap();
        let node = shell.vfs.node(node_id);
        if let NodeKind::File { contents } = &node.kind {
            assert_eq!(contents, b"\x7fELFfakebinarycontent");
        } else {
            panic!("expected regular file");
        }
    }

    #[test]
    fn sftp_upload_truncation_at_cap() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();
        let max_upload = 10u64;

        let open_pkt = make_pkt(SSH_FXP_OPEN, |p| {
            put_u32(p, 1);
            put_str(p, "/tmp/big.bin");
            put_u32(p, SSH_FXF_WRITE);
            put_u32(p, 0);
        });
        let (out1, _) = session.feed(&open_pkt, &mut shell, max_upload);
        let mut cur = &out1[5..];
        let _id = get_u32(&mut cur).unwrap();
        let handle = get_bytes(&mut cur).unwrap().to_vec();

        let write_pkt = make_pkt(SSH_FXP_WRITE, |p| {
            put_u32(p, 2);
            put_bytes(p, &handle);
            put_u64(p, 0);
            put_bytes(p, b"0123456789abcdefghij"); // 20 bytes
        });
        session.feed(&write_pkt, &mut shell, max_upload);

        let close_pkt = make_pkt(SSH_FXP_CLOSE, |p| {
            put_u32(p, 3);
            put_bytes(p, &handle);
        });
        let (_, completed) = session.feed(&close_pkt, &mut shell, max_upload);
        assert_eq!(completed.len(), 1);
        let upload = &completed[0];
        assert_eq!(upload.size, 20);
        assert_eq!(upload.data.len(), 10);
        assert!(upload.truncated);
    }

    #[test]
    fn sftp_into_pending_uploads_on_dropped_session() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        let open_pkt = make_pkt(SSH_FXP_OPEN, |p| {
            put_u32(p, 1);
            put_str(p, "/tmp/dropped.bin");
            put_u32(p, SSH_FXF_WRITE);
            put_u32(p, 0);
        });
        let (out1, _) = session.feed(&open_pkt, &mut shell, 1024);
        let mut cur = &out1[5..];
        let _id = get_u32(&mut cur).unwrap();
        let handle = get_bytes(&mut cur).unwrap().to_vec();

        let write_pkt = make_pkt(SSH_FXP_WRITE, |p| {
            put_u32(p, 2);
            put_bytes(p, &handle);
            put_u64(p, 0);
            put_bytes(p, b"data-before-drop");
        });
        session.feed(&write_pkt, &mut shell, 1024);

        // Session drops without SSH_FXP_CLOSE
        let pending = session.into_pending_uploads(&mut shell);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].name, "dropped.bin");
        assert_eq!(pending[0].data, b"data-before-drop");
    }

    #[test]
    fn sftp_file_read_download() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        // 1. Open /etc/hostname for read
        let open_pkt = make_pkt(SSH_FXP_OPEN, |p| {
            put_u32(p, 10);
            put_str(p, "/etc/hostname");
            put_u32(p, SSH_FXF_READ);
            put_u32(p, 0);
        });
        let (out1, _) = session.feed(&open_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out1[4], SSH_FXP_HANDLE);
        let mut cur = &out1[5..];
        let _id = get_u32(&mut cur).unwrap();
        let handle = get_bytes(&mut cur).unwrap().to_vec();

        // 2. Read
        let read_pkt = make_pkt(SSH_FXP_READ, |p| {
            put_u32(p, 11);
            put_bytes(p, &handle);
            put_u64(p, 0);
            put_u32(p, 1024);
        });
        let (out2, _) = session.feed(&read_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out2[4], SSH_FXP_DATA);
        let mut cur = &out2[5..];
        let _id = get_u32(&mut cur).unwrap();
        let data = get_bytes(&mut cur).unwrap();
        assert_eq!(data, b"debian\n");

        // 3. Read at EOF
        let read_eof = make_pkt(SSH_FXP_READ, |p| {
            put_u32(p, 12);
            put_bytes(p, &handle);
            put_u64(p, 7);
            put_u32(p, 1024);
        });
        let (out3, _) = session.feed(&read_eof, &mut shell, 1024 * 1024);
        assert_eq!(out3[4], SSH_FXP_STATUS);
        let mut cur = &out3[5..];
        let _id = get_u32(&mut cur).unwrap();
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_EOF);
    }

    #[test]
    fn sftp_opendir_and_readdir() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        let opendir_pkt = make_pkt(SSH_FXP_OPENDIR, |p| {
            put_u32(p, 20);
            put_str(p, "/etc");
        });
        let (out1, _) = session.feed(&opendir_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out1[4], SSH_FXP_HANDLE);
        let mut cur = &out1[5..];
        let _id = get_u32(&mut cur).unwrap();
        let handle = get_bytes(&mut cur).unwrap().to_vec();

        let readdir_pkt = make_pkt(SSH_FXP_READDIR, |p| {
            put_u32(p, 21);
            put_bytes(p, &handle);
        });
        let (out2, _) = session.feed(&readdir_pkt, &mut shell, 1024 * 1024);
        assert_eq!(out2[4], SSH_FXP_NAME);
        let mut cur = &out2[5..];
        let _id = get_u32(&mut cur).unwrap();
        let count = get_u32(&mut cur).unwrap();
        assert!(count >= 2); // includes . and ..

        // Subsequent readdir returns EOF
        let readdir_eof = make_pkt(SSH_FXP_READDIR, |p| {
            put_u32(p, 22);
            put_bytes(p, &handle);
        });
        let (out3, _) = session.feed(&readdir_eof, &mut shell, 1024 * 1024);
        assert_eq!(out3[4], SSH_FXP_STATUS);
        let mut cur = &out3[5..];
        let _id = get_u32(&mut cur).unwrap();
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_EOF);
    }

    #[test]
    fn sftp_mkdir_rmdir_remove_rename_symlink() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        // 1. mkdir /tmp/testdir
        let mkdir_pkt = make_pkt(SSH_FXP_MKDIR, |p| {
            put_u32(p, 1);
            put_str(p, "/tmp/testdir");
            put_u32(p, 0);
        });
        let (out, _) = session.feed(&mkdir_pkt, &mut shell, 1024);
        assert_eq!(out[4], SSH_FXP_STATUS);

        // 2. symlink /tmp/testlink -> /tmp/testdir
        let symlink_pkt = make_pkt(SSH_FXP_SYMLINK, |p| {
            put_u32(p, 2);
            put_str(p, "/tmp/testlink");
            put_str(p, "/tmp/testdir");
        });
        let (out, _) = session.feed(&symlink_pkt, &mut shell, 1024);
        assert_eq!(out[4], SSH_FXP_STATUS);

        // 3. readlink /tmp/testlink
        let readlink_pkt = make_pkt(SSH_FXP_READLINK, |p| {
            put_u32(p, 3);
            put_str(p, "/tmp/testlink");
        });
        let (out, _) = session.feed(&readlink_pkt, &mut shell, 1024);
        assert_eq!(out[4], SSH_FXP_NAME);

        // 4. rename /tmp/testlink -> /tmp/renamedlink
        let rename_pkt = make_pkt(SSH_FXP_RENAME, |p| {
            put_u32(p, 4);
            put_str(p, "/tmp/testlink");
            put_str(p, "/tmp/renamedlink");
        });
        let (out, _) = session.feed(&rename_pkt, &mut shell, 1024);
        assert_eq!(out[4], SSH_FXP_STATUS);

        // 5. remove /tmp/renamedlink
        let remove_pkt = make_pkt(SSH_FXP_REMOVE, |p| {
            put_u32(p, 5);
            put_str(p, "/tmp/renamedlink");
        });
        let (out, _) = session.feed(&remove_pkt, &mut shell, 1024);
        assert_eq!(out[4], SSH_FXP_STATUS);

        // 6. rmdir /tmp/testdir
        let rmdir_pkt = make_pkt(SSH_FXP_RMDIR, |p| {
            put_u32(p, 6);
            put_str(p, "/tmp/testdir");
        });
        let (out, _) = session.feed(&rmdir_pkt, &mut shell, 1024);
        assert_eq!(out[4], SSH_FXP_STATUS);
    }

    #[test]
    fn sftp_rejects_empty_final_path_components_and_sanitizes_separators() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        // normalize_path strips control characters and converts backslashes
        assert_eq!(normalize_path("/root", r"a\b\c"), "/root/a/b/c");
        assert_eq!(
            normalize_path("/root", "/tmp/bot\x00\x1b.elf"),
            "/tmp/bot.elf"
        );

        // Opening "/" for write is rejected
        let open_root_pkt = make_pkt(SSH_FXP_OPEN, |p| {
            put_u32(p, 10);
            put_str(p, "/");
            put_u32(p, SSH_FXF_WRITE);
            put_u32(p, 0);
        });
        let (out1, _) = session.feed(&open_root_pkt, &mut shell, 1024);
        assert_eq!(out1[4], SSH_FXP_STATUS);
        let mut cur = &out1[5..];
        let _id = get_u32(&mut cur).unwrap();
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_FAILURE);

        // mkdir "/" is rejected
        let mkdir_root_pkt = make_pkt(SSH_FXP_MKDIR, |p| {
            put_u32(p, 11);
            put_str(p, "/");
            put_u32(p, 0);
        });
        let (out2, _) = session.feed(&mkdir_root_pkt, &mut shell, 1024);
        assert_eq!(out2[4], SSH_FXP_STATUS);
        let mut cur = &out2[5..];
        let _id = get_u32(&mut cur).unwrap();
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_FAILURE);

        // symlink "/" is rejected
        let symlink_root_pkt = make_pkt(SSH_FXP_SYMLINK, |p| {
            put_u32(p, 12);
            put_str(p, "/");
            put_str(p, "/tmp/target");
        });
        let (out3, _) = session.feed(&symlink_root_pkt, &mut shell, 1024);
        assert_eq!(out3[4], SSH_FXP_STATUS);
        let mut cur = &out3[5..];
        let _id = get_u32(&mut cur).unwrap();
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_FAILURE);
    }

    #[test]
    fn sftp_read_and_write_huge_offset_does_not_overflow() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        // Open existing file for read
        let open_pkt = make_pkt(SSH_FXP_OPEN, |p| {
            put_u32(p, 1);
            put_str(p, "/etc/hostname");
            put_u32(p, SSH_FXF_READ);
            put_u32(p, 0);
        });
        let (out1, _) = session.feed(&open_pkt, &mut shell, 1024);
        let mut cur = &out1[5..];
        let _id = get_u32(&mut cur).unwrap();
        let handle = get_bytes(&mut cur).unwrap().to_vec();

        // Read at offset u64::MAX returns EOF without wrapping
        let read_pkt = make_pkt(SSH_FXP_READ, |p| {
            put_u32(p, 2);
            put_bytes(p, &handle);
            put_u64(p, u64::MAX);
            put_u32(p, 100);
        });
        let (out2, _) = session.feed(&read_pkt, &mut shell, 1024);
        assert_eq!(out2[4], SSH_FXP_STATUS);
        let mut cur = &out2[5..];
        let _id = get_u32(&mut cur).unwrap();
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_EOF);
    }

    #[test]
    fn sftp_truncated_or_malformed_packets_return_bad_message() {
        let mut session = SftpSession::new();
        let mut shell = test_shell();

        // Packet with SSH_FXP_STAT but no path string bytes at all
        let malformed_stat = make_pkt(SSH_FXP_STAT, |p| {
            put_u32(p, 42);
            // omitted path
        });
        let (out, _) = session.feed(&malformed_stat, &mut shell, 1024);
        assert_eq!(out[4], SSH_FXP_STATUS);
        let mut cur = &out[5..];
        let id = get_u32(&mut cur).unwrap();
        assert_eq!(id, 42);
        let code = get_u32(&mut cur).unwrap();
        assert_eq!(code, SSH_FX_BAD_MESSAGE);
    }
}
