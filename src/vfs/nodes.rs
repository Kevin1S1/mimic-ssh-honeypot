//! Node types for the in-memory virtual filesystem.
//!
//! Nodes live in an arena ([`super::Vfs`]) and reference each other by
//! [`NodeId`] (an index) to keep the tree free of `Rc`/`RefCell` borrow
//! gymnastics. Nothing here touches the real filesystem.

use std::collections::BTreeMap;

/// File-type bit (`S_IFDIR`) for a directory.
pub const S_IFDIR: u32 = 0o040000;
/// File-type bit (`S_IFREG`) for a regular file.
pub const S_IFREG: u32 = 0o100000;
/// File-type bit (`S_IFLNK`) for a symbolic link.
pub const S_IFLNK: u32 = 0o120000;

/// Mask isolating the file-type bits of a mode.
pub const S_IFMT: u32 = 0o170000;

/// An index into the [`super::Vfs`] arena.
pub type NodeId = usize;

/// Ownership and permission metadata for a node.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// Permission bits **plus** the file-type bits (e.g. `S_IFDIR | 0o755`).
    pub mode: u32,
    /// Owning user id (0 = root).
    pub uid: u32,
    /// Owning group id (0 = root).
    pub gid: u32,
    /// Last modification time, unix seconds.
    pub mtime: i64,
}

impl Metadata {
    /// Build metadata, OR-ing the file-type bits into `perms`. A new node is
    /// stamped with the current time, which is what an attacker's `mkdir` or
    /// `>` should show; [`super::snapshot::build`] restamps the boot snapshot
    /// with the box's install date afterwards.
    pub fn new(file_type: u32, perms: u32, uid: u32, gid: u32) -> Self {
        Self {
            mode: file_type | (perms & 0o7777),
            uid,
            gid,
            mtime: crate::clock::now(),
        }
    }

    /// Whether this node is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    /// Whether this node is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    /// Whether a session with `uid`/`gid` may read this node's contents,
    /// per standard Unix semantics: root (`uid == 0`) always can; the owner
    /// needs the owner-read bit, group members need the group-read bit, and
    /// everyone else needs the other-read bit.
    pub fn readable_by(&self, uid: u32, gid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        if uid == self.uid {
            self.mode & 0o400 != 0
        } else if gid == self.gid {
            self.mode & 0o040 != 0
        } else {
            self.mode & 0o004 != 0
        }
    }

    /// Whether a session with `uid`/`gid` may write this node, following the
    /// same owner/group/other rule as [`Metadata::readable_by`] on the write
    /// bits. Creating or truncating a file checks this on the file itself when
    /// it exists, and on its parent directory when it does not.
    pub fn writable_by(&self, uid: u32, gid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        if uid == self.uid {
            self.mode & 0o200 != 0
        } else if gid == self.gid {
            self.mode & 0o020 != 0
        } else {
            self.mode & 0o002 != 0
        }
    }

    /// Whether a session with `uid`/`gid` may execute this node, following the
    /// same owner/group/other rule as [`Metadata::readable_by`] on the execute
    /// bits. On a directory that bit is search permission: entering it, which
    /// is what `cd` checks.
    pub fn executable_by(&self, uid: u32, gid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        if uid == self.uid {
            self.mode & 0o100 != 0
        } else if gid == self.gid {
            self.mode & 0o010 != 0
        } else {
            self.mode & 0o001 != 0
        }
    }
}

/// The payload of a node, discriminated by kind.
#[derive(Debug, Clone)]
pub enum NodeKind {
    /// A directory mapping child names to their node ids.
    Directory { children: BTreeMap<String, NodeId> },
    /// A regular file holding raw bytes.
    File { contents: Vec<u8> },
    /// A symbolic link to another path (absolute or relative).
    Symlink { target: String },
    /// A virtual file whose content is dynamically generated upon read (e.g. `/proc/uptime`).
    DynamicFile { generator: fn() -> Vec<u8> },
}

/// A single filesystem entry.
#[derive(Debug, Clone)]
pub struct Node {
    /// The entry's own name (the root's name is empty).
    pub name: String,
    /// Parent node id; `None` only for the root.
    pub parent: Option<NodeId>,
    /// Node payload.
    pub kind: NodeKind,
    /// Ownership and permissions.
    pub meta: Metadata,
}

impl Node {
    /// Return the contents of the file as bytes (borrowed slice for regular files,
    /// freshly generated vector for dynamic files), or `None` if this node is
    /// a directory or symlink.
    pub fn file_bytes(&self) -> Option<std::borrow::Cow<'_, [u8]>> {
        match &self.kind {
            NodeKind::File { contents } => Some(std::borrow::Cow::Borrowed(contents)),
            NodeKind::DynamicFile { generator } => Some(std::borrow::Cow::Owned(generator())),
            _ => None,
        }
    }
}
