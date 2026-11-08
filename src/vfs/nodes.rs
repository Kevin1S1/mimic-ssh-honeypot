use std::collections::BTreeMap;

pub const S_IFDIR: u32 = 0o040000;

pub const S_IFREG: u32 = 0o100000;

pub const S_IFLNK: u32 = 0o120000;

pub const S_IFMT: u32 = 0o170000;

pub type NodeId = usize;

#[derive(Debug, Clone)]
pub struct Metadata {
    pub mode: u32,

    pub uid: u32,

    pub gid: u32,

    pub mtime: i64,
}

impl Metadata {
    pub fn new(file_type: u32, perms: u32, uid: u32, gid: u32) -> Self {
        Self {
            mode: file_type | (perms & 0o7777),
            uid,
            gid,
            mtime: crate::clock::now(),
        }
    }

    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

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

#[derive(Debug, Clone)]
pub enum NodeKind {
    Directory { children: BTreeMap<String, NodeId> },

    File { contents: Vec<u8> },

    Symlink { target: String },

    DynamicFile { generator: fn() -> Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,

    pub parent: Option<NodeId>,

    pub kind: NodeKind,

    pub meta: Metadata,
}

impl Node {
    pub fn file_bytes(&self) -> Option<std::borrow::Cow<'_, [u8]>> {
        match &self.kind {
            NodeKind::File { contents } => Some(std::borrow::Cow::Borrowed(contents)),
            NodeKind::DynamicFile { generator } => Some(std::borrow::Cow::Owned(generator())),
            _ => None,
        }
    }
}
