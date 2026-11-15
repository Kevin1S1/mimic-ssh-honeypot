use super::{
    now_ts, Metadata, Node, NodeId, NodeKind, Vfs, DEFAULT_FILE_MODE, MAX_VFS_BYTES, S_IFDIR,
    S_IFLNK, S_IFREG,
};
use std::collections::BTreeMap;

impl Vfs {
    pub(super) fn insert(
        &mut self,
        parent: NodeId,
        name: &str,
        kind: NodeKind,
        meta: Metadata,
    ) -> NodeId {
        if self.is_full(parent) {
            return parent;
        }
        let id = self.nodes.len();
        self.nodes.push(Node {
            name: name.to_string(),
            parent: Some(parent),
            kind,
            meta,
        });
        if let NodeKind::Directory { children } = &mut self.nodes[parent].kind {
            children.insert(name.to_string(), id);
        }
        id
    }

    pub fn mkdir(&mut self, parent: NodeId, name: &str, perms: u32, uid: u32, gid: u32) -> NodeId {
        if let Some(existing) = self.child(parent, name) {
            return existing;
        }
        let kind = NodeKind::Directory {
            children: BTreeMap::new(),
        };
        self.insert(parent, name, kind, Metadata::new(S_IFDIR, perms, uid, gid))
    }

    pub fn add_file(
        &mut self,
        parent: NodeId,
        name: &str,
        contents: impl Into<Vec<u8>>,
        perms: u32,
        uid: u32,
        gid: u32,
    ) -> NodeId {
        let contents = contents.into();
        let new_len = contents.len();
        let existing = self.child(parent, name);

        let old_len = existing
            .map(|id| match &self.nodes[id].kind {
                NodeKind::File { contents } => contents.len(),
                _ => 0,
            })
            .unwrap_or(0);
        if self.content_bytes - old_len + new_len > MAX_VFS_BYTES {
            return existing.unwrap_or(parent);
        }
        let kind = NodeKind::File { contents };
        let meta = Metadata::new(S_IFREG, perms, uid, gid);
        if let Some(existing) = existing {
            self.nodes[existing].kind = kind;
            self.nodes[existing].meta = meta;
            self.content_bytes = self.content_bytes - old_len + new_len;
            return existing;
        }
        let id = self.insert(parent, name, kind, meta);
        if id != parent {
            self.content_bytes += new_len;
        }
        id
    }

    pub fn add_dynamic_file(
        &mut self,
        parent: NodeId,
        name: &str,
        generator: fn() -> Vec<u8>,
        perms: u32,
        uid: u32,
        gid: u32,
    ) -> NodeId {
        let kind = NodeKind::DynamicFile { generator };
        let meta = Metadata::new(S_IFREG, perms, uid, gid);
        if let Some(existing) = self.child(parent, name) {
            self.nodes[existing].kind = kind;
            self.nodes[existing].meta = meta;
            return existing;
        }
        self.insert(parent, name, kind, meta)
    }

    pub fn write_file(&mut self, id: NodeId, data: &[u8], append: bool) -> bool {
        let NodeKind::File { contents } = &self.nodes[id].kind else {
            return false;
        };
        let old_len = contents.len();
        let new_len = if append {
            old_len + data.len()
        } else {
            data.len()
        };
        if self.content_bytes - old_len + new_len > MAX_VFS_BYTES {
            return false;
        }
        let NodeKind::File { contents } = &mut self.nodes[id].kind else {
            return false;
        };
        if append {
            contents.extend_from_slice(data);
        } else {
            contents.clear();
            contents.extend_from_slice(data);
        }
        self.content_bytes = self.content_bytes - old_len + new_len;
        self.nodes[id].meta.mtime = now_ts();
        true
    }

    pub fn add_symlink(&mut self, parent: NodeId, name: &str, target: &str) -> NodeId {
        if let Some(existing) = self.child(parent, name) {
            return existing;
        }
        let kind = NodeKind::Symlink {
            target: target.to_string(),
        };
        self.insert(parent, name, kind, Metadata::new(S_IFLNK, 0o777, 0, 0))
    }

    pub fn mkdir_p(&mut self, path: &str, perms: u32, uid: u32, gid: u32) -> Option<NodeId> {
        let mut current = self.root;
        for comp in path.split('/') {
            if comp.is_empty() || comp == "." {
                continue;
            }
            let next = self.mkdir(current, comp, perms, uid, gid);

            if next == current {
                return None;
            }
            current = next;
        }
        Some(current)
    }

    pub fn touch(&mut self, parent: NodeId, name: &str, uid: u32, gid: u32) -> NodeId {
        let now = now_ts();
        if let Some(existing) = self.child(parent, name) {
            self.nodes[existing].meta.mtime = now;
            return existing;
        }
        let id = self.add_file(parent, name, Vec::new(), DEFAULT_FILE_MODE, uid, gid);
        self.nodes[id].meta.mtime = now;
        id
    }
}
