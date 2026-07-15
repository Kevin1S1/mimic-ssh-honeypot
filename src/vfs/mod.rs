//! In-memory virtual filesystem.
//!
//! The VFS is an arena of [`Node`]s addressed by [`NodeId`]. It exposes
//! path resolution (with `.`/`..`/symlink handling), directory listing, and
//! mutation helpers used by emulated commands (`mkdir`, `touch`, `rm`, ...).
//!
//! **Security invariant:** every operation is purely in-memory. No method here
//! ever opens, reads, or writes a real path.

pub mod nodes;
pub mod snapshot;

pub use nodes::{Metadata, Node, NodeId, NodeKind, S_IFDIR, S_IFLNK, S_IFREG};

use std::collections::BTreeMap;

/// Maximum symlink-resolution depth before giving up (loop protection).
const MAX_SYMLINK_DEPTH: usize = 40;

/// Hard ceiling on the number of nodes in the arena. Bounds memory so a hostile
/// `mkdir -p`/copy storm cannot exhaust the host; inserts past the cap are
/// silently dropped.
const MAX_VFS_NODES: usize = 2_000;

/// Hard ceiling on total file-content bytes held in the arena. The node cap
/// alone does not bound memory: an SCP upload (up to `max_upload_bytes`) can be
/// amplified with `cp` up to the node cap. Uploads are preserved in full in the
/// quarantine store, so capping the in-memory mirror loses no forensic data.
/// Writes past the cap are silently dropped, like node-cap overflow.
const MAX_VFS_BYTES: usize = 8 * 1024 * 1024;

/// An in-memory filesystem tree.
#[derive(Debug, Clone)]
pub struct Vfs {
    nodes: Vec<Node>,
    root: NodeId,
    /// Total file-content bytes allocated in the arena, including orphaned
    /// tombstones (their buffers stay resident by design; see [`Vfs::unlink`]).
    content_bytes: usize,
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
    /// Create a VFS containing only an empty root directory owned by root.
    pub fn new() -> Self {
        let root = Node {
            name: String::new(),
            parent: None,
            kind: NodeKind::Directory {
                children: BTreeMap::new(),
            },
            meta: Metadata::new(S_IFDIR, 0o755, 0, 0),
        };
        Self {
            nodes: vec![root],
            root: 0,
            content_bytes: 0,
        }
    }

    /// The root directory's id.
    pub fn root(&self) -> NodeId {
        self.root
    }

    /// Borrow a node by id.
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    /// Resolve `path` starting from `start` (used for relative paths),
    /// following symlinks. Returns the target node id, or `None` if any
    /// component is missing or traverses through a non-directory.
    pub fn resolve(&self, start: NodeId, path: &str) -> Option<NodeId> {
        self.resolve_inner(start, path, 0)
    }

    fn resolve_inner(&self, start: NodeId, path: &str, depth: usize) -> Option<NodeId> {
        if depth > MAX_SYMLINK_DEPTH {
            return None;
        }
        let mut current = if path.starts_with('/') {
            self.root
        } else {
            start
        };
        for comp in path.split('/') {
            match comp {
                "" | "." => continue,
                ".." => {
                    current = self.nodes[current].parent.unwrap_or(self.root);
                }
                name => {
                    let child = match &self.nodes[current].kind {
                        NodeKind::Directory { children } => *children.get(name)?,
                        _ => return None,
                    };
                    current = self.follow(child, depth)?;
                }
            }
        }
        Some(current)
    }

    /// If `id` is a symlink, resolve it relative to its parent; otherwise
    /// return `id` unchanged.
    fn follow(&self, id: NodeId, depth: usize) -> Option<NodeId> {
        match &self.nodes[id].kind {
            NodeKind::Symlink { target } => {
                let parent = self.nodes[id].parent.unwrap_or(self.root);
                self.resolve_inner(parent, target, depth + 1)
            }
            _ => Some(id),
        }
    }

    /// Look up a single named child of `dir` without following symlinks on the
    /// result. Returns `None` if `dir` is not a directory or has no such child.
    pub fn child(&self, dir: NodeId, name: &str) -> Option<NodeId> {
        match &self.nodes[dir].kind {
            NodeKind::Directory { children } => children.get(name).copied(),
            _ => None,
        }
    }

    /// Sorted `(name, NodeId)` entries of a directory. Returns `None` if `id`
    /// is not a directory.
    pub fn entries(&self, id: NodeId) -> Option<Vec<(String, NodeId)>> {
        match &self.nodes[id].kind {
            NodeKind::Directory { children } => {
                Some(children.iter().map(|(k, v)| (k.clone(), *v)).collect())
            }
            _ => None,
        }
    }

    /// Reconstruct the absolute path of `id` by walking parents.
    pub fn path_of(&self, id: NodeId) -> String {
        let mut parts = Vec::new();
        let mut current = id;
        while let Some(parent) = self.nodes[current].parent {
            parts.push(self.nodes[current].name.clone());
            current = parent;
        }
        if parts.is_empty() {
            return "/".to_string();
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    /// Split `path` into its directory portion and final component, e.g.
    /// `/etc/passwd` -> (`/etc`, `passwd`).
    pub fn split_path(path: &str) -> (&str, &str) {
        match path.rfind('/') {
            Some(0) => ("/", &path[1..]),
            Some(i) => (&path[..i], &path[i + 1..]),
            None => (".", path),
        }
    }

    // --- Mutation helpers -------------------------------------------------

    /// Insert a freshly built node under `parent`, returning its id. The
    /// caller must ensure `parent` is a directory. If the arena is at its hard
    /// node cap, the insert is dropped and `parent` is returned unchanged.
    fn insert(&mut self, parent: NodeId, name: &str, kind: NodeKind, meta: Metadata) -> NodeId {
        if self.nodes.len() >= MAX_VFS_NODES {
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

    /// Create a child directory. Returns the existing node if one with that
    /// name is already present.
    pub fn mkdir(&mut self, parent: NodeId, name: &str, perms: u32, uid: u32, gid: u32) -> NodeId {
        if let Some(existing) = self.child(parent, name) {
            return existing;
        }
        let kind = NodeKind::Directory {
            children: BTreeMap::new(),
        };
        self.insert(parent, name, kind, Metadata::new(S_IFDIR, perms, uid, gid))
    }

    /// Create or overwrite a regular file with the given contents. If the write
    /// would push total arena content past the byte cap, it is dropped: an
    /// existing file keeps its old contents, otherwise `parent` is returned
    /// unchanged.
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
        // Only an in-place file overwrite frees its old buffer; replacing a
        // dir/symlink or unlinking leaves tombstones resident, so those bytes
        // stay counted.
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
            // `insert` returns `parent` unchanged when the node cap drops it.
            self.content_bytes += new_len;
        }
        id
    }

    /// Create a symbolic link node pointing at `target`.
    pub fn add_symlink(&mut self, parent: NodeId, name: &str, target: &str) -> NodeId {
        if let Some(existing) = self.child(parent, name) {
            return existing;
        }
        let kind = NodeKind::Symlink {
            target: target.to_string(),
        };
        self.insert(parent, name, kind, Metadata::new(S_IFLNK, 0o777, 0, 0))
    }

    /// Create every directory along `path` (like `mkdir -p`), returning the
    /// id of the final directory. `path` must be absolute.
    pub fn mkdir_p(&mut self, path: &str, perms: u32, uid: u32, gid: u32) -> NodeId {
        let mut current = self.root;
        for comp in path.split('/') {
            if comp.is_empty() || comp == "." {
                continue;
            }
            current = self.mkdir(current, comp, perms, uid, gid);
        }
        current
    }

    /// Create an empty regular file under `parent` with the given name if it
    /// does not already exist; otherwise refresh the existing node's mtime.
    /// Returns the node id. Mirrors `touch`.
    pub fn touch(&mut self, parent: NodeId, name: &str, uid: u32, gid: u32) -> NodeId {
        let now = now_ts();
        if let Some(existing) = self.child(parent, name) {
            self.nodes[existing].meta.mtime = now;
            return existing;
        }
        let id = self.add_file(parent, name, Vec::new(), 0o644, uid, gid);
        self.nodes[id].meta.mtime = now;
        id
    }

    /// Set the permission bits of `id`, preserving the file-type bits.
    pub fn chmod(&mut self, id: NodeId, perms: u32) {
        let file_type = self.nodes[id].meta.mode & nodes::S_IFMT;
        self.nodes[id].meta.mode = file_type | (perms & 0o7777);
    }

    /// Detach the child `name` from directory `parent`, returning its id if it
    /// existed. The node itself is left orphaned in the arena (a tombstone);
    /// this keeps every other [`NodeId`] stable, which matters because callers
    /// hold ids across mutations. Orphaned slots are unreachable and bounded by
    /// the per-session lifetime, so the leak is acceptable for a honeypot.
    pub fn unlink(&mut self, parent: NodeId, name: &str) -> Option<NodeId> {
        match &mut self.nodes[parent].kind {
            NodeKind::Directory { children } => children.remove(name),
            _ => None,
        }
    }

    /// Move/rename `id` to be the child `new_name` of `new_parent`. Any node
    /// already at the destination name is detached first. Returns `false` if
    /// `new_parent` is not a directory.
    pub fn rename(&mut self, id: NodeId, new_parent: NodeId, new_name: &str) -> bool {
        if !matches!(self.nodes[new_parent].kind, NodeKind::Directory { .. }) {
            return false;
        }
        // Detach from the old parent.
        if let Some(old_parent) = self.nodes[id].parent {
            let old_name = self.nodes[id].name.clone();
            if let NodeKind::Directory { children } = &mut self.nodes[old_parent].kind {
                children.remove(&old_name);
            }
        }
        // Drop any node currently occupying the destination name.
        if let NodeKind::Directory { children } = &mut self.nodes[new_parent].kind {
            children.remove(new_name);
        }
        self.nodes[id].name = new_name.to_string();
        self.nodes[id].parent = Some(new_parent);
        if let NodeKind::Directory { children } = &mut self.nodes[new_parent].kind {
            children.insert(new_name.to_string(), id);
        }
        true
    }

    /// Recursively copy the subtree rooted at `src` into `dst_parent` under
    /// `dst_name`, returning the id of the new copy. Any existing destination
    /// node with that name is replaced.
    pub fn deep_copy(&mut self, src: NodeId, dst_parent: NodeId, dst_name: &str) -> NodeId {
        self.deep_copy_inner(src, dst_parent, dst_name, 0)
    }

    fn deep_copy_inner(
        &mut self,
        src: NodeId,
        dst_parent: NodeId,
        dst_name: &str,
        depth: usize,
    ) -> NodeId {
        const MAX_COPY_DEPTH: usize = 64;
        if depth > MAX_COPY_DEPTH {
            return dst_parent;
        }
        let kind = self.nodes[src].kind.clone();
        let mut meta = self.nodes[src].meta.clone();
        meta.mtime = now_ts();
        match kind {
            NodeKind::File { contents } => self.add_file(
                dst_parent,
                dst_name,
                contents,
                meta.mode & 0o7777,
                meta.uid,
                meta.gid,
            ),
            NodeKind::Symlink { target } => {
                self.unlink(dst_parent, dst_name);
                self.insert(dst_parent, dst_name, NodeKind::Symlink { target }, meta)
            }
            NodeKind::Directory { .. } => {
                let new_dir =
                    self.mkdir(dst_parent, dst_name, meta.mode & 0o7777, meta.uid, meta.gid);
                let children: Vec<(String, NodeId)> = self.entries(src).unwrap_or_default();
                for (name, child) in children {
                    self.deep_copy_inner(child, new_dir, &name, depth + 1);
                }
                new_dir
            }
        }
    }
}

/// Current wall-clock time in unix seconds, for freshly created/modified nodes.
fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vfs {
        let mut fs = Vfs::new();
        let root = fs.root();
        let tmp = fs.mkdir(root, "tmp", 0o1777, 0, 0);
        fs.add_file(tmp, "a", &b"hello"[..], 0o644, 0, 0);
        let d = fs.mkdir(tmp, "d", 0o755, 0, 0);
        fs.add_file(d, "inner", &b"x"[..], 0o644, 0, 0);
        fs
    }

    #[test]
    fn resolves_absolute_and_relative_paths() {
        let fs = fixture();
        let root = fs.root();
        let tmp = fs.resolve(root, "/tmp").unwrap();
        // Relative resolution from /tmp reaches the same node as an absolute path.
        assert_eq!(fs.resolve(tmp, "d/inner"), fs.resolve(root, "/tmp/d/inner"));
        // `.` segments and a trailing slash are no-ops.
        assert_eq!(
            fs.resolve(root, "/tmp/./d/"),
            Some(fs.child(tmp, "d").unwrap())
        );
        // A component that traverses through a file fails.
        assert!(fs.resolve(root, "/tmp/a/nope").is_none());
    }

    #[test]
    fn split_path_separates_dir_and_final() {
        assert_eq!(Vfs::split_path("/etc/passwd"), ("/etc", "passwd"));
        assert_eq!(Vfs::split_path("/top"), ("/", "top"));
        assert_eq!(Vfs::split_path("bare"), (".", "bare"));
    }

    #[test]
    fn resolve_follows_symlink() {
        let mut fs = fixture();
        let root = fs.root();
        // /link -> /tmp/d ; resolving through it must reach the real directory.
        fs.add_symlink(root, "link", "/tmp/d");
        let via_link = fs.resolve(root, "/link/inner").unwrap();
        let direct = fs.resolve(root, "/tmp/d/inner").unwrap();
        assert_eq!(via_link, direct);
    }

    #[test]
    fn symlink_loop_terminates() {
        let mut fs = fixture();
        let root = fs.root();
        // Two mutually-referential links must not spin: resolution bails out
        // at the depth cap and returns None instead of looping forever.
        fs.add_symlink(root, "a", "/b");
        fs.add_symlink(root, "b", "/a");
        assert_eq!(fs.resolve(root, "/a"), None);
    }

    #[test]
    fn dotdot_clamps_at_root() {
        let fs = fixture();
        let root = fs.root();
        // Walking `..` past the root stays pinned at the root — no escape.
        assert_eq!(fs.resolve(root, "/../../.."), Some(root));
        assert_eq!(fs.resolve(root, "/tmp/../.."), Some(root));
    }

    #[test]
    fn mkdir_p_creates_and_reuses_chain() {
        let mut fs = fixture();
        let made = fs.mkdir_p("/var/log/app", 0o755, 0, 0);
        assert_eq!(fs.resolve(fs.root(), "/var/log/app"), Some(made));
        // Re-running over an existing prefix reuses nodes rather than duplicating.
        let again = fs.mkdir_p("/var/log/app", 0o755, 0, 0);
        assert_eq!(again, made);
    }

    #[test]
    fn node_cap_bounds_allocation() {
        let mut fs = Vfs::new();
        let root = fs.root();
        // Inserting well past the cap must not grow the arena without bound.
        for i in 0..(MAX_VFS_NODES + 50) {
            fs.add_file(root, &format!("f{i}"), &b""[..], 0o644, 0, 0);
        }
        assert!(fs.nodes.len() <= MAX_VFS_NODES);
    }

    #[test]
    fn byte_cap_bounds_total_content() {
        let mut fs = Vfs::new();
        let root = fs.root();
        let big = vec![0u8; MAX_VFS_BYTES / 2 + 1];

        // First large file fits.
        let a = fs.add_file(root, "a", big.clone(), 0o644, 0, 0);
        assert!(fs.child(root, "a").is_some());

        // A copy would exceed the cap: dropped without creating a node
        // (this is the `scp` upload + `cp` amplification path).
        assert_eq!(fs.add_file(root, "b", big.clone(), 0o644, 0, 0), root);
        assert!(fs.child(root, "b").is_none());

        // Small writes still fit under the cap.
        fs.add_file(root, "c", &b"ok"[..], 0o644, 0, 0);
        assert!(fs.child(root, "c").is_some());

        // Overwriting `a` with empty contents frees its budget for new writes.
        assert_eq!(fs.add_file(root, "a", Vec::new(), 0o644, 0, 0), a);
        fs.add_file(root, "b", big, 0o644, 0, 0);
        assert!(fs.child(root, "b").is_some());
    }

    #[test]
    fn unlink_detaches_child() {
        let mut fs = fixture();
        let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
        assert!(fs.child(tmp, "a").is_some());
        assert!(fs.unlink(tmp, "a").is_some());
        assert!(fs.child(tmp, "a").is_none());
    }

    #[test]
    fn rename_moves_node() {
        let mut fs = fixture();
        let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
        let a = fs.child(tmp, "a").unwrap();
        let d = fs.child(tmp, "d").unwrap();
        assert!(fs.rename(a, d, "b"));
        assert!(fs.child(tmp, "a").is_none());
        assert_eq!(fs.resolve(fs.root(), "/tmp/d/b"), Some(a));
        assert_eq!(fs.path_of(a), "/tmp/d/b");
    }

    #[test]
    fn deep_copy_duplicates_subtree() {
        let mut fs = fixture();
        let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
        let d = fs.child(tmp, "d").unwrap();
        let copy = fs.deep_copy(d, tmp, "d2");
        assert_ne!(copy, d);
        let orig_inner = fs.resolve(fs.root(), "/tmp/d/inner").unwrap();
        let copy_inner = fs.resolve(fs.root(), "/tmp/d2/inner").unwrap();
        assert_ne!(orig_inner, copy_inner);
        if let NodeKind::File { contents } = &fs.node(copy_inner).kind {
            assert_eq!(contents, b"x");
        } else {
            panic!("expected file");
        }
    }

    #[test]
    fn chmod_preserves_file_type() {
        let mut fs = fixture();
        let a = fs.resolve(fs.root(), "/tmp/a").unwrap();
        fs.chmod(a, 0o600);
        let mode = fs.node(a).meta.mode;
        assert_eq!(mode & 0o7777, 0o600);
        assert_eq!(mode & nodes::S_IFMT, S_IFREG);
    }

    #[test]
    fn touch_creates_then_updates() {
        let mut fs = fixture();
        let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
        let id = fs.touch(tmp, "fresh", 0, 0);
        assert_eq!(fs.child(tmp, "fresh"), Some(id));
        // Touch again returns the same node.
        assert_eq!(fs.touch(tmp, "fresh", 0, 0), id);
    }
}
