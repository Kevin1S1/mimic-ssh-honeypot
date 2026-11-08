pub mod nodes;
pub mod snapshot;

pub use nodes::{Metadata, Node, NodeId, NodeKind, S_IFDIR, S_IFLNK, S_IFREG};

use std::collections::BTreeMap;

const MAX_SYMLINK_DEPTH: usize = 40;

const MAX_VFS_NODES: usize = 2_000;

const MAX_VFS_BYTES: usize = 8 * 1024 * 1024;

const MAX_VFS_DEPTH: usize = 128;

#[derive(Debug, Clone)]
pub struct Vfs {
    nodes: Vec<Node>,
    root: NodeId,

    content_bytes: usize,
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
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

    pub fn root(&self) -> NodeId {
        self.root
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

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

    fn follow(&self, id: NodeId, depth: usize) -> Option<NodeId> {
        match &self.nodes[id].kind {
            NodeKind::Symlink { target } => {
                let parent = self.nodes[id].parent.unwrap_or(self.root);
                self.resolve_inner(parent, target, depth + 1)
            }
            _ => Some(id),
        }
    }

    pub fn child(&self, dir: NodeId, name: &str) -> Option<NodeId> {
        match &self.nodes[dir].kind {
            NodeKind::Directory { children } => children.get(name).copied(),
            _ => None,
        }
    }

    pub fn entries(&self, id: NodeId) -> Option<Vec<(String, NodeId)>> {
        match &self.nodes[id].kind {
            NodeKind::Directory { children } => {
                Some(children.iter().map(|(k, v)| (k.clone(), *v)).collect())
            }
            _ => None,
        }
    }

    pub fn path_of(&self, id: NodeId) -> String {
        let mut parts = Vec::new();
        let mut current = id;

        for _ in 0..self.nodes.len() {
            let Some(parent) = self.nodes[current].parent else {
                break;
            };
            parts.push(self.nodes[current].name.clone());
            current = parent;
        }
        if parts.is_empty() {
            return "/".to_string();
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    pub fn split_path(path: &str) -> (&str, &str) {
        match path.rfind('/') {
            Some(0) => ("/", &path[1..]),
            Some(i) => (&path[..i], &path[i + 1..]),
            None => (".", path),
        }
    }

    pub fn is_full(&self, parent: NodeId) -> bool {
        self.nodes.len() >= MAX_VFS_NODES || self.depth_of(parent) >= MAX_VFS_DEPTH
    }

    fn depth_of(&self, id: NodeId) -> usize {
        let mut depth = 0;
        let mut current = id;

        while let Some(parent) = self.nodes[current].parent {
            depth += 1;
            if depth > self.nodes.len() {
                break;
            }
            current = parent;
        }
        depth
    }

    fn height_of(&self, id: NodeId) -> usize {
        let mut height = 0;
        let mut stack = vec![(id, 0)];
        while let Some((node, h)) = stack.pop() {
            height = height.max(h);
            if let NodeKind::Directory { children } = &self.nodes[node].kind {
                stack.extend(children.values().map(|&child| (child, h + 1)));
            }
        }
        height
    }

    fn insert(&mut self, parent: NodeId, name: &str, kind: NodeKind, meta: Metadata) -> NodeId {
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
        let id = self.add_file(parent, name, Vec::new(), 0o644, uid, gid);
        self.nodes[id].meta.mtime = now;
        id
    }

    pub fn set_all_mtimes(&mut self, ts: i64) {
        for node in &mut self.nodes {
            node.meta.mtime = ts;
        }
    }

    pub fn chmod(&mut self, id: NodeId, perms: u32) {
        let file_type = self.nodes[id].meta.mode & nodes::S_IFMT;
        self.nodes[id].meta.mode = file_type | (perms & 0o7777);
    }

    pub fn chown(&mut self, id: NodeId, uid: u32, gid: u32) {
        self.nodes[id].meta.uid = uid;
        self.nodes[id].meta.gid = gid;
    }

    pub fn set_mtime(&mut self, id: NodeId, mtime: i64) {
        self.nodes[id].meta.mtime = mtime;
    }

    pub fn unlink(&mut self, parent: NodeId, name: &str) -> Option<NodeId> {
        match &mut self.nodes[parent].kind {
            NodeKind::Directory { children } => children.remove(name),
            _ => None,
        }
    }

    pub fn is_ancestor_of(&self, id: NodeId, other: NodeId) -> bool {
        let mut current = Some(other);

        for _ in 0..self.nodes.len() {
            match current {
                Some(c) if c == id => return true,
                Some(c) => current = self.nodes[c].parent,
                None => return false,
            }
        }

        true
    }

    pub fn rename(&mut self, id: NodeId, new_parent: NodeId, new_name: &str) -> bool {
        if !matches!(self.nodes[new_parent].kind, NodeKind::Directory { .. }) {
            return false;
        }

        if self.is_ancestor_of(id, new_parent) {
            return false;
        }

        if self.depth_of(new_parent) + 1 + self.height_of(id) > MAX_VFS_DEPTH {
            return false;
        }

        if let Some(old_parent) = self.nodes[id].parent {
            let old_name = self.nodes[id].name.clone();
            if let NodeKind::Directory { children } = &mut self.nodes[old_parent].kind {
                children.remove(&old_name);
            }
        }

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
            NodeKind::DynamicFile { generator } => self.add_dynamic_file(
                dst_parent,
                dst_name,
                generator,
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

fn now_ts() -> i64 {
    crate::clock::now()
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

        assert_eq!(fs.resolve(tmp, "d/inner"), fs.resolve(root, "/tmp/d/inner"));

        assert_eq!(
            fs.resolve(root, "/tmp/./d/"),
            Some(fs.child(tmp, "d").unwrap())
        );

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

        fs.add_symlink(root, "link", "/tmp/d");
        let via_link = fs.resolve(root, "/link/inner").unwrap();
        let direct = fs.resolve(root, "/tmp/d/inner").unwrap();
        assert_eq!(via_link, direct);
    }

    #[test]
    fn symlink_loop_terminates() {
        let mut fs = fixture();
        let root = fs.root();

        fs.add_symlink(root, "a", "/b");
        fs.add_symlink(root, "b", "/a");
        assert_eq!(fs.resolve(root, "/a"), None);
    }

    #[test]
    fn dotdot_clamps_at_root() {
        let fs = fixture();
        let root = fs.root();

        assert_eq!(fs.resolve(root, "/../../.."), Some(root));
        assert_eq!(fs.resolve(root, "/tmp/../.."), Some(root));
    }

    #[test]
    fn mkdir_p_creates_and_reuses_chain() {
        let mut fs = fixture();
        let made = fs.mkdir_p("/var/log/app", 0o755, 0, 0);
        assert_eq!(fs.resolve(fs.root(), "/var/log/app"), made);

        let again = fs.mkdir_p("/var/log/app", 0o755, 0, 0);
        assert_eq!(again, made);
    }

    #[test]
    fn mkdir_p_reports_failure_instead_of_an_ancestor() {
        let mut fs = Vfs::new();
        let root = fs.root();
        while fs.nodes.len() < MAX_VFS_NODES {
            fs.mkdir(root, &format!("d{}", fs.nodes.len()), 0o755, 0, 0);
        }

        assert_eq!(fs.mkdir_p("/srv/deep/tree", 0o755, 0, 0), None);
        assert!(fs.resolve(root, "/srv").is_none());
    }

    #[test]
    fn node_cap_bounds_allocation() {
        let mut fs = Vfs::new();
        let root = fs.root();

        for i in 0..(MAX_VFS_NODES + 50) {
            fs.add_file(root, &format!("f{i}"), &b""[..], 0o644, 0, 0);
        }
        assert!(fs.nodes.len() <= MAX_VFS_NODES);
    }

    #[test]
    fn depth_cap_bounds_tree_depth() {
        let mut fs = Vfs::new();
        let mut current = fs.root();
        for _ in 0..MAX_VFS_DEPTH + 10 {
            current = fs.mkdir(current, "a", 0o755, 0, 0);
        }
        assert_eq!(fs.depth_of(current), MAX_VFS_DEPTH);
        assert!(fs.is_full(current));
        assert!(fs
            .mkdir_p(&"/b".repeat(MAX_VFS_DEPTH + 1), 0o755, 0, 0)
            .is_none());
    }

    #[test]
    fn rename_refuses_to_stack_chains_past_the_depth_cap() {
        let mut fs = Vfs::new();
        let root = fs.root();
        let half = MAX_VFS_DEPTH / 2 + 1;
        let top = fs.mkdir_p(&"/x".repeat(half), 0o755, 0, 0).unwrap();
        fs.mkdir_p(&"/y".repeat(half), 0o755, 0, 0).unwrap();
        let y = fs.child(root, "y").unwrap();

        assert!(!fs.rename(y, top, "y"));
        assert_eq!(fs.child(root, "y"), Some(y));
        let x = fs.child(root, "x").unwrap();
        assert!(fs.rename(x, y, "x"), "a move that fits is still allowed");
    }

    #[test]
    fn byte_cap_bounds_total_content() {
        let mut fs = Vfs::new();
        let root = fs.root();
        let big = vec![0u8; MAX_VFS_BYTES / 2 + 1];

        let a = fs.add_file(root, "a", big.clone(), 0o644, 0, 0);
        assert!(fs.child(root, "a").is_some());

        assert_eq!(fs.add_file(root, "b", big.clone(), 0o644, 0, 0), root);
        assert!(fs.child(root, "b").is_none());

        fs.add_file(root, "c", &b"ok"[..], 0o644, 0, 0);
        assert!(fs.child(root, "c").is_some());

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
    fn rename_refuses_move_into_own_subtree() {
        let mut fs = fixture();
        let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
        let d = fs.child(tmp, "d").unwrap();

        assert!(!fs.rename(tmp, d, "tmp"), "cyclic move must be refused");

        assert!(!fs.rename(tmp, tmp, "tmp"));

        assert_eq!(fs.child(fs.root(), "tmp"), Some(tmp));
        assert_eq!(fs.path_of(d), "/tmp/d");

        let a = fs.child(tmp, "a").unwrap();
        assert!(fs.rename(a, d, "a"));
        assert_eq!(fs.path_of(a), "/tmp/d/a");
    }

    #[test]
    fn path_of_terminates_for_every_node() {
        let fs = fixture();
        for id in 0..fs.nodes.len() {
            let path = fs.path_of(id);
            assert!(path.starts_with('/'));
        }
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

        assert_eq!(fs.touch(tmp, "fresh", 0, 0), id);
    }
}
