use super::{nodes, now_ts, NodeId, NodeKind, Vfs, MAX_COPY_DEPTH, MAX_VFS_DEPTH};

impl Vfs {
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
