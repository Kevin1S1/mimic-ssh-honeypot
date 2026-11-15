use super::{NodeId, NodeKind, Vfs, MAX_SYMLINK_DEPTH};

impl Vfs {
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
}
