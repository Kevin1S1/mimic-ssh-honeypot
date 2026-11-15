mod create;
mod lookup;
mod mutate;
pub mod nodes;
pub mod snapshot;

pub use nodes::{Metadata, Node, NodeId, NodeKind, S_IFDIR, S_IFLNK, S_IFREG};

use std::collections::BTreeMap;

pub const DEFAULT_FILE_MODE: u32 = 0o644;

const MAX_SYMLINK_DEPTH: usize = 40;

const MAX_VFS_NODES: usize = 2_000;

const MAX_VFS_BYTES: usize = 8 * 1024 * 1024;

const MAX_VFS_DEPTH: usize = 128;

const MAX_COPY_DEPTH: usize = 64;

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
}

fn now_ts() -> i64 {
    crate::clock::now()
}

#[cfg(test)]
mod tests;
