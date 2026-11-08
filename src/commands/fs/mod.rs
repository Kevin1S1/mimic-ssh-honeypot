mod du;
mod find;
mod format;
mod grep;
mod ls;
mod mutate;
mod nav;
mod perms;
mod read;
mod stat;
mod tar;

use crate::shell::Shell;
use crate::vfs::{NodeId, Vfs};

pub use du::du;
pub use find::find;
pub(crate) use format::{format_time, gid_name, mode_string, node_size, uid_name};
pub use grep::grep;
pub use ls::ls;
pub use mutate::{cp, ln, mkdir, mv, rm, rmdir, touch};
pub use nav::{cd, pwd};
pub use perms::{chgrp, chmod, chown};
pub use read::{cat, head, tail, wc};
pub use stat::stat;
pub use tar::tar;

fn strip_trailing_slashes(p: &str) -> &str {
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        "/"
    } else {
        trimmed
    }
}

pub(crate) fn resolve_parent(shell: &Shell, path: &str) -> Option<(NodeId, String)> {
    let path = strip_trailing_slashes(path);
    let (dir, name) = Vfs::split_path(path);
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    let parent = shell.vfs.resolve(shell.cwd, dir)?;
    if !shell.vfs.node(parent).meta.is_dir() {
        return None;
    }
    Some((parent, name.to_string()))
}

fn basename(path: &str) -> &str {
    Vfs::split_path(strip_trailing_slashes(path)).1
}
