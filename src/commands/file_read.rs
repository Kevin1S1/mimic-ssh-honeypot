use std::borrow::Cow;

use crate::shell::Shell;

pub(crate) enum ReadFailure {
    Missing,
    Denied,
    Directory,
    NotRegular,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Checked,
    Unchecked,
}

pub(crate) fn read_vfs_file<'a>(
    shell: &'a Shell,
    path: &str,
    access: Access,
) -> Result<Cow<'a, [u8]>, ReadFailure> {
    let id = shell
        .vfs
        .resolve(shell.cwd, path)
        .ok_or(ReadFailure::Missing)?;
    let node = shell.vfs.node(id);
    if access == Access::Checked && !node.meta.readable_by(shell.uid, shell.gid) {
        return Err(ReadFailure::Denied);
    }
    node.file_bytes().ok_or(if node.meta.is_dir() {
        ReadFailure::Directory
    } else {
        ReadFailure::NotRegular
    })
}

impl ReadFailure {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            ReadFailure::Missing => "No such file or directory",
            ReadFailure::Denied => "Permission denied",
            ReadFailure::Directory | ReadFailure::NotRegular => "Is a directory",
        }
    }
}
