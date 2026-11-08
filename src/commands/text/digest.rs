use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use super::{failure_status, split_args, stdin_text, vfs_file};
use crate::commands::CommandResult;
use crate::shell::Shell;

pub fn md5sum(shell: &Shell, args: &[String]) -> CommandResult {
    digest_command::<Md5>(shell, args, "md5sum")
}

pub fn sha1sum(shell: &Shell, args: &[String]) -> CommandResult {
    digest_command::<Sha1>(shell, args, "sha1sum")
}

pub fn sha256sum(shell: &Shell, args: &[String]) -> CommandResult {
    digest_command::<Sha256>(shell, args, "sha256sum")
}

pub fn sha512sum(shell: &Shell, args: &[String]) -> CommandResult {
    digest_command::<Sha512>(shell, args, "sha512sum")
}

fn hex_digest<D: Digest>(data: &[u8]) -> String {
    D::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn digest_command<D: Digest>(shell: &Shell, args: &[String], tool: &str) -> CommandResult {
    let (_, operands) = split_args(args);

    if operands.is_empty() {
        let text = stdin_text(shell);
        return CommandResult::ok(format!("{}  -\n", hex_digest::<D>(text.as_bytes())));
    }

    let mut out = String::new();
    let mut errs = String::new();
    for file in operands {
        match vfs_file(shell, tool, file) {
            Ok(bytes) => out.push_str(&format!("{}  {file}\n", hex_digest::<D>(&bytes))),
            Err(message) => errs.push_str(&message),
        }
    }
    let status = failure_status(&errs);
    CommandResult::streams(out, errs, status)
}
