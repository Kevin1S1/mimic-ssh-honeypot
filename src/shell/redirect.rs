use super::parser::{Redirect, Stream, Target};
use super::{Shell, REGULAR_FILE_MODE};
use crate::commands::{self, CommandResult};
use crate::vfs::NodeId;

/// The bit bucket. Writes to it are discarded instead of filling the VFS —
/// `> /dev/null` is in most bot payloads, and a real one never grows.
const DEV_NULL: &str = "/dev/null";

const NO_SUCH_FILE: &str = "No such file or directory";
const IS_A_DIRECTORY: &str = "Is a directory";
const PERMISSION_DENIED: &str = "Permission denied";
const NO_SPACE_LEFT: &str = "No space left on device";
const AMBIGUOUS_REDIRECT: &str = "ambiguous redirect";

const WRITE_FAILURE_STATUS: i32 = 1;

fn bash_error(path: &str, reason: &str) -> String {
    format!("-bash: {path}: {reason}\n")
}

/// An opened redirect target: where a stream's output goes, and whether it adds
/// to what is already there.
#[derive(Debug, Clone)]
struct Sink {
    /// The expanded target path, for error messages.
    path: String,
    /// The node the output lands in, fixed when the target was opened. `None`
    /// is `/dev/null`.
    node: Option<NodeId>,
    /// `>>`: keep the existing contents.
    append: bool,
}

/// Which sink each of a stage's output streams was pointed at. `None` means the
/// stream still reaches the client.
#[derive(Debug, Default)]
pub(super) struct Sinks {
    /// Target for `>`, `1>`, and the stdout half of `&>`.
    stdout: Option<Sink>,
    /// Target for `2>` and the stderr half of `&>`.
    stderr: Option<Sink>,
    /// `2>&1` while stdout was still the terminal: the two share one
    /// descriptor, so what the command writes to stderr comes back to the
    /// client on stdout — which is what puts it in the pipe that
    /// `cmd 2>&1 | grep` is built around.
    stderr_merged: bool,
    /// `>&2`/`1>&2`, the mirror case.
    stdout_merged: bool,
}

impl Sinks {
    pub(super) fn stdout_reaches_client(&self) -> bool {
        self.stdout.is_none()
    }

    /// Redirects apply left to right, so a later one pointing the same
    /// stream at a file undoes an earlier dup — which is the whole
    /// difference between `> f 2>&1` and `2>&1 > f`.
    fn point(&mut self, stream: Stream, sink: Option<Sink>, merged: bool) {
        if matches!(stream, Stream::Stdout | Stream::Both) {
            self.stdout = sink.clone();
            self.stdout_merged = merged;
        }
        if matches!(stream, Stream::Stderr | Stream::Both) {
            self.stderr = sink;
            self.stderr_merged = merged;
        }
    }

    /// A stream duplicated onto one still reaching the client comes back on
    /// that one instead, so `2>&1` puts the error where a pipe can see it.
    fn merge_onto_client(&self, result: &mut CommandResult) {
        if self.stderr_merged {
            let mut merged = std::mem::take(&mut result.stderr);
            merged.push_str(&result.output);
            result.output = merged;
        }
        if self.stdout_merged {
            let stdout = std::mem::take(&mut result.output);
            result.stderr.push_str(&stdout);
        }
    }
}

impl Shell {
    /// Create or truncate every redirect target, resolving which sink each
    /// stream ends up pointing at. Returns the bash error text for the first
    /// target that cannot be opened.
    pub(super) fn open_redirects(&mut self, redirects: &[Redirect]) -> Result<Sinks, String> {
        let mut sinks = Sinks::default();
        for redirect in redirects {
            // `>&1` and `2>&2` point a stream at itself, which changes nothing.
            if matches!(&redirect.target, Target::Dup(s) if *s == redirect.stream) {
                continue;
            }
            let (sink, merged) = match &redirect.target {
                Target::File { path, append } => (Some(self.open_file_sink(path, *append)?), false),
                // A dup against a stream that is still the terminal cannot be
                // resolved to a sink: it means "come back on that stream
                // instead", which only the routing below can honour.
                Target::Dup(Stream::Stdout) => (sinks.stdout.clone(), sinks.stdout.is_none()),
                // The parser only builds `Dup` from descriptor 1 or 2.
                Target::Dup(_) => (sinks.stderr.clone(), sinks.stderr.is_none()),
            };
            sinks.point(redirect.stream, sink, merged);
        }
        Ok(sinks)
    }

    /// The target word is expanded like any other, so `> $HOME/f` and
    /// `> "my file"` land where bash puts them. An unset or multi-word target
    /// is a redirect bash cannot resolve to one file, and it says so.
    fn open_file_sink(&mut self, word: &str, append: bool) -> Result<Sink, String> {
        let mut words = self.parse_line(word);
        if words.len() != 1 {
            return Err(bash_error(word, AMBIGUOUS_REDIRECT));
        }
        let path = words.remove(0);
        let node = self.open_redirect(&path, append)?;
        Ok(Sink { path, node, append })
    }

    /// Create `path` if it is missing and truncate it unless `append`, the way
    /// opening a redirect target does, without writing anything yet. Returns
    /// the node the write will land in — `None` for `/dev/null` — so the write
    /// goes where the open did even if the command moves the working directory
    /// out from under the path, exactly as an already-open descriptor does.
    fn open_redirect(&mut self, path: &str, append: bool) -> Result<Option<NodeId>, String> {
        let (parent, name) = commands::fs::resolve_parent(self, path)
            .ok_or_else(|| bash_error(path, NO_SUCH_FILE))?;
        match self.vfs.child(parent, &name) {
            Some(existing) => self.reopen_existing(existing, path, append),
            None => self.create_target(parent, &name, path).map(Some),
        }
    }

    fn reopen_existing(
        &mut self,
        existing: NodeId,
        path: &str,
        append: bool,
    ) -> Result<Option<NodeId>, String> {
        // Matched by node, not by path, so `cd /dev && echo x > null` is
        // swallowed too rather than filling the bit bucket up.
        if Some(existing) == self.vfs.resolve(self.vfs.root(), DEV_NULL) {
            return Ok(None);
        }
        let meta = &self.vfs.node(existing).meta;
        if meta.is_dir() {
            return Err(bash_error(path, IS_A_DIRECTORY));
        }
        if !meta.writable_by(self.uid, self.gid) {
            return Err(bash_error(path, PERMISSION_DENIED));
        }
        if !append && !self.vfs.write_file(existing, &[], false) {
            return Err(bash_error(path, NO_SPACE_LEFT));
        }
        Ok(Some(existing))
    }

    fn create_target(&mut self, parent: NodeId, name: &str, path: &str) -> Result<NodeId, String> {
        if !self.vfs.node(parent).meta.writable_by(self.uid, self.gid) {
            return Err(bash_error(path, PERMISSION_DENIED));
        }
        let (uid, gid) = (self.uid, self.gid);
        let id = self
            .vfs
            .add_file(parent, name, Vec::new(), REGULAR_FILE_MODE, uid, gid);
        if id == parent {
            // The node cap refused the file; say so rather than reporting a
            // write that never happened.
            return Err(bash_error(path, NO_SPACE_LEFT));
        }
        Ok(id)
    }

    /// Send each of a command's streams to whichever sink it was redirected
    /// to, returning what is left for the client.
    pub(super) fn route_output(
        &mut self,
        mut result: CommandResult,
        sinks: &Sinks,
    ) -> CommandResult {
        // The streams go out in the order [`Output::push`] shows them, so
        // `> f 2>&1` — where both descriptors are dups of one open file — puts
        // the same bytes in the file that a terminal would have shown, and the
        // second write follows the first rather than truncating it, exactly as
        // one shared file offset does.
        let mut written = None;
        let mut failure = None;
        if let Some(sink) = sinks.stderr.as_ref() {
            let text = std::mem::take(&mut result.stderr);
            failure = self.divert(sink, &text, &mut written);
        }
        if let Some(sink) = sinks.stdout.as_ref() {
            let text = std::mem::take(&mut result.output);
            failure = self.divert(sink, &text, &mut written).or(failure);
        }
        // A refused write is reported to the client, like a full disk.
        if let Some(message) = failure {
            result.stderr.push_str(&message);
            result.status = WRITE_FAILURE_STATUS;
        }
        sinks.merge_onto_client(&mut result);
        result
    }

    /// Write one stream into its sink, recording the node it landed in so a
    /// second stream pointed at the same file appends after it instead of
    /// truncating what the first one wrote.
    fn divert(&mut self, sink: &Sink, text: &str, written: &mut Option<NodeId>) -> Option<String> {
        if text.is_empty() {
            return None;
        }
        let append = sink.append || (sink.node.is_some() && sink.node == *written);
        *written = sink.node;
        self.write_redirect(sink, text.as_bytes(), append).err()
    }

    /// Write `data` into an already-opened sink. A sink with no node is
    /// `/dev/null`, which swallows it.
    fn write_redirect(&mut self, sink: &Sink, data: &[u8], append: bool) -> Result<(), String> {
        let Some(node) = sink.node else {
            return Ok(());
        };
        if !self.vfs.write_file(node, data, append) {
            return Err(bash_error(&sink.path, NO_SPACE_LEFT));
        }
        Ok(())
    }
}
