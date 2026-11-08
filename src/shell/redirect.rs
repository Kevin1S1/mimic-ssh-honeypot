use super::parser::{Redirect, Stream, Target};
use super::{Shell, REGULAR_FILE_MODE};
use crate::commands::{self, CommandResult};
use crate::vfs::NodeId;

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

#[derive(Debug, Clone)]
struct Sink {
    path: String,

    node: Option<NodeId>,

    append: bool,
}

#[derive(Debug, Default)]
pub(super) struct Sinks {
    stdout: Option<Sink>,

    stderr: Option<Sink>,

    stderr_merged: bool,

    stdout_merged: bool,
}

impl Sinks {
    pub(super) fn stdout_reaches_client(&self) -> bool {
        self.stdout.is_none()
    }

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
    pub(super) fn open_redirects(&mut self, redirects: &[Redirect]) -> Result<Sinks, String> {
        let mut sinks = Sinks::default();
        for redirect in redirects {
            if matches!(&redirect.target, Target::Dup(s) if *s == redirect.stream) {
                continue;
            }
            let (sink, merged) = match &redirect.target {
                Target::File { path, append } => (Some(self.open_file_sink(path, *append)?), false),

                Target::Dup(Stream::Stdout) => (sinks.stdout.clone(), sinks.stdout.is_none()),

                Target::Dup(_) => (sinks.stderr.clone(), sinks.stderr.is_none()),
            };
            sinks.point(redirect.stream, sink, merged);
        }
        Ok(sinks)
    }

    fn open_file_sink(&mut self, word: &str, append: bool) -> Result<Sink, String> {
        let mut words = self.parse_line(word);
        if words.len() != 1 {
            return Err(bash_error(word, AMBIGUOUS_REDIRECT));
        }
        let path = words.remove(0);
        let node = self.open_redirect(&path, append)?;
        Ok(Sink { path, node, append })
    }

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
            return Err(bash_error(path, NO_SPACE_LEFT));
        }
        Ok(id)
    }

    pub(super) fn route_output(
        &mut self,
        mut result: CommandResult,
        sinks: &Sinks,
    ) -> CommandResult {
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

        if let Some(message) = failure {
            result.stderr.push_str(&message);
            result.status = WRITE_FAILURE_STATUS;
        }
        sinks.merge_onto_client(&mut result);
        result
    }

    fn divert(&mut self, sink: &Sink, text: &str, written: &mut Option<NodeId>) -> Option<String> {
        if text.is_empty() {
            return None;
        }
        let append = sink.append || (sink.node.is_some() && sink.node == *written);
        *written = sink.node;
        self.write_redirect(sink, text.as_bytes(), append).err()
    }

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
