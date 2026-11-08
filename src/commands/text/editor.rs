use std::iter;

use super::newline_terminated;
use crate::commands::CommandResult;
use crate::shell::{Screen, Shell};

/// Visible buffer rows before the status/footer line(s) — `vi`/`nano` fill
/// unused rows with `~`/blank lines up to here. Like
/// [`TopScreen`](crate::commands::system::TopScreen), this has no real
/// awareness of the client's terminal height (`pty-req`'s rows never reach this
/// layer); it targets a plausible common size rather than the one the client
/// asked for.
const EDITOR_ROWS: usize = 23;

const VI_EMPTY_ROW: &str = "~";
const NANO_EMPTY_ROW: &str = "";
const NANO_UNNAMED_TITLE: &str = "New Buffer";
const NANO_SHORTCUTS: &str =
    "^G Help      ^O Write Out ^W Where Is  ^K Cut       ^T Execute   ^C Location\n\
     ^X Exit      ^R Read File ^\\ Replace   ^U Paste     ^J Justify   ^_ Go To Line\n";

/// Which editor a [`EditorScreen`] renders as. The two use unrelated layouts
/// and quit keys, but share everything else about being a screen-holding
/// read-only stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorKind {
    Vi,
    Nano,
}

/// One `vi`/`nano` display: a read-only view of the file it was invoked on
/// (or a blank buffer for a bare invocation), held until the client quits it.
///
/// ponytail: read-only — no keystroke inserts text, and nothing is ever
/// written back to the VFS, so `i`nsert mode, `^O` (Write Out) and `:wq` save
/// nothing (they still quit; see the network layer's quit handling). Upgrade
/// to a real per-keystroke buffer if a payload dropped through an editor
/// rather than `wget`/`cat <<EOF` turns out to matter.
#[derive(Clone)]
pub struct EditorScreen {
    kind: EditorKind,
    path: String,
    lines: Vec<String>,
    exists: bool,
}

impl EditorScreen {
    /// Which editor this is. `vi` and `nano` render and quit differently, and
    /// the network layer needs to know which without holding this whole value
    /// (see `network::ssh::ScreenHold`).
    pub fn kind(&self) -> EditorKind {
        self.kind
    }

    /// Render the whole display as of now. It never changes after this — see
    /// this type's `ponytail` note — so, unlike `top`, nothing ever calls this
    /// twice for one hold.
    pub fn render(&self) -> String {
        match self.kind {
            EditorKind::Vi => self.render_vi(),
            EditorKind::Nano => self.render_nano(),
        }
    }

    fn unnamed(kind: EditorKind) -> Self {
        EditorScreen {
            kind,
            path: String::new(),
            lines: Vec::new(),
            exists: false,
        }
    }

    fn buffer_rows(&self, empty_row: &str) -> String {
        let shown = &self.lines[..self.lines.len().min(EDITOR_ROWS)];
        let padding = iter::repeat_n(empty_row, EDITOR_ROWS - shown.len());
        newline_terminated(shown.iter().map(String::as_str).chain(padding))
    }

    fn render_vi(&self) -> String {
        let mut out = self.buffer_rows(VI_EMPTY_ROW);
        // A bare `vi` opens an unnamed buffer; real vi's status line stays
        // blank until the buffer is named with `:w file`.
        if !self.path.is_empty() {
            out.push_str(&self.vi_status_line());
        }
        out
    }

    fn vi_status_line(&self) -> String {
        if !self.exists {
            return format!("\"{}\" [New File]\n", self.path);
        }
        let bytes: usize = self.lines.iter().map(|l| l.len() + 1).sum();
        format!("\"{}\" {}L, {}B\n", self.path, self.lines.len(), bytes)
    }

    fn render_nano(&self) -> String {
        let title = if self.path.is_empty() {
            NANO_UNNAMED_TITLE
        } else {
            &self.path
        };
        // No version number: real nano always shows one, but a wrong one
        // (unverifiable against the actual bookworm package) is a sharper
        // fingerprint than a missing one — see `USR_BIN`'s doc comment on not
        // inventing details this box cannot source.
        let mut out = format!("  GNU nano    {title}\n");
        out.push_str(&self.buffer_rows(NANO_EMPTY_ROW));
        out.push_str(NANO_SHORTCUTS);
        out
    }
}

/// Build the [`EditorScreen`] for `vi`/`nano FILE`, reading the target from
/// the VFS the same way `cat` does. `None` is a bare invocation with no
/// operand: an unnamed, empty buffer.
fn open_editor(shell: &Shell, kind: EditorKind, arg: Option<&str>) -> EditorScreen {
    let Some(arg) = arg else {
        return EditorScreen::unnamed(kind);
    };
    let node = shell.vfs.resolve(shell.cwd, arg);
    let lines = node
        .and_then(|id| shell.vfs.node(id).file_bytes())
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    EditorScreen {
        kind,
        path: arg.to_string(),
        lines,
        exists: node.is_some(),
    }
}

/// Shared body of [`vi`] and [`nano`]: takes the terminal only on an
/// interactive PTY, the same gate `top` uses. There is no real full-screen
/// editor behaviour for a pipe or a one-shot `exec` to fall back to, so those
/// get nothing, exactly like any other listed-but-unimplemented binary (see
/// `vfs::snapshot::USR_BIN`'s doc comment).
fn open_screen(shell: &mut Shell, kind: EditorKind, args: &[String]) -> CommandResult {
    if !(shell.interactive && shell.stdout_is_tty) {
        return CommandResult::empty();
    }
    let arg = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    let screen = open_editor(shell, kind, arg);
    shell.screen = Some(Screen::Editor(screen));
    CommandResult::empty()
}

/// `vi [FILE]` — see [`open_screen`].
pub fn vi(shell: &mut Shell, args: &[String]) -> CommandResult {
    open_screen(shell, EditorKind::Vi, args)
}

/// `nano [FILE]` — see [`open_screen`].
pub fn nano(shell: &mut Shell, args: &[String]) -> CommandResult {
    open_screen(shell, EditorKind::Nano, args)
}
