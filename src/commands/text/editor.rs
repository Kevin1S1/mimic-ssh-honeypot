use std::iter;

use super::newline_terminated;
use crate::commands::CommandResult;
use crate::shell::{Screen, Shell};

const EDITOR_ROWS: usize = 23;

const VI_EMPTY_ROW: &str = "~";
const NANO_EMPTY_ROW: &str = "";
const NANO_UNNAMED_TITLE: &str = "New Buffer";
const NANO_SHORTCUTS: &str =
    "^G Help      ^O Write Out ^W Where Is  ^K Cut       ^T Execute   ^C Location\n\
     ^X Exit      ^R Read File ^\\ Replace   ^U Paste     ^J Justify   ^_ Go To Line\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorKind {
    Vi,
    Nano,
}

#[derive(Clone)]
pub struct EditorScreen {
    kind: EditorKind,
    path: String,
    lines: Vec<String>,
    exists: bool,
}

impl EditorScreen {
    pub fn kind(&self) -> EditorKind {
        self.kind
    }

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

        let mut out = format!("  GNU nano    {title}\n");
        out.push_str(&self.buffer_rows(NANO_EMPTY_ROW));
        out.push_str(NANO_SHORTCUTS);
        out
    }
}

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

pub fn vi(shell: &mut Shell, args: &[String]) -> CommandResult {
    open_screen(shell, EditorKind::Vi, args)
}

pub fn nano(shell: &mut Shell, args: &[String]) -> CommandResult {
    open_screen(shell, EditorKind::Nano, args)
}
