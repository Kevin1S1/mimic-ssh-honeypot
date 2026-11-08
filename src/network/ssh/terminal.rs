use crate::shell::Shell;

pub(super) const CTRL_C: u8 = 0x03;
pub(super) const BACKSPACE: u8 = 0x08;
pub(super) const CTRL_X: u8 = 0x18;
pub(super) const ESC: u8 = 0x1b;
pub(super) const DELETE: u8 = 0x7f;
/// What the client asked for in `pty-req`, kept so the session environment can
/// reflect it rather than inventing a terminal the client never requested.
pub(super) struct PtyRequest {
    pub(super) term: String,
    pub(super) cols: u32,
    pub(super) rows: u32,
}

pub(super) const DEFAULT_COLS: u32 = 80;
pub(super) const DEFAULT_ROWS: u32 = 24;
pub(super) const MAX_TERMINAL_DIMENSION: u32 = 10_000;

impl PtyRequest {
    pub(super) fn export_size(&self, shell: &mut Shell) {
        shell.env.set("COLUMNS", &self.cols.to_string());
        shell.env.set("LINES", &self.rows.to_string());
    }
}

pub(super) fn terminal_dimension(requested: u32, fallback: u32) -> u32 {
    if requested == 0 {
        fallback
    } else {
        requested.min(MAX_TERMINAL_DIMENSION)
    }
}

pub(super) const MAX_ACCEPTED_ENV: usize = 32;
pub(super) const MAX_TERM_LEN: usize = 64;
pub(super) const MAX_ENV_VALUE_LEN: usize = 256;
pub(super) const FALLBACK_TERM: &str = "xterm-256color";

pub(super) fn is_locale_variable(name: &str) -> bool {
    name == "LANG" || name.starts_with("LC_")
}

/// Keep only what a terminal name can legally hold, bounded.
///
/// `TERM` is attacker-controlled and reaches `env` output, so it is restricted
/// to the character class terminfo names actually use. An empty or hostile value
/// falls back to what a client that sent nothing would get.
pub(super) fn sanitise_term(term: &str) -> String {
    let cleaned: String = term
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
        .take(MAX_TERM_LEN)
        .collect();
    if cleaned.is_empty() {
        FALLBACK_TERM.to_string()
    } else {
        cleaned
    }
}

/// Strip control characters from an accepted `env` value and bound its length.
///
/// `Env::set` bounds length too, but a locale value reaches the terminal through
/// `env`/`printenv` output, so escape sequences come out here rather than at the
/// far end.
pub(super) fn sanitise_env_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ENV_VALUE_LEN)
        .collect()
}

/// Lay candidate strings out in newline-separated columns the way bash prints
/// ambiguous completions. Kept simple: a single space-padded grid.
pub(super) fn format_columns(items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let width = items.iter().map(String::len).max().unwrap_or(0) + 2;
    let cols = (80 / width).max(1);
    let mut out = String::new();
    for (i, item) in items.iter().enumerate() {
        out.push_str(item);
        if (i + 1) % cols == 0 || i + 1 == items.len() {
            out.push('\n');
        } else {
            for _ in item.len()..width {
                out.push(' ');
            }
        }
    }
    out
}
