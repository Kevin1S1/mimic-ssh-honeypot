//! Interactive line editor (readline-like) for the emulated PTY shell.
//!
//! A real OpenSSH login runs bash with GNU readline, so attackers expect
//! cursor movement, kill/yank keys, command history (↑/↓), and incremental
//! reverse-search (Ctrl-R). A honeypot that only echoes characters and handles
//! backspace is trivially distinguishable. This module reproduces the common
//! readline keybindings as a **pure state machine**: it consumes input bytes
//! and produces the bytes to echo back, never touching real I/O.
//!
//! **Security:** the buffer and history are bounded (`max_line`, `max_history`)
//! so a malicious client cannot drive unbounded memory growth through the line
//! editor. Printable ASCII and the bytes of non-ASCII characters are buffered
//! verbatim — a UTF-8 payload has to reach the log the way it was typed —
//! while everything else is interpreted as an editing command or ignored.

use std::collections::VecDeque;

const ESC: u8 = 0x1b;

/// What the network layer should do after feeding a byte to the editor.
#[derive(Debug, PartialEq, Eq)]
pub enum Reaction {
    /// Nothing to send; keep editing.
    Ignore,
    /// Write these bytes to the client, keep editing.
    Write(Vec<u8>),
    /// The user pressed Enter. `echo` (a CRLF) has already been emitted to the
    /// client; the caller should run `line`, print its output, then call
    /// [`LineEditor::render`] to draw the next prompt.
    Submit { echo: Vec<u8>, line: String },
    /// Ctrl-D on an empty line: the caller should close the session.
    Eof,
    /// Tab was pressed; the caller should compute completions for the current
    /// word and call [`LineEditor::current_word`] / [`LineEditor::apply_completion`]
    /// / [`LineEditor::show_listing`].
    Complete,
}

/// ANSI escape-sequence parser state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Esc {
    /// Not currently in an escape sequence.
    None,
    /// Saw `ESC`, awaiting `[` / `O` or a final byte.
    Got,
    /// Saw `ESC [` (CSI), accumulating numeric parameters.
    Csi,
}

/// Incremental reverse-search (Ctrl-R) state.
struct Search {
    /// The query typed so far.
    query: Vec<u8>,
    /// Index into history of the current match, if any.
    matched: Option<usize>,
}

/// A bounded, readline-style single-line editor.
pub struct LineEditor {
    prompt: Vec<u8>,
    buf: Vec<u8>,
    /// Cursor position as a byte index into `buf`. Screen columns are counted
    /// separately, since a non-ASCII character spans several bytes.
    cursor: usize,
    /// Text removed by the last kill (Ctrl-U/K/W), waiting for Ctrl-Y.
    ///
    /// ponytail: one slot, not readline's kill ring — consecutive kills replace
    /// rather than accumulate; upgrade when a probe uses Meta-Y or stacked kills.
    kill: Vec<u8>,
    history: VecDeque<String>,
    /// When browsing history, the index into `history` currently shown.
    hist_pos: Option<usize>,
    /// The in-progress line stashed while browsing history.
    stash: Vec<u8>,
    esc: Esc,
    csi_params: Vec<u8>,
    search: Option<Search>,
    max_line: usize,
    max_history: usize,
}

impl LineEditor {
    /// Create an editor with the given resource caps.
    pub fn new(max_line: usize, max_history: usize) -> Self {
        Self {
            prompt: Vec::new(),
            buf: Vec::new(),
            cursor: 0,
            kill: Vec::new(),
            history: VecDeque::new(),
            hist_pos: None,
            stash: Vec::new(),
            esc: Esc::None,
            csi_params: Vec::new(),
            search: None,
            max_line,
            max_history,
        }
    }

    /// Set the prompt string drawn before the editable line.
    pub fn set_prompt(&mut self, prompt: &str) {
        self.prompt = prompt.as_bytes().to_vec();
    }

    /// Bytes that draw the prompt and (empty) line. Used for the first prompt
    /// and after every submitted command.
    pub fn render(&self) -> Vec<u8> {
        self.redraw()
    }

    /// The word under/just-before the cursor and whether it is the first word
    /// on the line (i.e. a command-name position rather than an argument).
    pub fn current_word(&self) -> (String, bool) {
        let start = self.word_start();
        let word = String::from_utf8_lossy(&self.buf[start..self.cursor]).into_owned();
        let is_command = self.buf[..start].iter().all(|b| b.is_ascii_whitespace());
        (word, is_command)
    }

    /// Replace the current word with `replacement`, optionally appending a
    /// trailing space (done when a completion is unambiguous). Returns the
    /// bytes to write to the client.
    pub fn apply_completion(&mut self, replacement: &str, add_space: bool) -> Vec<u8> {
        let start = self.word_start();
        let mut tail = self.buf.split_off(self.cursor);
        self.buf.truncate(start);
        self.buf.extend_from_slice(replacement.as_bytes());
        if add_space {
            self.buf.push(b' ');
        }
        if self.buf.len() + tail.len() > self.max_line {
            // Trim the overflow back to a character boundary, so what is kept
            // is still the text the client typed.
            let mut keep = self.max_line.saturating_sub(self.buf.len());
            while keep > 0 && is_continuation(tail[keep]) {
                keep -= 1;
            }
            tail.truncate(keep);
        }
        self.cursor = self.buf.len();
        self.buf.append(&mut tail);
        self.redraw()
    }

    /// Print a candidate listing (e.g. ambiguous completions) on a new line,
    /// then redraw the prompt and current line beneath it — exactly what bash
    /// does on a second Tab.
    pub fn show_listing(&self, listing: &str) -> Vec<u8> {
        let mut out = Vec::from(&b"\r\n"[..]);
        out.extend_from_slice(crlf(listing).as_slice());
        if !listing.ends_with('\n') {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(&self.redraw());
        out
    }

    /// Feed one input byte, returning the resulting [`Reaction`].
    pub fn input(&mut self, byte: u8) -> Reaction {
        // Escape-sequence handling takes precedence over everything else.
        match self.esc {
            Esc::Got => return self.input_after_esc(byte),
            Esc::Csi => return self.input_csi(byte),
            Esc::None => {}
        }

        if self.search.is_some() {
            return self.input_search(byte);
        }

        match byte {
            b'\r' | b'\n' => self.submit(),
            ESC => {
                self.esc = Esc::Got;
                Reaction::Ignore
            }
            0x09 => Reaction::Complete,      // Tab
            0x08 | 0x7f => self.backspace(), // Backspace / DEL
            0x01 => self.move_home(),        // Ctrl-A
            0x05 => self.move_end(),         // Ctrl-E
            0x02 => self.move_left(),        // Ctrl-B
            0x06 => self.move_right(),       // Ctrl-F
            0x10 => self.history_prev(),     // Ctrl-P
            0x0e => self.history_next(),     // Ctrl-N
            0x15 => self.kill_to_start(),    // Ctrl-U
            0x0b => self.kill_to_end(),      // Ctrl-K
            0x17 => self.kill_word(),        // Ctrl-W
            0x19 => self.yank(),             // Ctrl-Y
            0x0c => self.clear_screen(),     // Ctrl-L
            0x12 => self.start_search(),     // Ctrl-R
            0x03 => self.interrupt(),        // Ctrl-C
            0x04 => self.ctrl_d(),           // Ctrl-D
            // Printable ASCII, plus the bytes of any non-ASCII character.
            0x20..=0x7e | 0x80..=0xff => self.insert(byte),
            _ => Reaction::Ignore, // other control bytes
        }
    }

    // --- escape sequence decoding ----------------------------------------

    fn input_after_esc(&mut self, byte: u8) -> Reaction {
        match byte {
            b'[' | b'O' => {
                self.esc = Esc::Csi;
                self.csi_params.clear();
                Reaction::Ignore
            }
            _ => {
                // Unrecognised ESC-prefixed key; drop it.
                self.esc = Esc::None;
                Reaction::Ignore
            }
        }
    }

    fn input_csi(&mut self, byte: u8) -> Reaction {
        // Accumulate parameter bytes (digits and ';') until a final byte.
        if byte.is_ascii_digit() || byte == b';' {
            if self.csi_params.len() < 8 {
                self.csi_params.push(byte);
            }
            return Reaction::Ignore;
        }
        self.esc = Esc::None;
        let params = std::mem::take(&mut self.csi_params);
        match byte {
            b'A' => self.history_prev(), // Up
            b'B' => self.history_next(), // Down
            b'C' => self.move_right(),   // Right
            b'D' => self.move_left(),    // Left
            b'H' => self.move_home(),    // Home
            b'F' => self.move_end(),     // End
            b'~' => match params.as_slice() {
                b"1" | b"7" => self.move_home(),
                b"4" | b"8" => self.move_end(),
                b"3" => self.delete_forward(), // Delete
                _ => Reaction::Ignore,
            },
            _ => Reaction::Ignore,
        }
    }

    // --- reverse incremental search (Ctrl-R) -----------------------------

    fn start_search(&mut self) -> Reaction {
        self.search = Some(Search {
            query: Vec::new(),
            matched: None,
        });
        Reaction::Write(self.render_search())
    }

    fn input_search(&mut self, byte: u8) -> Reaction {
        match byte {
            b'\r' | b'\n' => {
                // Accept the match into the buffer and submit it.
                self.accept_search();
                self.submit()
            }
            0x12 => {
                // Ctrl-R again: step to the next older match.
                self.search_step();
                Reaction::Write(self.render_search())
            }
            0x07 | 0x03 | ESC => {
                // Ctrl-G / Ctrl-C / Esc: abort, restore the original line.
                self.search = None;
                Reaction::Write(self.redraw())
            }
            0x08 | 0x7f => {
                if let Some(s) = self.search.as_mut() {
                    s.query.pop();
                }
                self.search_recompute();
                Reaction::Write(self.render_search())
            }
            0x20..=0x7e | 0x80..=0xff => {
                if let Some(s) = self.search.as_mut() {
                    if s.query.len() < self.max_line {
                        s.query.push(byte);
                    }
                }
                self.search_recompute();
                Reaction::Write(self.render_search())
            }
            _ => {
                // Any other editing key accepts the current match, leaves
                // search mode, then re-processes the key normally.
                self.accept_search();
                let redraw = self.redraw();
                match self.input(byte) {
                    Reaction::Write(mut more) => {
                        let mut out = redraw;
                        out.append(&mut more);
                        Reaction::Write(out)
                    }
                    Reaction::Ignore => Reaction::Write(redraw),
                    other => other,
                }
            }
        }
    }

    /// Recompute the most recent history entry containing the query, starting
    /// from the newest.
    fn search_recompute(&mut self) {
        let query = match &self.search {
            Some(s) => s.query.clone(),
            None => return,
        };
        let matched = self.find_match(self.history.len(), &query);
        if let Some(s) = self.search.as_mut() {
            s.matched = matched;
        }
    }

    /// Step to the next match older than the current one.
    fn search_step(&mut self) {
        let (query, from) = match &self.search {
            Some(s) => (s.query.clone(), s.matched.unwrap_or(self.history.len())),
            None => return,
        };
        let matched = self.find_match(from, &query);
        if let Some(s) = self.search.as_mut() {
            if matched.is_some() {
                s.matched = matched;
            }
        }
    }

    /// Find the newest history index strictly below `before` whose entry
    /// contains `query` as a substring.
    fn find_match(&self, before: usize, query: &[u8]) -> Option<usize> {
        if query.is_empty() {
            return None;
        }
        let upper = before.min(self.history.len());
        (0..upper)
            .rev()
            .find(|&i| contains(self.history[i].as_bytes(), query))
    }

    /// Copy the current search match (if any) into the edit buffer and leave
    /// search mode.
    fn accept_search(&mut self) {
        if let Some(s) = self.search.take() {
            if let Some(idx) = s.matched {
                self.buf = self.history[idx].as_bytes().to_vec();
                self.buf.truncate(self.max_line);
            }
            self.cursor = self.buf.len();
            self.hist_pos = None;
        }
    }

    fn render_search(&self) -> Vec<u8> {
        let s = match &self.search {
            Some(s) => s,
            None => return self.redraw(),
        };
        let matched = s
            .matched
            .map(|i| self.history[i].clone())
            .unwrap_or_default();
        let mut out = Vec::from(&b"\r"[..]);
        out.extend_from_slice(b"(reverse-i-search)`");
        out.extend_from_slice(&s.query);
        out.extend_from_slice(b"': ");
        out.extend_from_slice(matched.as_bytes());
        out.extend_from_slice(b"\x1b[K");
        out
    }

    // --- editing primitives ----------------------------------------------

    fn submit(&mut self) -> Reaction {
        let line = String::from_utf8_lossy(&self.buf).into_owned();
        self.push_history(&line);
        self.buf.clear();
        self.cursor = 0;
        self.hist_pos = None;
        self.stash.clear();
        Reaction::Submit {
            echo: b"\r\n".to_vec(),
            line,
        }
    }

    fn insert(&mut self, byte: u8) -> Reaction {
        if self.buf.len() >= self.max_line {
            // ponytail: a non-ASCII character straddling the cap keeps only the
            // bytes that fit, so the line submits with one U+FFFD in place of
            // that character; upgrade when payloads that long matter.
            return Reaction::Ignore;
        }
        self.buf.insert(self.cursor, byte);
        self.cursor += 1;
        self.hist_pos = None;
        // Fast path: appending at end needs no full redraw.
        if self.cursor == self.buf.len() {
            return Reaction::Write(vec![byte]);
        }
        Reaction::Write(self.redraw())
    }

    fn backspace(&mut self) -> Reaction {
        if self.cursor == 0 {
            return Reaction::Ignore;
        }
        let start = self.prev_char(self.cursor);
        self.buf.drain(start..self.cursor);
        self.cursor = start;
        Reaction::Write(self.redraw())
    }

    fn delete_forward(&mut self) -> Reaction {
        if self.cursor >= self.buf.len() {
            return Reaction::Ignore;
        }
        let end = self.next_char(self.cursor);
        self.buf.drain(self.cursor..end);
        Reaction::Write(self.redraw())
    }

    fn move_home(&mut self) -> Reaction {
        self.cursor = 0;
        Reaction::Write(self.redraw())
    }

    fn move_end(&mut self) -> Reaction {
        self.cursor = self.buf.len();
        Reaction::Write(self.redraw())
    }

    fn move_left(&mut self) -> Reaction {
        if self.cursor == 0 {
            return Reaction::Ignore;
        }
        self.cursor = self.prev_char(self.cursor);
        Reaction::Write(b"\x1b[D".to_vec())
    }

    fn move_right(&mut self) -> Reaction {
        if self.cursor >= self.buf.len() {
            return Reaction::Ignore;
        }
        self.cursor = self.next_char(self.cursor);
        Reaction::Write(b"\x1b[C".to_vec())
    }

    fn kill_to_start(&mut self) -> Reaction {
        if self.cursor == 0 {
            return Reaction::Ignore;
        }
        self.kill = self.buf.drain(0..self.cursor).collect();
        self.cursor = 0;
        Reaction::Write(self.redraw())
    }

    fn kill_to_end(&mut self) -> Reaction {
        if self.cursor >= self.buf.len() {
            return Reaction::Ignore;
        }
        self.kill = self.buf.split_off(self.cursor);
        Reaction::Write(self.redraw())
    }

    fn kill_word(&mut self) -> Reaction {
        if self.cursor == 0 {
            return Reaction::Ignore;
        }
        let mut start = self.cursor;
        while start > 0 && self.buf[start - 1].is_ascii_whitespace() {
            start -= 1;
        }
        while start > 0 && !self.buf[start - 1].is_ascii_whitespace() {
            start -= 1;
        }
        self.kill = self.buf.drain(start..self.cursor).collect();
        self.cursor = start;
        Reaction::Write(self.redraw())
    }

    /// Ctrl-Y: reinsert the last killed text at the cursor, as readline does.
    fn yank(&mut self) -> Reaction {
        if self.kill.is_empty() || self.buf.len() + self.kill.len() > self.max_line {
            return Reaction::Ignore;
        }
        let kill = std::mem::take(&mut self.kill);
        self.buf
            .splice(self.cursor..self.cursor, kill.iter().copied());
        self.cursor += kill.len();
        self.kill = kill;
        self.hist_pos = None;
        Reaction::Write(self.redraw())
    }

    fn clear_screen(&mut self) -> Reaction {
        let mut out = Vec::from(&b"\x1b[H\x1b[2J"[..]);
        out.extend_from_slice(&self.redraw());
        Reaction::Write(out)
    }

    fn interrupt(&mut self) -> Reaction {
        self.buf.clear();
        self.cursor = 0;
        self.hist_pos = None;
        self.stash.clear();
        let mut out = Vec::from(&b"^C\r\n"[..]);
        out.extend_from_slice(&self.redraw());
        Reaction::Write(out)
    }

    fn ctrl_d(&mut self) -> Reaction {
        if self.buf.is_empty() {
            Reaction::Eof
        } else {
            self.delete_forward()
        }
    }

    // --- history ----------------------------------------------------------

    fn push_history(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        if self.history.back().map(String::as_str) == Some(line) {
            return; // collapse consecutive duplicates, like bash's default
        }
        self.history.push_back(line.to_string());
        while self.history.len() > self.max_history {
            self.history.pop_front();
        }
    }

    fn history_prev(&mut self) -> Reaction {
        if self.history.is_empty() {
            return Reaction::Ignore;
        }
        let next = match self.hist_pos {
            None => {
                self.stash = self.buf.clone();
                self.history.len() - 1
            }
            Some(0) => return Reaction::Ignore,
            Some(i) => i - 1,
        };
        self.hist_pos = Some(next);
        self.buf = self.history[next].as_bytes().to_vec();
        self.cursor = self.buf.len();
        Reaction::Write(self.redraw())
    }

    fn history_next(&mut self) -> Reaction {
        match self.hist_pos {
            None => Reaction::Ignore,
            Some(i) if i + 1 < self.history.len() => {
                self.hist_pos = Some(i + 1);
                self.buf = self.history[i + 1].as_bytes().to_vec();
                self.cursor = self.buf.len();
                Reaction::Write(self.redraw())
            }
            Some(_) => {
                self.hist_pos = None;
                self.buf = std::mem::take(&mut self.stash);
                self.cursor = self.buf.len();
                Reaction::Write(self.redraw())
            }
        }
    }

    // --- helpers ----------------------------------------------------------

    /// Byte index where the word ending at the cursor begins.
    fn word_start(&self) -> usize {
        let mut start = self.cursor;
        while start > 0 && !self.buf[start - 1].is_ascii_whitespace() {
            start -= 1;
        }
        start
    }

    /// Byte index of the character before `i`.
    fn prev_char(&self, i: usize) -> usize {
        let mut start = i - 1;
        while start > 0 && is_continuation(self.buf[start]) {
            start -= 1;
        }
        start
    }

    /// Byte index just past the character starting at `i`.
    fn next_char(&self, i: usize) -> usize {
        let mut end = i + 1;
        while end < self.buf.len() && is_continuation(self.buf[end]) {
            end += 1;
        }
        end
    }

    /// Redraw the whole line: return to column 0, reprint prompt + buffer,
    /// clear any trailing leftovers, and reposition the cursor.
    fn redraw(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.prompt.len() + self.buf.len() + 16);
        out.push(b'\r');
        out.extend_from_slice(&self.prompt);
        out.extend_from_slice(&self.buf);
        out.extend_from_slice(b"\x1b[K");
        // ponytail: one column per character, so a wide CJK glyph or a
        // combining mark leaves the cursor a column out; upgrade when the box
        // has to look right under a non-Latin locale.
        let back = self.buf[self.cursor..]
            .iter()
            .filter(|b| !is_continuation(**b))
            .count();
        if back > 0 {
            out.extend_from_slice(format!("\x1b[{back}D").as_bytes());
        }
        out
    }
}

/// True if `b` continues a multi-byte UTF-8 character rather than starting one.
pub(crate) fn is_continuation(b: u8) -> bool {
    b & 0xc0 == 0x80
}

/// True if `haystack` contains `needle` as a contiguous byte substring.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Convert bare LF to CRLF for terminal output.
fn crlf(text: &str) -> Vec<u8> {
    text.replace('\n', "\r\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor() -> LineEditor {
        let mut e = LineEditor::new(4096, 100);
        e.set_prompt("$ ");
        e
    }

    /// Feed a byte string, returning the last `Submit` line seen (if any).
    fn feed(e: &mut LineEditor, bytes: &[u8]) -> Option<String> {
        let mut submitted = None;
        for &b in bytes {
            if let Reaction::Submit { line, .. } = e.input(b) {
                submitted = Some(line);
            }
        }
        submitted
    }

    #[test]
    fn types_and_submits_a_line() {
        let mut e = editor();
        assert_eq!(feed(&mut e, b"ls -la\r").as_deref(), Some("ls -la"));
    }

    #[test]
    fn backspace_removes_last_char() {
        let mut e = editor();
        assert_eq!(feed(&mut e, b"lsx\x7f\r").as_deref(), Some("ls"));
    }

    #[test]
    fn cursor_left_then_insert() {
        let mut e = editor();
        // type "ls", move left, insert 'X' -> "lXs"
        feed(&mut e, b"ls");
        e.input(ESC);
        e.input(b'[');
        e.input(b'D'); // left
        assert_eq!(feed(&mut e, b"X\r").as_deref(), Some("lXs"));
    }

    #[test]
    fn ctrl_a_and_ctrl_e_move_to_ends() {
        let mut e = editor();
        feed(&mut e, b"world");
        e.input(0x01); // Ctrl-A -> start
        feed(&mut e, b"hello ");
        e.input(0x05); // Ctrl-E -> end
        assert_eq!(feed(&mut e, b"!\r").as_deref(), Some("hello world!"));
    }

    #[test]
    fn ctrl_u_kills_to_start() {
        let mut e = editor();
        feed(&mut e, b"rm -rf /");
        e.input(0x15); // Ctrl-U clears whole line (cursor at end)
        assert_eq!(feed(&mut e, b"ls\r").as_deref(), Some("ls"));
    }

    #[test]
    fn ctrl_w_deletes_word() {
        let mut e = editor();
        feed(&mut e, b"cat /etc/passwd");
        e.input(0x17); // Ctrl-W removes "/etc/passwd"
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("cat "));
    }

    #[test]
    fn ctrl_k_kills_to_end() {
        let mut e = editor();
        feed(&mut e, b"hello world");
        e.input(0x01); // home
        for _ in 0..5 {
            e.input(0x06); // Ctrl-F x5 -> after "hello"
        }
        e.input(0x0b); // Ctrl-K kills " world"
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("hello"));
    }

    #[test]
    fn history_up_recalls_previous() {
        let mut e = editor();
        feed(&mut e, b"first\r");
        feed(&mut e, b"second\r");
        e.input(ESC);
        e.input(b'[');
        e.input(b'A'); // up -> "second"
        e.input(ESC);
        e.input(b'[');
        e.input(b'A'); // up -> "first"
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("first"));
    }

    #[test]
    fn history_down_restores_stashed_line() {
        let mut e = editor();
        feed(&mut e, b"old\r");
        feed(&mut e, b"new"); // in-progress, not submitted
        e.input(ESC);
        e.input(b'[');
        e.input(b'A'); // up -> "old"
        e.input(ESC);
        e.input(b'[');
        e.input(b'B'); // down -> back to "new"
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("new"));
    }

    #[test]
    fn reverse_search_finds_and_submits() {
        let mut e = editor();
        feed(&mut e, b"wget http://evil\r");
        feed(&mut e, b"ls\r");
        e.input(0x12); // Ctrl-R
        feed_no_submit(&mut e, b"wget");
        // Enter accepts the match and submits it.
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("wget http://evil"));
    }

    #[test]
    fn reverse_search_abort_restores_line() {
        let mut e = editor();
        feed(&mut e, b"history\r");
        feed(&mut e, b"abc"); // in progress
        e.input(0x12); // Ctrl-R
        feed_no_submit(&mut e, b"hist");
        e.input(0x07); // Ctrl-G aborts
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("abc"));
    }

    #[test]
    fn ctrl_d_on_empty_is_eof() {
        let mut e = editor();
        assert_eq!(e.input(0x04), Reaction::Eof);
    }

    #[test]
    fn ctrl_d_with_text_deletes_forward() {
        let mut e = editor();
        feed(&mut e, b"abc");
        e.input(0x01); // home
        e.input(0x04); // Ctrl-D deletes 'a'
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("bc"));
    }

    #[test]
    fn line_length_is_bounded() {
        let mut e = LineEditor::new(8, 10);
        e.set_prompt("$ ");
        let long = vec![b'a'; 100];
        feed(&mut e, &long);
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("aaaaaaaa"));
    }

    #[test]
    fn history_is_bounded() {
        let mut e = LineEditor::new(64, 2);
        e.set_prompt("$ ");
        feed(&mut e, b"a\r");
        feed(&mut e, b"b\r");
        feed(&mut e, b"c\r");
        assert_eq!(e.history.len(), 2);
        assert_eq!(e.history.front().map(String::as_str), Some("b"));
    }

    #[test]
    fn current_word_distinguishes_command_position() {
        let mut e = editor();
        feed(&mut e, b"ls");
        let (word, is_cmd) = e.current_word();
        assert_eq!(word, "ls");
        assert!(is_cmd);
        feed(&mut e, b" /et");
        let (word, is_cmd) = e.current_word();
        assert_eq!(word, "/et");
        assert!(!is_cmd);
    }

    #[test]
    fn apply_completion_inserts_replacement() {
        let mut e = editor();
        feed(&mut e, b"cat /etc/pass");
        e.apply_completion("/etc/passwd", true);
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("cat /etc/passwd "));
    }

    #[test]
    fn non_ascii_reaches_the_submitted_line() {
        let mut e = editor();
        assert_eq!(
            feed(&mut e, "ééunicode\r".as_bytes()).as_deref(),
            Some("ééunicode")
        );
    }

    #[test]
    fn backspace_removes_a_whole_character() {
        let mut e = editor();
        feed(&mut e, "aé".as_bytes());
        e.input(0x7f);
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("a"));
    }

    #[test]
    fn delete_removes_a_whole_character() {
        let mut e = editor();
        feed(&mut e, "éa".as_bytes());
        e.input(0x01); // home
        e.input(0x04); // Ctrl-D deletes 'é' whole
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("a"));
    }

    #[test]
    fn cursor_moves_and_redraws_by_column_not_byte() {
        let mut e = editor();
        feed(&mut e, "é".as_bytes());
        // Left arrow steps over both bytes of 'é' but is one column.
        assert_eq!(e.input(ESC), Reaction::Ignore);
        assert_eq!(e.input(b'['), Reaction::Ignore);
        assert_eq!(e.input(b'D'), Reaction::Write(b"\x1b[D".to_vec()));
        assert_eq!(e.cursor, 0);
        // Inserting before it redraws with the cursor one column back, not two.
        assert_eq!(
            e.input(b'x'),
            Reaction::Write("\r$ xé\x1b[K\x1b[1D".as_bytes().to_vec())
        );
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("xé"));
    }

    #[test]
    fn ctrl_u_then_ctrl_y_restores_the_line() {
        let mut e = editor();
        feed(&mut e, b"rm -rf /");
        e.input(0x15); // Ctrl-U
        e.input(0x19); // Ctrl-Y
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("rm -rf /"));
    }

    #[test]
    fn ctrl_k_kill_yanks_at_the_cursor() {
        let mut e = editor();
        feed(&mut e, b"hello world");
        e.input(0x01); // home
        e.input(0x0b); // Ctrl-K takes the whole line
        feed(&mut e, b"echo ");
        e.input(0x19); // Ctrl-Y
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("echo hello world"));
    }

    #[test]
    fn ctrl_w_kill_is_yankable_and_repeatable() {
        let mut e = editor();
        feed(&mut e, b"cat passwd");
        e.input(0x17); // Ctrl-W takes "passwd"
        e.input(0x19); // yank it back
        e.input(0x19); // and again — the kill survives a yank
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("cat passwdpasswd"));
    }

    #[test]
    fn yank_is_bounded_by_max_line() {
        let mut e = LineEditor::new(8, 10);
        e.set_prompt("$ ");
        feed(&mut e, b"aaaaaaaa");
        e.input(0x15); // Ctrl-U kills all 8
        feed(&mut e, b"bbb");
        assert_eq!(e.input(0x19), Reaction::Ignore); // would exceed max_line
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("bbb"));
    }

    #[test]
    fn yank_with_nothing_killed_does_nothing() {
        let mut e = editor();
        assert_eq!(e.input(0x19), Reaction::Ignore);
    }

    #[test]
    fn completion_trims_the_tail_at_a_character_boundary() {
        let mut e = LineEditor::new(5, 10);
        e.set_prompt("$ ");
        feed(&mut e, "xé".as_bytes()); // 3 bytes
        e.input(0x01); // home, so "xé" is the tail
        e.apply_completion("cmd", false);
        // Only "x" fits after "cmd"; half of 'é' must not be kept.
        assert_eq!(feed(&mut e, b"\r").as_deref(), Some("cmdx"));
    }

    #[test]
    fn no_panic_on_arbitrary_bytes() {
        // Robustness: every byte value, in sequence, must not panic.
        let mut e = editor();
        for b in 0u8..=255 {
            let _ = e.input(b);
        }
    }

    /// Feed bytes asserting none of them submit (helper for search tests).
    fn feed_no_submit(e: &mut LineEditor, bytes: &[u8]) {
        for &b in bytes {
            assert!(!matches!(e.input(b), Reaction::Submit { .. }));
        }
    }
}
