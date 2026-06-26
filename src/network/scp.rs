//! SCP sink ("`scp -t`") protocol emulation for upload capture.
//!
//! This implements just enough of the rcp/SCP wire protocol to accept files an
//! attacker pushes to the honeypot, so their payloads can be quarantined and
//! logged. It is a pure state machine: [`ScpSink::feed`] consumes the incoming
//! byte stream and returns the acknowledgement bytes to send plus any completed
//! files. The network layer performs the actual quarantine write and logging.

/// What an `scp` remote command is asking the server to do.
pub enum ScpMode {
    /// `scp -t TARGET`: receive files into `TARGET` (the common upload path).
    Sink { target: String, recursive: bool },
    /// `scp -f PATH`: send files from `PATH` (download from the honeypot). Not
    /// fully emulated — the caller responds with a not-found error.
    Source { path: String },
}

/// Parse an exec command line, returning the SCP mode if it is an `scp`
/// invocation in transfer mode.
pub fn parse_scp(cmd: &str) -> Option<ScpMode> {
    let argv = crate::shell::parser::tokenize(cmd);
    let first = argv.first()?;
    let base = first.rsplit(['/', '\\']).next().unwrap_or(first);
    if base != "scp" {
        return None;
    }

    let mut sink = false;
    let mut source = false;
    let mut recursive = false;
    let mut path: Option<String> = None;

    for tok in &argv[1..] {
        if tok == "--" {
            continue;
        }
        if let Some(flags) = tok.strip_prefix('-') {
            for ch in flags.chars() {
                match ch {
                    't' => sink = true,
                    'f' => source = true,
                    'r' => recursive = true,
                    _ => {}
                }
            }
        } else {
            // The last non-flag operand is the path/target.
            path = Some(tok.clone());
        }
    }

    let path = path?;
    if sink {
        Some(ScpMode::Sink {
            target: path,
            recursive,
        })
    } else if source {
        Some(ScpMode::Source { path })
    } else {
        None
    }
}

/// A file fully received over SCP, ready to be quarantined.
pub struct CompletedFile {
    /// The name from the SCP `C` control message.
    pub name: String,
    /// Relative directory (from nested `D`/`E` messages), `/`-joined; empty for
    /// a top-level file.
    pub rel_dir: String,
    /// Unix mode from the control message.
    pub mode: u32,
    /// The (possibly truncated) file contents.
    pub data: Vec<u8>,
    /// Declared size from the control message.
    pub size: u64,
    /// Whether the stored data was truncated at the configured cap.
    pub truncated: bool,
}

/// State for an in-progress file body.
struct Incoming {
    name: String,
    mode: u32,
    size: u64,
    remaining: u64,
    data: Vec<u8>,
    truncated: bool,
}

/// The SCP sink state machine.
pub struct ScpSink {
    target: String,
    recursive: bool,
    max_bytes: u64,
    dirs: Vec<String>,
    buf: Vec<u8>,
    file: Option<Incoming>,
}

impl ScpSink {
    /// Create a sink targeting `target`, capping stored bytes per file at
    /// `max_bytes`.
    pub fn new(target: String, recursive: bool, max_bytes: u64) -> Self {
        Self {
            target,
            recursive,
            max_bytes,
            dirs: Vec::new(),
            buf: Vec::new(),
            file: None,
        }
    }

    /// The target operand from the `scp -t` command line.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Whether the transfer was started in recursive (`-r`) mode.
    pub fn recursive(&self) -> bool {
        self.recursive
    }

    /// Consume `data`, returning `(ack_bytes, completed_files)`. Each `ack_bytes`
    /// element is a zero byte that must be written back to the client.
    pub fn feed(&mut self, data: &[u8]) -> (Vec<u8>, Vec<CompletedFile>) {
        let mut acks = Vec::new();
        let mut done = Vec::new();

        for &b in data {
            if let Some(file) = self.file.as_mut() {
                if file.remaining > 0 {
                    if (file.data.len() as u64) < self.max_bytes {
                        file.data.push(b);
                    } else {
                        file.truncated = true;
                    }
                    file.remaining -= 1;
                    continue;
                }
                // The byte after the body is the transfer's trailing NUL.
                let f = self.file.take().expect("file present");
                done.push(CompletedFile {
                    name: f.name,
                    rel_dir: self.dirs.join("/"),
                    mode: f.mode,
                    data: f.data,
                    size: f.size,
                    truncated: f.truncated,
                });
                acks.push(0); // acknowledge the completed file
                continue;
            }

            if b == b'\n' {
                let line = std::mem::take(&mut self.buf);
                self.handle_control(&line);
                acks.push(0); // every control message is acknowledged
            } else if b != b'\r' {
                const MAX_CONTROL_LINE: usize = 8192;
                if self.buf.len() < MAX_CONTROL_LINE {
                    self.buf.push(b);
                } else {
                    // Control line exceeds safety cap — reset SCP state.
                    self.buf.clear();
                    self.file = None;
                    self.dirs.clear();
                }
            }
        }

        (acks, done)
    }

    /// Process one control line (without its terminating newline).
    fn handle_control(&mut self, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let mut chars = text.chars();
        match chars.next() {
            Some('C') => {
                if let Some((mode, size, name)) = parse_cd(&text) {
                    self.file = Some(Incoming {
                        name,
                        mode,
                        size,
                        remaining: size,
                        data: Vec::new(),
                        truncated: false,
                    });
                }
            }
            Some('D') => {
                const MAX_SCP_DEPTH: usize = 32;
                if let Some((_, _, name)) = parse_cd(&text) {
                    if self.dirs.len() < MAX_SCP_DEPTH {
                        self.dirs.push(name);
                    }
                }
            }
            Some('E') => {
                self.dirs.pop();
            }
            // 'T' (times) and anything else: just acknowledged, no state change.
            _ => {}
        }
    }
}

/// Parse a `C`/`D` control line: `<kind><mode> <size> <name>`.
fn parse_cd(line: &str) -> Option<(u32, u64, String)> {
    let mut it = line.splitn(3, ' ');
    let mode_field = it.next()?; // e.g. "C0644"
    let size_field = it.next()?;
    let raw_name = it.next()?.trim().to_string();
    let mode = u32::from_str_radix(mode_field.get(1..)?, 8).ok()?;
    let size = size_field.parse::<u64>().ok()?;
    // Sanitise: strip path separators and ".." to prevent directory traversal.
    let name = raw_name.replace(['/', '\\'], "_").replace("..", "_");
    let name = if name.is_empty() {
        "unnamed".to_string()
    } else {
        name
    };
    Some((mode, size, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sink_and_source() {
        match parse_scp("scp -t /tmp/") {
            Some(ScpMode::Sink { target, recursive }) => {
                assert_eq!(target, "/tmp/");
                assert!(!recursive);
            }
            _ => panic!("expected sink"),
        }
        match parse_scp("scp -r -t /var/www") {
            Some(ScpMode::Sink { recursive, .. }) => assert!(recursive),
            _ => panic!("expected recursive sink"),
        }
        assert!(matches!(
            parse_scp("scp -f /etc/passwd"),
            Some(ScpMode::Source { .. })
        ));
        assert!(parse_scp("ls -la").is_none());
        assert!(parse_scp("scp").is_none());
    }

    #[test]
    fn receives_a_single_file() {
        let mut sink = ScpSink::new("/tmp/".into(), false, 1024);
        let body = b"#!/bin/sh\nrm -rf /\n";
        let mut stream = Vec::new();
        stream.extend_from_slice(format!("C0755 {} payload.sh\n", body.len()).as_bytes());
        stream.extend_from_slice(body);
        stream.push(0); // trailing NUL

        let (acks, files) = sink.feed(&stream);
        // One ack for the C message, one for the completed file.
        assert_eq!(acks.len(), 2);
        assert!(acks.iter().all(|&b| b == 0));
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "payload.sh");
        assert_eq!(files[0].mode, 0o755);
        assert_eq!(files[0].data, body);
        assert!(!files[0].truncated);
    }

    #[test]
    fn truncates_oversized_file() {
        let mut sink = ScpSink::new("/tmp/".into(), false, 4);
        let body = b"AAAAAAAAAA"; // 10 bytes, cap 4
        let mut stream = Vec::new();
        stream.extend_from_slice(format!("C0644 {} big.bin\n", body.len()).as_bytes());
        stream.extend_from_slice(body);
        stream.push(0);

        let (_, files) = sink.feed(&stream);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].data.len(), 4);
        assert!(files[0].truncated);
        assert_eq!(files[0].size, 10);
    }

    #[test]
    fn handles_byte_at_a_time_streaming() {
        let mut sink = ScpSink::new("/tmp/x".into(), false, 1024);
        let body = b"data";
        let mut stream = Vec::new();
        stream.extend_from_slice(format!("C0644 {} x\n", body.len()).as_bytes());
        stream.extend_from_slice(body);
        stream.push(0);

        let mut files = Vec::new();
        for b in stream {
            let (_, mut f) = sink.feed(&[b]);
            files.append(&mut f);
        }
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].data, body);
    }

    #[test]
    fn traversal_filename_is_neutralised() {
        // A crafted control name must never carry path separators or `..`
        // through to the caller — the stored name is flattened to a single
        // path component so it cannot escape the upload directory.
        let mut sink = ScpSink::new("/tmp/".into(), false, 1024);
        let body = b"x";
        let mut stream = Vec::new();
        stream.extend_from_slice(format!("C0644 {} ../../etc/passwd\n", body.len()).as_bytes());
        stream.extend_from_slice(body);
        stream.push(0);

        let (_, files) = sink.feed(&stream);
        assert_eq!(files.len(), 1);
        let name = &files[0].name;
        assert!(!name.contains('/'), "no path separators: {name}");
        assert!(!name.contains(".."), "no parent refs: {name}");
    }
}
