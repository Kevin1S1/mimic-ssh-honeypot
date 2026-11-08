use sha2::{Digest, Sha256};

const ACK: u8 = 0;
const MAX_CONTROL_LINE: usize = 8192;
const MAX_SCP_DEPTH: usize = 32;
const UNNAMED_FILE: &str = "unnamed";

pub enum ScpMode {
    Sink { target: String, recursive: bool },

    Source { path: String },
}

#[derive(Default)]
struct ScpArgs {
    sink: bool,
    source: bool,
    recursive: bool,
    path: Option<String>,
}

impl ScpArgs {
    fn parse(operands: &[String]) -> Self {
        let mut args = Self::default();
        for token in operands.iter().filter(|token| *token != "--") {
            match token.strip_prefix('-') {
                Some(flags) => args.apply_flags(flags),
                None => args.path = Some(token.clone()),
            }
        }
        args
    }

    fn apply_flags(&mut self, flags: &str) {
        for flag in flags.chars() {
            match flag {
                't' => self.sink = true,
                'f' => self.source = true,
                'r' => self.recursive = true,
                _ => {}
            }
        }
    }
}

pub fn parse_scp(cmd: &str) -> Option<ScpMode> {
    let argv = crate::shell::parser::tokenize(cmd);
    let program = argv.first()?;
    let program_name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    if program_name != "scp" {
        return None;
    }

    let args = ScpArgs::parse(&argv[1..]);
    let path = args.path?;
    if args.sink {
        Some(ScpMode::Sink {
            target: path,
            recursive: args.recursive,
        })
    } else if args.source {
        Some(ScpMode::Source { path })
    } else {
        None
    }
}

pub struct CompletedFile {
    pub name: String,

    pub rel_dir: String,

    pub mode: u32,

    pub data: Vec<u8>,

    pub size: u64,

    pub payload_sha256: String,

    pub truncated: bool,
}

struct Incoming {
    name: String,
    mode: u32,
    size: u64,
    remaining: u64,
    data: Vec<u8>,

    hasher: Sha256,
    truncated: bool,
}

impl Incoming {
    fn new(name: String, mode: u32, size: u64) -> Self {
        Self {
            name,
            mode,
            size,
            remaining: size,
            data: Vec::new(),
            hasher: Sha256::new(),
            truncated: false,
        }
    }

    fn body_complete(&self) -> bool {
        self.remaining == 0
    }

    fn accept_body_byte(&mut self, byte: u8, max_bytes: u64) {
        self.hasher.update([byte]);
        if (self.data.len() as u64) < max_bytes {
            self.data.push(byte);
        } else {
            self.truncated = true;
        }
        self.remaining -= 1;
    }

    fn into_completed(self, rel_dir: String) -> CompletedFile {
        CompletedFile {
            name: self.name,
            rel_dir,
            mode: self.mode,
            data: self.data,
            size: self.size,
            payload_sha256: super::ssh::hex(&self.hasher.finalize()),
            truncated: self.truncated,
        }
    }
}

struct ControlEntry {
    mode: u32,
    size: u64,
    name: String,
}

pub struct ScpSink {
    target: String,
    recursive: bool,
    max_bytes: u64,
    dirs: Vec<String>,
    buf: Vec<u8>,
    file: Option<Incoming>,
}

impl ScpSink {
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

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn recursive(&self) -> bool {
        self.recursive
    }

    pub fn feed(&mut self, data: &[u8]) -> (Vec<u8>, Vec<CompletedFile>) {
        let mut acks = Vec::new();
        let mut done = Vec::new();

        for &byte in data {
            match self.file.as_mut() {
                Some(file) if !file.body_complete() => file.accept_body_byte(byte, self.max_bytes),
                Some(_) => {
                    done.push(self.finish_file());
                    acks.push(ACK);
                }
                None => {
                    if self.accept_control_byte(byte) {
                        acks.push(ACK);
                    }
                }
            }
        }

        (acks, done)
    }

    fn finish_file(&mut self) -> CompletedFile {
        let file = self.file.take().expect("file present");
        file.into_completed(self.dirs.join("/"))
    }

    fn accept_control_byte(&mut self, byte: u8) -> bool {
        match byte {
            b'\n' => {
                let line = std::mem::take(&mut self.buf);
                self.handle_control(&line);
                true
            }
            b'\r' => false,
            _ if self.buf.len() < MAX_CONTROL_LINE => {
                self.buf.push(byte);
                false
            }
            _ => {
                self.buf.clear();
                self.dirs.clear();
                false
            }
        }
    }

    fn handle_control(&mut self, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        match text.chars().next() {
            Some('C') => {
                if let Some(entry) = parse_cd(&text) {
                    self.file = Some(Incoming::new(entry.name, entry.mode, entry.size));
                }
            }
            Some('D') => {
                if let Some(entry) = parse_cd(&text) {
                    if self.dirs.len() < MAX_SCP_DEPTH {
                        self.dirs.push(entry.name);
                    }
                }
            }
            Some('E') => {
                self.dirs.pop();
            }

            _ => {}
        }
    }
}

fn parse_cd(line: &str) -> Option<ControlEntry> {
    let mut fields = line.splitn(3, ' ');
    let mode_field = fields.next()?;
    let size_field = fields.next()?;
    let raw_name = fields.next()?.trim();
    let mode = u32::from_str_radix(mode_field.get(1..)?, 8).ok()?;
    let size = size_field.parse::<u64>().ok()?;
    Some(ControlEntry {
        mode,
        size,
        name: sanitize_file_name(raw_name),
    })
}

fn sanitize_file_name(raw_name: &str) -> String {
    let without_controls: String = raw_name.chars().filter(|c| !c.is_control()).collect();
    let name = without_controls
        .replace(['/', '\\'], "_")
        .replace("..", "_");
    if name.is_empty() {
        UNNAMED_FILE.to_string()
    } else {
        name
    }
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
        stream.push(0);

        let (acks, files) = sink.feed(&stream);

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
        let body = b"AAAAAAAAAA";
        let mut stream = Vec::new();
        stream.extend_from_slice(format!("C0644 {} big.bin\n", body.len()).as_bytes());
        stream.extend_from_slice(body);
        stream.push(0);

        let (_, files) = sink.feed(&stream);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].data.len(), 4);
        assert!(files[0].truncated);
        assert_eq!(files[0].size, 10);

        let mut whole = Sha256::new();
        whole.update(body);
        assert_eq!(
            files[0].payload_sha256,
            super::super::ssh::hex(&whole.finalize())
        );

        let mut prefix = Sha256::new();
        prefix.update(&body[..4]);
        assert_ne!(
            files[0].payload_sha256,
            super::super::ssh::hex(&prefix.finalize())
        );
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
        let mut sink = ScpSink::new("/tmp/".into(), false, 1024);
        let body = b"x";
        let mut stream = Vec::new();
        stream
            .extend_from_slice(format!("C0644 {} ....//....//etc/passwd\n", body.len()).as_bytes());
        stream.extend_from_slice(body);
        stream.push(0);

        let (_, files) = sink.feed(&stream);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "________etc_passwd");
    }

    #[test]
    fn sanitises_hostile_control_names() {
        let cases = [
            ("../../etc/passwd", "____etc_passwd"),
            ("....//....//etc/passwd", "________etc_passwd"),
            ("....\\....\\etc\\passwd", "______etc_passwd"),
            ("a/b\\c", "a_b_c"),
            ("evil\0.sh", "evil.sh"),
            ("..\0../secret", "___secret"),
            (".\0.", "_"),
            ("..\0.", "_."),
            ("a\0.\0.\0b", "a_b"),
        ];
        for (raw, expected) in cases {
            let line = format!("C0644 1 {raw}");
            let name = parse_cd(&line).expect("control line parses").name;
            assert_eq!(name, expected, "raw={raw:?}");
        }
    }
}
