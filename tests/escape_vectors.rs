use std::fs;
use std::path::{Path, PathBuf};

const EMULATION_DIRS: &[&str] = &["src/shell", "src/vfs", "src/commands"];

// Needles are matched against each source line with all whitespace removed (see
// `collect_violations`), so `std :: fs` and `std::fs` both trip, and the brace
// and alias import forms below cannot slip past.
const FORBIDDEN: &[&str] = &[
    "std::process",
    "process::Command",
    "std::fs",
    "std::{",
    "std::env",
    "stdas",   // `use std as s;` then `s::fs::…`
    "tokio::fs",
    "tokio::net",
    "tokio::{", // `use tokio::{net::TcpStream};`
    "tokioas",  // `use tokio as t;`
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "File::open",
    "File::create",
    "set_permissions",
];

#[test]
fn emulation_layers_have_no_real_io() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations: Vec<String> = Vec::new();

    for dir in EMULATION_DIRS {
        let path = root.join(dir);
        collect_violations(&path, &mut violations);
    }

    assert!(
        violations.is_empty(),
        "real-OS access found in emulation layers (security invariant breach):\n{}",
        violations.join("\n")
    );
}

fn collect_violations(dir: &Path, out: &mut Vec<String>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_violations(&path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        for (lineno, line) in source.lines().enumerate() {
            // Remove whitespace so spacing tricks (`std :: fs`, line-wrapped use
            // statements collapse per-line but at least intra-line spacing) can't
            // defeat a substring needle.
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            for needle in FORBIDDEN {
                if compact.contains(needle) {
                    out.push(format!("{}:{}: {}", path.display(), lineno + 1, needle));
                }
            }
        }
    }
}
