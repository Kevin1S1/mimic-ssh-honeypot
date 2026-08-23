//! Security invariant test: the emulation layers must never touch the real OS.
//!
//! MIMIC's core safety guarantee is that the shell, virtual filesystem, and
//! command implementations operate purely on in-memory state. Real process
//! execution and real filesystem/network access are confined to the network
//! layer (host-key persistence, upload quarantine). This test fails the build
//! if any forbidden API leaks into an emulation-layer source file, turning the
//! architectural invariant into an automatically enforced one.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories whose contents must be free of real-OS access.
const EMULATION_DIRS: &[&str] = &["src/shell", "src/vfs", "src/commands"];

/// Substrings that indicate a real process / filesystem / network escape.
/// Chosen to be specific enough that they do not appear in ordinary prose
/// comments.
const FORBIDDEN: &[&str] = &[
    "std::process",
    "process::Command",
    "std::fs",
    // A brace-grouped import defeats every `std::…` entry above:
    // `use std::{fs, process};` contains neither `std::fs` nor `std::process`.
    // Nothing in the emulation layers groups a `std` import today, so banning
    // the form outright costs nothing and closes the hole permanently.
    "std::{",
    // Reading the real process environment is host information leakage, which
    // SECURITY.md puts in scope even though it is not a write.
    "std::env",
    "tokio::fs",
    "tokio::net",
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
            for needle in FORBIDDEN {
                if line.contains(needle) {
                    out.push(format!("{}:{}: {}", path.display(), lineno + 1, needle));
                }
            }
        }
    }
}
