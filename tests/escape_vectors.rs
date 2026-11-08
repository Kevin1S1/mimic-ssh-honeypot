use std::fs;
use std::path::{Path, PathBuf};

const EMULATION_DIRS: &[&str] = &["src/shell", "src/vfs", "src/commands"];

const FORBIDDEN: &[&str] = &[
    "std::process",
    "process::Command",
    "std::fs",
    "std::{",
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
