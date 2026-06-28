//! Security test: command output is capped to prevent memory-amplification DoS.
//!
//! Even though the VFS is node-bounded, a single command like `cat` on a large
//! attacker-written file can amplify into an unbounded `String`. The dispatch
//! layer caps output at `MAX_COMMAND_OUTPUT_BYTES`; this test verifies that
//! invariant holds.

use mimic::commands::MAX_COMMAND_OUTPUT_BYTES;
use mimic::shell::Shell;

/// Helper: run a command line and return the output text.
fn run(shell: &mut Shell, line: &str) -> String {
    shell.execute(line).text
}

#[test]
fn cat_large_file_is_truncated() {
    let mut shell = Shell::new("root", "debian");

    // Create a file that is well over the output cap (2 MiB of 'A's).
    let big_content = vec![b'A'; 2 * 1024 * 1024];
    let cwd = shell.cwd;
    shell
        .vfs
        .add_file(cwd, "bigfile.txt", big_content, 0o644, 0, 0);

    let output = run(&mut shell, "cat bigfile.txt");

    // Output must be truncated: it should be much smaller than 2 MiB.
    assert!(
        output.len() < 2 * 1024 * 1024,
        "output was not truncated: {} bytes",
        output.len()
    );

    // It should be roughly MAX_COMMAND_OUTPUT_BYTES plus the truncation notice.
    let notice = "\n... (output truncated)\n";
    assert!(
        output.ends_with(notice),
        "truncated output must end with the truncation notice"
    );
    assert!(
        output.len() <= MAX_COMMAND_OUTPUT_BYTES + notice.len(),
        "output ({} bytes) should not exceed cap + notice ({})",
        output.len(),
        MAX_COMMAND_OUTPUT_BYTES + notice.len()
    );
}

#[test]
fn small_output_is_not_truncated() {
    let mut shell = Shell::new("root", "debian");
    let output = run(&mut shell, "echo hello world");

    assert_eq!(output, "hello world\n");
    assert!(
        !output.contains("output truncated"),
        "small output must not be truncated"
    );
}

#[test]
fn ls_large_directory_is_truncated() {
    let mut shell = Shell::new("root", "debian");

    // Build a directory with many files with long names to push `ls` output
    // over the 1 MiB cap.
    let cwd = shell.cwd;
    let long_name_segment = "a".repeat(200);
    let dir = shell.vfs.mkdir(cwd, &long_name_segment, 0o755, 0, 0);
    for i in 0..6000 {
        let name = format!("{long_name_segment}_{i:05}.txt");
        shell.vfs.add_file(dir, &name, b"x".to_vec(), 0o644, 0, 0);
    }

    let output = run(&mut shell, &format!("ls -1 {long_name_segment}"));

    let notice = "\n... (output truncated)\n";
    let max_with_notice = MAX_COMMAND_OUTPUT_BYTES + notice.len();

    // The output must not exceed the cap + truncation notice.
    assert!(
        output.len() <= max_with_notice,
        "ls output ({} bytes) exceeded cap + notice ({} bytes)",
        output.len(),
        max_with_notice
    );

    // If the output was large enough to trigger truncation, it should end
    // with the truncation notice.
    if output.len() > MAX_COMMAND_OUTPUT_BYTES {
        assert!(
            output.ends_with(notice),
            "truncated output must end with the truncation notice"
        );
    }
}
