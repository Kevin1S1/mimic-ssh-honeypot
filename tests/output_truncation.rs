use mimic::commands::MAX_COMMAND_OUTPUT_BYTES;
use mimic::shell::Shell;

fn run(shell: &mut Shell, line: &str) -> String {
    shell.execute(line).text
}

#[test]
fn cat_large_file_is_truncated() {
    let mut shell = Shell::new("root", "debian");

    let big_content = vec![b'A'; 2 * 1024 * 1024];
    let cwd = shell.cwd;
    shell
        .vfs
        .add_file(cwd, "bigfile.txt", big_content, 0o644, 0, 0);

    let output = run(&mut shell, "cat bigfile.txt");

    assert!(
        output.len() < 2 * 1024 * 1024,
        "output was not truncated: {} bytes",
        output.len()
    );

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
fn command_substitution_is_bounded_per_line() {
    let mut shell = Shell::new("root", "debian");

    let cwd = shell.cwd;
    shell
        .vfs
        .add_file(cwd, "big.txt", vec![b'A'; 2 * 1024 * 1024], 0o644, 0, 0);

    let line = format!("echo {}", "$(cat big.txt)".repeat(200));
    let output = run(&mut shell, &line);

    assert!(
        output.len() <= MAX_COMMAND_OUTPUT_BYTES + 64,
        "substitution output ({} bytes) exceeded the per-line budget",
        output.len()
    );
}

#[test]
fn nested_substitution_is_depth_bounded() {
    let mut shell = Shell::new("root", "debian");

    let depth = 5_000;
    let line = format!("echo {}whoami{}", "$(".repeat(depth), ")".repeat(depth));
    let output = run(&mut shell, &line);

    assert_eq!(output, "\n");
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

    assert!(
        output.len() <= max_with_notice,
        "ls output ({} bytes) exceeded cap + notice ({} bytes)",
        output.len(),
        max_with_notice
    );

    if output.len() > MAX_COMMAND_OUTPUT_BYTES {
        assert!(
            output.ends_with(notice),
            "truncated output must end with the truncation notice"
        );
    }
}
