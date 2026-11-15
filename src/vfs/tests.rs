use super::*;

fn fixture() -> Vfs {
    let mut fs = Vfs::new();
    let root = fs.root();
    let tmp = fs.mkdir(root, "tmp", 0o1777, 0, 0);
    fs.add_file(tmp, "a", &b"hello"[..], 0o644, 0, 0);
    let d = fs.mkdir(tmp, "d", 0o755, 0, 0);
    fs.add_file(d, "inner", &b"x"[..], 0o644, 0, 0);
    fs
}

#[test]
fn resolves_absolute_and_relative_paths() {
    let fs = fixture();
    let root = fs.root();
    let tmp = fs.resolve(root, "/tmp").unwrap();

    assert_eq!(fs.resolve(tmp, "d/inner"), fs.resolve(root, "/tmp/d/inner"));

    assert_eq!(
        fs.resolve(root, "/tmp/./d/"),
        Some(fs.child(tmp, "d").unwrap())
    );

    assert!(fs.resolve(root, "/tmp/a/nope").is_none());
}

#[test]
fn split_path_separates_dir_and_final() {
    assert_eq!(Vfs::split_path("/etc/passwd"), ("/etc", "passwd"));
    assert_eq!(Vfs::split_path("/top"), ("/", "top"));
    assert_eq!(Vfs::split_path("bare"), (".", "bare"));
}

#[test]
fn resolve_follows_symlink() {
    let mut fs = fixture();
    let root = fs.root();

    fs.add_symlink(root, "link", "/tmp/d");
    let via_link = fs.resolve(root, "/link/inner").unwrap();
    let direct = fs.resolve(root, "/tmp/d/inner").unwrap();
    assert_eq!(via_link, direct);
}

#[test]
fn symlink_loop_terminates() {
    let mut fs = fixture();
    let root = fs.root();

    fs.add_symlink(root, "a", "/b");
    fs.add_symlink(root, "b", "/a");
    assert_eq!(fs.resolve(root, "/a"), None);
}

#[test]
fn dotdot_clamps_at_root() {
    let fs = fixture();
    let root = fs.root();

    assert_eq!(fs.resolve(root, "/../../.."), Some(root));
    assert_eq!(fs.resolve(root, "/tmp/../.."), Some(root));
}

#[test]
fn mkdir_p_creates_and_reuses_chain() {
    let mut fs = fixture();
    let made = fs.mkdir_p("/var/log/app", 0o755, 0, 0);
    assert_eq!(fs.resolve(fs.root(), "/var/log/app"), made);

    let again = fs.mkdir_p("/var/log/app", 0o755, 0, 0);
    assert_eq!(again, made);
}

#[test]
fn mkdir_p_reports_failure_instead_of_an_ancestor() {
    let mut fs = Vfs::new();
    let root = fs.root();
    while fs.nodes.len() < MAX_VFS_NODES {
        fs.mkdir(root, &format!("d{}", fs.nodes.len()), 0o755, 0, 0);
    }

    assert_eq!(fs.mkdir_p("/srv/deep/tree", 0o755, 0, 0), None);
    assert!(fs.resolve(root, "/srv").is_none());
}

#[test]
fn node_cap_bounds_allocation() {
    let mut fs = Vfs::new();
    let root = fs.root();

    for i in 0..(MAX_VFS_NODES + 50) {
        fs.add_file(root, &format!("f{i}"), &b""[..], 0o644, 0, 0);
    }
    assert!(fs.nodes.len() <= MAX_VFS_NODES);
}

#[test]
fn depth_cap_bounds_tree_depth() {
    let mut fs = Vfs::new();
    let mut current = fs.root();
    for _ in 0..MAX_VFS_DEPTH + 10 {
        current = fs.mkdir(current, "a", 0o755, 0, 0);
    }
    assert_eq!(fs.depth_of(current), MAX_VFS_DEPTH);
    assert!(fs.is_full(current));
    assert!(fs
        .mkdir_p(&"/b".repeat(MAX_VFS_DEPTH + 1), 0o755, 0, 0)
        .is_none());
}

#[test]
fn rename_refuses_to_stack_chains_past_the_depth_cap() {
    let mut fs = Vfs::new();
    let root = fs.root();
    let half = MAX_VFS_DEPTH / 2 + 1;
    let top = fs.mkdir_p(&"/x".repeat(half), 0o755, 0, 0).unwrap();
    fs.mkdir_p(&"/y".repeat(half), 0o755, 0, 0).unwrap();
    let y = fs.child(root, "y").unwrap();

    assert!(!fs.rename(y, top, "y"));
    assert_eq!(fs.child(root, "y"), Some(y));
    let x = fs.child(root, "x").unwrap();
    assert!(fs.rename(x, y, "x"), "a move that fits is still allowed");
}

#[test]
fn byte_cap_bounds_total_content() {
    let mut fs = Vfs::new();
    let root = fs.root();
    let big = vec![0u8; MAX_VFS_BYTES / 2 + 1];

    let a = fs.add_file(root, "a", big.clone(), 0o644, 0, 0);
    assert!(fs.child(root, "a").is_some());

    assert_eq!(fs.add_file(root, "b", big.clone(), 0o644, 0, 0), root);
    assert!(fs.child(root, "b").is_none());

    fs.add_file(root, "c", &b"ok"[..], 0o644, 0, 0);
    assert!(fs.child(root, "c").is_some());

    assert_eq!(fs.add_file(root, "a", Vec::new(), 0o644, 0, 0), a);
    fs.add_file(root, "b", big, 0o644, 0, 0);
    assert!(fs.child(root, "b").is_some());
}

#[test]
fn unlink_detaches_child() {
    let mut fs = fixture();
    let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
    assert!(fs.child(tmp, "a").is_some());
    assert!(fs.unlink(tmp, "a").is_some());
    assert!(fs.child(tmp, "a").is_none());
}

#[test]
fn rename_moves_node() {
    let mut fs = fixture();
    let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
    let a = fs.child(tmp, "a").unwrap();
    let d = fs.child(tmp, "d").unwrap();
    assert!(fs.rename(a, d, "b"));
    assert!(fs.child(tmp, "a").is_none());
    assert_eq!(fs.resolve(fs.root(), "/tmp/d/b"), Some(a));
    assert_eq!(fs.path_of(a), "/tmp/d/b");
}

#[test]
fn rename_refuses_move_into_own_subtree() {
    let mut fs = fixture();
    let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
    let d = fs.child(tmp, "d").unwrap();

    assert!(!fs.rename(tmp, d, "tmp"), "cyclic move must be refused");

    assert!(!fs.rename(tmp, tmp, "tmp"));

    assert_eq!(fs.child(fs.root(), "tmp"), Some(tmp));
    assert_eq!(fs.path_of(d), "/tmp/d");

    let a = fs.child(tmp, "a").unwrap();
    assert!(fs.rename(a, d, "a"));
    assert_eq!(fs.path_of(a), "/tmp/d/a");
}

#[test]
fn path_of_terminates_for_every_node() {
    let fs = fixture();
    for id in 0..fs.nodes.len() {
        let path = fs.path_of(id);
        assert!(path.starts_with('/'));
    }
}

#[test]
fn deep_copy_duplicates_subtree() {
    let mut fs = fixture();
    let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
    let d = fs.child(tmp, "d").unwrap();
    let copy = fs.deep_copy(d, tmp, "d2");
    assert_ne!(copy, d);
    let orig_inner = fs.resolve(fs.root(), "/tmp/d/inner").unwrap();
    let copy_inner = fs.resolve(fs.root(), "/tmp/d2/inner").unwrap();
    assert_ne!(orig_inner, copy_inner);
    if let NodeKind::File { contents } = &fs.node(copy_inner).kind {
        assert_eq!(contents, b"x");
    } else {
        panic!("expected file");
    }
}

#[test]
fn chmod_preserves_file_type() {
    let mut fs = fixture();
    let a = fs.resolve(fs.root(), "/tmp/a").unwrap();
    fs.chmod(a, 0o600);
    let mode = fs.node(a).meta.mode;
    assert_eq!(mode & 0o7777, 0o600);
    assert_eq!(mode & nodes::S_IFMT, S_IFREG);
}

#[test]
fn touch_creates_then_updates() {
    let mut fs = fixture();
    let tmp = fs.resolve(fs.root(), "/tmp").unwrap();
    let id = fs.touch(tmp, "fresh", 0, 0);
    assert_eq!(fs.child(tmp, "fresh"), Some(id));

    assert_eq!(fs.touch(tmp, "fresh", 0, 0), id);
}
