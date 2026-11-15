use sha2::{Digest, Sha256};
use std::fmt::Write;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub(super) fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub(super) fn finish_sha256_hex(hasher: Sha256) -> String {
    hex(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_the_known_empty_digest() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn streamed_and_one_shot_digests_agree() {
        let mut hasher = Sha256::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        assert_eq!(finish_sha256_hex(hasher), sha256_hex(b"abc"));
    }
}
