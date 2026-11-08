//! Pure Rust cryptographic hashing primitives backed by audited `sha2`.
//!
//! Provides deterministic SHA-256 computation for input manifests, content-addressed
//! digests, and execution audit trails (REQ-F01/F02, DG-4, OQ-24).

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Computes the standard SHA-256 digest of byte data, returning a 64-character lowercase hex string.
pub fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let output = hasher.finalize();
    encode_hex(&output)
}

/// Computes the standard SHA-256 digest of byte data, returning the digest prefixed with `sha256:`.
pub fn sha256_prefixed(data: &[u8]) -> String {
    format!("sha256:{}", sha256_digest(data))
}

/// Computes the raw 32-byte SHA-256 digest of byte data.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Incremental streaming SHA-256 hasher.
#[derive(Clone, Default)]
pub struct Sha256Stream {
    inner: Sha256,
}

impl Sha256Stream {
    /// Creates a new streaming SHA-256 hasher.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feeds additional bytes into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the hash, returning raw 32 bytes.
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }

    /// Finalizes the hash, returning a 64-character lowercase hex string.
    pub fn finalize_hex(self) -> String {
        encode_hex(&self.inner.finalize())
    }

    /// Finalizes the hash, returning a prefixed string (`sha256:<hex>`).
    pub fn finalize_prefixed(self) -> String {
        format!("sha256:{}", self.finalize_hex())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nist_sha256_empty_string() {
        let digest = sha256_digest(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_prefixed(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_nist_sha256_abc() {
        let digest = sha256_digest(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_nist_sha256_long_message() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha256_digest(input);
        assert_eq!(
            digest,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_streaming_hasher_matches_one_shot() {
        let mut stream = Sha256Stream::new();
        stream.update(b"abcdbcdecdefdefgefgh");
        stream.update(b"fghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            stream.finalize_hex(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
