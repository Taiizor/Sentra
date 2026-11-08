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

/// Block size of SHA-256 in bytes (RFC 2104 / RFC 4231).
const SHA256_BLOCK_SIZE: usize = 64;

/// Computes HMAC-SHA256 (RFC 2104) over message bytes using secret key.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; SHA256_BLOCK_SIZE];
    if key.len() > SHA256_BLOCK_SIZE {
        let hash = sha256_bytes(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA256_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA256_BLOCK_SIZE];
    for i in 0..SHA256_BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    // Inner hash: H(K ^ ipad || message)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(ipad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H(K ^ opad || inner_hash)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(opad);
    outer_hasher.update(inner_hash);
    outer_hasher.finalize().into()
}

/// Computes HMAC-SHA256 and formats it as a 64-character lowercase hex string.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    encode_hex(&hmac_sha256(key, message))
}

/// Performs constant-time comparison of two byte slices to mitigate timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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

    #[test]
    fn test_rfc_4231_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(hmac_sha256_hex(&key, data), expected);
    }

    #[test]
    fn test_rfc_4231_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(hmac_sha256_hex(key, data), expected);
    }

    #[test]
    fn test_rfc_4231_case_3() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
        assert_eq!(hmac_sha256_hex(&key, &data), expected);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hello world"));
    }
}
