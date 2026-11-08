use std::{
    fmt,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::domain::error::DomainError;

static GLOBAL_ID_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// A 128-bit type-safe identifier compatible with the standard 8-4-4-4-12 UUID format.
/// Implemented entirely using the Rust Standard Library with zero third-party dependencies.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identifier {
    bytes: [u8; 16],
}

impl Identifier {
    /// Creates an identifier directly from a 16-byte array.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// Returns the raw 16-byte representation.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Returns the 4-bit UUID version encoded in bits 4-7 of byte 6.
    pub const fn version(&self) -> u8 {
        (self.bytes[6] >> 4) & 0x0f
    }

    /// Returns the 2-bit UUID variant encoded in bits 6-7 of byte 8 (1 = RFC 4122 variant).
    pub const fn variant(&self) -> u8 {
        (self.bytes[8] >> 6) & 0x03
    }

    /// Creates a deterministic identifier from a 64-bit sequence counter and a domain salt.
    ///
    /// Primarily intended for reproducible test fixtures and simulation environments.
    pub fn new_deterministic(domain_tag: u64, sequence: u64) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&domain_tag.to_be_bytes());
        bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
        // Set UUID version 4 (bits 4-7 of byte 6 = 0100) and variant 1 (bits 6-7 of byte 8 = 10)
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self { bytes }
    }

    /// Generates a sequential identifier using the monotonic atomic counter and system clock.
    ///
    /// NOTE: This generator is pseudo-random and monotonic for single-process in-memory sessions
    /// and tests. It does NOT provide cryptographic unpredictability or multi-process collision resistance.
    pub fn new_sequential(domain_salt: u64) -> Self {
        let seq = GLOBAL_ID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mixed = domain_salt ^ now_millis;
        Self::new_deterministic(mixed, seq)
    }

    /// Attempts to generate a cryptographically secure random UUIDv4.
    ///
    /// Under Phase 1 Increment 5.2 constraints (zero third-party dependencies and no unsafe code),
    /// OS CSPRNG is not directly accessible through safe `std`. This method fails closed explicitly
    /// rather than silently returning a predictable sequential value. Full CSPRNG UUIDv4 generation
    /// is deferred to Increment 5.4 when the approved `uuid` / `getrandom` dependency is introduced.
    pub fn generate_production_v4() -> Result<Self, DomainError> {
        Err(DomainError::EntropySourceUnavailable(
            "cryptographically secure OS CSPRNG source is unavailable in safe std; production UUID generation is deferred to Increment 5.4".to_string(),
        ))
    }

    /// Parses a standard 36-character hyphenated UUID string.
    pub fn parse_hyphenated(s: &str) -> Result<Self, DomainError> {
        let trimmed = s.trim();
        if trimmed.len() != 36 {
            return Err(DomainError::InvalidIdentifier(format!(
                "expected 36-char hyphenated UUID string, got {} in '{s}'",
                trimmed.len()
            )));
        }
        let b = trimmed.as_bytes();
        if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
            return Err(DomainError::InvalidIdentifier(format!(
                "hyphens in incorrect positions in '{s}'"
            )));
        }
        Self::from_str(trimmed)
    }

    /// Formats the identifier as a standard 36-character hyphenated UUID string:
    /// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    pub fn to_hyphenated_string(&self) -> String {
        let b = &self.bytes;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hyphenated_string())
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identifier({})", self.to_hyphenated_string())
    }
}

impl FromStr for Identifier {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let hex_str = if trimmed.len() == 36 {
            let b = trimmed.as_bytes();
            if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
                return Err(DomainError::InvalidIdentifier(format!(
                    "hyphens in incorrect positions in '{s}'"
                )));
            }
            format!(
                "{}{}{}{}{}",
                &trimmed[0..8],
                &trimmed[9..13],
                &trimmed[14..18],
                &trimmed[19..23],
                &trimmed[24..36]
            )
        } else if trimmed.len() == 32 {
            trimmed.to_string()
        } else {
            return Err(DomainError::InvalidIdentifier(format!(
                "expected 32 hex chars or 36-char hyphenated UUID, got {} chars in '{s}'",
                trimmed.len()
            )));
        };

        let mut bytes = [0u8; 16];
        for i in 0..16 {
            let hex_slice = &hex_str[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(hex_slice, 16).map_err(|e| {
                DomainError::InvalidIdentifier(format!(
                    "invalid hex byte '{hex_slice}' in '{s}': {e}"
                ))
            })?;
        }

        Ok(Self { bytes })
    }
}

macro_rules! define_typed_id {
    ($name:ident, $tag:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Identifier);

        impl $name {
            #[doc = "Generates a new sequential identifier."]
            pub fn new() -> Self {
                Self(Identifier::new_sequential($tag))
            }

            #[doc = "Constructs an identifier from a 16-byte array."]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(Identifier::from_bytes(bytes))
            }

            #[doc = "Returns the underlying 16-byte array."]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            #[doc = "Constructs a deterministic identifier from a sequence counter for reproducible testing."]
            pub fn from_sequence(seq: u64) -> Self {
                Self(Identifier::new_deterministic($tag, seq))
            }

            #[doc = "Alias for `from_sequence`, clearly marking deterministic test usage."]
            pub fn for_test_sequence(seq: u64) -> Self {
                Self::from_sequence(seq)
            }

            #[doc = "Attempts to generate a cryptographically secure random production identifier."]
            #[doc = "Fails closed until approved CSPRNG dependencies are available in Increment 5.4."]
            pub fn generate_production() -> Result<Self, DomainError> {
                Identifier::generate_production_v4().map(Self)
            }

            #[doc = "Returns the 4-bit UUID version."]
            pub const fn version(&self) -> u8 {
                self.0.version()
            }

            #[doc = "Returns the 2-bit UUID variant."]
            pub const fn variant(&self) -> u8 {
                self.0.variant()
            }

            #[doc = "Returns a reference to the inner Identifier."]
            pub fn inner(&self) -> &Identifier {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Identifier::from_str(s).map(Self)
            }
        }
    };
}

define_typed_id!(
    SessionId,
    0x5345_4e54_5241_0001,
    "Unique identifier for a research session."
);
define_typed_id!(
    TaskId,
    0x5345_4e54_5241_0002,
    "Unique identifier for an execution task."
);
define_typed_id!(
    ApprovalId,
    0x5345_4e54_5241_0003,
    "Unique identifier for a human approval request."
);
define_typed_id!(
    EventId,
    0x5345_4e54_5241_0004,
    "Unique identifier for an audit trail event."
);
define_typed_id!(
    EvidenceId,
    0x5345_4e54_5241_0005,
    "Unique identifier for an evidence artifact."
);
define_typed_id!(
    ExecutionId,
    0x5345_4e54_5241_0006,
    "Unique identifier for an execution dispatch request."
);
define_typed_id!(
    AttemptId,
    0x5345_4e54_5241_0007,
    "Unique identifier for a durable execution attempt."
);
define_typed_id!(
    ManifestId,
    0x5345_4e54_5241_0008,
    "Unique identifier for a canonical manifest."
);
define_typed_id!(
    ReservationId,
    0x5345_4e54_5241_0009,
    "Unique identifier for a budget reservation."
);
