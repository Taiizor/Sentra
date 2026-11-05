# SQLite Dependency Audit & Packaging Analysis — Increment 5.4.1

Date: 2026-11-05. **Architecture and dependency audit complete. Zero dependency downloads. Zero Cargo manifest or lockfile modifications.**
This report provides a strict, offline audit of candidate dependencies for the upcoming SQLite persistence foundation (Increment 5.4). It establishes exact crate candidates, licensing, transitive dependency trees, native C compilation requirements, Windows MSVC x64 compatibility, and `#![forbid(unsafe_code)]` compliance.

**Increment 5.4.2 correction:** This was a cache/design assessment, not build evidence. The [implementation report](INCREMENT_5_4_2_SQLITE_IMPLEMENTATION.md) supersedes its selected-version/build claims: the executed bundled runtime is **SQLite 3.46.0**, the Windows graph has 29 external packages, and `pkg-config`/`vcpkg` are compiled build dependencies although the bundled route selects MSVC. Unfiltered offline metadata fails on unused `syn 2.0.119`; Windows-filtered metadata and builds succeed without downloads. An in-tree SHA-256 implementation is prohibited; ACID/WAL provide no storage-administrator tamper authentication. Proposed alternatives not selected here remain unvalidated.

---

## 1. Executive Summary & Audit Outcome

In accordance with `AGENTS.md`, ADR-0002, ADR-0007, and Phase 1 offline constraints:

1. **`rusqlite` with Bundled SQLite is Available Offline:**
   - Both `rusqlite 0.32.1` and `rusqlite 0.41.1`, along with their respective `libsqlite3-sys` companion crates (`0.30.1` and `0.39.1`), are **already present in the local Cargo cache** (`~/.cargo/registry/cache` and `~/.cargo/registry/src`).
   - The selected bundled SQLite C amalgamation (`sqlite3.c`, version **3.46.0** in `0.30.1`, corrected by the 5.4.2 source/runtime inspection) is self-contained within `libsqlite3-sys`. Pre-generated bindgen bindings are included. No external `sqlite3.dll`, LLVM/Clang installation, or network connection was needed for the selected Windows x64 build. The unselected `0.39.1` alternative was not compiled in 5.4.2.
   - The native C compilation is handled by `cc = "1.10.0"` (cached locally) targeting the installed Windows MSVC toolchain (`cl.exe` v14.52.37025).

2. **Serialization Dependencies are Available Offline:**
   - `serde 1.0.229` (with derive macro) and `serde_json 1.0.154` are **already present in the local Cargo cache**.
   - Their entire macro expansion toolchain (`proc-macro2 1.0.107`, `quote 1.0.47`, `syn 3.0.9`, `unicode-ident 1.0.27`, `itoa 1.0.18`, `memchr 2.8.3`, `serde_core 1.0.229`, `zmij 1.0.23`) is completely present in local storage.

3. **External UUID and Chrono Dependencies are Unnecessary:**
   - Although `uuid 1.29.0` and `chrono 0.4.45` exist in the local cache, **Sentra Core will NOT depend on them**.
   - `sentra-core::domain` already implements zero-dependency, safe domain types:
     - `Identifier` (`SessionId`, `TaskId`, `ApprovalId`, `EventId`): 128-bit UUID-compatible representation with standard 36-character hyphenated RFC 4122 string formatting, parsing, and byte-array conversions.
     - `TimestampUtc`: Deterministic RFC 3339 string formatting, parsing, and epoch-millisecond integer conversions.
   - Persisting identifiers as SQLite `TEXT` (or `BLOB`) and timestamps as `TEXT` (or `INTEGER` epoch milliseconds) requires zero third-party dependencies.

4. **Cryptographic Hashing Dependency (`sha2`) is Absent from Local Cache:**
   - The `sha2` crate is **NOT present** in the local Cargo cache.
   - Because network downloads are prohibited in Phase 1, `sha2` must not be added to `Cargo.toml`.
   - **Owner-directed correction in 5.4.2:** Store canonical V2 length-prefixed action identifiers as `TEXT`; they are not cryptographic integrity proofs. Do not implement SHA-256 in-tree. Cryptographic evidence and migration authentication remain deferred until an audited dependency is explicitly approved.

---

## 2. Local Cargo Cache Audit (Read-Only Inspection)

A read-only audit of the local Cargo registry cache (`C:\Users\Taiizor\.cargo\registry\cache\index.crates.io-1949cf8c6b5b557f`) and unpacked source trees (`C:\Users\Taiizor\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f`) verified the offline availability of the following crates:

| Crate Name | Cached Version | License | Category / Role | Complete Offline Tree? |
| --- | --- | --- | --- | --- |
| `rusqlite` | `0.32.1` & `0.41.1` | MIT | SQLite high-level wrapper | **Yes** (see feature constraints below) |
| `libsqlite3-sys` | `0.30.1` & `0.39.1` | MIT | SQLite FFI + bundled amalgamation | **Yes** (includes `sqlite3.c` & bindings) |
| `cc` | `1.10.0` | MIT OR Apache-2.0 | C compiler build-dependency | **Yes** |
| `bitflags` | `2.13.2` | MIT OR Apache-2.0 | Flag representation for SQLite open | **Yes** |
| `fallible-iterator` | `0.3.0` | MIT OR Apache-2.0 | Iterator abstraction for SQLite rows | **Yes** |
| `fallible-streaming-iterator` | `0.1.9` | MIT OR Apache-2.0 | Streaming row iterator | **Yes** |
| `hashlink` | `0.9.1` & `0.12.2` | MIT OR Apache-2.0 | LRU cache for prepared statements | **Yes** |
| `smallvec` | `1.16.4` | MIT OR Apache-2.0 | Small vector optimization | **Yes** |
| `serde` | `1.0.229` | MIT OR Apache-2.0 | Core serialization framework | **Yes** |
| `serde_derive` | `1.0.229` | MIT OR Apache-2.0 | Derive macro for Serialize/Deserialize | **Yes** |
| `serde_json` | `1.0.154` | MIT OR Apache-2.0 | JSON value and text serialization | **Yes** |
| `syn` | `3.0.9` | MIT OR Apache-2.0 | Macro parsing | **Yes** |
| `quote` | `1.0.47` | MIT OR Apache-2.0 | Macro code generation | **Yes** |
| `proc-macro2` | `1.0.107` | MIT OR Apache-2.0 | Macro token stream | **Yes** |
| `sha2` | *None* | — | Cryptographic SHA-256 | **NO (Absent from cache)** |

---

## 3. Detailed Dependency Evaluation

### 3.1. `rusqlite` with Bundled SQLite

#### Candidate Comparison: Version 0.32.1 vs 0.41.1

| Metric | `rusqlite 0.32.1` (Recommended) | `rusqlite 0.41.1` |
| --- | --- | --- |
| **Rust Edition** | 2021 | 2024 (MSRV 1.89.0) |
| **Companion FFI Crate** | `libsqlite3-sys 0.30.1` | `libsqlite3-sys 0.39.1` |
| **Bundled SQLite C Version** | **3.46.0**, source/runtime verified in 5.4.2 | Unselected alternative; historical source estimate not execution validation |
| **Default Features** | None (clean) | `["cache", "ffi-sqlite-wasm-rs"]` |
| **Wasm Entanglement Risk** | **None.** Does not reference wasm crates. | **High if default features used.** `ffi-sqlite-wasm-rs` references `sqlite-wasm-rs` which is **absent** from the local cache. Requires mandatory `default-features = false`. |
| **Direct Dependencies** | `bitflags 2.6.0`, `fallible-iterator 0.3`, `fallible-streaming-iterator 0.1`, `hashlink 0.9`, `libsqlite3-sys 0.30.1`, `smallvec 1.6.1` | `bitflags 2.6.0`, `fallible-iterator 0.3`, `fallible-streaming-iterator 0.1`, `hashlink 0.12`, `libsqlite3-sys 0.39.0`, `smallvec 1.6.1` |
| **Build Dependencies** | `libsqlite3-sys` requires `cc = "1.1.6"`. Satisfied by cached `cc-1.10.0`. | `libsqlite3-sys` requires `cc = "1.2.27"`. Satisfied by cached `cc-1.10.0`. |
| **Recommendation** | **STRONGLY RECOMMENDED.** Clean dependency graph, zero wasm risk, 100% offline verified. | Viable only with strict `default-features = false, features = ["bundled"]`. |

#### Native Compilation Requirements
- Bundled SQLite does not link against dynamic system libraries (`sqlite3.dll`). Instead, `libsqlite3-sys/build.rs` compiles `sqlite3.c` directly into a static library during Cargo build.
- Compiler requirement: Host C compiler. On Windows 11 x64, this is satisfied by Microsoft C/C++ Optimizing Compiler (`cl.exe` v14.52.37025 from Visual Studio 2026 Pre-release), which was validated in Phase 1 Milestone 1.
- `pkg-config` and `vcpkg` are present and compiled as Rust build dependencies in the actual Windows feature graph. The selected bundled path compiles the included C source with MSVC and uses pre-generated bindings; no external SQLite/package-manager installation or LLVM bindgen execution was required. See the 5.4.2 native build log.

#### Windows MSVC x64 Compatibility
- SQLite has native support for Win32/MSVC APIs (`THREADSAFE=1`, `MUTEX_W32`, native Windows file locking).
- Compatible with Windows long paths and UTF-8 path handling.

#### Security Maintenance & Known Concerns
- `rusqlite` is maintained by the `rusqlite` team under the MIT license with over 10 years of active production use across the Rust ecosystem.
- SQLite is the world's most tested database engine.
- Known concern: C code execution in-process. Memory corruption in SQLite C code could compromise the host process. Mitigated by using official amalgamations and enabling standard SQLite security compile flags.

#### Impact on `#![forbid(unsafe_code)]`
- The `sentra-core` crate enforces `#![forbid(unsafe_code)]` at its root.
- The `forbid(unsafe_code)` lint applies strictly to the AST of the crate in which it is declared. It prohibits unsafe blocks, unsafe functions, and unsafe trait implementations inside `sentra-core`.
- `rusqlite` encapsulates all internal FFI calls (`unsafe { ffi::sqlite3_... }`) within safe Rust abstractions (`Connection`, `Statement`, `Transaction`, `Row`).
- Calling safe methods of `rusqlite` from `sentra-core` **does not violate** `#![forbid(unsafe_code)]`. `sentra-core` remains 100% safe Rust.

---

### 3.2. Serialization Dependencies: `serde` and `serde_json`

#### Technical Profile
- **Crates:** `serde = "1.0.229"`, `serde_derive = "1.0.229"`, `serde_json = "1.0.154"`.
- **License:** MIT OR Apache-2.0.
- **Transitive Footprint:**
  - `proc-macro2 1.0.107`
  - `quote 1.0.47`
  - `syn 3.0.9`
  - `unicode-ident 1.0.27`
  - `serde_core 1.0.229`
  - `itoa 1.0.18`
  - `memchr 2.8.3`
  - `zmij 1.0.23`
  All 8 transitive dependencies are present in the local Cargo cache.
- **Role in Persistence:**
  - Storing structured domain metadata (such as `SessionMetadata`, `AuditEvent::details`, and `OperationAction` arguments) as validated JSON in SQLite `TEXT` columns.
  - Ensuring zero data loss across database serialization and deserialization.
- **Safety Profile:** Safe Rust code, highly optimized, memory-safe.

---

### 3.3. Identifier & Timestamp Serialization (No External Dependencies)

#### Technical Evaluation
- External crates `uuid` and `chrono` are present in the local cache, but introducing them into `sentra-core` is **unnecessary and discouraged**:
  1. **Identifiers:** `sentra-core::domain::Identifier` represents 128-bit UUID-compatible IDs. It already provides zero-dependency RFC 4122 string formatting (`to_string()`), hyphenated string parsing (`parse_hyphenated()`), and raw byte-array conversions (`to_bytes_le()`, `from_bytes_le()`).
     - In SQLite, identifiers will be stored as `TEXT NOT NULL` (e.g. `'01931a54-6e84-7832-8431-419b4cf1a201'`), ensuring human-readable auditability and indexed lookup.
  2. **Timestamps:** `sentra-core::domain::TimestampUtc` stores millisecond-precision UTC timestamps. It already provides zero-dependency RFC 3339 string formatting (`to_rfc3339()`), RFC 3339 parsing (`parse_rfc3339()`), and epoch millisecond integer conversions (`epoch_millis()`, `from_epoch_millis()`).
     - In SQLite, timestamps will be stored as `TEXT NOT NULL` (RFC 3339 UTC string, e.g. `'2026-11-05T22:18:16.000Z'`), allowing lexicographical sorting and SQLite datetime functions (`strftime()`).
- **Conclusion:** By using Sentra's existing strong domain types, we avoid 2 external dependencies and eliminate potential version skew across crates.

---

### 3.4. Cryptographic Hashing for Persistence Integrity

#### Technical Evaluation
- The `sha2` crate is **NOT present** in the local Cargo cache. Attempting to add `sha2` to `Cargo.toml` would fail offline compilation.
- **Analysis of Integrity Requirements:**
  - `action_digest` is currently a canonical V2 length-prefixed structured descriptor (`action_digest()`, e.g. `EXECUTE_TOOL|tool_id#7...`). It is stored directly as `TEXT` in the database.
  - ACID transactions, FULL synchronization, WAL and foreign keys support consistency/recovery; they do **not** authenticate records or resist a compromised database owner/administrator.
  - Cryptographic hashing is deferred. The owner explicitly prohibits a custom SHA-256 implementation in 5.4.2. Its FNV-1a migration fingerprint detects accidental drift only; it is not tamper protection. No hash-linked evidence/audit implementation is claimed.

---

## 4. Concrete Recommendation & Architecture Selection

### Recommended Dependency Manifest for Increment 5.4.2

When manifest modification is authorized in Increment 5.4.2, the following minimal dependency block is recommended for `crates/sentra-core/Cargo.toml`:

```toml
[dependencies]
# SQLite persistence engine with bundled C amalgamation
rusqlite = { version = "=0.32.1", default-features = false, features = ["bundled"] }

# Structured JSON serialization for metadata and audit payloads
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.154"
```

### Trade-Off Analysis

| Option | Pros | Cons | Recommendation |
| --- | --- | --- | --- |
| **Option 1: `rusqlite 0.32.1` (`bundled`) + `serde`** | Selected Windows graph builds offline; self-contained C; no external UUID/Chrono dependency. | Native compilation/FFI inside dependencies; 5.4.2 measured 68.6 s for its initial recorded native build; no general timing promise. | **SELECTED** |
| **Option 2: `rusqlite 0.41.1` (`bundled`)** | Alternative cache candidate; not compiled for 5.4.2. | Unselected features/native behavior remain unvalidated here. | **Not selected** |
| **Option 3: External Dynamic SQLite (`libsqlite3-sys` unbundled)** | No C compilation during build. | Requires host system `sqlite3.dll` / developer SDK. Violates zero-host-mutation rule and breaks deterministic reproducible builds. | **REJECTED (Violates ADR-0002/0007)** |
| **Option 4: Pure-Rust Storage Engine (no SQLite)** | Zero C code; 100% pure Rust. | Extreme complexity; reinventing B-trees, WAL, concurrency, and crash recovery; directly violates ADR-0003. | **REJECTED** |

---

## 5. Offline Resolution Plan for Increment 5.4.2

1. **Manifest Configuration:** In Increment 5.4.2, add only `rusqlite 0.32.1` (`bundled`) and `serde`/`serde_json` to `crates/sentra-core/Cargo.toml`.
2. **Offline Build Verification:** Run `cargo check --offline --workspace --all-targets` to confirm that Cargo resolves all crates strictly from the local cache without initiating network sockets.
3. **Compilation Verification:** Verify that `cl.exe` successfully compiles the bundled `sqlite3.c` amalgamation under the existing MSVC toolchain without warnings.
4. **Toolchain Lints:** Ensure `cargo clippy --workspace --all-targets --all-features -- -D warnings` remains 100% warning-free.
