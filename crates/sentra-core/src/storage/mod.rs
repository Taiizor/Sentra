//! Content-addressed storage (CAS), blob publication, and quota management.

pub mod cas;
pub mod error;
pub mod model;
pub mod traits;

pub use cas::FileSystemCasBlobStore;
pub use error::{StorageError, StorageErrorKind};
pub use model::{BlobId, BlobMetadata, StorageLimits, StorageUsage};
pub use traits::BlobStore;
