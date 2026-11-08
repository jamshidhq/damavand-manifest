//! Wire names for the damavand-proto `manifest` capability.
//!
//! Defined here until this crate depends on damavand-proto. Error codes are
//! in the block 2000-2999 of the damavand-proto code registry.

use serde_json::{Value, json};

use crate::digest::ManifestDigest;

/// Capability name. Its parameters are `{"digests": [...]}`, see
/// [`capability_params`].
pub const CAPABILITY: &str = "manifest";
/// Read one manifest (canonical form and digest) by id.
pub const METHOD_GET: &str = "manifest/get";
/// List manifest ids and digests.
pub const METHOD_LIST: &str = "manifest/list";
/// Validate a manifest text. Never writes to the store.
pub const METHOD_VALIDATE: &str = "manifest/validate";

/// Wire error codes (block 2000-2999).
pub mod codes {
    /// The manifest breaks a rule.
    pub const MANIFEST_INVALID: i64 = 2000;
    /// No manifest with this id.
    pub const UNKNOWN_MANIFEST: i64 = 2001;
    /// No command with this name.
    pub const UNKNOWN_COMMAND: i64 = 2002;
    /// The arguments of a command call are invalid.
    pub const ARGS_INVALID: i64 = 2003;
    /// The digest is not the one pinned.
    pub const DIGEST_MISMATCH: i64 = 2004;
    /// The schema version is not supported.
    pub const SCHEMA_UNSUPPORTED: i64 = 2005;
}

/// The capability parameters `{"digests": [...]}`: lowercase hex digests,
/// sorted, without duplicates.
pub fn capability_params(digests: &[ManifestDigest]) -> Value {
    let mut hex: Vec<String> = digests.iter().map(ToString::to_string).collect();
    hex.sort();
    hex.dedup();
    json!({ "digests": hex })
}
