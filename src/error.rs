//! The one error type, with its wire code.

use crate::digest::ManifestDigest;
use crate::wire::codes;

/// Why a manifest or a command call is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestError {
    /// The manifest breaks a rule. `message` starts with the
    /// path of the offending field.
    Invalid {
        /// What is wrong, and where.
        message: String,
    },
    /// No manifest with this id in the store. The crate holds no store; the
    /// variant is here for the code.
    UnknownManifest {
        /// The id asked for.
        id: String,
    },
    /// The manifest has no command with this name.
    UnknownCommand {
        /// The name asked for.
        name: String,
    },
    /// The arguments of a command call break the command's rules.
    ArgsInvalid {
        /// What is wrong.
        message: String,
    },
    /// The digest is not the one expected.
    DigestMismatch {
        /// The digest the caller pinned.
        expected: ManifestDigest,
        /// The digest of the manifest at hand.
        actual: ManifestDigest,
    },
    /// The `schema` version is neither the current one nor one it can
    /// migrate.
    SchemaUnsupported {
        /// The version found, or -1 when it is not an integer.
        schema: i64,
    },
}

impl ManifestError {
    /// The wire error code (block 2000-2999).
    pub fn code(&self) -> i64 {
        match self {
            ManifestError::Invalid { .. } => codes::MANIFEST_INVALID,
            ManifestError::UnknownManifest { .. } => codes::UNKNOWN_MANIFEST,
            ManifestError::UnknownCommand { .. } => codes::UNKNOWN_COMMAND,
            ManifestError::ArgsInvalid { .. } => codes::ARGS_INVALID,
            ManifestError::DigestMismatch { .. } => codes::DIGEST_MISMATCH,
            ManifestError::SchemaUnsupported { .. } => codes::SCHEMA_UNSUPPORTED,
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        ManifestError::Invalid {
            message: message.into(),
        }
    }

    pub(crate) fn args(message: impl Into<String>) -> Self {
        ManifestError::ArgsInvalid {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Invalid { message } => write!(f, "manifest invalid: {message}"),
            ManifestError::UnknownManifest { id } => write!(f, "unknown manifest {id:?}"),
            ManifestError::UnknownCommand { name } => write!(f, "unknown command {name:?}"),
            ManifestError::ArgsInvalid { message } => write!(f, "arguments invalid: {message}"),
            ManifestError::DigestMismatch { expected, actual } => {
                write!(f, "digest mismatch: expected {expected}, got {actual}")
            }
            ManifestError::SchemaUnsupported { schema } => {
                write!(f, "schema version {schema} is not supported")
            }
        }
    }
}

impl std::error::Error for ManifestError {}
