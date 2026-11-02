//! Module manifests for the damavand agent-safety crates.
//!
//! A manifest says what one module (a jamshid project, a connector, a
//! source, a loop, an executor) may do: its MCP tools with their action
//! class and parameters, its named commands (argv templates, never a
//! shell), its exact egress hosts and the secrets bound to them, and caps
//! that can only lower autonomy. Manifests are reviewed like code; nothing
//! an agent sends can widen one.
//!
//! - [`Manifest::parse_toml`] parses strictly (unknown fields, duplicate
//!   keys, floats and limits refused) and validates every rule.
//! - [`Manifest::canonical_json`] is RFC 8785 JSON with defaults filled in;
//!   [`Manifest::digest`] is SHA-256 over it, domain-separated.
//! - [`Manifest::constraints`] lists the enum and pattern constraints that
//!   clear taint, for the policy engine.
//! - [`Command::resolve`] fills an argv template from tainted values.
//! - [`CommandProposal`] is a pending command addition the user approves.
//! - [`pattern`] is the pattern-safety code shared with damavand-policy.
#![forbid(unsafe_code)]

mod command;
mod digest;
mod error;
mod manifest;
pub mod pattern;
mod revision;
mod schema;
mod validate;
pub mod wire;

pub use command::{Args, ArgvElement, Command, Output, ResolvedArgv};
pub use digest::{
    DIGEST_DOMAIN, MAX_SAFE_INTEGER, ManifestDigest, canonical_json, digest_canonical,
};
pub use error::ManifestError;
pub use manifest::{
    Audit, Constraint, ConstraintKey, Egress, Kind, Manifest, ModuleId, Param, ParamType, Pattern,
    SCHEMA_VERSION, Secret, Tool, limits,
};
pub use revision::{CommandProposal, PROPOSAL_DOMAIN, ProposalDigest};
pub use schema::{
    ActionClass, CODE_FLAGS, DENIED_ENV, INTERPRETER_PROGRAMS, MCP_CALL, NEVER_ACTIONS,
    NEVER_PROGRAMS, PROPOSAL_ENV_ALLOW, PROPOSAL_FORBIDDEN_CHARS, REMOTE_PROGRAMS, RUN_COMMAND,
    SCHEMA_VERBS, WRAPPER_PROGRAMS, glob_matches, is_code_flag, is_denied_env, program_basename,
    program_matches,
};
