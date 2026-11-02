//! A proposed addition of a missing named command.
//!
//! An agent may propose; it never runs the command once. The user approves
//! the diff ([`CommandProposal::diff`]); the core then calls
//! [`CommandProposal::apply`] and commits the result as a user-authored
//! revision with a new digest. The approval flow lives in the core.

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::command::Command;
use crate::digest::{ManifestDigest, canonical_json, feed};
use crate::error::ManifestError;
use crate::manifest::{Manifest, command_json, parse_table};
use crate::validate;

/// Domain tag of the proposal digest.
pub const PROPOSAL_DOMAIN: &str = "damavand-manifest/proposal/v1";

/// SHA-256 that binds an approval to one exact proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProposalDigest(pub [u8; 32]);

impl std::fmt::Display for ProposalDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A pending command addition against one base manifest. Never active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandProposal {
    pub(crate) base: ManifestDigest,
    pub(crate) name: String,
    pub(crate) command: Command,
}

impl CommandProposal {
    /// Parse the body of `[commands.<name>]` (a TOML table) as an addition
    /// to `base`. Refuses a name already present and anything the
    /// resulting manifest would fail on.
    pub fn parse(base: &Manifest, name: &str, toml: &str) -> Result<Self, ManifestError> {
        let path = format!("commands.{name}");
        let table = parse_table(toml)?;
        validate::walk_toml_table(&path, &table)?;
        let command = validate::command(name, validate::raw_command_from_toml(table)?)?;
        let proposal = CommandProposal {
            base: base.digest(),
            name: name.to_string(),
            command,
        };
        proposal.revised(base)?;
        Ok(proposal)
    }
    /// The digest of the manifest it extends.
    pub fn base(&self) -> ManifestDigest {
        self.base
    }
    /// The new command's name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The new command.
    pub fn command(&self) -> &Command {
        &self.command
    }
    /// SHA-256 over the domain tag, the base digest, the name and the
    /// command's canonical JSON.
    pub fn digest(&self) -> ProposalDigest {
        let mut h = Sha256::new();
        feed(&mut h, PROPOSAL_DOMAIN.as_bytes());
        feed(&mut h, self.base.as_bytes());
        feed(&mut h, self.name.as_bytes());
        feed(&mut h, &self.command_bytes());
        ProposalDigest(h.finalize().into())
    }

    fn command_bytes(&self) -> Vec<u8> {
        canonical_json(&command_json(&self.command))
            .expect("a validated command holds only safe integers")
    }
    /// The change for the user to review: the new `[commands.<name>]` table
    /// as TOML, each line prefixed with `+ `.
    pub fn diff(&self) -> String {
        let value = json!({ "commands": { self.name.as_str(): command_json(&self.command) } });
        let text = toml::Value::try_from(value)
            .and_then(|v| toml::to_string(&v))
            .expect("a command serialises as TOML");
        text.lines()
            .map(|l| {
                if l.is_empty() {
                    "+".to_string()
                } else {
                    format!("+ {l}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    /// The revised manifest. Call only after the user approved this
    /// proposal. `DigestMismatch` when `base` is not the manifest it was
    /// made against.
    pub fn apply(&self, base: &Manifest) -> Result<Manifest, ManifestError> {
        let actual = base.digest();
        if actual != self.base {
            return Err(ManifestError::DigestMismatch {
                expected: self.base,
                actual,
            });
        }
        self.revised(base)
    }

    fn revised(&self, base: &Manifest) -> Result<Manifest, ManifestError> {
        if base.commands.contains_key(&self.name) {
            return Err(ManifestError::invalid(format!(
                "commands.{}: a command with this name exists",
                self.name
            )));
        }
        let mut m = base.clone();
        m.commands.insert(self.name.clone(), self.command.clone());
        validate::cross_check(&m)?;
        Ok(m)
    }
}
