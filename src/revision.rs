//! A proposed addition of a missing named command.
//!
//! An agent may propose; it never runs the command once. The user approves
//! the diff ([`CommandProposal::diff`]); the core then calls
//! [`CommandProposal::apply`] and commits the result as a user-authored
//! revision with a new digest. The approval flow lives in the core.

use serde_json::Value;
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
    /// resulting manifest would fail on. An agent wrote it, so it is held
    /// to more than a manifest: `argv[0]` may not be a wrapper program
    /// ([`crate::WRAPPER_PROGRAMS`]), and `env` may only name variables in
    /// [`crate::PROPOSAL_ENV_ALLOW`] (none in v0.1).
    pub fn parse(base: &Manifest, name: &str, toml: &str) -> Result<Self, ManifestError> {
        let path = format!("commands.{name}");
        let table = parse_table(toml)?;
        validate::walk_toml_table(&path, &table)?;
        let command = validate::command(
            name,
            validate::raw_command_from_toml(table)?,
            validate::Origin::Agent,
        )?;
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
    /// The change for the user to review, one line per field, each
    /// prefixed with `+ `: a `[commands.<name>]` header, the derived class
    /// as a comment, then `path = value` for every field of the command's
    /// canonical form (`argv[0] = "cargo"`, `env."K" = "v"`,
    /// `args."a".max_len = 200`). Every string is quoted; `"` and `\` are
    /// escaped with `\`, and every character outside printable ASCII as
    /// `\u{XXXX}`. A key is bare only when it is `[a-z0-9_]+`, else quoted.
    /// So the diff is printable ASCII and maps one to one onto the argv,
    /// env and cwd that run.
    pub fn diff(&self) -> String {
        let mut lines = vec![
            format!("[commands.{}]", render_key(&self.name)),
            format!(
                "# class: {} (derived from argv; not a field)",
                self.command.class().name()
            ),
        ];
        render_value("", &command_json(&self.command), &mut lines);
        lines
            .iter()
            .map(|l| format!("+ {l}"))
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

/// A string in double quotes: printable ASCII as is, except `"` and `\`
/// (escaped with `\`); everything else as `\u{XXXX}`.
fn render_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => out.push_str(&format!("\\u{{{:04X}}}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// A key: bare when `[a-z0-9_]+`, else a quoted string.
fn render_key(k: &str) -> String {
    if !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        k.to_string()
    } else {
        render_str(k)
    }
}

/// One `path = value` line per scalar; an empty object or list is written
/// as `{}` or `[]` so that every field shows.
fn render_value(path: &str, v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            for (k, v) in m {
                let key = render_key(k);
                let p = if path.is_empty() {
                    key
                } else {
                    format!("{path}.{key}")
                };
                render_value(&p, v, out);
            }
        }
        Value::Object(_) => out.push(format!("{path} = {{}}")),
        Value::Array(items) if !items.is_empty() => {
            for (i, v) in items.iter().enumerate() {
                render_value(&format!("{path}[{i}]"), v, out);
            }
        }
        Value::Array(_) => out.push(format!("{path} = []")),
        Value::String(s) => out.push(format!("{path} = {}", render_str(s))),
        other => out.push(format!("{path} = {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn strings_are_quoted_and_escaped() {
        assert_eq!(render_str("a b~"), r#""a b~""#);
        assert_eq!(render_str(r#"q"\"#), r#""q\"\\""#);
        assert_eq!(
            render_str("\n\u{7f}é\u{202e}\u{1F600}"),
            r#""\u{000A}\u{007F}\u{00E9}\u{202E}\u{1F600}""#
        );
        // A literal that spells an escape is not the escaped character.
        assert_ne!(render_str("\\u{000A}"), render_str("\n"));
        assert_eq!(render_str(""), r#""""#);
    }

    #[test]
    fn keys_are_bare_only_when_plain() {
        assert_eq!(render_key("max_len9"), "max_len9");
        assert_eq!(render_key("a.b"), r#""a.b""#);
        assert_eq!(render_key("RUST_LOG"), r#""RUST_LOG""#);
        assert_eq!(render_key(""), r#""""#);
        assert_eq!(render_key("a-b"), r#""a-b""#);
    }

    #[test]
    fn every_field_gets_one_line() {
        let mut out = Vec::new();
        render_value(
            "",
            &json!({"env": {"K": "a\nb"}, "args": {}, "argv": ["x", "{p}"], "list": [], "n": 5, "b": true}),
            &mut out,
        );
        assert_eq!(
            out,
            vec![
                "args = {}",
                "argv[0] = \"x\"",
                "argv[1] = \"{p}\"",
                "b = true",
                r#"env."K" = "a\u{000A}b""#,
                "list = []",
                "n = 5",
            ]
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

        #[test]
        fn rendering_is_printable_and_injective(a in any::<String>(), b in any::<String>()) {
            for s in [&a, &b] {
                let r = render_str(s);
                prop_assert!(r.bytes().all(|c| (0x20..=0x7e).contains(&c)), "{r:?}");
            }
            prop_assert_eq!(render_str(&a) == render_str(&b), a == b);
        }
    }
}
