//! What a manifest must not touch: the built-in schema verbs and the Never
//! actions. Kept equal to the Damavand schema v1 and damavand-policy.

use serde::{Deserialize, Serialize};

/// Action class. Names match the `class:<name>` groups of the Damavand
/// schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ActionClass {
    /// `class:read`
    #[serde(rename = "read")]
    Read,
    /// `class:draft`
    #[serde(rename = "draft")]
    Draft,
    /// `class:write.worktree`
    #[serde(rename = "write.worktree")]
    WriteWorktree,
    /// `class:write.remote`
    #[serde(rename = "write.remote")]
    WriteRemote,
    /// `class:egress`
    #[serde(rename = "egress")]
    Egress,
    /// `class:k8s.mutate`
    #[serde(rename = "k8s.mutate")]
    K8sMutate,
    /// `class:secret.use`
    #[serde(rename = "secret.use")]
    SecretUse,
    /// `class:never`. A manifest can never set it.
    #[serde(rename = "never")]
    Never,
}

impl ActionClass {
    /// Every class.
    pub fn all() -> &'static [ActionClass] {
        &[
            ActionClass::Read,
            ActionClass::Draft,
            ActionClass::WriteWorktree,
            ActionClass::WriteRemote,
            ActionClass::Egress,
            ActionClass::K8sMutate,
            ActionClass::SecretUse,
            ActionClass::Never,
        ]
    }

    /// The class name without the `class:` prefix.
    pub fn name(self) -> &'static str {
        match self {
            ActionClass::Read => "read",
            ActionClass::Draft => "draft",
            ActionClass::WriteWorktree => "write.worktree",
            ActionClass::WriteRemote => "write.remote",
            ActionClass::Egress => "egress",
            ActionClass::K8sMutate => "k8s.mutate",
            ActionClass::SecretUse => "secret.use",
            ActionClass::Never => "never",
        }
    }

    /// The class for a name without the `class:` prefix.
    pub fn from_name(name: &str) -> Option<Self> {
        ActionClass::all()
            .iter()
            .copied()
            .find(|c| c.name() == name)
    }
}

/// Actions that are Never whatever any bundle or manifest says. Same list as
/// damavand-policy.
pub const NEVER_ACTIONS: &[&str] = &[
    "terraform_apply",
    "terraform_destroy",
    "terraform_import",
    "tofu_apply",
    "tofu_destroy",
    "tofu_import",
];

/// The built-in verbs of the Damavand schema v1 with their fixed class. A
/// manifest never reclassifies them, and no tool id may reuse one.
/// `mcp_call` has no fixed class: each manifest tool sets its own.
pub const SCHEMA_VERBS: &[(&str, Option<ActionClass>)] = &[
    ("j_read", Some(ActionClass::Read)),
    ("j_edit", Some(ActionClass::WriteWorktree)),
    ("draft_pr", Some(ActionClass::Draft)),
    ("run_command", Some(ActionClass::WriteWorktree)),
    ("git_push", Some(ActionClass::WriteRemote)),
    ("http_request", Some(ActionClass::Egress)),
    ("k8s_apply", Some(ActionClass::K8sMutate)),
    ("use_secret", Some(ActionClass::SecretUse)),
    ("mcp_call", None),
    ("terraform_apply", Some(ActionClass::Never)),
];

/// The verb named commands run as.
pub const RUN_COMMAND: &str = "run_command";
/// The verb manifest tools are called through.
pub const MCP_CALL: &str = "mcp_call";

/// The fixed class of a schema verb, `None` when `name` is not one (or is
/// `mcp_call`).
pub fn verb_class(name: &str) -> Option<ActionClass> {
    SCHEMA_VERBS
        .iter()
        .find(|(v, _)| *v == name)
        .and_then(|(_, c)| *c)
}

/// True when `name` is a schema verb, `mcp_call` included.
pub fn is_schema_verb(name: &str) -> bool {
    SCHEMA_VERBS.iter().any(|(v, _)| *v == name)
}

/// True when `name` is a Never action: in [`NEVER_ACTIONS`] or a schema verb
/// of class Never.
pub fn is_never(name: &str) -> bool {
    NEVER_ACTIONS.contains(&name) || verb_class(name) == Some(ActionClass::Never)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names_round_trip() {
        for c in ActionClass::all() {
            assert_eq!(ActionClass::from_name(c.name()), Some(*c));
        }
        assert_eq!(ActionClass::from_name("class:read"), None);
        assert_eq!(ActionClass::from_name("Read"), None);
    }

    #[test]
    fn verbs_and_never() {
        assert_eq!(verb_class("run_command"), Some(ActionClass::WriteWorktree));
        assert_eq!(verb_class("j_read"), Some(ActionClass::Read));
        assert_eq!(verb_class("mcp_call"), None);
        assert_eq!(verb_class("nope"), None);
        assert!(is_schema_verb("mcp_call"));
        assert!(!is_schema_verb("nope"));
        for n in NEVER_ACTIONS {
            assert!(is_never(n), "{n}");
        }
        assert!(!is_never("j_edit"));
        assert!(!is_never("mcp_call"));
    }
}
