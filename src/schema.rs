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

/// Programs that apply infrastructure: Never by owner rule, so no named
/// command may run one. Matched against the basename of `argv[0]`, and of
/// every word of every later literal when `argv[0]` is a
/// [`WRAPPER_PROGRAMS`] entry (`env X=1 tool`, `sh -c "cd d && tool
/// apply"`); see [`program_matches`].
///
/// The check sees only argv. It cannot see through a script or a build
/// tool that runs one of these (`make apply`, `./deploy.sh`, `npx <tool>`,
/// `docker run <image>`): such a command is reviewed with the manifest that
/// names it, and the sandbox bounds what it does.
pub const NEVER_PROGRAMS: &[&str] = &[
    "terraform",
    "tofu",
    "terragrunt",
    "tfp",
    "pulumi",
    "cdk",
    "cdktf",
    "sam",
];

/// Programs that reach remote systems with the module's credentials. A
/// named command whose `argv[0]` (or, behind a wrapper, any later literal
/// word) is one of them is at least class `write.remote` (see
/// [`crate::Command::class`]), so policy autonomy and approval apply; it
/// is never classed lower. Read operations stay possible.
pub const REMOTE_PROGRAMS: &[&str] = &[
    "kubectl",
    "helm",
    "argocd",
    "flux",
    "ansible-playbook",
    "aws",
    "gcloud",
    "az",
];

/// Programs that run another program, or code, given as an argument:
/// shells, interpreters, privilege and process wrappers. They are a lint
/// warning ([`crate::Manifest::lints`]) and make the Never and class checks
/// look at every later word. An entry ending in `*` matches by prefix.
pub const WRAPPER_PROGRAMS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "env", "xargs", "find",
    "nohup", "timeout", "nice", "sudo", "doas", "su", "busybox", "python*", "node", "perl", "ruby",
];

/// Shells and interpreters: whatever code they are given can reach the
/// network with the module's credentials, so a command whose program
/// (`argv[0]`, or a literal word behind a wrapper) is one of them is at
/// least class `write.remote`, like [`REMOTE_PROGRAMS`]. An entry ending in
/// `*` matches by prefix.
pub const INTERPRETER_PROGRAMS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "busybox", "python*",
    "node", "perl", "ruby", "deno", "bun", "lua", "php", "awk", "gawk", "mawk", "nawk",
];

/// Environment variable names no command may set: they change which code
/// runs (loader, interpreter, tool wrappers, search paths, shell start-up).
/// The list from the review plus the siblings `RUSTC_WORKSPACE_WRAPPER`,
/// `RUSTDOC`, `RUSTDOCFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
/// `CARGO_*_LINKER` and `BASHOPTS`. One `*` matches any run of characters.
pub const DENIED_ENV: &[&str] = &[
    "LD_*",
    "DYLD_*",
    "PATH",
    "BASH_ENV",
    "BASHOPTS",
    "ENV",
    "*_OPTIONS",
    "GIT_*",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_*_RUNNER",
    "CARGO_*_LINKER",
    "CARGO_BUILD_*",
    "PYTHON*",
    "NODE_*",
    "PERL5*",
    "IFS",
    "SHELLOPTS",
];

/// `s` matches `pat`, where one `*` in `pat` stands for any run of
/// characters, the empty run included.
pub fn glob_matches(pat: &str, s: &str) -> bool {
    match pat.split_once('*') {
        None => pat == s,
        Some((pre, suf)) => {
            s.len() >= pre.len() + suf.len() && s.starts_with(pre) && s.ends_with(suf)
        }
    }
}

/// True when the environment variable name is in [`DENIED_ENV`].
pub fn is_denied_env(name: &str) -> bool {
    DENIED_ENV.iter().any(|p| glob_matches(p, name))
}

/// The program name of an argv word: the part after the last `/`,
/// lowercased (a case-insensitive file system runs `TOOL` as `tool`).
pub fn program_basename(word: &str) -> String {
    word.rsplit('/').next().unwrap_or(word).to_ascii_lowercase()
}

/// True when the program word (a path or a name) names an entry of `list`:
/// its basename equals the entry, or is the entry followed by a variant
/// suffix that starts with `-`, `_` or `.` (`tool-1.9`, `tool_v2`,
/// `tool.exe`), or by a bare version of digits and dots (`tool3`,
/// `tool1.5`; not `tool8s`). An entry ending in `*` matches by prefix.
pub fn program_matches(list: &[&str], word: &str) -> bool {
    let base = program_basename(word);
    list.iter().any(|entry| {
        if entry.ends_with('*') {
            return glob_matches(entry, &base);
        }
        match base.strip_prefix(entry) {
            Some(rest) => {
                rest.is_empty()
                    || rest.starts_with(['-', '_', '.'])
                    || (rest.starts_with(|c: char| c.is_ascii_digit())
                        && rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
            }
            None => false,
        }
    })
}

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

    #[test]
    fn globs() {
        assert!(glob_matches("LD_*", "LD_PRELOAD"));
        assert!(glob_matches("LD_*", "LD_"));
        assert!(!glob_matches("LD_*", "LD"));
        assert!(!glob_matches("LD_*", "XLD_A"));
        assert!(glob_matches("*_OPTIONS", "JAVA_TOOL_OPTIONS"));
        assert!(!glob_matches("*_OPTIONS", "OPTIONS"));
        assert!(!glob_matches("*_OPTIONS", "_OPTIONS_X"));
        assert!(glob_matches("CARGO_*_RUNNER", "CARGO_TARGET_X_RUNNER"));
        // Prefix and suffix must not overlap.
        assert!(!glob_matches("AB*BC", "ABC"));
        assert!(glob_matches("AB*BC", "ABBC"));
        assert!(glob_matches("PATH", "PATH"));
        assert!(!glob_matches("PATH", "PATHX"));
        assert!(is_denied_env("PYTHONPATH"));
        assert!(is_denied_env("GIT_DIR"));
        assert!(!is_denied_env("RUST_BACKTRACE"));
        assert!(!is_denied_env("CARGO_TERM_COLOR"));
    }

    #[test]
    fn program_names() {
        assert_eq!(program_basename("/usr/bin/Terraform"), "terraform");
        assert_eq!(program_basename("tofu"), "tofu");
        assert_eq!(program_basename("a/"), "");
        for w in [
            "terraform",
            "/opt/terraform",
            "TOFU",
            "terraform-1.9",
            "terraform_1.9",
            "terraform.exe",
            "tofu1",
            "tofu1.6",
            "cdktf",
            "terragrunt",
        ] {
            assert!(program_matches(NEVER_PROGRAMS, w), "{w}");
        }
        for w in [
            "terraformer",
            "samtools",
            "cdkx",
            "cdk8s",
            "tofu1a",
            "tf",
            "",
            "pulumi/",
        ] {
            assert!(!program_matches(NEVER_PROGRAMS, w), "{w}");
        }
        for w in [
            "python",
            "python3",
            "python3.12",
            "/usr/bin/env",
            "sh",
            "busybox",
        ] {
            assert!(program_matches(WRAPPER_PROGRAMS, w), "{w}");
        }
        for w in ["cargo", "shx", "envsubst", "pyth", "nodes"] {
            assert!(!program_matches(WRAPPER_PROGRAMS, w), "{w}");
        }
        // The deny set holds only the apply tools; remote programs are a
        // class floor, not Never.
        for w in REMOTE_PROGRAMS {
            assert!(!program_matches(NEVER_PROGRAMS, w), "{w}");
        }
    }
}
