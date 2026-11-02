//! Proposed command additions.

mod common;

use common::*;
use damavand_manifest::{Args, CommandProposal, ManifestError, wire};

const CLIPPY: &str = r#"
argv = ["cargo", "clippy", "--", "{lint}"]
timeout_secs = 600
output = "errors-only"
args.lint = { type = "string", constraint = { enum = ["-Dwarnings"] }, allow_dash = true }
"#;

#[test]
fn a_proposal_is_pending_until_applied() {
    let base = full();
    let p = CommandProposal::parse(&base, "clippy", CLIPPY).unwrap();
    assert_eq!(p.base(), base.digest());
    assert_eq!(p.name(), "clippy");
    assert_eq!(p.command().timeout_secs(), 600);
    // Not active: the base manifest is unchanged.
    assert!(base.command("clippy").is_none());

    let revised = p.apply(&base).unwrap();
    assert_ne!(revised.digest(), base.digest());
    let r = revised
        .resolve("clippy", &Args::new().with("lint", "-Dwarnings"))
        .unwrap();
    assert_eq!(r.argv, vec!["cargo", "clippy", "--", "-Dwarnings"]);
    assert!(r.uncleared.is_empty());
    // Everything else is kept.
    assert_eq!(revised.commands().count(), base.commands().count() + 1);
    assert_eq!(revised.tools().count(), base.tools().count());
    assert_eq!(revised.id(), base.id());
    // The revised manifest round-trips like any other.
    let back = damavand_manifest::Manifest::from_canonical_json(&revised.canonical_json()).unwrap();
    assert_eq!(back, revised);
}

#[test]
fn apply_refuses_another_base() {
    let base = full();
    let p = CommandProposal::parse(&base, "clippy", CLIPPY).unwrap();
    let revised = p.apply(&base).unwrap();
    // Applying twice: the base moved on.
    let e = p.apply(&revised).unwrap_err();
    assert_eq!(
        e,
        ManifestError::DigestMismatch {
            expected: base.digest(),
            actual: revised.digest()
        }
    );
    assert_eq!(e.code(), wire::codes::DIGEST_MISMATCH);
}

#[test]
fn proposals_are_validated_like_manifests() {
    let base = full();
    for (name, body, want) in [
        ("test", CLIPPY, "exists"),
        ("Bad", CLIPPY, "commands"),
        (
            "x",
            "argv = [\"sh\", \"-c\", \"{s}\"]\ntimeout_secs = 1\nargs.s = { type = \"string\" }\n",
            "`--`",
        ),
        ("x", "argv = [\"x\"]\n", "timeout_secs"),
        (
            "x",
            "argv = [\"x\"]\ntimeout_secs = 1\nshell = true\n",
            "unknown field",
        ),
        (
            "x",
            "argv = [\"x\"]\ntimeout_secs = 1\ncwd = \"..\"\n",
            "cwd",
        ),
        ("x", "argv = [\"x\"\n", ""),
        ("x", "argv = [\"x\"]\ntimeout_secs = 1.0\n", "float"),
    ] {
        let e = CommandProposal::parse(&base, name, body).unwrap_err();
        assert_eq!(e.code(), wire::codes::MANIFEST_INVALID, "{name}: {e}");
        assert!(e.to_string().contains(want), "{name}: {e}");
    }
    let big = format!(
        "argv = [\"x\"]\ntimeout_secs = 1\n#{}\n",
        "x".repeat(256 * 1024)
    );
    assert!(CommandProposal::parse(&base, "x", &big).is_err());
}

#[test]
fn proposals_respect_manifest_level_rules() {
    // Read-only module with audit = metadata: a command would break it.
    let ro = parse(&with("audit = \"metadata\"\n"));
    let e = CommandProposal::parse(&ro, "x", "argv = [\"x\"]\ntimeout_secs = 1\n").unwrap_err();
    assert!(e.to_string().contains("metadata"), "{e}");
    // The command limit counts the base's commands.
    let many: String = (0..damavand_manifest::limits::MAX_COMMANDS)
        .map(|i| format!("\n[commands.c{i}]\nargv = [\"x\"]\ntimeout_secs = 1\n"))
        .collect();
    let full_base = parse(&with(&many));
    let e =
        CommandProposal::parse(&full_base, "x", "argv = [\"x\"]\ntimeout_secs = 1\n").unwrap_err();
    assert!(e.to_string().contains("commands"), "{e}");
}

#[test]
fn diff_shows_the_new_table() {
    let base = full();
    let p = CommandProposal::parse(&base, "clippy", CLIPPY).unwrap();
    let diff = p.diff();
    assert!(
        diff.lines().all(|l| l.starts_with("+ ") || l == "+"),
        "{diff}"
    );
    assert!(diff.contains("[commands.clippy]"), "{diff}");
    assert!(diff.contains("\"cargo\""), "{diff}");
    assert!(diff.contains("timeout_secs = 600"), "{diff}");
    assert!(diff.contains("-Dwarnings"), "{diff}");
    // The diff parses back to the same command (strip the prefixes).
    let toml: String = diff
        .lines()
        .map(|l| l.strip_prefix("+ ").unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let reparsed = parse(&format!("{}\n{toml}\n", MINIMAL));
    assert_eq!(reparsed.command("clippy"), Some(p.command()));
}

#[test]
fn proposal_digest_binds_base_name_and_command() {
    let base = full();
    let p = CommandProposal::parse(&base, "clippy", CLIPPY).unwrap();
    let same = CommandProposal::parse(&base, "clippy", &CLIPPY.replace("\n\n", "\n")).unwrap();
    assert_eq!(p.digest(), same.digest());
    let renamed = CommandProposal::parse(&base, "clippy2", CLIPPY).unwrap();
    assert_ne!(p.digest(), renamed.digest());
    let changed = CommandProposal::parse(&base, "clippy", &CLIPPY.replace("600", "601")).unwrap();
    assert_ne!(p.digest(), changed.digest());
    let other_base = parse(MINIMAL);
    let rebased = CommandProposal::parse(&other_base, "clippy", CLIPPY).unwrap();
    assert_ne!(p.digest(), rebased.digest());
    assert_eq!(p.digest().to_string().len(), 64);
}
