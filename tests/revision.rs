//! Proposed command additions.

mod common;

use common::*;
use std::collections::BTreeMap;

use damavand_manifest::{
    Args, ArgvElement, CommandProposal, ManifestError, PROPOSAL_FORBIDDEN_CHARS, wire,
};
use proptest::prelude::*;

const CLIPPY: &str = r#"
argv = ["cargo", "clippy", "--", "{lint}"]
timeout_secs = 600
output = "errors-only"
args.lint = { type = "string", constraint = { enum = ["warnings"] } }
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
        .resolve("clippy", &Args::new().with("lint", "warnings"))
        .unwrap();
    assert_eq!(r.argv, vec!["cargo", "clippy", "--", "warnings"]);
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
            "argv = [\"x\", \"-v\", \"{s}\"]\ntimeout_secs = 1\nargs.s = { type = \"string\" }\n",
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

/// Undo `diff`'s string quoting: `\"`, `\\` and `\u{XXXX}`.
pub fn unquote(q: &str) -> String {
    let inner = q
        .strip_prefix('"')
        .and_then(|q| q.strip_suffix('"'))
        .unwrap_or_else(|| panic!("not quoted: {q:?}"));
    let mut out = String::new();
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            assert!(c != '"', "bare quote in {q:?}");
            out.push(c);
            continue;
        }
        match it.next() {
            Some(e @ ('"' | '\\')) => out.push(e),
            Some('u') => {
                assert_eq!(it.next(), Some('{'), "{q:?}");
                let hex: String = it.by_ref().take_while(|c| *c != '}').collect();
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).unwrap()).unwrap());
            }
            other => panic!("bad escape {other:?} in {q:?}"),
        }
    }
    out
}

/// What a reviewer reads off the diff: argv, env and cwd. Panics on a
/// line it cannot map.
pub fn read_diff(diff: &str) -> (Vec<String>, BTreeMap<String, String>, String) {
    let (mut argv, mut env, mut cwd) = (Vec::new(), BTreeMap::new(), None);
    for line in diff.lines() {
        let line = line.strip_prefix("+ ").expect("every line is added");
        if line.starts_with('[') || line.starts_with('#') {
            continue;
        }
        let (path, value) = line.split_once(" = ").expect("path = value");
        if let Some(i) = path.strip_prefix("argv[").and_then(|r| r.strip_suffix(']')) {
            assert_eq!(i.parse::<usize>().unwrap(), argv.len(), "argv in order");
            argv.push(unquote(value));
        } else if let Some(k) = path.strip_prefix("env.") {
            let k = if k.starts_with('"') {
                unquote(k)
            } else {
                k.to_string()
            };
            assert!(env.insert(k, unquote(value)).is_none(), "env key twice");
        } else if path == "cwd" {
            assert!(cwd.replace(unquote(value)).is_none());
        }
    }
    (argv, env, cwd.expect("cwd shown"))
}

/// The template as the manifest writes it.
pub fn template(c: &damavand_manifest::Command) -> Vec<String> {
    c.argv()
        .iter()
        .map(|e| match e {
            ArgvElement::Literal(s) => s.clone(),
            ArgvElement::Placeholder(n) => format!("{{{n}}}"),
            _ => unreachable!(),
        })
        .collect()
}

#[test]
fn diff_shows_one_field_per_line() {
    let base = full();
    let p = CommandProposal::parse(&base, "clippy", CLIPPY).unwrap();
    let diff = p.diff();
    let want = [
        "+ [commands.clippy]",
        "+ # class: write.worktree (derived from argv; not a field)",
        "+ args.lint.allow_option = false",
        "+ args.lint.allow_path_escape = false",
        "+ args.lint.constraint.enum[0] = \"warnings\"",
        "+ args.lint.max_len = 4096",
        "+ args.lint.required = false",
        "+ args.lint.type = \"string\"",
        "+ argv[0] = \"cargo\"",
        "+ argv[1] = \"clippy\"",
        "+ argv[2] = \"--\"",
        "+ argv[3] = \"{lint}\"",
        "+ cwd = \".\"",
        "+ env = {}",
        "+ max_output_bytes = 1048576",
        "+ options_ok = false",
        "+ output = \"errors-only\"",
        "+ timeout_secs = 600",
    ];
    assert_eq!(diff, want.join("\n"));
    let (argv, env, cwd) = read_diff(&diff);
    assert_eq!(argv, template(p.command()));
    assert!(env.is_empty());
    assert_eq!(cwd, ".");
    // A remote program shows its floor class, and keys outside
    // [a-z0-9_] are quoted.
    let base = parse(&with(
        "\n[commands.k]\nargv = [\"kubectl\", \"version\"]\ntimeout_secs = 1\n",
    ));
    let p = CommandProposal::parse(
        &base,
        "k.get",
        "argv = [\"kubectl\", \"get\", \"pods\"]\ntimeout_secs = 1\n",
    )
    .unwrap();
    let diff = p.diff();
    assert!(
        diff.starts_with("+ [commands.\"k.get\"]\n+ # class: write.remote"),
        "{diff}"
    );
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
    let other_base = parse(&with(
        "\n[commands.t]\nargv = [\"cargo\", \"test\"]\ntimeout_secs = 1\n",
    ));
    let rebased = CommandProposal::parse(&other_base, "clippy", CLIPPY).unwrap();
    assert_ne!(p.digest(), rebased.digest());
    assert_eq!(p.digest().to_string().len(), 64);
}

#[test]
fn proposal_rejection_corpus() {
    let base = full();
    let dir = fixture_path("reject-proposal");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    names.sort();
    assert!(names.len() >= 15, "corpus has {} files", names.len());
    let mut failures = Vec::new();
    for path in &names {
        let text = std::fs::read_to_string(path).unwrap();
        let spec = text
            .lines()
            .next()
            .unwrap()
            .strip_prefix("# expect: ")
            .expect("expect header");
        let (code, want) = spec.split_once(' ').unwrap_or((spec, ""));
        let code: i64 = code.parse().unwrap();
        match CommandProposal::parse(&base, "x", &text) {
            Ok(_) => failures.push(format!("{}: accepted", path.display())),
            Err(e) if e.code() != code || !e.to_string().contains(want) => failures.push(format!(
                "{}: want {code} {want:?}, got {} {e}",
                path.display(),
                e.code()
            )),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn diff_is_printable_ascii_whatever_the_command_holds() {
    // Enum values are not refused for controls or bidi characters, so the
    // diff must show them escaped: what the user reads is what runs.
    let base = full();
    let body = "argv = [\"cargo\", \"--\", \"{p}\"]\ntimeout_secs = 1\nargs.p = { type = \"string\", constraint = { enum = [\"a\\u202Eb\", \"c\\nd\", \"e\\u0085\", \"x\\\\y\", \"q\\\"z\"] } }\n";
    let p = CommandProposal::parse(&base, "x", body).unwrap();
    let diff = p.diff();
    for line in diff.lines() {
        assert!(
            line.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "not printable ASCII: {line:?}"
        );
    }
    assert!(diff.contains("\\u{202E}"), "{diff}");
    assert!(diff.contains("\\u{000A}"), "{diff}");
    assert!(diff.contains("\\u{0085}"), "{diff}");
    assert!(diff.contains(r#""x\\y""#), "{diff}");
    assert!(diff.contains(r#""q\"z""#), "{diff}");
}

/// Printable ASCII without braces (a brace makes a placeholder), heavy on
/// quotes, backslashes and things that look like escapes.
fn plain_char() -> impl Strategy<Value = char> {
    prop_oneof![
        3 => prop::char::range(' ', '~').prop_filter("no braces", |c| *c != '{' && *c != '}'),
        1 => prop::sample::select(vec!['"', '\\', 'u', '0', 'A']),
    ]
}

/// Anything, including controls, bidi and non-ASCII.
fn tricky_char() -> impl Strategy<Value = char> {
    prop_oneof![
        2 => plain_char(),
        1 => prop::sample::select(vec![
            '\n', '\r', '\t', '\u{7f}', '\u{85}', '\u{202e}', '\u{200b}', '\u{2028}', 'é', 'с',
        ]),
        1 => any::<char>(),
    ]
}

/// Mostly printable strings (accepted, so the diff is checked), sometimes
/// tricky ones (refused, so the refusal is checked).
fn tricky_string(max: usize) -> impl Strategy<Value = String> {
    prop_oneof![
        4 => prop::collection::vec(plain_char(), 1..max),
        1 => prop::collection::vec(tricky_char(), 1..max),
    ]
    .prop_map(|v| v.into_iter().collect())
}

/// Literals a proposal may write: printable ASCII without quotes or shell
/// metacharacters; sometimes anything (refused).
fn word_string(max: usize) -> impl Strategy<Value = String> {
    let word = prop::char::range(' ', '~').prop_filter("no metacharacter", |c| {
        !PROPOSAL_FORBIDDEN_CHARS.contains(c)
    });
    prop_oneof![
        4 => prop::collection::vec(word, 1..max),
        1 => prop::collection::vec(tricky_char(), 1..max),
    ]
    .prop_map(|v| v.into_iter().collect())
}

fn printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    /// For any command a proposal is accepted with, the diff is printable
    /// ASCII and reads back to exactly the argv template and cwd that
    /// resolve runs (and the canonical form the digest binds). Any command
    /// whose argv literals or cwd hold a character outside printable ASCII
    /// is refused.
    #[test]
    fn diff_maps_one_to_one_onto_what_runs(
        literals in prop::collection::vec(word_string(12), 0..4),
        cwd in prop::option::of(tricky_string(10)),
        values in prop::collection::vec(tricky_string(8), 1..4),
    ) {
        // The proposal reuses the base's program, as it must.
        let base = parse(&with(
            "\n[commands.b]\nargv = [\"prog\"]\ntimeout_secs = 1\n",
        ));
        let mut table = toml::Table::new();
        let mut argv: Vec<toml::Value> = vec!["prog".into()];
        argv.extend(literals.iter().cloned().map(toml::Value::String));
        argv.push("--".into());
        argv.push("{p}".into());
        table.insert("argv".into(), toml::Value::Array(argv));
        table.insert("timeout_secs".into(), 1.into());
        if let Some(c) = &cwd {
            table.insert("cwd".into(), c.clone().into());
        }
        let enum_values: Vec<toml::Value> =
            values.iter().cloned().map(toml::Value::String).collect();
        let mut constraint = toml::Table::new();
        constraint.insert("enum".into(), toml::Value::Array(enum_values));
        let mut arg = toml::Table::new();
        arg.insert("type".into(), "string".into());
        arg.insert("constraint".into(), toml::Value::Table(constraint));
        let mut args = toml::Table::new();
        args.insert("p".into(), toml::Value::Table(arg));
        table.insert("args".into(), toml::Value::Table(args));
        let text = toml::to_string(&table).unwrap();
        let plain = literals.iter().chain(cwd.iter()).all(|s| printable(s));
        match CommandProposal::parse(&base, "c", &text) {
            // Refused for a reason other than plain text is fine (a
            // wrapper, a duplicate enum value, `..` in cwd), but
            // non-printable text is always refused (checked below).
            Err(_) => {}
            Ok(p) => {
                prop_assert!(plain, "accepted non-printable text: {literals:?} {cwd:?}");
                let diff = p.diff();
                for line in diff.lines() {
                    prop_assert!(printable(line), "{line:?}");
                }
                let (shown_argv, shown_env, shown_cwd) = read_diff(&diff);
                prop_assert_eq!(&shown_argv, &template(p.command()));
                prop_assert_eq!(&shown_env, p.command().env());
                prop_assert_eq!(shown_cwd.as_str(), p.command().cwd());
                // What resolve runs is the template with the value in place.
                let v = &values[0];
                if let Ok(r) = p.command().resolve(&Args::new().with("p", v.as_str())) {
                    let mut want: Vec<String> = shown_argv[..shown_argv.len() - 1].to_vec();
                    want.push(v.clone());
                    prop_assert_eq!(&r.argv, &want);
                    prop_assert_eq!(&r.cwd, &shown_cwd);
                }
                // Applying the proposal adds exactly the command shown.
                let revised = p.apply(&base).unwrap();
                prop_assert_eq!(revised.command("c"), Some(p.command()));
            }
        }
        if !plain {
            prop_assert!(CommandProposal::parse(&base, "c", &text).is_err());
        }
    }
}

#[test]
fn proposal_literals_hold_no_shell_metacharacter() {
    let base = full();
    for c in [
        '\'', '"', '\\', '$', '`', ';', '|', '&', '<', '>', '(', ')', '*', '?', '[', ']', '{', '}',
        '~', '#', '!',
    ] {
        let mut lit = String::from("a");
        lit.push(c);
        let mut argv = toml::Table::new();
        argv.insert(
            "argv".into(),
            toml::Value::Array(vec!["cargo".into(), lit.clone().into()]),
        );
        argv.insert("timeout_secs".into(), 1.into());
        let text = toml::to_string(&argv).unwrap();
        let e = CommandProposal::parse(&base, "x", &text).unwrap_err();
        assert_eq!(e.code(), wire::codes::MANIFEST_INVALID, "{lit:?}: {e}");
        // Braces make a bad placeholder before the metacharacter rule runs.
        if c != '{' && c != '}' {
            assert!(
                e.to_string().contains("shell metacharacter"),
                "{lit:?}: {e}"
            );
        }
    }
    // Plain words, options and paths are fine.
    let ok = "argv = [\"cargo\", \"test\", \"--release\", \"-p\", \"a-b_c.d/e=f+g,h:i@j%k^l\"]\ntimeout_secs = 1\n";
    CommandProposal::parse(&base, "x", ok).unwrap();
}

#[test]
fn proposal_program_must_already_be_approved() {
    // The base runs only cargo; kubectl is refused until the user adds it.
    let base = full();
    let kubectl = "argv = [\"kubectl\", \"get\", \"pods\"]\ntimeout_secs = 1\n";
    let e = CommandProposal::parse(&base, "k", kubectl).unwrap_err();
    assert!(
        e.to_string()
            .contains("not the program of a command in the base manifest"),
        "{e}"
    );
    let with_kubectl = parse(&with(
        "\n[commands.k]\nargv = [\"kubectl\", \"version\"]\ntimeout_secs = 1\n",
    ));
    CommandProposal::parse(&with_kubectl, "k2", kubectl).unwrap();
    // A user-approved shell can be proposed again, but not with code from
    // an argument.
    let with_sh = parse(&with(
        "\n[commands.s]\nargv = [\"sh\", \"scripts/check.sh\"]\ntimeout_secs = 1\n",
    ));
    CommandProposal::parse(
        &with_sh,
        "s2",
        "argv = [\"sh\", \"scripts/lint.sh\"]\ntimeout_secs = 1\n",
    )
    .unwrap();
    let e = CommandProposal::parse(
        &with_sh,
        "s3",
        "argv = [\"sh\", \"-c\", \"--\", \"{code}\"]\ntimeout_secs = 1\nargs.code = { type = \"string\" }\n",
    )
    .unwrap_err();
    assert!(
        e.to_string()
            .contains("follows the code-taking flag \"-c\""),
        "{e}"
    );
    // A placeholder before the flag is not code.
    CommandProposal::parse(
        &with_sh,
        "s4",
        "argv = [\"sh\", \"--\", \"{f}\", \"-c\"]\ntimeout_secs = 1\nargs.f = { type = \"string\", constraint = { enum = [\"a\"] } }\n",
    )
    .unwrap();
}
