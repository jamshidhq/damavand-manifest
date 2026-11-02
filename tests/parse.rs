//! Parsing, validation rules, limits and the rejection corpus.

mod common;

use common::*;
use damavand_manifest::{
    ActionClass, Audit, Constraint, ConstraintKey, Kind, Manifest, ManifestError, ParamType,
    limits, wire,
};
use serde_json::json;

#[test]
fn rejection_corpus() {
    let dir = fixture_path("reject");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        // Files that are not valid TOML end in `.txt`, so the check-toml hook
        // leaves them alone.
        .filter(|p| p.extension().is_some_and(|x| x == "toml" || x == "txt"))
        .collect();
    names.sort();
    assert!(names.len() >= 100, "corpus has {} files", names.len());
    let mut failures = Vec::new();
    for path in &names {
        let text = std::fs::read_to_string(path).unwrap();
        let header = text.lines().next().unwrap();
        let spec = header.strip_prefix("# expect: ").expect("expect header");
        let (code, want) = spec.split_once(' ').unwrap_or((spec, ""));
        let code: i64 = code.parse().unwrap();
        match Manifest::parse_toml(&text) {
            Ok(_) => failures.push(format!("{}: accepted", path.display())),
            Err(e) => {
                if e.code() != code || !e.to_string().contains(want) {
                    failures.push(format!(
                        "{}: want {code} {want:?}, got {} {e}",
                        path.display(),
                        e.code()
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn full_fixture_is_valid_and_sorted() {
    let m = full();
    assert_eq!(m.id().as_str(), "jamshid");
    assert_eq!(m.kind(), Kind::Project);
    assert_eq!(m.audit(), Audit::Full);
    assert_eq!(
        m.aws_role(),
        Some("arn:aws:iam::123456789012:role/jamshid-reader")
    );
    assert_eq!(m.autonomy_cap(ActionClass::WriteRemote), Some(1));
    assert_eq!(m.autonomy_cap(ActionClass::Egress), Some(2));
    assert_eq!(m.autonomy_cap(ActionClass::Read), None);
    let egress: Vec<_> = m.egress().map(|e| (e.host(), e.port())).collect();
    assert_eq!(
        egress,
        vec![
            ("api.github.com", 443),
            ("crates.io", 443),
            ("static.crates.io", 8443)
        ]
    );
    let secrets: Vec<_> = m
        .secrets()
        .map(|s| (s.name(), s.host(), s.header(), s.scheme()))
        .collect();
    assert_eq!(
        secrets,
        vec![
            ("crates_token", "crates.io", "X-Token", None),
            (
                "github_token",
                "api.github.com",
                "Authorization",
                Some("Bearer")
            ),
        ]
    );
    let tools: Vec<_> = m
        .tools()
        .map(|t| (t.id(), t.upstream(), t.class()))
        .collect();
    assert_eq!(
        tools,
        vec![
            ("gh.comment", "add_issue_comment", ActionClass::WriteRemote),
            ("gh.issue_read", "get_issue", ActionClass::Read),
        ]
    );
    let read = m.tool("gh.issue_read").unwrap();
    let params: Vec<_> = read.params().map(|(n, p)| (n, p.param_type())).collect();
    assert_eq!(
        params,
        vec![
            ("number", ParamType::Integer),
            ("repo", ParamType::String),
            ("state", ParamType::String)
        ]
    );
    let (_, number) = read.params().next().unwrap();
    assert!(number.required());
    assert_eq!((number.min(), number.max()), (Some(1), Some(1_000_000)));
    assert_eq!(number.max_len(), None);
    let (_, state) = read.params().nth(2).unwrap();
    assert!(!state.required());
    assert_eq!(state.max_len(), Some(4096), "default max_len is filled in");
    assert_eq!(
        state.constraint(),
        Some(&Constraint::Enum(vec!["closed".into(), "open".into()]))
    );
    assert!(m.tool("nope").is_none());
    let names: Vec<_> = m.commands().map(|(n, _)| n).collect();
    assert_eq!(names, vec!["bench", "fmt", "test"]);
    let fmt = m.command("fmt").unwrap();
    assert_eq!(fmt.cwd(), ".");
    assert_eq!(fmt.timeout_secs(), 60);
    assert_eq!(fmt.max_output_bytes(), limits::DEFAULT_OUTPUT_BYTES);
    assert_eq!(fmt.output(), damavand_manifest::Output::Full);
    assert!(!fmt.options_ok());
    assert!(fmt.env().is_empty());
    let test = m.command("test").unwrap();
    assert_eq!(test.output(), damavand_manifest::Output::FailuresOnly);
    assert_eq!(
        test.env().get("RUST_BACKTRACE").map(String::as_str),
        Some("1")
    );
    assert!(m.command("bench").unwrap().options_ok());
    assert!(m.command("nope").is_none());
}

#[test]
fn constraints_are_keyed_by_what_they_clear() {
    let m = full();
    let keys: Vec<_> = m.constraints().map(|(k, _)| k).collect();
    assert_eq!(
        keys,
        vec![
            ConstraintKey::Verb {
                verb: "j_edit",
                param: "mode"
            },
            ConstraintKey::Verb {
                verb: "j_edit",
                param: "path"
            },
            ConstraintKey::Tool {
                tool: "gh.issue_read",
                param: "repo"
            },
            ConstraintKey::Tool {
                tool: "gh.issue_read",
                param: "state"
            },
            ConstraintKey::Command {
                command: "test",
                arg: "filter"
            },
        ]
    );
    let (_, mode) = m.constraints().next().unwrap();
    assert_eq!(
        mode,
        &Constraint::Enum(vec!["append".into(), "replace".into()])
    );
}

#[test]
fn constraint_clears_only_non_empty_matches() {
    let m = full();
    let get = |k: ConstraintKey<'_>| m.constraints().find(|(x, _)| *x == k).unwrap().1.clone();
    let mode = get(ConstraintKey::Verb {
        verb: "j_edit",
        param: "mode",
    });
    assert!(mode.clears("append"));
    assert!(!mode.clears("append "));
    assert!(!mode.clears(""));
    let path = get(ConstraintKey::Verb {
        verb: "j_edit",
        param: "path",
    });
    assert!(path.clears("src/lib.rs"));
    assert!(!path.clears("src/lib.rs; curl evil"));
    assert!(!path.clears(""));
    let Constraint::Pattern(p) = &path else {
        panic!("pattern")
    };
    assert_eq!(p.source(), "[a-z0-9/._-]+");
    assert!(p.is_match("a"));
}

#[test]
fn empty_enum_value_cannot_be_written_so_empty_never_clears() {
    // Built past the parser: only `clears` stands between an empty value
    // and a clear.
    let e = Constraint::Enum(vec![String::new(), "a".into()]);
    assert!(!e.clears(""));
    assert!(e.clears("a"));
}

#[test]
fn effective_autonomy_only_lowers() {
    let m = full();
    // manifest caps write.remote at 1 and egress at 2; read has no cap.
    assert_eq!(m.effective_autonomy(ActionClass::WriteRemote, 3, None), 1);
    assert_eq!(m.effective_autonomy(ActionClass::WriteRemote, 0, None), 0);
    assert_eq!(m.effective_autonomy(ActionClass::Egress, 3, Some(1)), 1);
    assert_eq!(m.effective_autonomy(ActionClass::Egress, 3, Some(3)), 2);
    assert_eq!(m.effective_autonomy(ActionClass::Egress, 1, Some(3)), 1);
    assert_eq!(m.effective_autonomy(ActionClass::Read, 3, None), 3);
    assert_eq!(m.effective_autonomy(ActionClass::Read, 2, Some(1)), 1);
    assert_eq!(m.effective_autonomy(ActionClass::Read, 2, Some(3)), 2);
}

#[test]
fn audit_metadata_is_allowed_for_read_only_modules() {
    let m = parse(&with(
        "audit = \"metadata\"\n\n[[egress]]\nhost = \"api.example.com\"\n\n[[tools]]\nid = \"t\"\nupstream = \"t\"\nclass = \"read\"\n",
    ));
    assert_eq!(m.audit(), Audit::Metadata);
    // Without tools at all, still read-only.
    parse(&with("audit = \"metadata\"\n"));
    // One draft tool is no longer read-only.
    let e = refuse(&with(
        "audit = \"metadata\"\n\n[[tools]]\nid = \"t\"\nupstream = \"t\"\nclass = \"draft\"\n",
    ));
    assert!(e.contains("metadata"), "{e}");
}

#[test]
fn every_kind_parses() {
    for (name, kind) in [
        ("project", Kind::Project),
        ("connector", Kind::Connector),
        ("source", Kind::Source),
        ("loop", Kind::Loop),
        ("executor", Kind::Executor),
    ] {
        let m = parse(&format!("schema = 1\nid = \"m\"\nkind = \"{name}\"\n"));
        assert_eq!(m.kind(), kind);
        assert_eq!(kind.name(), name);
    }
}

#[test]
fn ids_follow_the_grammar() {
    for id in ["a", "a.b", "a_b", "a1", "z.9_x"] {
        parse(&format!("schema = 1\nid = \"{id}\"\nkind = \"loop\"\n"));
    }
    for id in ["", "A", "1", "_a", ".a", "a-b", "a b", "aé"] {
        refuse(&format!("schema = 1\nid = \"{id}\"\nkind = \"loop\"\n"));
    }
}

#[test]
fn egress_hosts_are_exact_lowercase_a_labels() {
    for host in [
        "example.com",
        "a.b.c.example.com",
        "xn--bcher-kva.example",
        "a-b.example.com",
        "1.example.com",
        "example.c0m",
    ] {
        parse(&with(&format!("\n[[egress]]\nhost = \"{host}\"\n")));
    }
    let long_label = format!("{}.com", "a".repeat(64));
    let long_host = format!("{}com", "a.".repeat(126));
    for host in [
        "example",
        "*.example.com",
        "Example.com",
        "a..com",
        ".a.com",
        "a.com.",
        "a_b.com",
        "a-.com",
        "1.2.3.4",
        "[::1]",
        long_label.as_str(),
        long_host.as_str(),
    ] {
        let e = refuse(&with(&format!("\n[[egress]]\nhost = \"{host}\"\n")));
        assert!(e.contains("host"), "{host}: {e}");
    }
    // 63-byte label and 253-byte host are the limits.
    parse(&with(&format!(
        "\n[[egress]]\nhost = \"{}.com\"\n",
        "a".repeat(63)
    )));
    let host253 = format!("{}a.com", "a.".repeat(124));
    assert_eq!(host253.len(), 253);
    parse(&with(&format!("\n[[egress]]\nhost = \"{host253}\"\n")));
    // Same host, two ports: two entries.
    let m = parse(&with(
        "\n[[egress]]\nhost = \"a.com\"\nport = 8443\n\n[[egress]]\nhost = \"a.com\"\n",
    ));
    assert_eq!(m.egress().count(), 2);
    parse(&with("\n[[egress]]\nhost = \"a.com\"\nport = 65535\n"));
    parse(&with("\n[[egress]]\nhost = \"a.com\"\nport = 1\n"));
}

#[test]
fn aws_role_grammar() {
    for arn in [
        "arn:aws:iam::123456789012:role/r",
        "arn:aws-us-gov:iam::123456789012:role/path/to/r+=,.@_-",
        "arn:aws-cn:iam::123456789012:role/r",
    ] {
        let m = parse(&with(&format!("\n[identity]\naws_role = \"{arn}\"\n")));
        assert_eq!(m.aws_role(), Some(arn));
    }
    for arn in [
        "arn:aws:iam::12345678901:role/r",
        "arn:aws:iam::123456789012:role/",
        "arn:aws:iam::123456789012:role/r x",
        "arn:aws:sts::123456789012:role/r",
        "xarn:aws:iam::123456789012:role/r",
        "arn:aws:iam::123456789012:role/r\n",
    ] {
        let e = refuse(&with(&format!(
            "\n[identity]\naws_role = {}\n",
            serde_json::to_string(arn).unwrap()
        )));
        assert!(e.contains("aws_role"), "{arn}: {e}");
    }
    // An empty identity table is the same as none.
    assert_eq!(parse(&with("\n[identity]\n")), parse(MINIMAL));
}

#[test]
fn schema_versions() {
    let e = Manifest::parse_toml("schema = 0\nid = \"m\"\nkind = \"loop\"\n").unwrap_err();
    assert_eq!(e, ManifestError::SchemaUnsupported { schema: 0 });
    assert_eq!(e.code(), wire::codes::SCHEMA_UNSUPPORTED);
    // The version is read before the rest, so a future manifest with new
    // fields is reported as unsupported, not invalid.
    let e = Manifest::parse_toml("schema = 2\nid = \"m\"\nkind = \"loop\"\nnew = 1\n").unwrap_err();
    assert_eq!(e, ManifestError::SchemaUnsupported { schema: 2 });
    let e = Manifest::parse_toml("schema = true\nid = \"m\"\nkind = \"loop\"\n").unwrap_err();
    assert_eq!(e, ManifestError::SchemaUnsupported { schema: -1 });
    let e = Manifest::parse_toml("id = \"m\"\nkind = \"loop\"\n").unwrap_err();
    assert_eq!(e.code(), wire::codes::MANIFEST_INVALID);
}

#[test]
fn migrate_passes_the_current_schema_through() {
    let text = fixture("fixtures/full.toml");
    assert_eq!(Manifest::migrate(&text).unwrap(), text);
    for v in [0, 2, -1] {
        let e =
            Manifest::migrate(&format!("schema = {v}\nid = \"m\"\nkind = \"loop\"\n")).unwrap_err();
        assert_eq!(e, ManifestError::SchemaUnsupported { schema: v });
    }
    // An invalid current manifest is not passed through.
    let e = Manifest::migrate(&with("extra = 1\n")).unwrap_err();
    assert_eq!(e.code(), wire::codes::MANIFEST_INVALID);
}

fn tool(i: usize, params: &str) -> String {
    format!("\n[[tools]]\nid = \"t{i}\"\nupstream = \"u{i}\"\nclass = \"read\"\n{params}")
}

#[test]
fn limits_are_inclusive() {
    use limits::*;
    // tools
    let tools = |n: usize| (0..n).map(|i| tool(i, "")).collect::<String>();
    parse(&with(&tools(MAX_TOOLS)));
    assert!(refuse(&with(&tools(MAX_TOOLS + 1))).contains("tools"));
    // params per tool
    let params = |n: usize| {
        tool(
            0,
            &(0..n)
                .map(|i| format!("params.p{i} = {{ type = \"boolean\" }}\n"))
                .collect::<String>(),
        )
    };
    parse(&with(&params(MAX_PARAMS)));
    assert!(refuse(&with(&params(MAX_PARAMS + 1))).contains("params"));
    // commands
    let commands = |n: usize| {
        (0..n)
            .map(|i| format!("\n[commands.c{i}]\nargv = [\"x\"]\ntimeout_secs = 1\n"))
            .collect::<String>()
    };
    parse(&with(&commands(MAX_COMMANDS)));
    assert!(refuse(&with(&commands(MAX_COMMANDS + 1))).contains("commands"));
    // argv
    let argv = |n: usize| {
        let elems = vec!["\"x\""; n].join(", ");
        format!("\n[commands.c]\nargv = [{elems}]\ntimeout_secs = 1\n")
    };
    parse(&with(&argv(MAX_ARGV)));
    assert!(refuse(&with(&argv(MAX_ARGV + 1))).contains("argv"));
    // args per command
    let args = |n: usize| {
        let ph = (0..n).map(|i| format!("\"{{a{i}}}\"")).collect::<Vec<_>>();
        let decl = (0..n)
            .map(|i| format!("args.a{i} = {{ type = \"boolean\" }}\n"))
            .collect::<String>();
        format!(
            "\n[commands.c]\nargv = [\"x\", \"--\", {}]\ntimeout_secs = 1\n{decl}",
            ph.join(", ")
        )
    };
    // argv holds 2 + n elements, so stay under MAX_ARGV.
    parse(&with(&args(MAX_ARGV - 2)));
    // egress
    let egress = |n: usize| {
        (0..n)
            .map(|i| format!("\n[[egress]]\nhost = \"h{i}.example.com\"\n"))
            .collect::<String>()
    };
    parse(&with(&egress(MAX_EGRESS)));
    assert!(refuse(&with(&egress(MAX_EGRESS + 1))).contains("egress"));
    // secrets
    let secrets = |n: usize| {
        egress(1)
            + &(0..n)
                .map(|i| {
                    format!(
                        "\n[[secrets]]\nname = \"s{i}\"\nhost = \"h0.example.com\"\nheader = \"X-{i}\"\n"
                    )
                })
                .collect::<String>()
    };
    parse(&with(&secrets(MAX_SECRETS)));
    assert!(refuse(&with(&secrets(MAX_SECRETS + 1))).contains("secrets"));
    // env
    let env = |n: usize| {
        let vars = (0..n)
            .map(|i| format!("V{i} = \"1\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("\n[commands.c]\nargv = [\"x\"]\ntimeout_secs = 1\nenv = {{ {vars} }}\n")
    };
    parse(&with(&env(MAX_ENV)));
    assert!(refuse(&with(&env(MAX_ENV + 1))).contains("env"));
    // enum
    let enums = |n: usize| {
        let vals = (0..n)
            .map(|i| format!("\"v{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        tool(
            0,
            &format!("params.p = {{ type = \"string\", constraint = {{ enum = [{vals}] }} }}\n"),
        )
    };
    parse(&with(&enums(MAX_ENUM)));
    assert!(refuse(&with(&enums(MAX_ENUM + 1))).contains("enum"));
    // string length
    let s = |n: usize| {
        with(&format!(
            "\n[commands.c]\nargv = [\"{}\"]\ntimeout_secs = 1\n",
            "x".repeat(n)
        ))
    };
    parse(&s(MAX_STRING_BYTES));
    assert!(refuse(&s(MAX_STRING_BYTES + 1)).contains("4096"));
    // key length
    let k = |n: usize| {
        with(&format!(
            "\n[commands.c]\nargv = [\"x\"]\ntimeout_secs = 1\nenv = {{ {} = \"1\" }}\n",
            "K".repeat(n)
        ))
    };
    parse(&k(MAX_STRING_BYTES));
    assert!(refuse(&k(MAX_STRING_BYTES + 1)).contains("4096"));
    // upstream
    let up = |n: usize| {
        with(&format!(
            "\n[[tools]]\nid = \"t\"\nupstream = \"{}\"\nclass = \"read\"\n",
            "u".repeat(n)
        ))
    };
    parse(&up(MAX_UPSTREAM_BYTES));
    assert!(refuse(&up(MAX_UPSTREAM_BYTES + 1)).contains("upstream"));
    // timeout and output
    let t = |n: u64| {
        with(&format!(
            "\n[commands.c]\nargv = [\"x\"]\ntimeout_secs = {n}\n"
        ))
    };
    parse(&t(u64::from(MAX_TIMEOUT_SECS)));
    parse(&t(1));
    assert!(refuse(&t(u64::from(MAX_TIMEOUT_SECS) + 1)).contains("timeout_secs"));
    let o = |n: u64| {
        with(&format!(
            "\n[commands.c]\nargv = [\"x\"]\ntimeout_secs = 1\nmax_output_bytes = {n}\n"
        ))
    };
    parse(&o(MAX_OUTPUT_BYTES));
    parse(&o(1));
    assert!(refuse(&o(MAX_OUTPUT_BYTES + 1)).contains("max_output_bytes"));
    // max_len
    let ml = |n: usize| {
        tool(
            0,
            &format!("params.p = {{ type = \"string\", max_len = {n} }}\n"),
        )
    };
    parse(&with(&ml(MAX_STRING_BYTES)));
    parse(&with(&ml(1)));
    // integers at the JCS limit
    let int = |n: i64| {
        tool(
            0,
            &format!(
                "params.p = {{ type = \"integer\", min = {n}, max = {} }}\n",
                damavand_manifest::MAX_SAFE_INTEGER
            ),
        )
    };
    parse(&with(&int(-damavand_manifest::MAX_SAFE_INTEGER)));
    assert!(refuse(&with(&int(-damavand_manifest::MAX_SAFE_INTEGER - 1))).contains("2^53"));
    // autonomy 0 and 3
    parse(&with("\n[autonomy]\nread = 0\n\"secret.use\" = 3\n"));
}

#[test]
fn file_size_is_limited() {
    // Pad with a comment so only the size differs.
    let pad = |total: usize| {
        let base = MINIMAL.len() + 2;
        format!("{MINIMAL}#{}\n", "x".repeat(total - base))
    };
    let ok = pad(limits::MAX_FILE_BYTES);
    assert_eq!(ok.len(), limits::MAX_FILE_BYTES);
    parse(&ok);
    let big = pad(limits::MAX_FILE_BYTES + 1);
    assert!(refuse(&big).contains("256 KiB"));
}

#[test]
fn input_schema_is_closed() {
    let m = full();
    let schema = m.tool("gh.issue_read").unwrap().input_schema();
    assert_eq!(
        schema,
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "number": {"type": "integer", "minimum": 1, "maximum": 1000000},
                "repo": {"type": "string", "maxLength": 100, "pattern": "^(?:[a-z0-9_.-]+/[a-z0-9_.-]+)$"},
                "state": {"type": "string", "maxLength": 4096, "enum": ["closed", "open"]},
            },
            "required": ["number", "repo"],
        })
    );
    let schema = m.tool("gh.comment").unwrap().input_schema();
    assert_eq!(
        schema,
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "body": {"type": "string", "maxLength": 4000},
                "draft": {"type": "boolean"},
            },
            "required": ["body"],
        })
    );
}

#[test]
fn error_codes() {
    use wire::codes::*;
    assert_eq!(
        [
            MANIFEST_INVALID,
            UNKNOWN_MANIFEST,
            UNKNOWN_COMMAND,
            ARGS_INVALID,
            DIGEST_MISMATCH,
            SCHEMA_UNSUPPORTED
        ],
        [2000, 2001, 2002, 2003, 2004, 2005]
    );
    assert_eq!(
        ManifestError::UnknownManifest { id: "x".into() }.code(),
        2001
    );
    assert_eq!(
        ManifestError::UnknownCommand { name: "x".into() }.code(),
        2002
    );
    assert_eq!(wire::CAPABILITY, "manifest");
    assert_eq!(
        [
            wire::METHOD_GET,
            wire::METHOD_LIST,
            wire::METHOD_VALIDATE,
            wire::METHOD_PROPOSE
        ],
        [
            "manifest/get",
            "manifest/list",
            "manifest/validate",
            "manifest/propose"
        ]
    );
}

#[test]
fn errors_display() {
    let d = full().digest();
    for (e, want) in [
        (
            ManifestError::UnknownManifest { id: "x".into() },
            "unknown manifest \"x\"",
        ),
        (
            ManifestError::UnknownCommand { name: "y".into() },
            "unknown command \"y\"",
        ),
        (
            ManifestError::SchemaUnsupported { schema: 7 },
            "schema version 7 is not supported",
        ),
    ] {
        assert_eq!(e.to_string(), want);
    }
    let e = ManifestError::DigestMismatch {
        expected: d,
        actual: d,
    };
    assert!(e.to_string().contains(&d.to_string()));
}

#[test]
fn limit_values_are_the_documented_ones() {
    use limits::*;
    assert_eq!(MAX_FILE_BYTES, 262_144);
    assert_eq!(MAX_CANONICAL_BYTES, 1_048_576);
    assert_eq!(MAX_STRING_BYTES, 4096);
    assert_eq!(
        (MAX_TOOLS, MAX_PARAMS, MAX_COMMANDS, MAX_ARGV),
        (256, 64, 128, 64)
    );
    assert_eq!(
        (MAX_EGRESS, MAX_SECRETS, MAX_ENV, MAX_ENUM),
        (64, 32, 64, 256)
    );
    assert_eq!(MAX_UPSTREAM_BYTES, 128);
    assert_eq!(MAX_TIMEOUT_SECS, 3600);
    assert_eq!(MAX_OUTPUT_BYTES, 67_108_864);
    assert_eq!(DEFAULT_OUTPUT_BYTES, 1_048_576);
}

#[test]
fn module_id_displays_as_written() {
    let m = full();
    assert_eq!(m.id().to_string(), "jamshid");
}

#[test]
fn patterns_compare_by_source() {
    let a = parse(&with(&tool(
        0,
        "params.p = { type = \"string\", constraint = { pattern = \"[a-z]+\" } }\n",
    )));
    let b = parse(&with(&tool(
        0,
        "params.p = { type = \"string\", constraint = { pattern = \"[a-y]+\" } }\n",
    )));
    let c = |m: &Manifest| m.constraints().next().unwrap().1.clone();
    assert_ne!(c(&a), c(&b));
    assert_eq!(c(&a), c(&a.clone()));
    assert_ne!(a, b);
}

#[test]
fn verb_params_and_integer_bounds_limits() {
    let verb = |n: usize| {
        let body: String = (0..n)
            .map(|i| format!("\n[verbs.j_edit.p{i}]\nconstraint = {{ enum = [\"a\"] }}\n"))
            .collect();
        format!("schema = 1\nid = \"m\"\nkind = \"project\"\n{body}")
    };
    parse(&verb(limits::MAX_PARAMS));
    assert!(refuse(&verb(limits::MAX_PARAMS + 1)).contains("verbs.j_edit"));
    // min == max is one allowed value.
    let m = parse(&with(&tool(
        0,
        "params.p = { type = \"integer\", min = 5, max = 5 }\n",
    )));
    let (_, p) = m.tool("t0").unwrap().params().next().unwrap();
    assert_eq!((p.min(), p.max()), (Some(5), Some(5)));
}

#[test]
fn tool_class_defaults_to_write_remote() {
    let m = parse(&with("\n[[tools]]\nid = \"t\"\nupstream = \"t\"\n"));
    assert_eq!(m.tool("t").unwrap().class(), ActionClass::WriteRemote);
    let m = parse(&with(
        "\n[[tools]]\nid = \"t\"\nupstream = \"t\"\nclass = \"read\"\n",
    ));
    assert_eq!(m.tool("t").unwrap().class(), ActionClass::Read);
}

#[test]
fn secrets_are_bound_to_host_and_port() {
    let m = parse(&with(
        "\n[[egress]]\nhost = \"a.example.com\"\nport = 8443\n\n[[egress]]\nhost = \"b.example.com\"\n\n\
         [[secrets]]\nname = \"s\"\nhost = \"a.example.com\"\nport = 8443\nheader = \"X-Key\"\n\n\
         [[secrets]]\nname = \"t\"\nhost = \"b.example.com\"\nheader = \"X-Key\"\n",
    ));
    let s: Vec<_> = m
        .secrets()
        .map(|s| (s.name(), s.host(), s.port()))
        .collect();
    assert_eq!(
        s,
        vec![("s", "a.example.com", 8443), ("t", "b.example.com", 443)]
    );
    let base = "\n[[egress]]\nhost = \"a.example.com\"\nport = 8443\n\n[[secrets]]\nname = \"s\"\nhost = \"a.example.com\"\nheader = \"X-Key\"\n";
    for (port, want) in [
        ("443", "\"a.example.com\":443 is not in egress"),
        ("0", "port: 0 is not 1-65535"),
        ("65536", "port: 65536 is not 1-65535"),
        ("-1", "port: -1 is not 1-65535"),
    ] {
        let e = refuse(&with(&format!("{base}port = {port}\n")));
        assert!(e.contains(want), "{port}: {e}");
    }
    parse(&with(&format!("{base}port = 8443\n")));
}

#[test]
fn harmless_env_names_are_kept() {
    let m = parse(&with(
        "\n[commands.c]\nargv = [\"x\"]\ntimeout_secs = 1\nenv = { RUST_BACKTRACE = \"1\", CARGO_TERM_COLOR = \"never\", NODE = \"x\", LANG = \"C\", OPTIONS = \"a b\" }\n",
    ));
    assert_eq!(m.command("c").unwrap().env().len(), 5);
}

#[test]
fn lints_name_wrappers_and_read_tools() {
    let m = parse(&with(
        "\n[[tools]]\nid = \"r\"\nupstream = \"get\"\nclass = \"read\"\n\n\
         [[tools]]\nid = \"w\"\nupstream = \"put\"\n\n\
         [commands.a]\nargv = [\"/bin/sh\", \"-c\", \"make\"]\ntimeout_secs = 1\n\n\
         [commands.b]\nargv = [\"python3.12\", \"x.py\"]\ntimeout_secs = 1\n\n\
         [commands.c]\nargv = [\"cargo\", \"sh\"]\ntimeout_secs = 1\n",
    ));
    assert_eq!(
        m.lints(),
        vec![
            "commands.a.argv[0]: \"/bin/sh\" is a wrapper program; it runs whatever its arguments say".to_string(),
            "commands.b.argv[0]: \"python3.12\" is a wrapper program; it runs whatever its arguments say".to_string(),
            "tools.r.class: read is the author's assertion that \"get\" only reads".to_string(),
        ]
    );
    assert!(parse(MINIMAL).lints().is_empty());
    let lints = full().lints();
    assert_eq!(lints.len(), 1, "{lints:?}");
    assert!(
        lints[0].starts_with("tools.gh.issue_read.class"),
        "{lints:?}"
    );
}
