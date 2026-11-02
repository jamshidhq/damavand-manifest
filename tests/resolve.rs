//! Named-command argv resolution.

mod common;

use common::*;
use damavand_manifest::{ActionClass, Args, ArgvElement, ManifestError, Output, wire};
use serde_json::json;

fn argv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn args_err(r: Result<damavand_manifest::ResolvedArgv, ManifestError>) -> String {
    let e = r.unwrap_err();
    assert_eq!(e.code(), wire::codes::ARGS_INVALID, "{e}");
    e.to_string()
}

#[test]
fn template_is_parsed_into_literals_and_placeholders() {
    let m = full();
    let test = m.command("test").unwrap();
    assert_eq!(
        test.argv(),
        &[
            ArgvElement::Literal("cargo".into()),
            ArgvElement::Literal("test".into()),
            ArgvElement::Literal("--workspace".into()),
            ArgvElement::Literal("--".into()),
            ArgvElement::Placeholder("filter".into()),
        ]
    );
    let names: Vec<_> = m.command("bench").unwrap().args().map(|(n, _)| n).collect();
    assert_eq!(names, vec!["jobs", "name", "offset", "quick"]);
}

#[test]
fn absent_optional_arg_deletes_its_element() {
    let m = full();
    let r = m.command("test").unwrap().resolve(&Args::new()).unwrap();
    assert_eq!(r.argv, argv(&["cargo", "test", "--workspace", "--"]));
    assert_eq!(r.cwd, ".");
    assert_eq!(r.env.get("RUST_BACKTRACE").map(String::as_str), Some("1"));
    assert_eq!(r.env.len(), 1);
    assert_eq!(r.timeout_secs, 900);
    assert_eq!(r.max_output_bytes, 1_048_576);
    assert_eq!(r.output, Output::FailuresOnly);
    assert!(r.uncleared.is_empty());
}

#[test]
fn constrained_value_is_cleared_and_fills_one_element() {
    let m = full();
    let r = m
        .command("test")
        .unwrap()
        .resolve(&Args::new().with("filter", "parse::limits"))
        .unwrap();
    assert_eq!(
        r.argv,
        argv(&["cargo", "test", "--workspace", "--", "parse::limits"])
    );
    assert!(r.uncleared.is_empty());
}

#[test]
fn value_its_constraint_does_not_clear_is_kept_but_uncleared() {
    let m = full();
    let r = m
        .command("test")
        .unwrap()
        .resolve(&Args::new().with("filter", "a b; rm -rf /"))
        .unwrap();
    assert_eq!(r.argv.len(), 5);
    assert_eq!(r.argv[4], "a b; rm -rf /");
    assert_eq!(r.uncleared, vec!["filter".to_string()]);
}

#[test]
fn empty_value_is_never_cleared() {
    let m = parse(&with(
        "\n[commands.c]\nargv = [\"x\", \"--\", \"{p}\"]\ntimeout_secs = 1\nargs.p = { type = \"string\", constraint = { enum = [\"a\"] } }\n",
    ));
    let r = m
        .command("c")
        .unwrap()
        .resolve(&Args::new().with("p", ""))
        .unwrap();
    assert_eq!(r.argv, argv(&["x", "--", ""]));
    assert_eq!(r.uncleared, vec!["p".to_string()]);
}

#[test]
fn dash_values_are_refused_unless_allowed() {
    let m = full();
    let test = m.command("test").unwrap();
    for v in ["-x", "--all", "-", "--"] {
        let e = args_err(test.resolve(&Args::new().with("filter", v)));
        assert!(e.contains("filter") && e.contains('-'), "{e}");
    }
    let bench = m.command("bench").unwrap();
    // jobs has no allow_option: a negative integer starts with '-'.
    let e = args_err(bench.resolve(&Args::new().with("name", "x").with("jobs", "-1")));
    assert!(e.contains("jobs"), "{e}");
    let e = args_err(bench.resolve(&Args::new().with("name", "-rf")));
    assert!(e.contains("name"), "{e}");
    // offset has allow_option.
    let r = bench
        .resolve(
            &Args::new()
                .with("name", "x")
                .with("offset", "-3")
                .with("jobs", "4")
                .with("quick", "true"),
        )
        .unwrap();
    assert_eq!(
        r.argv,
        argv(&["cargo", "bench", "-3", "--", "x", "4", "true"])
    );
    assert_eq!(r.cwd, "crates/core");
    assert!(r.env.is_empty());
    // Unconstrained values (free text, integers, booleans) are never cleared.
    assert_eq!(r.uncleared, argv(&["jobs", "name", "offset", "quick"]));
}

#[test]
fn shape_is_checked() {
    let m = full();
    let bench = m.command("bench").unwrap();
    let base = || Args::new().with("name", "x");
    for (arg, v) in [
        ("offset", "11"),
        ("offset", "-11"),
        ("offset", "abc"),
        ("offset", "+1"),
        ("offset", "01"),
        ("offset", "1.0"),
        ("offset", ""),
        ("offset", "99999999999999999999"),
        ("jobs", "0"),
        ("jobs", "65"),
        ("quick", "yes"),
        ("quick", "True"),
        ("quick", ""),
    ] {
        let e = args_err(bench.resolve(&base().with(arg, v)));
        assert!(e.contains(arg), "{arg}={v}: {e}");
    }
    for (arg, v) in [
        ("offset", "10"),
        ("offset", "-10"),
        ("offset", "0"),
        ("jobs", "1"),
        ("jobs", "64"),
        ("quick", "false"),
    ] {
        assert!(bench.resolve(&base().with(arg, v)).is_ok(), "{arg}={v}");
    }
    let test = m.command("test").unwrap();
    let e = args_err(test.resolve(&Args::new().with("filter", "a".repeat(201))));
    assert!(e.contains("200"), "{e}");
    assert!(
        test.resolve(&Args::new().with("filter", "a".repeat(200)))
            .is_ok()
    );
    let e = args_err(test.resolve(&Args::new().with("filter", "a\0b")));
    assert!(e.contains("NUL"), "{e}");
}

#[test]
fn missing_and_unknown_args_are_refused() {
    let m = full();
    let e = args_err(m.command("bench").unwrap().resolve(&Args::new()));
    assert!(e.contains("name") && e.contains("required"), "{e}");
    let e = args_err(
        m.command("fmt")
            .unwrap()
            .resolve(&Args::new().with("x", "1")),
    );
    assert!(e.contains("unknown"), "{e}");
}

#[test]
fn manifest_resolve_reports_unknown_commands() {
    let m = full();
    assert_eq!(
        m.resolve("nope", &Args::new()).unwrap_err(),
        ManifestError::UnknownCommand {
            name: "nope".into()
        }
    );
    let r = m.resolve("fmt", &Args::new()).unwrap();
    assert_eq!(r.argv, argv(&["cargo", "fmt", "--check"]));
    assert_eq!(r.timeout_secs, 60);
}

#[test]
fn args_from_json() {
    let a = Args::from_json(&json!({"s": "x", "n": -3, "b": true})).unwrap();
    assert_eq!(
        a,
        Args::new().with("s", "x").with("n", "-3").with("b", "true")
    );
    assert_eq!(Args::from_json(&json!({})).unwrap(), Args::new());
    for bad in [
        json!([]),
        json!("x"),
        json!({"a": null}),
        json!({"a": 1.5}),
        json!({"a": [1]}),
        json!({"a": {"b": 1}}),
    ] {
        let e = Args::from_json(&bad).unwrap_err();
        assert_eq!(e.code(), wire::codes::ARGS_INVALID, "{bad}");
    }
}

/// One command with a free string argument after `--`.
fn free_arg() -> damavand_manifest::Manifest {
    parse(&with(
        "\n[commands.c]\nargv = [\"x\", \"--\", \"{p}\"]\ntimeout_secs = 1\nargs.p = { type = \"string\" }\n",
    ))
}

#[test]
fn option_like_values_are_refused_unless_allowed() {
    // `@file` (response files: rustc, javac, gcc) and `+toolchain`
    // (rustup proxies, `+opt` options) act like `-` options.
    let m = free_arg();
    let c = m.command("c").unwrap();
    for v in ["@/etc/shadow", "@args.txt", "+nightly", "+", "@"] {
        let e = args_err(c.resolve(&Args::new().with("p", v)));
        assert!(
            e.contains("\"p\"") && e.contains("allow_option"),
            "{v}: {e}"
        );
    }
    // Inside a value they are plain text.
    assert!(c.resolve(&Args::new().with("p", "a@b+c-d")).is_ok());
}

#[test]
fn path_escapes_are_refused_unless_allowed() {
    let m = free_arg();
    let c = m.command("c").unwrap();
    for v in [
        "..",
        "../secrets",
        "a/../../b",
        "a/..",
        "/etc/passwd",
        "/",
        "a\\..\\b",
        "x=../y",
    ] {
        let e = args_err(c.resolve(&Args::new().with("p", v)));
        assert!(
            e.contains("\"p\"") && e.contains("allow_path_escape"),
            "{v}: {e}"
        );
    }
    for v in ["a..b", "...", "a/b", "./a", "a/.../b", "a/b/"] {
        assert!(c.resolve(&Args::new().with("p", v)).is_ok(), "{v}");
    }
}

#[test]
fn option_and_path_flags_are_independent() {
    let m = parse(&with(
        "\n[commands.c]\nargv = [\"x\", \"{o}\", \"{e}\", \"{b}\"]\noptions_ok = true\ntimeout_secs = 1\n\
         args.o = { type = \"string\", allow_option = true }\n\
         args.e = { type = \"string\", allow_path_escape = true }\n\
         args.b = { type = \"string\", allow_option = true, allow_path_escape = true }\n",
    ));
    let c = m.command("c").unwrap();
    let (_, o) = c.args().find(|(n, _)| *n == "o").unwrap();
    assert!(o.allow_option() && !o.allow_path_escape());
    // An option flag does not let a path escape through `=`.
    for v in ["--out=../x", "--out=/etc/passwd", "@/etc/shadow"] {
        let e = args_err(c.resolve(&Args::new().with("o", v)));
        assert!(e.contains("allow_path_escape"), "{v}: {e}");
    }
    assert!(c.resolve(&Args::new().with("o", "--out=x/y")).is_ok());
    // A path flag does not let an option through.
    let e = args_err(c.resolve(&Args::new().with("e", "-x")));
    assert!(e.contains("allow_option"), "{e}");
    assert!(c.resolve(&Args::new().with("e", "../x")).is_ok());
    assert!(c.resolve(&Args::new().with("e", "/abs")).is_ok());
    assert!(c.resolve(&Args::new().with("b", "--out=/abs/../x")).is_ok());
}

#[test]
fn remote_programs_are_at_least_write_remote() {
    for prog in [
        "kubectl",
        "helm",
        "argocd",
        "flux",
        "ansible-playbook",
        "aws",
        "gcloud",
        "az",
        "/usr/local/bin/kubectl",
        "AWS",
        "helm3",
        "kubectl-1.31",
    ] {
        let m = parse(&with(&format!(
            "\n[commands.c]\nargv = [\"{prog}\", \"get\"]\ntimeout_secs = 1\n"
        )));
        let c = m.command("c").unwrap();
        assert_eq!(c.class(), ActionClass::WriteRemote, "{prog}");
        assert_eq!(
            c.resolve(&Args::new()).unwrap().class,
            ActionClass::WriteRemote,
            "{prog}"
        );
    }
    // Behind a wrapper the class follows the wrapped program.
    for argv in [
        r#"["sudo", "kubectl", "apply"]"#,
        r#"["env", "A=1", "/opt/bin/helm", "upgrade"]"#,
        r#"["sh", "-c", "aws s3 sync . s3://b"]"#,
    ] {
        let m = parse(&with(&format!(
            "\n[commands.c]\nargv = {argv}\ntimeout_secs = 1\n"
        )));
        assert_eq!(
            m.command("c").unwrap().class(),
            ActionClass::WriteRemote,
            "{argv}"
        );
    }
    // Not a remote program, and not behind a wrapper: run_command's class.
    for argv in [
        r#"["cargo", "test"]"#,
        r#"["azure-thing"]"#,
        r#"["awsume"]"#,
        r#"["cargo", "kubectl"]"#,
        r#"["sudo"]"#,
    ] {
        let m = parse(&with(&format!(
            "\n[commands.c]\nargv = {argv}\ntimeout_secs = 1\n"
        )));
        let c = m.command("c").unwrap();
        assert_eq!(c.class(), ActionClass::WriteWorktree, "{argv}");
        assert_eq!(
            c.resolve(&Args::new()).unwrap().class,
            ActionClass::WriteWorktree
        );
    }
    assert_eq!(
        full().command("test").unwrap().class(),
        ActionClass::WriteWorktree
    );
}

#[test]
fn values_behind_a_wrapper_can_raise_the_class_or_be_refused() {
    let m = parse(&with(
        "\n[commands.c]\nargv = [\"env\", \"--\", \"{p}\", \"{q}\"]\ntimeout_secs = 1\nargs.p = { type = \"string\" }\nargs.q = { type = \"string\" }\n",
    ));
    let c = m.command("c").unwrap();
    assert_eq!(c.class(), ActionClass::WriteWorktree);
    let r = c.resolve(&Args::new().with("p", "kubectl")).unwrap();
    assert_eq!(r.class, ActionClass::WriteRemote);
    let r = c
        .resolve(&Args::new().with("p", "cargo").with("q", "x;gcloud"))
        .unwrap();
    assert_eq!(r.class, ActionClass::WriteRemote);
    for v in ["terraform", "x/tofu", "pulumi"] {
        let e = args_err(c.resolve(&Args::new().with("p", v)));
        assert!(e.contains("Never program"), "{v}: {e}");
    }
    // Without a wrapper a value is an argument, not a program.
    let m = free_arg();
    let r = m
        .command("c")
        .unwrap()
        .resolve(&Args::new().with("p", "terraform"))
        .unwrap();
    assert_eq!(r.class, ActionClass::WriteWorktree);
}

#[test]
fn remote_programs_are_not_never_programs() {
    for prog in ["kubectl", "helm", "argocd", "flux", "ansible-playbook"] {
        parse(&with(&format!(
            "\n[commands.c]\nargv = [\"{prog}\", \"get\"]\ntimeout_secs = 1\n"
        )));
    }
}

#[test]
fn args_from_json_str_refuses_duplicate_keys() {
    let e = Args::from_json_str(r#"{"a": "x", "a": "-rf"}"#).unwrap_err();
    assert_eq!(e.code(), wire::codes::ARGS_INVALID);
    assert!(e.to_string().contains("duplicate argument \"a\""), "{e}");
    assert_eq!(
        Args::from_json_str(r#"{"s": "x", "n": -3, "b": true}"#).unwrap(),
        Args::new().with("s", "x").with("n", "-3").with("b", "true")
    );
    let e = Args::from_json_str("[]").unwrap_err().to_string();
    assert!(e.contains("expected a JSON object"), "{e}");
    for bad in ["[]", "\"x\"", "{", r#"{"a": null}"#, r#"{"a": 1.5}"#] {
        let e = Args::from_json_str(bad).unwrap_err();
        assert_eq!(e.code(), wire::codes::ARGS_INVALID, "{bad}");
    }
}

#[test]
fn shells_and_interpreters_are_at_least_write_remote() {
    for prog in [
        "sh",
        "bash",
        "/bin/zsh",
        "dash",
        "fish",
        "busybox",
        "python3",
        "python3.12",
        "node",
        "perl",
        "ruby",
        "deno",
        "bun",
        "lua",
        "lua5.4",
        "php",
        "awk",
        "gawk",
    ] {
        let m = parse(&with(&format!(
            "\n[commands.c]\nargv = [\"{prog}\", \"x\"]\ntimeout_secs = 1\n"
        )));
        let c = m.command("c").unwrap();
        assert_eq!(c.class(), ActionClass::WriteRemote, "{prog}");
        assert_eq!(
            c.resolve(&Args::new()).unwrap().class,
            ActionClass::WriteRemote,
            "{prog}"
        );
    }
    // Behind a wrapper too.
    let m = parse(&with(
        "\n[commands.c]\nargv = [\"nice\", \"python3\", \"x.py\"]\ntimeout_secs = 1\n",
    ));
    assert_eq!(m.command("c").unwrap().class(), ActionClass::WriteRemote);
    for prog in ["cargo", "make", "shellcheck", "nodemon", "rubocop"] {
        let m = parse(&with(&format!(
            "\n[commands.c]\nargv = [\"{prog}\", \"x\"]\ntimeout_secs = 1\n"
        )));
        assert_eq!(
            m.command("c").unwrap().class(),
            ActionClass::WriteWorktree,
            "{prog}"
        );
    }
}

#[test]
fn env_values_cannot_set_variables() {
    // `env A=1 prog`: a value with `=` would set a variable, not name a
    // program or argument.
    let m = parse(&with(
        "\n[commands.c]\nargv = [\"/usr/bin/env\", \"--\", \"{p}\", \"{q}\"]\ntimeout_secs = 1\nargs.p = { type = \"string\" }\nargs.q = { type = \"string\" }\n",
    ));
    let c = m.command("c").unwrap();
    for v in ["LD_PRELOAD=x.so", "A=", "=x"] {
        let e = args_err(c.resolve(&Args::new().with("p", "cargo").with("q", v)));
        assert!(e.contains("\"q\"") && e.contains('='), "{v}: {e}");
    }
    assert!(
        c.resolve(&Args::new().with("p", "cargo").with("q", "test"))
            .is_ok()
    );
    // Other programs take `=` in values as before.
    let m = free_arg();
    assert!(
        m.command("c")
            .unwrap()
            .resolve(&Args::new().with("p", "a=b"))
            .is_ok()
    );
}
