//! Named-command argv resolution.

mod common;

use common::*;
use damavand_manifest::{Args, ArgvElement, ManifestError, Output, wire};
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
    // jobs has no allow_dash: a negative integer starts with '-'.
    let e = args_err(bench.resolve(&Args::new().with("name", "x").with("jobs", "-1")));
    assert!(e.contains("jobs"), "{e}");
    let e = args_err(bench.resolve(&Args::new().with("name", "-rf")));
    assert!(e.contains("name"), "{e}");
    // offset has allow_dash.
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
