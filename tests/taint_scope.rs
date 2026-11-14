//! Integer and boolean taint clearing is the same for command arguments,
//! tool parameters and verb parameters.

mod common;

use common::*;
use damavand_manifest::{Constraint, ConstraintKey, MAX_SAFE_INTEGER, Manifest};
use serde_json::json;

/// The constraint `constraints()` lists for a key, as text, by the
/// parameter name.
fn constraint_of(m: &Manifest, name: &str) -> Option<Constraint> {
    m.constraints()
        .find(|(k, _)| match k {
            ConstraintKey::Tool { param, .. } | ConstraintKey::Verb { param, .. } => *param == name,
            ConstraintKey::Command { arg, .. } => *arg == name,
            _ => false,
        })
        .map(|(_, c)| c.clone())
}

const TOOL: &str = r#"
[[tools]]
id = "t"
upstream = "t"
class = "read"
params.range = { type = "integer", min = 1, max = 10 }
params.list = { type = "integer", allowed = [8, 2] }
params.yes = { type = "boolean", allowed = [true] }
params.low = { type = "integer", min = 1 }
params.high = { type = "integer", max = 9 }
params.free = { type = "integer" }
params.flag = { type = "boolean" }
"#;

const VERB: &str = r#"schema = 1
id = "m"
kind = "project"

[verbs.j_edit.range]
type = "integer"
min = 1
max = 10

[verbs.j_edit.list]
type = "integer"
allowed = [8, 2]

[verbs.j_edit.yes]
type = "boolean"
allowed = [true]

[verbs.j_edit.mode]
constraint = { enum = ["a"] }
"#;

/// Every manifest form clears the same values.
fn check_clearing(m: &Manifest) {
    let range = constraint_of(m, "range").expect("a two-sided bound clears");
    assert_eq!(range, Constraint::IntegerRange { min: 1, max: 10 });
    for v in ["1", "5", "10"] {
        assert!(range.clears(v), "{v}");
    }
    for v in ["0", "11", "-1", "01", "+1", ""] {
        assert!(!range.clears(v), "{v}");
    }
    let list = constraint_of(m, "list").expect("an allowed list clears");
    assert_eq!(list, Constraint::Integers(vec![2, 8]));
    assert!(list.clears("2") && list.clears("8"));
    assert!(!list.clears("3") && !list.clears("08"));
    let yes = constraint_of(m, "yes").expect("a boolean allowed list clears");
    assert_eq!(yes, Constraint::Booleans(vec![true]));
    assert!(yes.clears("true"));
    assert!(!yes.clears("false") && !yes.clears("1"));
}

#[test]
fn tool_params_clear_like_command_args() {
    let m = parse(&with(TOOL));
    check_clearing(&m);
    // One-sided, unbounded and unlisted values stay tainted.
    for name in ["low", "high", "free", "flag"] {
        assert_eq!(constraint_of(&m, name), None, "{name}");
    }
}

#[test]
fn verb_params_clear_like_command_args() {
    let m = parse(VERB);
    check_clearing(&m);
    assert_eq!(
        constraint_of(&m, "mode"),
        Some(Constraint::Enum(vec!["a".into()]))
    );
}

#[test]
fn tool_param_bounds_reach_the_input_schema() {
    let m = parse(&with(TOOL));
    let s = m.tool("t").unwrap().input_schema();
    assert_eq!(s["properties"]["range"]["minimum"], json!(1));
    assert_eq!(s["properties"]["range"]["maximum"], json!(10));
    // `allowed` clears taint; it is not a shape: no enum in the schema.
    assert!(s["properties"]["list"].get("enum").is_none(), "{s}");
}

#[test]
fn full_fixture_tool_bound_now_clears() {
    let m = full();
    assert_eq!(
        constraint_of(&m, "number"),
        Some(Constraint::IntegerRange {
            min: 1,
            max: 1_000_000
        })
    );
    // A boolean without a list stays tainted.
    assert_eq!(constraint_of(&m, "draft"), None);
}

#[test]
fn allowed_outside_the_bound_is_refused_for_tools_and_verbs() {
    let e = refuse(&with(
        "[[tools]]\nid = \"t\"\nupstream = \"t\"\nclass = \"read\"\nparams.n = { type = \"integer\", min = 1, max = 5, allowed = [3, 6] }\n",
    ));
    assert!(
        e.contains("tools[0].params.n.allowed[1]: 6 is outside 1..=5"),
        "{e}"
    );
    let e = refuse(
        "schema = 1\nid = \"m\"\nkind = \"project\"\n[verbs.j_edit.n]\ntype = \"integer\"\nmin = 1\nmax = 5\nallowed = [3, 6]\n",
    );
    assert!(
        e.contains("verbs.j_edit.n.allowed[1]: 6 is outside 1..=5"),
        "{e}"
    );
}

#[test]
fn verb_params_that_clear_nothing_are_refused() {
    let verb = |body: &str| {
        format!("schema = 1\nid = \"m\"\nkind = \"project\"\n[verbs.j_edit.p]\n{body}")
    };
    for (body, want) in [
        // One-sided or default bounds never clear, so the entry is refused.
        (
            "type = \"integer\"\nmin = 1\n",
            "verbs.j_edit.p: clears no value",
        ),
        (
            "type = \"integer\"\nmax = 9\n",
            "verbs.j_edit.p: clears no value",
        ),
        ("type = \"integer\"\n", "verbs.j_edit.p: clears no value"),
        (
            &format!("type = \"integer\"\nmin = -{MAX_SAFE_INTEGER}\nmax = 5\n"),
            "verbs.j_edit.p: clears no value",
        ),
        ("type = \"boolean\"\n", "verbs.j_edit.p: clears no value"),
        // Same field rules as everywhere else.
        (
            "type = \"integer\"\nconstraint = { enum = [\"1\"] }\nmin = 1\nmax = 2\n",
            "verbs.j_edit.p.constraint: not allowed for type integer",
        ),
        (
            "type = \"boolean\"\nmin = 1\nallowed = [true]\n",
            "verbs.j_edit.p.min: not allowed for type boolean",
        ),
        (
            "constraint = { enum = [\"a\"] }\nallowed = [1]\n",
            "verbs.j_edit.p.allowed: not allowed for type string",
        ),
        ("type = \"string\"\n", "missing field `constraint`"),
        // Not widened: command-only and tool-only fields stay unknown.
        (
            "type = \"integer\"\nallowed = [1]\nallow_option = true\n",
            "unknown field",
        ),
        (
            "type = \"integer\"\nallowed = [1]\nrequired = true\n",
            "unknown field",
        ),
        (
            "constraint = { enum = [\"a\"] }\nmax_len = 3\n",
            "unknown field",
        ),
    ] {
        let e = refuse(&verb(body));
        assert!(e.contains(want), "{body}: {e}");
    }
}

#[test]
fn new_forms_have_exact_canonical_bytes_and_round_trip() {
    let m = parse(VERB);
    let text = String::from_utf8(m.canonical_json()).unwrap();
    let want = concat!(
        r#""verbs":{"j_edit":{"list":{"allowed":[2,8],"max":9007199254740991,"min":-9007199254740991,"type":"integer"},"#,
        r#""mode":{"constraint":{"enum":["a"]}},"range":{"max":10,"min":1,"type":"integer"},"#,
        r#""yes":{"allowed":[true],"type":"boolean"}}}"#
    );
    assert!(text.contains(want), "{text}");
    let t = parse(&with(TOOL));
    let ttext = String::from_utf8(t.canonical_json()).unwrap();
    assert!(
        ttext.contains(r#""list":{"allowed":[2,8],"max":9007199254740991,"min":-9007199254740991,"required":false,"type":"integer"}"#),
        "{ttext}"
    );
    assert!(
        ttext.contains(r#""yes":{"allowed":[true],"required":false,"type":"boolean"}"#),
        "{ttext}"
    );
    for m in [m, t] {
        let bytes = m.canonical_json();
        let back = Manifest::from_canonical_json(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.canonical_json(), bytes);
        let keys = |m: &Manifest| {
            m.constraints()
                .map(|(k, c)| format!("{k:?} {c:?}"))
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(&back), keys(&m));
    }
    // A string verb parameter written with an explicit type is not canonical.
    let bytes = parse(VERB).canonical_json();
    let text = String::from_utf8(bytes).unwrap().replace(
        r#""mode":{"constraint""#,
        r#""mode":{"type":"string","constraint""#,
    );
    assert!(Manifest::from_canonical_json(text.as_bytes()).is_err());
}

#[test]
fn digests_of_manifests_without_the_new_forms_are_unchanged() {
    // Recorded on main at c0010b3, before tool and verb clearing.
    for (file, want) in [
        (
            "fixtures/full.toml",
            "6037f74ce2119ac4a0ead073703a1b72182d6db6bef59db8ef6429608f91b9f0",
        ),
        (
            "fixtures/full-reformatted.toml",
            "6037f74ce2119ac4a0ead073703a1b72182d6db6bef59db8ef6429608f91b9f0",
        ),
        (
            "fixtures/jamshid-default/manifest.toml",
            "cb794778b91cc9dd87c32623b0e32b55907981449f4b04cd56bc5a73808a25e8",
        ),
    ] {
        assert_eq!(parse(&fixture(file)).digest().to_string(), want, "{file}");
    }
}
