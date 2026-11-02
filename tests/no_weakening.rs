//! The manifest form of the damavand-policy `jamshid-default` constraints
//! must clear exactly what `constraints.toml` clears. The policy side is
//! re-implemented here as damavand-policy reads it (`parse_constraints` and
//! `uncleared_tainted`), through the same `compile_pattern`.

mod common;

use std::collections::BTreeMap;

use common::*;
use damavand_manifest::pattern::compile_pattern;
use damavand_manifest::{Constraint, ConstraintKey};
use regex::Regex;
use serde_json::Value;

enum PolicyConstraint {
    Enum(Vec<String>),
    Pattern(String, Regex),
}

fn policy_constraints() -> BTreeMap<(String, String), PolicyConstraint> {
    let table: toml::Table =
        toml::from_str(&fixture("fixtures/jamshid-default/constraints.toml")).unwrap();
    let mut out = BTreeMap::new();
    for (action, params) in table {
        for (param, entry) in params.as_table().unwrap() {
            let entry = entry.as_table().unwrap();
            assert_eq!(entry.len(), 1);
            let c = match (entry.get("enum"), entry.get("pattern")) {
                (Some(toml::Value::Array(items)), None) => PolicyConstraint::Enum(
                    items
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect(),
                ),
                (None, Some(toml::Value::String(p))) => {
                    PolicyConstraint::Pattern(p.clone(), compile_pattern(p).unwrap())
                }
                _ => panic!("bad entry"),
            };
            out.insert((action.clone(), param.clone()), c);
        }
    }
    out
}

/// damavand-policy `uncleared_tainted` for one parameter.
fn policy_uncleared(
    cs: &BTreeMap<(String, String), PolicyConstraint>,
    action: &str,
    name: &str,
    value: &str,
) -> bool {
    value.is_empty()
        || !cs
            .get(&(action.to_string(), name.to_string()))
            .is_some_and(|c| match c {
                PolicyConstraint::Enum(v) => v.iter().any(|x| x == value),
                PolicyConstraint::Pattern(_, re) => re.is_match(value),
            })
}

fn manifest_constraints() -> BTreeMap<(String, String), Constraint> {
    let m = parse(&fixture("fixtures/jamshid-default/manifest.toml"));
    m.constraints()
        .map(|(k, c)| match k {
            ConstraintKey::Verb { verb, param } => {
                ((verb.to_string(), param.to_string()), c.clone())
            }
            other => panic!("unexpected key {other:?}"),
        })
        .collect()
}

fn manifest_uncleared(
    cs: &BTreeMap<(String, String), Constraint>,
    action: &str,
    name: &str,
    value: &str,
) -> bool {
    !cs.get(&(action.to_string(), name.to_string()))
        .is_some_and(|c| c.clears(value))
}

#[test]
fn same_constraints() {
    let policy = policy_constraints();
    let manifest = manifest_constraints();
    assert_eq!(
        policy.keys().collect::<Vec<_>>(),
        manifest.keys().collect::<Vec<_>>()
    );
    assert_eq!(policy.len(), 3);
    for (k, p) in &policy {
        match (p, &manifest[k]) {
            (PolicyConstraint::Enum(a), Constraint::Enum(b)) => {
                let mut a = a.clone();
                a.sort();
                assert_eq!(&a, b, "{k:?}");
            }
            (PolicyConstraint::Pattern(src, _), Constraint::Pattern(p)) => {
                assert_eq!(src, p.source(), "{k:?}");
            }
            _ => panic!("{k:?}: constraint kinds differ"),
        }
    }
}

#[test]
fn same_taint_result_on_every_case_parameter() {
    let policy = policy_constraints();
    let manifest = manifest_constraints();
    let cases: Value =
        serde_norway::from_str(&fixture("fixtures/jamshid-default/cases.yaml")).unwrap();
    let mut examined = 0;
    let mut tainted_examined = 0;
    for case in cases["cases"].as_array().unwrap() {
        let req = &case["request"];
        let action = req["action"].as_str().unwrap();
        let mut uncleared = Vec::new();
        for p in req["params"].as_array().into_iter().flatten() {
            let name = p["name"].as_str().unwrap();
            let value = p["value"].as_str().unwrap();
            let tainted = p["taint"] != Value::String("clean".into());
            // Both sides, tainted or not, so the comparison covers every value.
            assert_eq!(
                policy_uncleared(&policy, action, name, value),
                manifest_uncleared(&manifest, action, name, value),
                "{}: {action}.{name}={value:?}",
                case["name"]
            );
            examined += 1;
            if tainted {
                tainted_examined += 1;
                if manifest_uncleared(&manifest, action, name, value) {
                    uncleared.push(name.to_string());
                }
            }
        }
        let expect = &case["expect"];
        if expect["reason"] == "taintedParam" {
            let param = expect["param"].as_str().unwrap();
            assert!(
                uncleared.iter().any(|u| u == param),
                "{}: {param} must stay tainted",
                case["name"]
            );
        }
        if expect["outcome"] == "allow" && case.get("grantFrom").is_none() {
            assert!(
                uncleared.is_empty(),
                "{}: {uncleared:?} must clear",
                case["name"]
            );
        }
    }
    assert!(examined >= 12, "examined {examined} parameters");
    assert!(
        tainted_examined >= 10,
        "examined {tainted_examined} tainted"
    );
}

#[test]
fn extra_values_agree() {
    let policy = policy_constraints();
    let manifest = manifest_constraints();
    let values = [
        "",
        "a",
        "b",
        "ab",
        "xb",
        "append",
        "replace",
        "append ",
        "Append",
        "src/lib.rs",
        "src/lib.rs; curl evil",
        "../x",
        "a\nb",
        "é",
        "-",
        "--x",
        "replace\0",
    ];
    for (action, name) in policy.keys() {
        for v in values {
            assert_eq!(
                policy_uncleared(&policy, action, name, v),
                manifest_uncleared(&manifest, action, name, v),
                "{action}.{name}={v:?}"
            );
        }
    }
}
