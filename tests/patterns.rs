//! The shared pattern corpus (`tests/patterns.toml`).

mod common;

use damavand_manifest::pattern::{PatternError, compile_pattern};

#[test]
fn shared_pattern_corpus() {
    let table: toml::Table = toml::from_str(&common::fixture("patterns.toml")).unwrap();
    let cases = table["case"].as_array().unwrap();
    assert!(cases.len() >= 45, "{} cases", cases.len());
    let mut seen = std::collections::BTreeMap::new();
    for case in cases {
        let pattern = case["pattern"].as_str().unwrap();
        let expect = case["expect"].as_str().unwrap();
        *seen.entry(expect.to_string()).or_insert(0) += 1;
        let got = compile_pattern(pattern);
        match (&got, expect) {
            (Ok(re), "ok") => {
                for v in case
                    .get("match")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                {
                    assert!(re.is_match(v.as_str().unwrap()), "{pattern:?} ~ {v}");
                }
                for v in case
                    .get("reject")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                {
                    assert!(!re.is_match(v.as_str().unwrap()), "{pattern:?} !~ {v}");
                }
            }
            (Err(e), want) => assert_eq!(e.name(), want, "{pattern:?}"),
            (Ok(_), want) => panic!("{pattern:?}: compiled, want {want}"),
        }
    }
    // Every outcome is exercised.
    for k in ["ok", "invalid", "too_broad", "matches_empty"] {
        assert!(seen.get(k).copied().unwrap_or(0) > 0, "no {k} case");
    }
}

#[test]
fn pattern_error_names_and_display() {
    assert_eq!(PatternError::Invalid.name(), "invalid");
    assert_eq!(PatternError::TooBroad.name(), "too_broad");
    assert_eq!(PatternError::MatchesEmpty.name(), "matches_empty");
    assert!(PatternError::TooBroad.to_string().contains("forbidden"));
    assert!(PatternError::MatchesEmpty.to_string().contains("empty"));
    assert!(PatternError::Invalid.to_string().contains("invalid"));
}
