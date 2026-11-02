//! Canonical JSON (RFC 8785), digests and round trips.

mod common;

use common::*;
use damavand_manifest::{
    MAX_SAFE_INTEGER, Manifest, ManifestDigest, ManifestError, canonical_json, digest_canonical,
    wire,
};
use serde_json::json;

const MINIMAL_CANONICAL: &str = r#"{"audit":"full","autonomy":{},"commands":{},"egress":[],"id":"m","kind":"connector","schema":1,"secrets":[],"tools":[],"verbs":{}}"#;

/// SHA-256(u64be(20) || "damavand-manifest/v1" || u64be(len) || canonical),
/// computed outside Rust.
const MINIMAL_DIGEST: &str = "5d427c97f23eb7aef3467b2cc8ea8d271fe2f4a788f733def1813e5e15f5c387";

const MEDIUM: &str = r#"
schema = 1
id = "gh"
kind = "connector"

[[egress]]
host = "api.github.com"

[[tools]]
id = "issue"
upstream = "get_issue"
class = "read"
params.n = { type = "integer", required = true }
params.s = { type = "string", constraint = { enum = ["b", "a"] } }

[commands.ls]
argv = ["ls", "--", "{p}"]
timeout_secs = 5
args.p = { type = "string", constraint = { pattern = "[a-z]+" } }
"#;

const MEDIUM_CANONICAL: &str = concat!(
    r#"{"audit":"full","autonomy":{},"commands":{"ls":{"args":{"p":{"allow_option":false,"allow_path_escape":false,"constraint":{"pattern":"[a-z]+"},"max_len":4096,"required":false,"type":"string"}},"#,
    r#""argv":["ls","--","{p}"],"cwd":".","env":{},"max_output_bytes":1048576,"options_ok":false,"output":"full","timeout_secs":5}},"#,
    r#""egress":[{"host":"api.github.com","port":443}],"id":"gh","kind":"connector","schema":1,"secrets":[],"#,
    r#""tools":[{"class":"read","id":"issue","params":{"n":{"max":9007199254740991,"min":-9007199254740991,"required":true,"type":"integer"},"#,
    r#""s":{"constraint":{"enum":["a","b"]},"max_len":4096,"required":false,"type":"string"}},"upstream":"get_issue"}],"verbs":{}}"#
);

#[test]
fn minimal_golden_bytes_and_digest() {
    let m = parse(MINIMAL);
    assert_eq!(
        String::from_utf8(m.canonical_json()).unwrap(),
        MINIMAL_CANONICAL
    );
    assert_eq!(m.digest().to_string(), MINIMAL_DIGEST);
    assert_eq!(
        digest_canonical(MINIMAL_CANONICAL.as_bytes()).to_string(),
        MINIMAL_DIGEST
    );
}

#[test]
fn medium_golden_bytes() {
    let m = parse(MEDIUM);
    assert_eq!(
        String::from_utf8(m.canonical_json()).unwrap(),
        MEDIUM_CANONICAL
    );
}

#[test]
fn identity_and_secret_scheme_are_written_when_set() {
    let m = full();
    let v: serde_json::Value = serde_json::from_slice(&m.canonical_json()).unwrap();
    assert_eq!(
        v["identity"],
        json!({"aws_role": "arn:aws:iam::123456789012:role/jamshid-reader"})
    );
    assert_eq!(
        v["secrets"],
        json!([
            {"header": "X-Token", "host": "crates.io", "name": "crates_token", "port": 443},
            {"header": "Authorization", "host": "api.github.com", "name": "github_token", "port": 443, "scheme": "Bearer"},
        ])
    );
    assert_eq!(v["autonomy"], json!({"egress": 2, "write.remote": 1}));
    assert_eq!(
        v["verbs"],
        json!({"j_edit": {
            "mode": {"constraint": {"enum": ["append", "replace"]}},
            "path": {"constraint": {"pattern": "[a-z0-9/._-]+"}},
        }})
    );
    assert_eq!(
        v["tools"][0]["params"]["draft"],
        json!({"required": false, "type": "boolean"})
    );
    assert_eq!(
        v["commands"]["bench"]["args"]["offset"],
        json!({"allow_option": true, "allow_path_escape": false, "max": 10, "min": -10, "required": false, "type": "integer"})
    );
}

#[test]
fn reformatted_toml_has_the_same_digest() {
    let a = full();
    let b = parse(&fixture("fixtures/full-reformatted.toml"));
    assert_eq!(a, b);
    assert_eq!(a.canonical_json(), b.canonical_json());
    assert_eq!(a.digest(), b.digest());
}

#[test]
fn round_trip_through_canonical_json() {
    for text in [
        MINIMAL.to_string(),
        MEDIUM.to_string(),
        fixture("fixtures/full.toml"),
    ] {
        let m = parse(&text);
        let bytes = m.canonical_json();
        let back = Manifest::from_canonical_json(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.canonical_json(), bytes);
        assert_eq!(back.digest(), m.digest());
    }
}

#[test]
fn every_change_changes_the_digest() {
    let base = parse(MEDIUM).digest();
    for (from, to) in [
        ("id = \"gh\"", "id = \"gh2\""),
        ("kind = \"connector\"", "kind = \"source\""),
        ("api.github.com\"", "api.github.com\"\nport = 444"),
        ("class = \"read\"", "class = \"draft\""),
        ("upstream = \"get_issue\"", "upstream = \"get_issue2\""),
        ("required = true", "required = false"),
        ("[\"b\", \"a\"]", "[\"b\", \"c\"]"),
        ("timeout_secs = 5", "timeout_secs = 6"),
        ("\"[a-z]+\"", "\"[a-y]+\""),
        ("\"ls\", \"--\"", "\"ls\", \"-l\", \"--\""),
    ] {
        assert!(MEDIUM.contains(from), "{from}");
        let changed = parse(&MEDIUM.replacen(from, to, 1)).digest();
        assert_ne!(changed, base, "{from} -> {to}");
    }
    // Comments and layout do not.
    let commented = MEDIUM.replace("\n[[egress]]", "\n# egress\n\n\n[[egress]]   # here");
    assert_eq!(parse(&commented).digest(), base);
}

#[test]
fn non_canonical_json_is_refused() {
    let m = parse(MINIMAL);
    let good = m.canonical_json();
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&good).unwrap())
            .unwrap();
    let dup_key = MINIMAL_CANONICAL.replacen("{\"audit\"", "{\"audit\":\"full\",\"audit\"", 1);
    let missing_default = MINIMAL_CANONICAL.replacen("\"audit\":\"full\",", "", 1);
    let reordered = MINIMAL_CANONICAL.replacen(
        "\"audit\":\"full\",\"autonomy\":{}",
        "\"autonomy\":{},\"audit\":\"full\"",
        1,
    );
    let unsorted_list = MEDIUM_CANONICAL.replacen("[\"a\",\"b\"]", "[\"b\",\"a\"]", 1);
    assert!(Manifest::from_canonical_json(MEDIUM_CANONICAL.as_bytes()).is_ok());
    for bad in [
        pretty,
        dup_key.into_bytes(),
        missing_default.into_bytes(),
        reordered.into_bytes(),
        unsorted_list.into_bytes(),
        format!("{MINIMAL_CANONICAL}\n").into_bytes(),
        b"not json".to_vec(),
        Vec::new(),
    ] {
        let e = Manifest::from_canonical_json(&bad).unwrap_err();
        assert_eq!(e.code(), wire::codes::MANIFEST_INVALID, "{e}");
    }
    // Unknown fields and floats are refused as in TOML.
    let unknown = MINIMAL_CANONICAL.replacen("{", "{\"aaa\":1,", 1);
    assert!(Manifest::from_canonical_json(unknown.as_bytes()).is_err());
    let float = MEDIUM_CANONICAL.replacen("\"timeout_secs\":5", "\"timeout_secs\":5.0", 1);
    assert!(Manifest::from_canonical_json(float.as_bytes()).is_err());
    let schema = MINIMAL_CANONICAL.replacen("\"schema\":1", "\"schema\":2", 1);
    assert_eq!(
        Manifest::from_canonical_json(schema.as_bytes()).unwrap_err(),
        ManifestError::SchemaUnsupported { schema: 2 }
    );
    // At the limit the size check passes and the JSON parser refuses.
    let at = vec![b' '; damavand_manifest::limits::MAX_CANONICAL_BYTES];
    let e = Manifest::from_canonical_json(&at).unwrap_err().to_string();
    assert!(!e.contains("1 MiB"), "{e}");
    let big = vec![b' '; damavand_manifest::limits::MAX_CANONICAL_BYTES + 1];
    assert!(
        Manifest::from_canonical_json(&big)
            .unwrap_err()
            .to_string()
            .contains("1 MiB")
    );
}

#[test]
fn verify_digest() {
    let m = parse(MINIMAL);
    let d: ManifestDigest = MINIMAL_DIGEST.parse().unwrap();
    assert_eq!(m.verify_digest(&d), Ok(()));
    let other = full().digest();
    assert_eq!(
        m.verify_digest(&other),
        Err(ManifestError::DigestMismatch {
            expected: other,
            actual: d
        })
    );
    assert_eq!(m.verify_digest(&other).unwrap_err().code(), 2004);
}

#[test]
fn digest_hex_parsing() {
    let d: ManifestDigest = MINIMAL_DIGEST.parse().unwrap();
    assert_eq!(d.to_string(), MINIMAL_DIGEST);
    assert_eq!(d.as_bytes()[0], 0x5d);
    for bad in [
        "",
        &MINIMAL_DIGEST[1..],
        &MINIMAL_DIGEST.to_uppercase(),
        &format!("{MINIMAL_DIGEST}0"),
        &MINIMAL_DIGEST.replacen('5', "g", 1),
    ] {
        assert!(bad.parse::<ManifestDigest>().is_err(), "{bad}");
    }
}

#[test]
fn jcs_vectors() {
    let s = |v: serde_json::Value| String::from_utf8(canonical_json(&v).unwrap()).unwrap();
    assert_eq!(
        s(json!({"b": 1, "a": [true, null, false]})),
        r#"{"a":[true,null,false],"b":1}"#
    );
    assert_eq!(
        s(json!("\u{f}\u{1f}\u{2028}é\"\\\n\r\t\u{8}\u{c}/\u{7f}")),
        "\"\\u000f\\u001f\u{2028}é\\\"\\\\\\n\\r\\t\\b\\f/\u{7f}\""
    );
    // UTF-16 order: U+10000 (D800 DC00) sorts before U+FFFF; UTF-8 order
    // would put it after.
    assert_eq!(
        s(json!({"\u{ffff}": 1, "\u{10000}": 2, "a": 3})),
        "{\"a\":3,\"\u{10000}\":2,\"\u{ffff}\":1}"
    );
    // Space (0x20) is the first character written as is.
    assert_eq!(s(json!(" \u{1f}")), "\" \\u001f\"");
    assert_eq!(s(json!(-0)), "0");
    assert_eq!(s(json!(-12)), "-12");
    assert_eq!(s(json!(MAX_SAFE_INTEGER)), "9007199254740991");
    assert_eq!(s(json!(-MAX_SAFE_INTEGER)), "-9007199254740991");
    assert_eq!(s(json!([])), "[]");
    assert_eq!(s(json!({})), "{}");
    assert!(canonical_json(&json!(MAX_SAFE_INTEGER + 1)).is_none());
    assert!(canonical_json(&json!(-MAX_SAFE_INTEGER - 1)).is_none());
    assert!(canonical_json(&json!(u64::MAX)).is_none());
    assert!(canonical_json(&json!([1.5])).is_none());
    assert!(canonical_json(&json!({"a": {"b": 1.0}})).is_none());
}

#[test]
fn capability_params_are_sorted_hex() {
    let a = parse(MINIMAL).digest();
    let b = full().digest();
    let v = wire::capability_params(&[b, a, b]);
    let mut want = vec![a.to_string(), b.to_string()];
    want.sort();
    assert_eq!(v, json!({"digests": want}));
}

#[test]
fn canonical_json_is_walked_like_toml() {
    let long = "a".repeat(4097);
    let m = MEDIUM_CANONICAL.replacen("[\"a\",\"b\"]", &format!("[\"a\",\"{long}\"]"), 1);
    let e = Manifest::from_canonical_json(m.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("tools[0].params.s.constraint.enum[1]: string longer than 4096"),
        "{e}"
    );
    let nul = MEDIUM_CANONICAL.replacen("[\"a\",\"b\"]", "[\"a\",\"b\\u0000\"]", 1);
    let e = Manifest::from_canonical_json(nul.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(e.contains("NUL"), "{e}");
    let huge = MEDIUM_CANONICAL.replacen(
        "\"timeout_secs\":5",
        "\"timeout_secs\":18446744073709551615",
        1,
    );
    let e = Manifest::from_canonical_json(huge.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("commands.ls.timeout_secs: integer 18446744073709551615 is beyond"),
        "{e}"
    );
    let float = MEDIUM_CANONICAL.replacen("\"timeout_secs\":5", "\"timeout_secs\":5.5", 1);
    let e = Manifest::from_canonical_json(float.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(e.contains("commands.ls.timeout_secs: float"), "{e}");
}

#[test]
fn canonical_json_schema_is_read_first() {
    let with_schema =
        |s: &str| MINIMAL_CANONICAL.replacen("\"schema\":1", &format!("\"schema\":{s}"), 1);
    for (s, want) in [("\"1\"", -1), ("1.5", -1), ("true", -1), ("0", 0)] {
        assert_eq!(
            Manifest::from_canonical_json(with_schema(s).as_bytes()).unwrap_err(),
            ManifestError::SchemaUnsupported { schema: want },
            "{s}"
        );
    }
    // A newer version with fields this crate does not know is unsupported,
    // not invalid.
    let newer = with_schema("2").replacen("{", "{\"zzz\":1,", 1);
    assert_eq!(
        Manifest::from_canonical_json(newer.as_bytes()).unwrap_err(),
        ManifestError::SchemaUnsupported { schema: 2 }
    );
    let missing = MINIMAL_CANONICAL.replacen(",\"schema\":1", "", 1);
    let e = Manifest::from_canonical_json(missing.as_bytes()).unwrap_err();
    assert!(e.to_string().contains("schema: missing"), "{e}");
}
