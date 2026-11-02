//! Property tests: resolver safety, parser robustness, digest order.

mod common;

use common::*;
use damavand_manifest::pattern::is_forbidden_char;
use damavand_manifest::{Args, Manifest};
use proptest::prelude::*;

const CMD: &str = r#"
[commands.c]
argv = ["prog", "lit", "--", "{p}", "{e}", "{f}", "{d}"]
timeout_secs = 10
args.p = { type = "string", max_len = 64, constraint = { pattern = "[a-z0-9_]+" } }
args.e = { type = "string", constraint = { enum = ["safe", "also-safe"] } }
args.f = { type = "string", max_len = 64 }
args.d = { type = "string", max_len = 64, allow_option = true }
"#;

/// Values an attacker would try: shell and quoting metacharacters, dashes,
/// controls, bidi and zero-width characters, separators, plus plain text.
fn hostile() -> impl Strategy<Value = String> {
    let atoms = prop_oneof![
        Just("-".to_string()),
        Just("--".to_string()),
        Just("@".to_string()),
        Just("+".to_string()),
        Just("/".to_string()),
        Just("..".to_string()),
        Just("=".to_string()),
        Just(";".to_string()),
        Just("$(id)".to_string()),
        Just("`id`".to_string()),
        Just("|".to_string()),
        Just("&&".to_string()),
        Just("'".to_string()),
        Just("\"".to_string()),
        Just("\\".to_string()),
        Just(">".to_string()),
        Just("\n".to_string()),
        Just("\0".to_string()),
        Just("\u{202e}".to_string()),
        Just("\u{200d}".to_string()),
        Just("\u{2028}".to_string()),
        Just(" ".to_string()),
        Just("safe".to_string()),
        Just("{p}".to_string()),
        "[a-z0-9_]{1,6}",
        any::<char>().prop_map(String::from),
    ];
    prop::collection::vec(atoms, 0..6).prop_map(|v| v.concat())
}

fn opt(s: impl Strategy<Value = String>) -> impl Strategy<Value = Option<String>> {
    prop::option::of(s)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn resolve_never_lets_hostile_input_through_unflagged(
        p in opt(hostile()), e in opt(hostile()), f in opt(hostile()), d in opt(hostile()),
    ) {
        let m = parse(&with(CMD));
        let cmd = m.command("c").unwrap();
        let mut args = Args::new();
        let given: Vec<(&str, &String)> = [("p", &p), ("e", &e), ("f", &f), ("d", &d)]
            .into_iter()
            .filter_map(|(n, v)| v.as_ref().map(|v| (n, v)))
            .collect();
        for (n, v) in &given {
            args = args.with(*n, v.as_str());
        }
        // No argument has allow_path_escape.
        let escapes = |v: &str| {
            v.split('=')
                .any(|p| p.trim_start_matches(['-', '@', '+']).starts_with('/') || p.split(['/', '\\']).any(|s| s == ".."))
        };
        let should_refuse = given.iter().any(|(n, v)| {
            v.contains('\0')
                || (*n != "d" && v.starts_with(['-', '@', '+']))
                || escapes(v)
                || (*n != "e" && v.len() > 64)
        });
        match cmd.resolve(&args) {
            Err(err) => {
                prop_assert!(should_refuse, "refused {given:?}: {err}");
                prop_assert_eq!(err.code(), 2003);
            }
            Ok(r) => {
                prop_assert!(!should_refuse, "accepted {given:?}");
                // The literal prefix is untouched; one element per value.
                prop_assert_eq!(&r.argv[..3], &["prog", "lit", "--"]);
                prop_assert_eq!(r.argv.len(), 3 + given.len());
                for (el, (name, v)) in r.argv[3..].iter().zip(&given) {
                    prop_assert_eq!(el, *v);
                    // Only allow_option args may look like an option.
                    if el.starts_with(['-', '@', '+']) {
                        prop_assert_eq!(*name, "d");
                    }
                    let cleared = !r.uncleared.iter().any(|u| u == name);
                    // A cleared element went through a constraint: it holds
                    // no forbidden character and is not empty.
                    if cleared {
                        prop_assert!(*name == "p" || *name == "e");
                        prop_assert!(!el.is_empty());
                        prop_assert!(!el.chars().any(is_forbidden_char), "{el:?}");
                    }
                    // A forbidden character always means escalation.
                    if el.chars().any(is_forbidden_char) {
                        prop_assert!(!cleared);
                    }
                }
            }
        }
    }

    #[test]
    fn parse_toml_never_panics(text in any::<String>()) {
        let _ = Manifest::parse_toml(&text);
    }

    #[test]
    fn parse_toml_never_panics_on_mutated_fixtures(
        pos in any::<prop::sample::Index>(),
        del in 0usize..8,
        ins in hostile(),
    ) {
        let base = fixture("fixtures/full.toml");
        let mut cut = pos.index(base.len() + 1);
        while !base.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut end = (cut + del).min(base.len());
        while !base.is_char_boundary(end) {
            end -= 1;
        }
        let text = format!("{}{}{}", &base[..cut], ins, &base[end..]);
        if let Ok(m) = Manifest::parse_toml(&text) {
            // Anything accepted round-trips.
            let back = Manifest::from_canonical_json(&m.canonical_json()).unwrap();
            prop_assert_eq!(back.digest(), m.digest());
        }
    }

    #[test]
    fn from_canonical_json_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Manifest::from_canonical_json(&bytes);
    }

    #[test]
    fn digest_ignores_the_order_of_unordered_things(
        egress in Just(vec![
            "\n[[egress]]\nhost = \"a.example.com\"\n",
            "\n[[egress]]\nhost = \"b.example.com\"\nport = 8443\n",
            "\n[[egress]]\nhost = \"b.example.com\"\n",
            "\n[[egress]]\nhost = \"c.example.com\"\n",
        ]).prop_shuffle(),
        secrets in Just(vec![
            "\n[[secrets]]\nname = \"s1\"\nhost = \"a.example.com\"\nheader = \"A\"\n",
            "\n[[secrets]]\nname = \"s2\"\nhost = \"b.example.com\"\nheader = \"B\"\nscheme = \"Bearer\"\n",
            "\n[[secrets]]\nname = \"s0\"\nhost = \"c.example.com\"\nheader = \"C\"\n",
        ]).prop_shuffle(),
        enum_vals in Just(vec!["\"x\"", "\"y\"", "\"z\"", "\"a-b\""]).prop_shuffle(),
        tools in Just(vec!["t1", "t2", "t0", "t3"]).prop_shuffle(),
        top in Just(vec!["schema = 1", "id = \"m\"", "kind = \"connector\"", "audit = \"full\""]).prop_shuffle(),
        params in Just(vec![
            "params.a = { type = \"integer\" }",
            "params.b = { type = \"boolean\" }",
            "params.c = { type = \"string\" }",
        ]).prop_shuffle(),
        caps in Just(vec!["read = 1", "draft = 2", "\"write.remote\" = 0"]).prop_shuffle(),
    ) {
        let build = |top: &[&str], egress: &[&str], secrets: &[&str], enum_vals: &[&str], tools: &[&str], params: &[&str], caps: &[&str]| {
            let mut s = top.join("\n") + "\n";
            s += &egress.concat();
            s += &secrets.concat();
            for t in tools {
                s += &format!(
                    "\n[[tools]]\nid = \"{t}\"\nupstream = \"up_{t}\"\nclass = \"read\"\nparams.e = {{ type = \"string\", constraint = {{ enum = [{}] }} }}\n{}\n",
                    enum_vals.join(", "),
                    params.join("\n"),
                );
            }
            s += &format!("\n[autonomy]\n{}\n", caps.join("\n"));
            s
        };
        let sorted = |mut v: Vec<&'static str>| { v.sort(); v };
        let base = build(
            &["schema = 1", "id = \"m\"", "kind = \"connector\"", "audit = \"full\""],
            &sorted(egress.clone()),
            &sorted(secrets.clone()),
            &sorted(enum_vals.clone()),
            &sorted(tools.clone()),
            &sorted(params.clone()),
            &sorted(caps.clone()),
        );
        let shuffled = build(&top, &egress, &secrets, &enum_vals, &tools, &params, &caps);
        let a = parse(&base);
        let b = parse(&shuffled);
        prop_assert_eq!(a.canonical_json(), b.canonical_json());
        prop_assert_eq!(a.digest(), b.digest());
    }
}
