//! Pattern safety: the only way a manifest pattern becomes a [`Regex`].
//!
//! Moved from damavand-policy (its `gates` module) unchanged; policy will
//! depend on this module. Until it does, both repos carry the same shared
//! corpus (`tests/patterns.toml`) so the two copies stay equal.
//!
//! A pattern must compile on its own, fit the size limits, be unable to match
//! the empty string, and be unable to match a character in Unicode category
//! `Cc`, `Cf`, `Zl` or `Zp` or a shell or quoting metacharacter
//! (`` $ ` ; | & < > \ " ' ``). It is then anchored as `\A(?:…)\z`.

use regex::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange};
use regex_syntax::hir::{Hir, HirKind};

/// Longest pattern accepted, in bytes.
pub const MAX_PATTERN_LEN: usize = 1024;
/// Compiled-program and lazy-DFA limits for one pattern.
const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Parser nesting limit for one pattern.
const REGEX_NEST_LIMIT: u32 = 64;

/// Why a pattern is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PatternError {
    /// It does not parse alone, is too long, or exceeds the size or nesting
    /// limits.
    Invalid,
    /// It can match a forbidden character.
    TooBroad,
    /// It matches the empty string.
    MatchesEmpty,
}

impl PatternError {
    /// Short name: `invalid`, `too_broad` or `matches_empty`.
    pub fn name(self) -> &'static str {
        match self {
            PatternError::Invalid => "invalid",
            PatternError::TooBroad => "too_broad",
            PatternError::MatchesEmpty => "matches_empty",
        }
    }
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PatternError::Invalid => "pattern is invalid or exceeds a limit",
            PatternError::TooBroad => "pattern can match a forbidden character",
            PatternError::MatchesEmpty => "pattern matches the empty string",
        })
    }
}

impl std::error::Error for PatternError {}

/// Unicode general categories a narrow value never needs and an injection
/// payload does: controls (`Cc`: C0, C1 and DEL, newline included), format
/// characters (`Cf`: bidi controls, zero-width joiners and spaces, U+061C,
/// U+FEFF, tag characters), and line and paragraph separators (`Zl`, `Zp`).
const FORBIDDEN_CATEGORIES: &str = r"[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]";

/// Every character in [`FORBIDDEN_CATEGORIES`] plus the shell and quoting
/// metacharacters `` $ ` ; | & < > \ " ' ``. Built from the Unicode tables
/// of `regex-syntax`, not a hand list.
fn forbidden_unicode() -> ClassUnicode {
    let hir = regex_syntax::parse(FORBIDDEN_CATEGORIES).expect("category class parses");
    let HirKind::Class(Class::Unicode(mut class)) = hir.into_kind() else {
        unreachable!("a bracket class of properties is a Unicode class")
    };
    let ascii = FORBIDDEN_ASCII
        .chars()
        .map(|c| ClassUnicodeRange::new(c, c));
    class.union(&ClassUnicode::new(ascii));
    class
}

const FORBIDDEN_ASCII: &str = "$`;|&<>\\\"'";

fn forbidden_bytes() -> ClassBytes {
    let mut ranges = vec![
        ClassBytesRange::new(0, 0x1f),
        // DEL and every non-ASCII byte: a byte class is not text.
        ClassBytesRange::new(0x7f, 0xff),
    ];
    for b in FORBIDDEN_ASCII.bytes() {
        ranges.push(ClassBytesRange::new(b, b));
    }
    ClassBytes::new(ranges)
}

/// True when `c` is a character no pattern may match: a shell or quoting
/// metacharacter, or a character in `Cc`, `Cf`, `Zl` or `Zp`.
pub fn is_forbidden_char(c: char) -> bool {
    forbidden_unicode()
        .ranges()
        .iter()
        .any(|r| r.start() <= c && c <= r.end())
}

/// True when some string the pattern matches can hold a forbidden
/// character. It walks the parsed pattern and collects every character any
/// literal or class can produce: an over-approximation, so a `false` is a
/// proof.
fn can_match_forbidden(hir: &Hir, uni: &ClassUnicode, bytes: &ClassBytes) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => false,
        HirKind::Literal(lit) => String::from_utf8_lossy(&lit.0)
            .chars()
            .any(|c| uni.ranges().iter().any(|r| r.start() <= c && c <= r.end())),
        HirKind::Class(Class::Unicode(c)) => {
            let mut c = c.clone();
            c.intersect(uni);
            !c.ranges().is_empty()
        }
        HirKind::Class(Class::Bytes(c)) => {
            let mut c = c.clone();
            c.intersect(bytes);
            !c.ranges().is_empty()
        }
        HirKind::Repetition(r) => can_match_forbidden(&r.sub, uni, bytes),
        HirKind::Capture(c) => can_match_forbidden(&c.sub, uni, bytes),
        HirKind::Concat(hs) | HirKind::Alternation(hs) => {
            hs.iter().any(|h| can_match_forbidden(h, uni, bytes))
        }
    }
}

/// Compile a manifest pattern. It must compile on its own (so `x)|(.*`
/// cannot close the anchoring group), fit the size limits, and be unable to
/// match a forbidden character. It is then anchored as `\A(?:…)\z`.
pub fn compile_pattern(pattern: &str) -> Result<Regex, PatternError> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(PatternError::Invalid);
    }
    let build = |p: &str| {
        RegexBuilder::new(p)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .nest_limit(REGEX_NEST_LIMIT)
            .build()
            .map_err(|_| PatternError::Invalid)
    };
    build(pattern)?;
    let hir = regex_syntax::ParserBuilder::new()
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .parse(pattern)
        .map_err(|_| PatternError::Invalid)?;
    if can_match_forbidden(&hir, &forbidden_unicode(), &forbidden_bytes()) {
        return Err(PatternError::TooBroad);
    }
    let re = build(&format!(r"\A(?:{pattern})\z"))?;
    // An empty value carries nothing to check; a pattern that clears it
    // clears an omitted value.
    if re.is_match("") {
        return Err(PatternError::MatchesEmpty);
    }
    Ok(re)
}

#[cfg(test)]
mod tests {
    use super::*;

    // damavand-policy checks through `constraint_clears`; a compiled pattern
    // clears exactly when it matches.
    fn clears(p: &str, v: &str) -> bool {
        compile_pattern(p).unwrap().is_match(v)
    }

    #[test]
    fn pattern_is_anchored() {
        assert!(clears("[a-z]+", "abc"));
        assert!(!clears("[a-z]+", "abc1"));
        assert!(!clears("[a-z]+", "1abc"));
        assert!(!clears("[a-z]+", "abc\n"));
        assert!(!clears("a|b", "xb"));
        assert!(!clears("a|b", "ax"));
        assert!(clears("a|b", "b"));
    }

    #[test]
    fn pattern_that_breaks_out_or_does_not_parse_is_invalid() {
        for p in ["x)|(.*", "(", "a{1000}{1000}"] {
            assert_eq!(
                compile_pattern(p).unwrap_err(),
                PatternError::Invalid,
                "{p}"
            );
        }
        let deep = format!("{}a{}", "(".repeat(100), ")".repeat(100));
        assert_eq!(compile_pattern(&deep).unwrap_err(), PatternError::Invalid);
    }

    #[test]
    fn pattern_length_is_limited() {
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert_eq!(compile_pattern(&long).unwrap_err(), PatternError::Invalid);
        let ok = "a".repeat(MAX_PATTERN_LEN);
        assert!(clears(&ok, &ok));
    }

    #[test]
    fn broad_patterns_are_refused() {
        for p in [
            ".*",
            "(?s).*",
            ".+",
            r"[\s\S]*",
            r"\S+",
            "[^x]*",
            ".*x",
            "[[:print:]]+",
            ".{0,999}",
            "a|.",
            "(a|b;)",
            r"\$",
            "[\u{202e}]",
            r"\x7f",
            r"(?-u:[\x00-\x7f])",
            r"(?i)[a-z|]+",
            "\u{0}",
        ] {
            assert_eq!(
                compile_pattern(p).unwrap_err(),
                PatternError::TooBroad,
                "{p:?}"
            );
        }
        for p in [
            // Bundle authors spell word characters out: `\w` admits ZWJ.
            "[a-z0-9_]+",
            "[a-z0-9/._-]+",
            "[a-z ]{1,40}",
            "append|replace",
            r"(?-u:[a-z])+",
            r"\bx\b",
            "é",
        ] {
            assert!(compile_pattern(p).is_ok(), "{p:?}");
        }
    }

    #[test]
    fn format_separator_and_control_chars_are_refused() {
        for p in [
            r"\w+",
            "[\u{200d}]",
            "[\u{200c}]",
            "[\u{200b}]",
            "[\u{2028}]",
            "[\u{2029}]",
            "[\u{061c}]",
            "[\u{feff}]",
            "[\u{e0041}]",
            r"\p{Cf}",
            r"\p{Zl}",
            r"[a-z\x{ad}]+",
            "a\u{200d}b",
        ] {
            assert_eq!(
                compile_pattern(p).unwrap_err(),
                PatternError::TooBroad,
                "{p:?}"
            );
        }
    }

    #[test]
    fn patterns_matching_empty_are_refused() {
        for p in ["", "a*", "(a|)", "[a-z]{0,3}", "a?", "(?:)"] {
            assert_eq!(
                compile_pattern(p).unwrap_err(),
                PatternError::MatchesEmpty,
                "{p:?}"
            );
        }
    }

    #[test]
    fn forbidden_chars() {
        for c in [
            '$', '`', ';', '|', '&', '<', '>', '\\', '"', '\'', '\n', '\0',
        ] {
            assert!(is_forbidden_char(c), "{c:?}");
        }
        for c in ['\u{202e}', '\u{200d}', '\u{2028}', '\u{2029}', '\u{7f}'] {
            assert!(is_forbidden_char(c), "{c:?}");
        }
        for c in ['a', 'Z', '0', '-', '_', '/', '.', ' ', 'é'] {
            assert!(!is_forbidden_char(c), "{c:?}");
        }
    }
}
