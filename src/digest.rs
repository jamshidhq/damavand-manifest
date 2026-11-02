//! RFC 8785 (JCS) canonical JSON and the domain-separated digest.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Domain tag of the manifest digest.
pub const DIGEST_DOMAIN: &str = "damavand-manifest/v1";

/// Largest integer magnitude a manifest holds: 2^53 - 1. JCS writes numbers
/// as IEEE doubles; up to here an integer prints exactly.
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// SHA-256 digest of a manifest's canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestDigest(pub [u8; 32]);

impl ManifestDigest {
    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for ManifestDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for ManifestDigest {
    type Err = String;
    /// Parse 64 lowercase hex characters.
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("digest {s:?} is not 64 lowercase hex characters");
        if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
        }
        Ok(ManifestDigest(out))
    }
}

pub(crate) fn feed(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_be_bytes());
    h.update(field);
}

/// SHA-256 over the length-prefixed domain tag [`DIGEST_DOMAIN`] followed
/// by the canonical bytes, length-prefixed too.
pub fn digest_canonical(canonical: &[u8]) -> ManifestDigest {
    let mut h = Sha256::new();
    feed(&mut h, DIGEST_DOMAIN.as_bytes());
    feed(&mut h, canonical);
    ManifestDigest(h.finalize().into())
}

/// RFC 8785 (JCS) serialisation of a JSON value: no whitespace, object keys
/// sorted by UTF-16 code units, strings escaped as ECMAScript
/// `JSON.stringify` does. `None` for a float or an integer beyond
/// ±[`MAX_SAFE_INTEGER`]: manifests hold integers only.
pub fn canonical_json(value: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Some(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Option<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            let i = n.as_i64()?;
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) {
                return None;
            }
            out.extend_from_slice(i.to_string().as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (n, k) in keys.into_iter().enumerate() {
                if n > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(&map[k], out)?;
            }
            out.push(b'}');
        }
    }
    Some(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}
