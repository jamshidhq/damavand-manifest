#![allow(dead_code)]

use std::path::{Path, PathBuf};

use damavand_manifest::Manifest;

pub fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name)
}

pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).unwrap()
}

pub fn full() -> Manifest {
    Manifest::parse_toml(&fixture("fixtures/full.toml")).unwrap()
}

/// The smallest valid manifest.
pub const MINIMAL: &str = "schema = 1\nid = \"m\"\nkind = \"connector\"\n";

/// MINIMAL plus `extra`.
pub fn with(extra: &str) -> String {
    format!("{MINIMAL}{extra}")
}

pub fn parse(text: &str) -> Manifest {
    match Manifest::parse_toml(text) {
        Ok(m) => m,
        Err(e) => panic!("expected a valid manifest, got {e}\n{text}"),
    }
}

pub fn refuse(text: &str) -> String {
    match Manifest::parse_toml(text) {
        Ok(_) => panic!("expected a refusal\n{text}"),
        Err(e) => e.to_string(),
    }
}
