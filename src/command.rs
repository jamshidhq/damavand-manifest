//! Named commands: argv templates, never a shell.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::{Deserializer, Error as _, MapAccess, Visitor};
use serde_json::{Map, Value};

use crate::error::ManifestError;
use crate::manifest::{Param, ParamType};
use crate::schema::{
    ActionClass, NEVER_PROGRAMS, REMOTE_PROGRAMS, WRAPPER_PROGRAMS, program_matches,
};

/// The words of an argv that name a program: `argv[0]`, and when `argv[0]`
/// is a wrapper program, every word of every later element (split on
/// anything but `[A-Za-z0-9._/+-]`, so `sh -c "cd d && tool apply"` yields
/// `tool`). The Never and class checks run over these words.
pub(crate) fn program_words<'a>(argv: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut it = argv.into_iter();
    let Some(first) = it.next() else {
        return Vec::new();
    };
    let mut words = vec![first];
    if program_matches(WRAPPER_PROGRAMS, first) {
        for el in it {
            words.extend(
                el.split(|c: char| !(c.is_ascii_alphanumeric() || "._/+-".contains(c)))
                    .filter(|w| !w.is_empty()),
            );
        }
    }
    words
}

/// The literal elements of an argv template.
pub(crate) fn literals(argv: &[ArgvElement]) -> impl Iterator<Item = &str> {
    argv.iter().filter_map(|e| match e {
        ArgvElement::Literal(s) => Some(s.as_str()),
        ArgvElement::Placeholder(_) => None,
    })
}

/// The class of a command run with these program words: `write.remote`
/// when one is a [`REMOTE_PROGRAMS`] entry, else `run_command`'s
/// `write.worktree`.
fn class_of(words: &[&str]) -> ActionClass {
    if words.iter().any(|w| program_matches(REMOTE_PROGRAMS, w)) {
        ActionClass::WriteRemote
    } else {
        ActionClass::WriteWorktree
    }
}

/// Which output filter the tools part applies. The full log is kept either
/// way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Output {
    /// Everything (the default).
    Full,
    /// Error lines only.
    ErrorsOnly,
    /// Test failures only.
    FailuresOnly,
    /// A summary.
    Summary,
}

impl Output {
    /// The name used in manifests.
    pub fn name(self) -> &'static str {
        match self {
            Output::Full => "full",
            Output::ErrorsOnly => "errors-only",
            Output::FailuresOnly => "failures-only",
            Output::Summary => "summary",
        }
    }
}

/// One element of an argv template.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArgvElement {
    /// Passed as written.
    Literal(String),
    /// Replaced, whole, by the value of this argument; removed when the
    /// argument is optional and absent.
    Placeholder(String),
}

/// A named command: an argv template with typed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub(crate) argv: Vec<ArgvElement>,
    pub(crate) cwd: String,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) output: Output,
    pub(crate) timeout_secs: u32,
    pub(crate) max_output_bytes: u64,
    pub(crate) options_ok: bool,
    pub(crate) args: BTreeMap<String, Param>,
}

impl Command {
    /// The argv template.
    pub fn argv(&self) -> &[ArgvElement] {
        &self.argv
    }
    /// Working directory, relative to the worktree, without `..`. Checked
    /// as text only: a symlink in the worktree that leads out of it is for
    /// the executor to refuse (`openat2` with `RESOLVE_BENEATH`).
    pub fn cwd(&self) -> &str {
        &self.cwd
    }
    /// The whole environment (fixed values; nothing is inherited).
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }
    /// Output filter.
    pub fn output(&self) -> Output {
        self.output
    }
    /// Timeout in seconds, 1-3600.
    pub fn timeout_secs(&self) -> u32 {
        self.timeout_secs
    }
    /// Largest output kept, in bytes.
    pub fn max_output_bytes(&self) -> u64 {
        self.max_output_bytes
    }
    /// True when a placeholder may come before `--`.
    pub fn options_ok(&self) -> bool {
        self.options_ok
    }
    /// The action class policy checks this command as: `write.remote` when
    /// its program (`argv[0]`, or a literal word behind a wrapper) is in
    /// [`REMOTE_PROGRAMS`], else `write.worktree` (the class of
    /// `run_command`). Derived from argv, never written in the manifest, so
    /// it cannot be set lower. Argument values can only raise it: see
    /// [`ResolvedArgv::class`].
    pub fn class(&self) -> ActionClass {
        class_of(&program_words(literals(&self.argv)))
    }
    /// Arguments by name.
    pub fn args(&self) -> impl Iterator<Item = (&str, &Param)> {
        self.args.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Fill the template. Refuses (`ArgsInvalid`) an unknown or missing
    /// required argument, a value of the wrong type or shape, a NUL, a
    /// value starting with `-`, `@` or `+` unless the argument has
    /// `allow_option`, an absolute path or `..` path segment unless it has
    /// `allow_path_escape`, and a value that makes a wrapper run a Never
    /// program. A value its constraint does not clear is kept and listed in
    /// [`ResolvedArgv::uncleared`]: every argument is tainted, and policy
    /// escalates the uncleared ones to the user.
    pub fn resolve(&self, args: &Args) -> Result<ResolvedArgv, ManifestError> {
        if let Some(name) = args.0.keys().find(|n| !self.args.contains_key(*n)) {
            return Err(ManifestError::args(format!("unknown argument {name:?}")));
        }
        if let Some((name, _)) = self
            .args
            .iter()
            .find(|(n, p)| p.required() && !args.0.contains_key(*n))
        {
            return Err(ManifestError::args(format!(
                "argument {name:?} is required"
            )));
        }
        let mut uncleared = Vec::new();
        for (name, value) in &args.0 {
            if !check_value(name, &self.args[name], value)? {
                uncleared.push(name.clone());
            }
        }
        let argv: Vec<String> = self
            .argv
            .iter()
            .filter_map(|e| match e {
                ArgvElement::Literal(s) => Some(s.clone()),
                ArgvElement::Placeholder(n) => args.0.get(n).cloned(),
            })
            .collect();
        let words = program_words(argv.iter().map(String::as_str));
        if let Some(w) = words.iter().find(|w| program_matches(NEVER_PROGRAMS, w)) {
            return Err(ManifestError::args(format!(
                "the arguments make the command run {w:?}, a Never program"
            )));
        }
        let class = class_of(&words);
        Ok(ResolvedArgv {
            class,
            argv,
            cwd: self.cwd.clone(),
            env: self.env.clone(),
            timeout_secs: self.timeout_secs,
            max_output_bytes: self.max_output_bytes,
            output: self.output,
            uncleared,
        })
    }
}

/// Check one value against its argument's shape. `Ok(true)` when its
/// constraint clears it. Integer and boolean values never clear taint in
/// v0.1 (they carry no constraint); the owner decides whether they should.
fn check_value(name: &str, p: &Param, value: &str) -> Result<bool, ManifestError> {
    let bad = |why: String| Err(ManifestError::args(format!("argument {name:?}: {why}")));
    if value.contains('\0') {
        return bad("NUL in value".into());
    }
    if value.starts_with(['-', '@', '+']) && !p.allow_option() {
        return bad("value starts with '-', '@' or '+' and allow_option is off".into());
    }
    if !p.allow_path_escape() && is_path_escape(value) {
        return bad(
            "value is an absolute path or holds a `..` segment, and allow_path_escape is off"
                .into(),
        );
    }
    match p.param_type() {
        ParamType::String => {
            let max = p.max_len().unwrap_or(0) as usize;
            if value.len() > max {
                return bad(format!("longer than {max} bytes"));
            }
            Ok(p.constraint().is_some_and(|c| c.clears(value)))
        }
        ParamType::Integer => {
            let n = match value.parse::<i64>() {
                Ok(n) if n.to_string() == value => n,
                _ => return bad("not a decimal integer".into()),
            };
            let (min, max) = (p.min().unwrap_or(i64::MIN), p.max().unwrap_or(i64::MAX));
            if n < min || n > max {
                return bad(format!("{n} is outside {min}..={max}"));
            }
            Ok(false)
        }
        ParamType::Boolean => {
            if value != "true" && value != "false" {
                return bad("not true or false".into());
            }
            Ok(false)
        }
    }
}

/// True when a value, or a part of it after `=` (`--out=/x`), is an
/// absolute path once leading `-`, `@` and `+` are dropped (`@/etc/x`), or
/// has a `..` segment (split on `/` and `\\`). A short option with the path
/// glued on (`-f/etc/x`) is not seen: such an argument needs a constraint.
fn is_path_escape(value: &str) -> bool {
    value.split('=').any(|part| {
        part.trim_start_matches(['-', '@', '+']).starts_with('/')
            || part.split(['/', '\\']).any(|seg| seg == "..")
    })
}

/// Argument values for one command call, by name. Integers and booleans are
/// given in their decimal and `true`/`false` text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args(pub(crate) BTreeMap<String, String>);

impl Args {
    /// No arguments.
    pub fn new() -> Self {
        Args::default()
    }
    /// Add (or replace) one argument.
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.insert(name.into(), value.into());
        self
    }
    /// Arguments from JSON text: an object of strings, integers and
    /// booleans. A key given twice is refused, so the value checked is the
    /// value used. Prefer this over [`Args::from_json`] when the raw text is
    /// at hand.
    pub fn from_json_str(text: &str) -> Result<Args, ManifestError> {
        let NoDupObject(map) = serde_json::from_str(text)
            .map_err(|e| ManifestError::args(format!("arguments: {e}")))?;
        Args::from_json(&Value::Object(map))
    }

    /// Arguments from a JSON object of strings, integers and booleans. A
    /// [`Value`] has already merged duplicate keys (the last one wins), so
    /// this cannot refuse them: parse raw text with [`Args::from_json_str`].
    pub fn from_json(value: &Value) -> Result<Args, ManifestError> {
        let Value::Object(map) = value else {
            return Err(ManifestError::args("arguments must be a JSON object"));
        };
        let mut out = Args::new();
        for (k, v) in map {
            let text = match v {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) if n.is_i64() => n.to_string(),
                _ => {
                    return Err(ManifestError::args(format!(
                        "argument {k:?}: must be a string, an integer or a boolean"
                    )));
                }
            };
            out.0.insert(k.clone(), text);
        }
        Ok(out)
    }
}

/// A JSON object whose keys are all distinct.
struct NoDupObject(Map<String, Value>);

impl<'de> Deserialize<'de> for NoDupObject {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = NoDupObject;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<NoDupObject, A::Error> {
                let mut m = Map::new();
                while let Some((k, v)) = a.next_entry::<String, Value>()? {
                    if m.contains_key(&k) {
                        return Err(A::Error::custom(format!("duplicate argument {k:?}")));
                    }
                    m.insert(k, v);
                }
                Ok(NoDupObject(m))
            }
        }
        d.deserialize_map(V)
    }
}

/// A command ready to run, without a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedArgv {
    /// The action class to check: [`Command::class`], raised to
    /// `write.remote` when a value behind a wrapper names a
    /// [`REMOTE_PROGRAMS`] entry.
    pub class: ActionClass,
    /// Program and arguments. `argv[0]` is a literal.
    pub argv: Vec<String>,
    /// Working directory, relative to the worktree.
    pub cwd: String,
    /// The whole environment.
    pub env: BTreeMap<String, String>,
    /// Timeout in seconds.
    pub timeout_secs: u32,
    /// Largest output kept, in bytes.
    pub max_output_bytes: u64,
    /// Output filter.
    pub output: Output,
    /// Arguments given whose value no constraint clears, sorted.
    pub uncleared: Vec<String>,
}
