//! Named commands: argv templates, never a shell.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::error::ManifestError;
use crate::manifest::{Param, ParamType};

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
    /// Working directory, relative to the worktree, without `..`.
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
    /// Arguments by name.
    pub fn args(&self) -> impl Iterator<Item = (&str, &Param)> {
        self.args.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Fill the template. Refuses (`ArgsInvalid`) an unknown or missing
    /// required argument, a value of the wrong type or shape, a NUL, and a
    /// value starting with `-` unless the argument has `allow_dash`. A
    /// value its constraint does not clear is kept and listed in
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
        let argv = self
            .argv
            .iter()
            .filter_map(|e| match e {
                ArgvElement::Literal(s) => Some(s.clone()),
                ArgvElement::Placeholder(n) => args.0.get(n).cloned(),
            })
            .collect();
        Ok(ResolvedArgv {
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
/// constraint clears it.
fn check_value(name: &str, p: &Param, value: &str) -> Result<bool, ManifestError> {
    let bad = |why: String| Err(ManifestError::args(format!("argument {name:?}: {why}")));
    if value.contains('\0') {
        return bad("NUL in value".into());
    }
    if value.starts_with('-') && !p.allow_dash() {
        return bad("value starts with '-' and allow_dash is off".into());
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
    /// Arguments from a JSON object of strings, integers and booleans.
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

/// A command ready to run, without a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedArgv {
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
