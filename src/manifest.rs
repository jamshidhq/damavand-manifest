//! The manifest: typed, validated, canonical.

use std::collections::BTreeMap;

use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::command::ArgvElement;
use crate::command::{Args, Command, ResolvedArgv};
use crate::digest::{ManifestDigest, digest_canonical};
use crate::error::ManifestError;
use crate::schema::{ActionClass, WRAPPER_PROGRAMS, program_matches};
use crate::validate;

/// The schema version this crate writes. The loader also reads
/// `SCHEMA_VERSION - 1` once a migration for it exists.
pub const SCHEMA_VERSION: i64 = 1;

/// Size and count limits.
pub mod limits {
    /// Largest manifest file, in bytes.
    pub const MAX_FILE_BYTES: usize = 256 * 1024;
    /// Largest canonical JSON accepted by `from_canonical_json`, in bytes.
    pub const MAX_CANONICAL_BYTES: usize = 1024 * 1024;
    /// Longest string or key, in bytes.
    pub const MAX_STRING_BYTES: usize = 4096;
    /// Most tools.
    pub const MAX_TOOLS: usize = 256;
    /// Most parameters per tool, per command and per verb.
    pub const MAX_PARAMS: usize = 64;
    /// Most named commands.
    pub const MAX_COMMANDS: usize = 128;
    /// Most argv elements per command.
    pub const MAX_ARGV: usize = 64;
    /// Most egress entries.
    pub const MAX_EGRESS: usize = 64;
    /// Most secrets.
    pub const MAX_SECRETS: usize = 32;
    /// Most environment variables per command.
    pub const MAX_ENV: usize = 64;
    /// Most values in one enum constraint.
    pub const MAX_ENUM: usize = 256;
    /// Longest `upstream` tool name, in bytes.
    pub const MAX_UPSTREAM_BYTES: usize = 128;
    /// Largest `timeout_secs`.
    pub const MAX_TIMEOUT_SECS: u32 = 3600;
    /// Largest `max_output_bytes`.
    pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
    /// `max_output_bytes` when absent.
    pub const DEFAULT_OUTPUT_BYTES: u64 = 1024 * 1024;
}

/// A module id: `^[a-z][a-z0-9_.]*$`, the policy action-id grammar.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleId(pub(crate) String);

impl ModuleId {
    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ModuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What kind of module the manifest describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Kind {
    /// A jamshid project. Only this kind may carry `verbs`.
    Project,
    /// An MCP connector.
    Connector,
    /// A data source.
    Source,
    /// A loop.
    Loop,
    /// An executor.
    Executor,
}

impl Kind {
    /// The name used in manifests.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Project => "project",
            Kind::Connector => "connector",
            Kind::Source => "source",
            Kind::Loop => "loop",
            Kind::Executor => "executor",
        }
    }
}

/// How much the audit log records for the module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Audit {
    /// Everything (the default).
    Full,
    /// Metadata only. Allowed only for read-only modules.
    Metadata,
}

impl Audit {
    /// The name used in manifests.
    pub fn name(self) -> &'static str {
        match self {
            Audit::Full => "full",
            Audit::Metadata => "metadata",
        }
    }
}

/// One allowed HTTPS destination: an exact host and a port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Egress {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Egress {
    /// Lowercase A-label host, matched exactly.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// TCP port (default 443).
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A secret the egress part injects into requests to one host. The
/// manifest holds the name, never the value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secret {
    pub(crate) name: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) header: String,
    pub(crate) scheme: Option<String>,
}

impl Secret {
    /// Secret name in the store.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The only host it is sent to. (`host`, `port`) is always in the
    /// manifest's egress list.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// The only port it is sent to (default 443).
    pub fn port(&self) -> u16 {
        self.port
    }
    /// HTTP header that carries it.
    pub fn header(&self) -> &str {
        &self.header
    }
    /// Auth scheme written before the value (`Bearer`), if any.
    pub fn scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }
}

/// A compiled, safe pattern (see [`crate::pattern`]).
#[derive(Debug, Clone)]
pub struct Pattern {
    pub(crate) source: String,
    pub(crate) regex: Regex,
}

impl Pattern {
    /// The pattern as written (unanchored).
    pub fn source(&self) -> &str {
        &self.source
    }
    /// True when the whole value matches.
    pub fn is_match(&self, value: &str) -> bool {
        self.regex.is_match(value)
    }
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for Pattern {}

/// The constraint that clears taint from a value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Constraint {
    /// One of these exact values (sorted, no duplicates, none empty).
    Enum(Vec<String>),
    /// The whole value matches this pattern.
    Pattern(Pattern),
}

impl Constraint {
    /// True when the value satisfies the constraint. An empty value never
    /// does.
    pub fn clears(&self, value: &str) -> bool {
        !value.is_empty()
            && match self {
                Constraint::Enum(values) => values.iter().any(|v| v == value),
                Constraint::Pattern(p) => p.is_match(value),
            }
    }
}

/// Type of a parameter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ParamType {
    /// A UTF-8 string.
    String,
    /// A signed integer.
    Integer,
    /// `true` or `false`.
    Boolean,
}

impl ParamType {
    /// The name used in manifests.
    pub fn name(self) -> &'static str {
        match self {
            ParamType::String => "string",
            ParamType::Integer => "integer",
            ParamType::Boolean => "boolean",
        }
    }
}

/// A tool parameter or command argument. Shape limits reject bad values
/// before policy; only the constraint clears taint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub(crate) ty: ParamType,
    pub(crate) required: bool,
    /// String only.
    pub(crate) max_len: Option<u32>,
    /// Integer only.
    pub(crate) min: Option<i64>,
    /// Integer only.
    pub(crate) max: Option<i64>,
    /// String only.
    pub(crate) constraint: Option<Constraint>,
    /// Command arguments only.
    pub(crate) allow_option: Option<bool>,
    /// Command arguments only.
    pub(crate) allow_path_escape: Option<bool>,
}

impl Param {
    /// Value type.
    pub fn param_type(&self) -> ParamType {
        self.ty
    }
    /// True when the value must be given.
    pub fn required(&self) -> bool {
        self.required
    }
    /// Longest string value, in bytes (strings only).
    pub fn max_len(&self) -> Option<u32> {
        self.max_len
    }
    /// Smallest integer value (integers only).
    pub fn min(&self) -> Option<i64> {
        self.min
    }
    /// Largest integer value (integers only).
    pub fn max(&self) -> Option<i64> {
        self.max
    }
    /// The constraint that clears taint, if any.
    pub fn constraint(&self) -> Option<&Constraint> {
        self.constraint.as_ref()
    }
    /// True when a value may look like an option: start with `-`, `@`
    /// (a response file for rustc, gcc, javac) or `+` (a rustup toolchain,
    /// `+opt` options). Command arguments only; default false.
    pub fn allow_option(&self) -> bool {
        self.allow_option.unwrap_or(false)
    }
    /// True when a value may be an absolute path or hold a `..` path
    /// segment. Command arguments only; default false.
    pub fn allow_path_escape(&self) -> bool {
        self.allow_path_escape.unwrap_or(false)
    }
}

/// An MCP tool the module offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    pub(crate) id: String,
    pub(crate) upstream: String,
    pub(crate) class: ActionClass,
    pub(crate) params: BTreeMap<String, Param>,
}

impl Tool {
    /// Tool id (action-id grammar; never a schema verb or Never action).
    pub fn id(&self) -> &str {
        &self.id
    }
    /// The real MCP tool name upstream.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }
    /// Action class (never `never`).
    pub fn class(&self) -> ActionClass {
        self.class
    }
    /// Parameters by name.
    pub fn params(&self) -> impl Iterator<Item = (&str, &Param)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v))
    }
    /// The MCP input JSON Schema: an object with `additionalProperties:
    /// false`, one property per parameter, and the required list.
    pub fn input_schema(&self) -> Value {
        let mut props = Map::new();
        for (name, p) in &self.params {
            let mut prop = Map::new();
            prop.insert("type".into(), p.ty.name().into());
            if let Some(n) = p.max_len {
                prop.insert("maxLength".into(), n.into());
            }
            if let Some(n) = p.min {
                prop.insert("minimum".into(), n.into());
            }
            if let Some(n) = p.max {
                prop.insert("maximum".into(), n.into());
            }
            match &p.constraint {
                Some(Constraint::Enum(values)) => {
                    prop.insert("enum".into(), values.clone().into());
                }
                Some(Constraint::Pattern(pat)) => {
                    prop.insert("pattern".into(), format!("^(?:{})$", pat.source).into());
                }
                None => {}
            }
            props.insert(name.clone(), Value::Object(prop));
        }
        let required: Vec<&String> = self
            .params
            .iter()
            .filter(|(_, p)| p.required)
            .map(|(n, _)| n)
            .collect();
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": props,
            "required": required,
        })
    }
}

/// Which (action, parameter) a constraint clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ConstraintKey<'a> {
    /// A parameter of a built-in schema verb (`project` manifests only).
    Verb {
        /// The verb, e.g. `j_edit`.
        verb: &'a str,
        /// The parameter.
        param: &'a str,
    },
    /// A parameter of a manifest tool, called through `mcp_call`.
    Tool {
        /// The tool id.
        tool: &'a str,
        /// The parameter.
        param: &'a str,
    },
    /// An argument of a named command, run through `run_command`.
    Command {
        /// The command name.
        command: &'a str,
        /// The argument.
        arg: &'a str,
    },
}

/// One module manifest. Fields are private: the only way in is a parser,
/// which validates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Manifest {
    pub(crate) id: ModuleId,
    pub(crate) kind: Kind,
    pub(crate) aws_role: Option<String>,
    pub(crate) audit: Audit,
    pub(crate) autonomy: BTreeMap<ActionClass, u8>,
    pub(crate) egress: Vec<Egress>,
    pub(crate) secrets: Vec<Secret>,
    pub(crate) tools: Vec<Tool>,
    pub(crate) verbs: BTreeMap<String, BTreeMap<String, Constraint>>,
    pub(crate) commands: BTreeMap<String, Command>,
}

impl Manifest {
    /// Parse and validate a TOML manifest.
    pub fn parse_toml(text: &str) -> Result<Manifest, ManifestError> {
        let table = parse_table(text)?;
        let (table, _) = validate::upgrade(table)?;
        validate::walk_toml_table("", &table)?;
        validate::validate(validate::raw_from_toml(table)?)
    }

    /// Parse and validate canonical JSON. Refuses bytes that are not exactly
    /// the canonical form of the manifest they describe.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        if bytes.len() > limits::MAX_CANONICAL_BYTES {
            return Err(ManifestError::invalid(
                "canonical JSON is larger than 1 MiB",
            ));
        }
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|e| ManifestError::invalid(format!("canonical JSON: {e}")))?;
        validate::check_json_schema(&value)?;
        validate::walk_json("", &value)?;
        let m = validate::validate(validate::raw_from_json(value)?)?;
        if m.canonical_json() != bytes {
            return Err(ManifestError::invalid(
                "canonical JSON: the bytes are not the canonical form",
            ));
        }
        Ok(m)
    }

    /// RFC 8785 JSON of the validated value, defaults filled in, unordered
    /// lists sorted.
    pub fn canonical_json(&self) -> Vec<u8> {
        crate::digest::canonical_json(&self.to_json())
            .expect("a validated manifest holds only safe integers")
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("schema".into(), SCHEMA_VERSION.into());
        m.insert("id".into(), self.id.0.clone().into());
        m.insert("kind".into(), self.kind.name().into());
        m.insert("audit".into(), self.audit.name().into());
        if let Some(r) = &self.aws_role {
            m.insert("identity".into(), json!({ "aws_role": r }));
        }
        let autonomy: Map<String, Value> = self
            .autonomy
            .iter()
            .map(|(c, l)| (c.name().to_string(), Value::from(*l)))
            .collect();
        m.insert("autonomy".into(), Value::Object(autonomy));
        let egress: Vec<Value> = self
            .egress
            .iter()
            .map(|e| json!({ "host": e.host, "port": e.port }))
            .collect();
        m.insert("egress".into(), egress.into());
        let secrets: Vec<Value> = self
            .secrets
            .iter()
            .map(|s| {
                let mut v = json!({
                    "name": s.name,
                    "host": s.host,
                    "port": s.port,
                    "header": s.header,
                });
                if let Some(scheme) = &s.scheme {
                    v["scheme"] = scheme.clone().into();
                }
                v
            })
            .collect();
        m.insert("secrets".into(), secrets.into());
        let tools: Vec<Value> = self
            .tools
            .iter()
            .map(|t| {
                json!({
                    "id": t.id,
                    "upstream": t.upstream,
                    "class": t.class.name(),
                    "params": params_json(&t.params),
                })
            })
            .collect();
        m.insert("tools".into(), tools.into());
        let verbs: Map<String, Value> = self
            .verbs
            .iter()
            .map(|(verb, params)| {
                let params: Map<String, Value> = params
                    .iter()
                    .map(|(n, c)| (n.clone(), json!({ "constraint": constraint_json(c) })))
                    .collect();
                (verb.clone(), Value::Object(params))
            })
            .collect();
        m.insert("verbs".into(), Value::Object(verbs));
        let commands: Map<String, Value> = self
            .commands
            .iter()
            .map(|(n, c)| (n.clone(), command_json(c)))
            .collect();
        m.insert("commands".into(), Value::Object(commands));
        Value::Object(m)
    }

    /// SHA-256 over the domain tag and the canonical JSON.
    pub fn digest(&self) -> ManifestDigest {
        digest_canonical(&self.canonical_json())
    }

    /// `Ok` when the digest is `expected`, else `DigestMismatch`.
    pub fn verify_digest(&self, expected: &ManifestDigest) -> Result<(), ManifestError> {
        let actual = self.digest();
        if actual == *expected {
            Ok(())
        } else {
            Err(ManifestError::DigestMismatch {
                expected: *expected,
                actual,
            })
        }
    }

    /// Upgrade a manifest of schema N-1 to schema N (TOML text). A current
    /// manifest is returned unchanged; any other version is
    /// `SchemaUnsupported`.
    pub fn migrate(text: &str) -> Result<String, ManifestError> {
        let table = parse_table(text)?;
        let (table, migrated) = validate::upgrade(table)?;
        if !migrated {
            Manifest::parse_toml(text)?;
            return Ok(text.to_string());
        }
        let out = toml::to_string(&table)
            .map_err(|e| ManifestError::invalid(format!("migrated TOML: {e}")))?;
        Manifest::parse_toml(&out)?;
        Ok(out)
    }

    /// Module id.
    pub fn id(&self) -> &ModuleId {
        &self.id
    }
    /// Module kind.
    pub fn kind(&self) -> Kind {
        self.kind
    }
    /// Audit level.
    pub fn audit(&self) -> Audit {
        self.audit
    }
    /// `identity.aws_role`, if set.
    pub fn aws_role(&self) -> Option<&str> {
        self.aws_role.as_deref()
    }
    /// The manifest's autonomy cap for a class, if it sets one.
    pub fn autonomy_cap(&self, class: ActionClass) -> Option<u8> {
        self.autonomy.get(&class).copied()
    }
    /// min(git cap, manifest cap, caller override): a manifest and an
    /// override can only lower the level.
    pub fn effective_autonomy(&self, class: ActionClass, git_cap: u8, over: Option<u8>) -> u8 {
        let mut level = git_cap;
        if let Some(cap) = self.autonomy_cap(class) {
            level = level.min(cap);
        }
        if let Some(o) = over {
            level = level.min(o);
        }
        level
    }
    /// Egress entries, sorted by host then port.
    pub fn egress(&self) -> impl Iterator<Item = &Egress> {
        self.egress.iter()
    }
    /// Secrets, sorted by name.
    pub fn secrets(&self) -> impl Iterator<Item = &Secret> {
        self.secrets.iter()
    }
    /// Tools, sorted by id.
    pub fn tools(&self) -> impl Iterator<Item = &Tool> {
        self.tools.iter()
    }
    /// The tool with this id.
    pub fn tool(&self, id: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.id == id)
    }
    /// The named command.
    pub fn command(&self, name: &str) -> Option<&Command> {
        self.commands.get(name)
    }
    /// Named commands, sorted by name.
    pub fn commands(&self) -> impl Iterator<Item = (&str, &Command)> {
        self.commands.iter().map(|(k, v)| (k.as_str(), v))
    }
    /// Resolve a named command call: `UnknownCommand` when absent.
    pub fn resolve(&self, name: &str, args: &Args) -> Result<ResolvedArgv, ManifestError> {
        self.command(name)
            .ok_or_else(|| ManifestError::UnknownCommand {
                name: name.to_string(),
            })?
            .resolve(args)
    }
    /// Every constraint that clears taint, keyed by what it applies to.
    pub fn constraints(&self) -> impl Iterator<Item = (ConstraintKey<'_>, &Constraint)> {
        let verbs = self.verbs.iter().flat_map(|(verb, params)| {
            params.iter().map(move |(param, c)| {
                (
                    ConstraintKey::Verb {
                        verb: verb.as_str(),
                        param: param.as_str(),
                    },
                    c,
                )
            })
        });
        let tools = self.tools.iter().flat_map(|t| {
            t.params.iter().filter_map(move |(param, p)| {
                p.constraint.as_ref().map(|c| {
                    (
                        ConstraintKey::Tool {
                            tool: t.id.as_str(),
                            param: param.as_str(),
                        },
                        c,
                    )
                })
            })
        });
        let commands = self.commands.iter().flat_map(|(command, cmd)| {
            cmd.args.iter().filter_map(move |(arg, p)| {
                p.constraint.as_ref().map(|c| {
                    (
                        ConstraintKey::Command {
                            command: command.as_str(),
                            arg: arg.as_str(),
                        },
                        c,
                    )
                })
            })
        });
        verbs.chain(tools).chain(commands)
    }

    /// Warnings about rules a user-authored manifest may break on purpose,
    /// for the reviewer: commands that run a wrapper program
    /// ([`WRAPPER_PROGRAMS`]: a proposal may not), and tools of class
    /// `read`. A tool's class is the author's assertion, reviewed in git; an
    /// agent never sets it, since proposals never touch tools. Each warning
    /// starts with the path of the field.
    pub fn lints(&self) -> Vec<String> {
        let wrappers = self.commands.iter().filter_map(|(name, c)| match c.argv.first() {
            Some(ArgvElement::Literal(prog)) if program_matches(WRAPPER_PROGRAMS, prog) => {
                Some(format!(
                    "commands.{name}.argv[0]: {prog:?} is a wrapper program; it runs whatever its arguments say"
                ))
            }
            _ => None,
        });
        let reads = self
            .tools
            .iter()
            .filter(|t| t.class == ActionClass::Read)
            .map(|t| {
                format!(
                    "tools.{}.class: read is the author's assertion that {:?} only reads",
                    t.id, t.upstream
                )
            });
        wrappers.chain(reads).collect()
    }
}

/// Parse TOML text into a table, refusing files over the size limit.
pub(crate) fn parse_table(text: &str) -> Result<toml::Table, ManifestError> {
    if text.len() > limits::MAX_FILE_BYTES {
        return Err(ManifestError::invalid(format!(
            "file is larger than 256 KiB ({} bytes)",
            text.len()
        )));
    }
    toml::from_str(text)
        .map_err(|e: toml::de::Error| ManifestError::invalid(format!("TOML: {}", e.message())))
}

fn constraint_json(c: &Constraint) -> Value {
    match c {
        Constraint::Enum(values) => json!({ "enum": values }),
        Constraint::Pattern(p) => json!({ "pattern": p.source }),
    }
}

fn param_json(p: &Param) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), p.ty.name().into());
    m.insert("required".into(), p.required.into());
    if let Some(n) = p.max_len {
        m.insert("max_len".into(), n.into());
    }
    if let Some(n) = p.min {
        m.insert("min".into(), n.into());
    }
    if let Some(n) = p.max {
        m.insert("max".into(), n.into());
    }
    if let Some(c) = &p.constraint {
        m.insert("constraint".into(), constraint_json(c));
    }
    if let Some(d) = p.allow_option {
        m.insert("allow_option".into(), d.into());
    }
    if let Some(d) = p.allow_path_escape {
        m.insert("allow_path_escape".into(), d.into());
    }
    Value::Object(m)
}

fn params_json(params: &BTreeMap<String, Param>) -> Value {
    Value::Object(
        params
            .iter()
            .map(|(n, p)| (n.clone(), param_json(p)))
            .collect(),
    )
}

/// The canonical JSON value of one command.
pub(crate) fn command_json(c: &Command) -> Value {
    let argv: Vec<String> = c
        .argv
        .iter()
        .map(|e| match e {
            ArgvElement::Literal(s) => s.clone(),
            ArgvElement::Placeholder(n) => format!("{{{n}}}"),
        })
        .collect();
    json!({
        "argv": argv,
        "cwd": c.cwd,
        "env": c.env,
        "output": c.output.name(),
        "timeout_secs": c.timeout_secs,
        "max_output_bytes": c.max_output_bytes,
        "options_ok": c.options_ok,
        "args": params_json(&c.args),
    })
}
