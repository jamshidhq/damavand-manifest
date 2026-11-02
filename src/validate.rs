//! Parsing and validation rules. Raw serde shapes in, validated types out.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::command::{ArgvElement, Command, Output};
use crate::digest::MAX_SAFE_INTEGER;
use crate::error::ManifestError;
use crate::manifest::{
    Audit, Constraint, Egress, Kind, Manifest, ModuleId, Param, ParamType, Pattern, SCHEMA_VERSION,
    Secret, Tool, limits,
};
use crate::pattern::compile_pattern;
use crate::schema::{ActionClass, MCP_CALL, RUN_COMMAND, is_never, is_schema_verb};

type Result<T> = std::result::Result<T, ManifestError>;

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(ManifestError::invalid(message))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawManifest {
    schema: i64,
    id: String,
    kind: Kind,
    identity: Option<RawIdentity>,
    audit: Option<Audit>,
    #[serde(default)]
    autonomy: BTreeMap<String, i64>,
    #[serde(default)]
    egress: Vec<RawEgress>,
    #[serde(default)]
    secrets: Vec<RawSecret>,
    #[serde(default)]
    tools: Vec<RawTool>,
    #[serde(default)]
    verbs: BTreeMap<String, BTreeMap<String, RawVerbParam>>,
    #[serde(default)]
    commands: BTreeMap<String, RawCommand>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    aws_role: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgress {
    host: String,
    port: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecret {
    name: String,
    host: String,
    header: String,
    scheme: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTool {
    id: String,
    upstream: String,
    class: String,
    #[serde(default)]
    params: BTreeMap<String, RawParam>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVerbParam {
    constraint: RawConstraint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConstraint {
    #[serde(rename = "enum")]
    enum_: Option<Vec<String>>,
    pattern: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParam {
    #[serde(rename = "type")]
    ty: ParamType,
    required: Option<bool>,
    max_len: Option<i64>,
    min: Option<i64>,
    max: Option<i64>,
    constraint: Option<RawConstraint>,
    allow_dash: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCommand {
    argv: Vec<String>,
    cwd: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    output: Option<Output>,
    timeout_secs: i64,
    max_output_bytes: Option<i64>,
    options_ok: Option<bool>,
    #[serde(default)]
    args: BTreeMap<String, RawParam>,
}

// ---------------------------------------------------------------- grammars

/// `^[a-z][a-z0-9_.]*$`
pub(crate) fn is_id(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

/// Lowercase A-label host name: at least two labels of 1-63 bytes from
/// `[a-z0-9-]`, no label starting or ending with `-`, at most 253 bytes,
/// and a top label that is not all digits (no IPv4 literal).
fn is_host(h: &str) -> bool {
    if h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    labels.iter().all(label_ok) && !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit())
}

/// `^[A-Za-z][A-Za-z0-9-]{0,63}$`: header names and auth schemes.
fn is_token(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `^[A-Z_][A-Z0-9_]*$`
fn is_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_aws_role(s: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\Aarn:aws(?:-[a-z]+)*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}\z")
            .expect("static regex")
    })
    .is_match(s)
}

/// 1-128 bytes of printable ASCII.
fn is_upstream(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= limits::MAX_UPSTREAM_BYTES
        && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

// ------------------------------------------------------------ value walks

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn check_str(path: &str, what: &str, s: &str) -> Result<()> {
    if s.len() > limits::MAX_STRING_BYTES {
        return invalid(format!(
            "{path}: {what} longer than {} bytes",
            limits::MAX_STRING_BYTES
        ));
    }
    if s.contains('\0') {
        return invalid(format!("{path}: NUL in {what}"));
    }
    Ok(())
}

fn check_int(path: &str, n: i64) -> Result<()> {
    if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) {
        Ok(())
    } else {
        invalid(format!("{path}: integer {n} is beyond ±(2^53 - 1)"))
    }
}

/// Every key and string at most 4 KiB without NUL, integers within
/// ±(2^53 - 1), no floats, no datetimes.
pub(crate) fn walk_toml(path: &str, v: &toml::Value) -> Result<()> {
    match v {
        toml::Value::String(s) => check_str(path, "string", s),
        toml::Value::Integer(n) => check_int(path, *n),
        toml::Value::Float(_) => invalid(format!("{path}: float values are not allowed")),
        toml::Value::Boolean(_) => Ok(()),
        toml::Value::Datetime(_) => invalid(format!("{path}: datetime values are not allowed")),
        toml::Value::Array(items) => items
            .iter()
            .enumerate()
            .try_for_each(|(i, item)| walk_toml(&format!("{path}[{i}]"), item)),
        toml::Value::Table(t) => walk_toml_table(path, t),
    }
}

pub(crate) fn walk_toml_table(path: &str, t: &toml::Table) -> Result<()> {
    for (k, v) in t {
        let p = join(path, k);
        check_str(&p, "key", k)?;
        walk_toml(&p, v)?;
    }
    Ok(())
}

pub(crate) fn walk_json(path: &str, v: &Value) -> Result<()> {
    match v {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::String(s) => check_str(path, "string", s),
        Value::Number(n) => match n.as_i64() {
            Some(i) => check_int(path, i),
            None if n.is_u64() => invalid(format!("{path}: integer {n} is beyond ±(2^53 - 1)")),
            None => invalid(format!("{path}: float values are not allowed")),
        },
        Value::Array(items) => items
            .iter()
            .enumerate()
            .try_for_each(|(i, item)| walk_json(&format!("{path}[{i}]"), item)),
        Value::Object(map) => {
            for (k, v) in map {
                let p = join(path, k);
                check_str(&p, "key", k)?;
                walk_json(&p, v)?;
            }
            Ok(())
        }
    }
}

// --------------------------------------------------------------- versions

/// One migration from `from` to `from + 1`. None exist yet: schema 1 is the
/// first version.
struct Migration {
    from: i64,
    apply: fn(toml::Table) -> Result<toml::Table>,
}

const MIGRATIONS: &[Migration] = &[];

/// Read `schema` and bring the table to [`SCHEMA_VERSION`]. Returns whether
/// a migration ran.
pub(crate) fn upgrade(table: toml::Table) -> Result<(toml::Table, bool)> {
    let version = match table.get("schema") {
        None => return invalid("schema: missing"),
        Some(toml::Value::Integer(n)) => *n,
        Some(_) => return Err(ManifestError::SchemaUnsupported { schema: -1 }),
    };
    if version == SCHEMA_VERSION {
        return Ok((table, false));
    }
    match find_migration(MIGRATIONS, version) {
        Some(m) => Ok(((m.apply)(table)?, true)),
        None => Err(ManifestError::SchemaUnsupported { schema: version }),
    }
}

/// The migration that reads `version`: only from N-1.
fn find_migration(table: &[Migration], version: i64) -> Option<&Migration> {
    table
        .iter()
        .find(|m| m.from == version && version == SCHEMA_VERSION - 1)
}

/// The `schema` of a canonical JSON object, checked the same way.
pub(crate) fn check_json_schema(v: &Value) -> Result<()> {
    match v.get("schema") {
        None => invalid("schema: missing"),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(SCHEMA_VERSION) => Ok(()),
            Some(other) => Err(ManifestError::SchemaUnsupported { schema: other }),
            None => Err(ManifestError::SchemaUnsupported { schema: -1 }),
        },
        Some(_) => Err(ManifestError::SchemaUnsupported { schema: -1 }),
    }
}

pub(crate) fn raw_from_toml(table: toml::Table) -> Result<RawManifest> {
    toml::Value::Table(table)
        .try_into()
        .map_err(|e: toml::de::Error| ManifestError::invalid(e.message().to_string()))
}

pub(crate) fn raw_from_json(v: Value) -> Result<RawManifest> {
    serde_json::from_value(v).map_err(|e| ManifestError::invalid(e.to_string()))
}

pub(crate) fn raw_command_from_toml(table: toml::Table) -> Result<RawCommand> {
    toml::Value::Table(table)
        .try_into()
        .map_err(|e: toml::de::Error| ManifestError::invalid(e.message().to_string()))
}

// ------------------------------------------------------------- validation

pub(crate) fn validate(raw: RawManifest) -> Result<Manifest> {
    if raw.schema != SCHEMA_VERSION {
        return Err(ManifestError::SchemaUnsupported { schema: raw.schema });
    }
    if !is_id(&raw.id) {
        return invalid(format!("id: {:?} is not [a-z][a-z0-9_.]*", raw.id));
    }
    let aws_role = match raw.identity.and_then(|i| i.aws_role) {
        Some(r) if !is_aws_role(&r) => {
            return invalid(format!("identity.aws_role: {r:?} is not an IAM role ARN"));
        }
        other => other,
    };
    let autonomy = autonomy(raw.autonomy)?;
    let egress = egress(raw.egress)?;
    let secrets = secrets(raw.secrets, &egress)?;
    let tools = tools(raw.tools)?;
    let verbs = verbs(raw.kind, raw.verbs)?;
    if raw.commands.len() > limits::MAX_COMMANDS {
        return invalid(format!(
            "commands: more than {} commands",
            limits::MAX_COMMANDS
        ));
    }
    let mut commands = BTreeMap::new();
    for (name, c) in raw.commands {
        let cmd = command(&name, c)?;
        commands.insert(name, cmd);
    }
    let m = Manifest {
        id: ModuleId(raw.id),
        kind: raw.kind,
        aws_role,
        audit: raw.audit.unwrap_or(Audit::Full),
        autonomy,
        egress,
        secrets,
        tools,
        verbs,
        commands,
    };
    cross_check(&m)?;
    Ok(m)
}

/// Rules over the whole manifest, also run on every revision.
pub(crate) fn cross_check(m: &Manifest) -> Result<()> {
    if m.commands.len() > limits::MAX_COMMANDS {
        return invalid(format!(
            "commands: more than {} commands",
            limits::MAX_COMMANDS
        ));
    }
    if m.audit == Audit::Metadata {
        let why = if let Some(t) = m.tools.iter().find(|t| t.class != ActionClass::Read) {
            Some(format!("tool {} is class {}", t.id, t.class.name()))
        } else if !m.commands.is_empty() {
            Some("it has commands".to_string())
        } else if !m.verbs.is_empty() {
            Some("it constrains verbs".to_string())
        } else if !m.secrets.is_empty() {
            Some("it uses secrets".to_string())
        } else {
            None
        };
        if let Some(why) = why {
            return invalid(format!(
                "audit: metadata is only for read-only modules, and {why}"
            ));
        }
    }
    Ok(())
}

fn autonomy(raw: BTreeMap<String, i64>) -> Result<BTreeMap<ActionClass, u8>> {
    let mut out = BTreeMap::new();
    for (k, v) in raw {
        let class = match ActionClass::from_name(&k) {
            None => return invalid(format!("autonomy.{k}: unknown class")),
            Some(ActionClass::Never) => {
                return invalid(format!("autonomy.{k}: a manifest cannot set never"));
            }
            Some(c) => c,
        };
        let level = match u8::try_from(v) {
            Ok(l) if l <= 3 => l,
            _ => return invalid(format!("autonomy.{k}: level {v} is not 0-3")),
        };
        out.insert(class, level);
    }
    Ok(out)
}

fn egress(raw: Vec<RawEgress>) -> Result<Vec<Egress>> {
    if raw.len() > limits::MAX_EGRESS {
        return invalid(format!("egress: more than {} entries", limits::MAX_EGRESS));
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, e) in raw.into_iter().enumerate() {
        if !is_host(&e.host) {
            return invalid(format!(
                "egress[{i}].host: {:?} is not a lowercase A-label host name",
                e.host
            ));
        }
        let port = match e.port {
            None => 443,
            Some(p) => match u16::try_from(p) {
                Ok(p) if p >= 1 => p,
                _ => return invalid(format!("egress[{i}].port: {p} is not 1-65535")),
            },
        };
        if !seen.insert((e.host.clone(), port)) {
            return invalid(format!("egress[{i}]: duplicate {}:{port}", e.host));
        }
        out.push(Egress { host: e.host, port });
    }
    out.sort();
    Ok(out)
}

fn secrets(raw: Vec<RawSecret>, egress: &[Egress]) -> Result<Vec<Secret>> {
    if raw.len() > limits::MAX_SECRETS {
        return invalid(format!(
            "secrets: more than {} secrets",
            limits::MAX_SECRETS
        ));
    }
    let mut out = Vec::new();
    let mut names = BTreeSet::new();
    for (i, s) in raw.into_iter().enumerate() {
        if !is_id(&s.name) {
            return invalid(format!(
                "secrets[{i}].name: {:?} is not [a-z][a-z0-9_.]*",
                s.name
            ));
        }
        if !egress.iter().any(|e| e.host == s.host) {
            return invalid(format!("secrets[{i}].host: {:?} is not in egress", s.host));
        }
        if !is_token(&s.header) {
            return invalid(format!(
                "secrets[{i}].header: {:?} is not [A-Za-z][A-Za-z0-9-]{{0,63}}",
                s.header
            ));
        }
        if let Some(scheme) = &s.scheme
            && !is_token(scheme)
        {
            return invalid(format!(
                "secrets[{i}].scheme: {scheme:?} is not [A-Za-z][A-Za-z0-9-]{{0,63}}"
            ));
        }
        if !names.insert(s.name.clone()) {
            return invalid(format!("secrets[{i}]: duplicate secret {:?}", s.name));
        }
        out.push(Secret {
            name: s.name,
            host: s.host,
            header: s.header,
            scheme: s.scheme,
        });
    }
    out.sort();
    Ok(out)
}

fn tools(raw: Vec<RawTool>) -> Result<Vec<Tool>> {
    if raw.len() > limits::MAX_TOOLS {
        return invalid(format!("tools: more than {} tools", limits::MAX_TOOLS));
    }
    let mut out: Vec<Tool> = Vec::new();
    for (i, t) in raw.into_iter().enumerate() {
        let path = format!("tools[{i}]");
        if !is_id(&t.id) {
            return invalid(format!("{path}.id: {:?} is not [a-z][a-z0-9_.]*", t.id));
        }
        if is_never(&t.id) {
            return invalid(format!("{path}.id: {:?} is a Never action", t.id));
        }
        if is_schema_verb(&t.id) {
            return invalid(format!("{path}.id: {:?} is a schema verb", t.id));
        }
        if !is_upstream(&t.upstream) {
            return invalid(format!(
                "{path}.upstream: {:?} is not 1-{} bytes of printable ASCII",
                t.upstream,
                limits::MAX_UPSTREAM_BYTES
            ));
        }
        let class = match ActionClass::from_name(&t.class) {
            None => return invalid(format!("{path}.class: unknown class {:?}", t.class)),
            Some(ActionClass::Never) => {
                return invalid(format!("{path}.class: a tool can never be class never"));
            }
            Some(c) => c,
        };
        if let Some(other) = out.iter().find(|o| o.id == t.id) {
            return invalid(format!("{path}.id: duplicate tool id {:?}", other.id));
        }
        if let Some(other) = out.iter().find(|o| o.upstream == t.upstream) {
            return invalid(format!(
                "{path}.upstream: {:?} is already tool {:?}",
                t.upstream, other.id
            ));
        }
        let params = params(&format!("{path}.params"), t.params, false)?;
        out.push(Tool {
            id: t.id,
            upstream: t.upstream,
            class,
            params,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn verbs(
    kind: Kind,
    raw: BTreeMap<String, BTreeMap<String, RawVerbParam>>,
) -> Result<BTreeMap<String, BTreeMap<String, Constraint>>> {
    if !raw.is_empty() && kind != Kind::Project {
        return invalid("verbs: only a project manifest can constrain verbs");
    }
    let mut out = BTreeMap::new();
    for (verb, params) in raw {
        let path = format!("verbs.{verb}");
        if is_never(&verb) {
            return invalid(format!("{path}: {verb:?} is a Never action"));
        }
        if verb == RUN_COMMAND {
            return invalid(format!(
                "{path}: {RUN_COMMAND} arguments are constrained under [commands]"
            ));
        }
        if verb == MCP_CALL {
            return invalid(format!(
                "{path}: {MCP_CALL} parameters are constrained under [[tools]]"
            ));
        }
        if !is_schema_verb(&verb) {
            return invalid(format!("{path}: unknown verb"));
        }
        if params.len() > limits::MAX_PARAMS {
            return invalid(format!(
                "{path}: more than {} parameters",
                limits::MAX_PARAMS
            ));
        }
        let mut cs = BTreeMap::new();
        for (name, p) in params {
            let ppath = format!("{path}.{name}");
            if !is_id(&name) {
                return invalid(format!("{ppath}: name is not [a-z][a-z0-9_.]*"));
            }
            cs.insert(
                name,
                constraint(&format!("{ppath}.constraint"), p.constraint)?,
            );
        }
        out.insert(verb, cs);
    }
    Ok(out)
}

fn constraint(path: &str, raw: RawConstraint) -> Result<Constraint> {
    match (raw.enum_, raw.pattern) {
        (Some(mut values), None) => {
            if values.is_empty() {
                return invalid(format!("{path}.enum: empty"));
            }
            if values.len() > limits::MAX_ENUM {
                return invalid(format!(
                    "{path}.enum: more than {} values",
                    limits::MAX_ENUM
                ));
            }
            if values.iter().any(String::is_empty) {
                return invalid(format!("{path}.enum: empty value"));
            }
            values.sort();
            let before = values.len();
            values.dedup();
            if values.len() != before {
                return invalid(format!("{path}.enum: duplicate value"));
            }
            Ok(Constraint::Enum(values))
        }
        (None, Some(source)) => match compile_pattern(&source) {
            Ok(regex) => Ok(Constraint::Pattern(Pattern { source, regex })),
            Err(e) => invalid(format!("{path}.pattern: {}: {e}", e.name())),
        },
        _ => invalid(format!("{path}: use one of enum or pattern")),
    }
}

fn params(
    path: &str,
    raw: BTreeMap<String, RawParam>,
    command_arg: bool,
) -> Result<BTreeMap<String, Param>> {
    if raw.len() > limits::MAX_PARAMS {
        return invalid(format!(
            "{path}: more than {} parameters",
            limits::MAX_PARAMS
        ));
    }
    let mut out = BTreeMap::new();
    for (name, p) in raw {
        let ppath = format!("{path}.{name}");
        if !is_id(&name) {
            return invalid(format!("{ppath}: name is not [a-z][a-z0-9_.]*"));
        }
        out.insert(name, param(&ppath, p, command_arg)?);
    }
    Ok(out)
}

fn param(path: &str, p: RawParam, command_arg: bool) -> Result<Param> {
    let not_for = |field: &str, ty: ParamType| {
        invalid::<Param>(format!(
            "{path}.{field}: not allowed for type {}",
            ty.name()
        ))
    };
    let allow_dash = match (command_arg, p.allow_dash) {
        (false, Some(_)) => {
            return invalid(format!("{path}.allow_dash: only for command arguments"));
        }
        (false, None) => None,
        (true, v) => Some(v.unwrap_or(false)),
    };
    let mut out = Param {
        ty: p.ty,
        required: p.required.unwrap_or(false),
        max_len: None,
        min: None,
        max: None,
        constraint: None,
        allow_dash,
    };
    match p.ty {
        ParamType::String => {
            if p.min.is_some() {
                return not_for("min", p.ty);
            }
            if p.max.is_some() {
                return not_for("max", p.ty);
            }
            let max_len = p.max_len.unwrap_or(limits::MAX_STRING_BYTES as i64);
            if !(1..=limits::MAX_STRING_BYTES as i64).contains(&max_len) {
                return invalid(format!(
                    "{path}.max_len: {max_len} is not 1-{}",
                    limits::MAX_STRING_BYTES
                ));
            }
            out.max_len = Some(max_len as u32);
            out.constraint = match p.constraint {
                Some(c) => Some(constraint(&format!("{path}.constraint"), c)?),
                None => None,
            };
        }
        ParamType::Integer => {
            if p.max_len.is_some() {
                return not_for("max_len", p.ty);
            }
            if p.constraint.is_some() {
                return not_for("constraint", p.ty);
            }
            let min = p.min.unwrap_or(-MAX_SAFE_INTEGER);
            let max = p.max.unwrap_or(MAX_SAFE_INTEGER);
            if min > max {
                return invalid(format!("{path}.min: {min} is above max {max}"));
            }
            out.min = Some(min);
            out.max = Some(max);
        }
        ParamType::Boolean => {
            for (field, set) in [
                ("max_len", p.max_len.is_some()),
                ("min", p.min.is_some()),
                ("max", p.max.is_some()),
                ("constraint", p.constraint.is_some()),
            ] {
                if set {
                    return not_for(field, p.ty);
                }
            }
        }
    }
    Ok(out)
}

pub(crate) fn command(name: &str, c: RawCommand) -> Result<Command> {
    let path = format!("commands.{name}");
    if !is_id(name) {
        return invalid(format!("{path}: name is not [a-z][a-z0-9_.]*"));
    }
    let args = params(&format!("{path}.args"), c.args, true)?;
    if c.argv.is_empty() {
        return invalid(format!("{path}.argv: empty"));
    }
    if c.argv.len() > limits::MAX_ARGV {
        return invalid(format!(
            "{path}.argv: more than {} elements",
            limits::MAX_ARGV
        ));
    }
    let mut argv = Vec::new();
    let mut used = BTreeSet::new();
    for (i, el) in c.argv.into_iter().enumerate() {
        let epath = format!("{path}.argv[{i}]");
        if el.is_empty() {
            return invalid(format!("{epath}: empty element"));
        }
        if !el.contains(['{', '}']) {
            argv.push(ArgvElement::Literal(el));
            continue;
        }
        let name = el
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .filter(|s| is_id(s));
        let Some(name) = name else {
            return invalid(format!(
                "{epath}: {el:?} is not a whole-element placeholder {{name}}"
            ));
        };
        if i == 0 {
            return invalid(format!("{epath}: argv[0] must be a literal program"));
        }
        if !args.contains_key(name) {
            return invalid(format!(
                "{epath}: placeholder {{{name}}} is undeclared in args"
            ));
        }
        if !used.insert(name.to_string()) {
            return invalid(format!(
                "{epath}: placeholder {{{name}}} used more than once"
            ));
        }
        argv.push(ArgvElement::Placeholder(name.to_string()));
    }
    if let Some(unused) = args.keys().find(|a| !used.contains(*a)) {
        return invalid(format!("{path}.args.{unused}: unused in argv"));
    }
    let options_ok = c.options_ok.unwrap_or(false);
    if !options_ok
        && let Some(first) = argv
            .iter()
            .position(|e| matches!(e, ArgvElement::Placeholder(_)))
        && !argv[..first]
            .iter()
            .any(|e| matches!(e, ArgvElement::Literal(s) if s == "--"))
    {
        return invalid(format!(
            "{path}.argv: `--` must come before the first placeholder (or set options_ok)"
        ));
    }
    let cwd = c.cwd.unwrap_or_else(|| ".".to_string());
    if cwd.is_empty() {
        return invalid(format!("{path}.cwd: empty"));
    }
    if cwd.starts_with('/') {
        return invalid(format!("{path}.cwd: {cwd:?} is absolute"));
    }
    if cwd.contains('\\') {
        return invalid(format!("{path}.cwd: {cwd:?} holds a backslash"));
    }
    if cwd.split('/').any(|c| c == "..") {
        return invalid(format!("{path}.cwd: {cwd:?} holds `..`"));
    }
    if c.env.len() > limits::MAX_ENV {
        return invalid(format!(
            "{path}.env: more than {} variables",
            limits::MAX_ENV
        ));
    }
    if let Some(k) = c.env.keys().find(|k| !is_env_name(k)) {
        return invalid(format!("{path}.env.{k}: name is not [A-Z_][A-Z0-9_]*"));
    }
    let timeout_secs = match u32::try_from(c.timeout_secs) {
        Ok(t) if (1..=limits::MAX_TIMEOUT_SECS).contains(&t) => t,
        _ => {
            return invalid(format!(
                "{path}.timeout_secs: {} is not 1-{}",
                c.timeout_secs,
                limits::MAX_TIMEOUT_SECS
            ));
        }
    };
    let max_output_bytes = match c.max_output_bytes {
        None => limits::DEFAULT_OUTPUT_BYTES,
        Some(n) => match u64::try_from(n) {
            Ok(n) if (1..=limits::MAX_OUTPUT_BYTES).contains(&n) => n,
            _ => {
                return invalid(format!(
                    "{path}.max_output_bytes: {n} is not 1-{}",
                    limits::MAX_OUTPUT_BYTES
                ));
            }
        },
    };
    Ok(Command {
        argv,
        cwd,
        env: c.env,
        output: c.output.unwrap_or(Output::Full),
        timeout_secs,
        max_output_bytes,
        options_ok,
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_migration_from_n_minus_1_is_used() {
        fn keep(t: toml::Table) -> Result<toml::Table> {
            Ok(t)
        }
        let table = [
            Migration {
                from: SCHEMA_VERSION - 3,
                apply: keep,
            },
            Migration {
                from: SCHEMA_VERSION - 1,
                apply: keep,
            },
            Migration {
                from: SCHEMA_VERSION + 1,
                apply: keep,
            },
        ];
        let found = find_migration(&table, SCHEMA_VERSION - 1).map(|m| m.from);
        assert_eq!(found, Some(SCHEMA_VERSION - 1));
        assert!(find_migration(&table, SCHEMA_VERSION - 3).is_none());
        assert!(find_migration(&table, SCHEMA_VERSION + 1).is_none());
        assert!(find_migration(&table, SCHEMA_VERSION).is_none());
        assert!(find_migration(&table[..1], SCHEMA_VERSION - 1).is_none());
        assert!(find_migration(MIGRATIONS, SCHEMA_VERSION - 1).is_none());
    }

    #[test]
    fn grammars() {
        assert!(is_id("a.b_9"));
        assert!(!is_id(""));
        assert!(!is_id("A"));
        assert!(is_token("Authorization"));
        assert!(is_token("X-Api-Key"));
        assert!(!is_token("X Key"));
        assert!(!is_token("-X"));
        assert!(!is_token(""));
        assert!(is_token(&"a".repeat(64)));
        assert!(!is_token(&"a".repeat(65)));
        assert!(is_env_name("RUST_BACKTRACE"));
        assert!(is_env_name("_X1"));
        assert!(!is_env_name("1X"));
        assert!(!is_env_name("x"));
        assert!(!is_env_name(""));
        assert!(is_upstream("a b~"));
        assert!(!is_upstream("a\u{7f}"));
        assert!(!is_upstream(""));
        assert!(is_upstream(&"a".repeat(128)));
        assert!(!is_upstream(&"a".repeat(129)));
    }
}
