# damavand-manifest: design

2026-11-02. Crate 3 of 8, Apache-2.0, repo `jamshidhq/damavand-manifest`.
Section 8 records the decisions on the open questions; section 9 records
where v0.1 differs from sections 0-7.

## 0. Decided (by owner or by earlier crates)

- One manifest per module, reviewed like code. Agents cannot widen it.
- jamshid keeps it in the core store, outside the worktree. Workers call `j_run {name, filter}`.
- The tool list is fixed per loop.
- Policy rules carry over unchanged: the action-id grammar `^[a-z][a-z0-9_.]*$`; one non-empty enum or one pattern per key; `compile_pattern` limits and forbidden set; an empty tainted value never clears; requests never carry constraints.
- Error block 2000-2999. MSRV 1.89.
- **Decided by necessity:** the policy bundle id covers every manifest digest. Otherwise a manifest swap changes what clears taint while live grants still verify.

Sections 1-7 were proposed by this doc and are accepted with the decisions
in section 8.

## 1. Schema

| Field | Type | Rule |
|---|---|---|
| `schema` | int | Required. `1`. |
| `id` | string | Action-id grammar. Unique in the store. |
| `kind` | enum | `project` (jamshid), `connector`, `source`, `loop`, `executor`. |
| `identity.aws_role` | string | Optional. ARN grammar. |
| `audit` | enum | `full` (default) or `metadata`. No `off`. |
| `autonomy` | table | Class → 0-3. No `never` key. |
| `egress` | list | `{host, port=443}`. Lowercase A-label hosts, exact match, HTTPS only, no wildcards. |
| `secrets` | list | `{name, host, header, scheme}`. Names only. `host` must be in `egress`. |
| `tools` | list | MCP tools (below). |
| `verbs` | table | Param constraints for built-in Cedar verbs. `project` kind only. |
| `commands` | table | Named commands (section 5). |

**Tool:** `id` (grammar), `upstream` (the real MCP name, any printable ASCII, max 128 bytes), `class` (ActionClass), `params`.

**Param:** `type` (`string`, `integer`, `boolean`), `required`, shape limits (`max_len`, `min`, `max`), and an optional `constraint` (`enum` or `pattern`). Shape rejects bad values before policy. Only `constraint` clears taint, so free text stays tainted. The crate generates MCP JSON Schema (`additionalProperties: false`); authors never write it.

**Class rules:** the manifest sets a class only for `mcp_call` tools, never for a schema verb. The loader refuses `class = never` and tool ids that collide with a schema verb or `NEVER_ACTIONS`.

**Autonomy:** effective cap = min(`autonomy.toml`, manifest, override). A manifest only lowers.

## 2. Format, canonical form, digest

- Authored as **TOML**: no anchors, no implicit typing, duplicate keys refused, same as policy.
- Canonical form: RFC 8785 JSON of the typed, validated value, with defaults filled in and lists sorted where order has no meaning. Integers only, no floats.
- Digest: SHA-256 over length-prefixed `damavand-manifest/v1` plus canonical bytes. The git sha is a label only. Comments and layout do not change it. Receivers recompute it.

## 3. Validation and versioning

- `deny_unknown_fields` at every level. Duplicate keys are refused. Every id follows the grammar.
- Limits: 256 KiB per file, 256 tools, 64 params per tool, 128 commands, 64 argv elements, 4 KiB per string, 64 egress hosts, 32 secrets.
- Patterns use the policy's `compile_pattern` unchanged.
- **Pattern safety moves to manifest; policy depends on manifest.** Until publish, manifest v0.1 carries a copy. A shared rejection corpus (`tests/patterns.toml`, same bytes in both repos) keeps the copies equal.
- Versioning: the loader reads `schema` N and N-1. `Manifest::migrate` upgrades N-1. Canonical form is always N. Other versions return 2005.

## 4. Consumers

- **Policy:** `Engine::load(bundle, manifests)`. The `verbs` table and tool params replace `constraints.toml`, keyed as (`run_command`, param), (verb, param) or (`mcp_call`, tool id, param). The bundle id domain tag becomes `bundle/v3` and covers the sorted manifest digests. Proof of no weakening: convert `jamshid-default/constraints.toml` to a manifest and require identical decisions on its `cases.yaml`.
- **Tools part:** lists manifest tools the role allows; runs commands via `Command::resolve`.
- **Egress:** loads `egress` and `secrets`; refuses other hosts.
- **Change path:** reviewed git change only. New digest, new bundle id, old grants invalid.

## 5. Named commands

```toml
[commands.test]
argv    = ["cargo", "test", "--workspace", "--", "{filter}"]
cwd     = "."
env     = { RUST_BACKTRACE = "1" }
output  = "failures-only"
timeout_secs = 900
max_output_bytes = 1048576
[commands.test.args.filter]
type = "string"
max_len = 200
constraint = { pattern = "[a-z0-9_:]+" }
```

- `argv` only. No shell, no splitting. `argv[0]` is a literal. The class is the schema class of `run_command`.
- Placeholders fill a whole element only. An absent optional arg deletes its element.
- Values starting with `-` are refused unless `allow_dash = true`. `--` must precede the first placeholder unless `options_ok = true`.
- Args are tainted. Policy checks them as (`run_command`, arg); uncleared args escalate to the user.
- `env`: fixed values only; inherited env cleared; never secrets.
- `cwd`: relative, inside the worktree, no `..`.
- `output`: `full`, `errors-only`, `failures-only`, `summary`, each a tools-part filter. The full log is kept.
- `timeout_secs` is required, at most 3600.

## 6. API and wire

```rust
#[non_exhaustive] pub struct Manifest { /* private */ }
impl Manifest {
    pub fn parse_toml(text: &str) -> Result<Manifest, ManifestError>;
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Manifest, ManifestError>;
    pub fn canonical_json(&self) -> Vec<u8>;
    pub fn digest(&self) -> ManifestDigest;
    pub fn id(&self) -> &ModuleId;
    pub fn kind(&self) -> Kind;
    pub fn tools(&self) -> impl Iterator<Item = &Tool>;
    pub fn command(&self, name: &str) -> Option<&Command>;
    pub fn constraints(&self) -> impl Iterator<Item = (ConstraintKey, &Constraint)>;
    pub fn migrate(text: &str) -> Result<String, ManifestError>;
}
impl Command { pub fn resolve(&self, args: &Args) -> Result<ResolvedArgv, ManifestError>; }
#[non_exhaustive] pub enum Kind { Project, Connector, Source, Loop, Executor }
```

Fields private, enums `#[non_exhaustive]`. Wire: capability `manifest` `{"digests": [...]}`; `manifest/get`, `manifest/list`, `manifest/validate` (no store write), `manifest/propose` (pending, never active).

| Code | Name |
|---|---|
| 2000 | `MANIFEST_INVALID` |
| 2001 | `UNKNOWN_MANIFEST` |
| 2002 | `UNKNOWN_COMMAND` |
| 2003 | `ARGS_INVALID` |
| 2004 | `DIGEST_MISMATCH` |
| 2005 | `SCHEMA_UNSUPPORTED` |

Follow-up: register codes in proto `error-codes.md` and its consts test.

## 7. Tests and dependency order

- Round trip: parse, canonicalise, parse: same digest, also for reformatted TOML.
- Rejection corpus: unknown fields, duplicate keys, bad ids, `never` class, reclassified verb, `NEVER_ACTIONS` collision, secret host outside egress, substring placeholder, missing `--`, `..` in cwd, each limit plus one, the pattern corpus.
- Proptest: `resolve` never emits a `-` value without `allow_dash`; every element is a literal or a constraint-checked value; digest ignores key order; parse never panics.
- Mutants: canonicaliser, digest, resolver, dash and `--` rules, limits, class rules.
- Order: manifest v0.1 is standalone (as policy v0.1 was), wire names and codes local, no git deps. After publish: proto, then manifest, then policy.

## 8. Decisions

The owner accepted every recommendation of the open questions.

1. **Missing-command approval.** The user approves a diff; the core commits
   it as a user-authored manifest revision with a new digest. An agent never
   gets a one-shot run. The crate provides the proposal type, its diff, its
   digest and the validation (`CommandProposal`); the approval flow stays in
   the core.
2. **Format.** TOML, not YAML.
3. **Pattern safety.** It moves from damavand-policy into this crate
   (public module `pattern`) and policy depends on manifest. Until policy
   switches, both repos keep a copy, held equal by the shared corpus
   `tests/patterns.toml`.
4. **Dependencies in CI.** Reviewed 0.x crates are published to crates.io.
   No git dependencies. This crate depends on no other damavand crate.
5. **Egress.** Exact hosts only in v1; no wildcards.
6. **`audit = metadata`.** Allowed only for read-only modules.

## 9. Implementation notes (v0.1)

Where the code is stricter than, or fills a gap in, sections 0-7:

- **Command constraint keys name the command.** `ConstraintKey::Command
  {command, arg}` instead of (`run_command`, arg): with a bare arg name, a
  pattern on `filter` in one command would clear an unconstrained `filter`
  in another. Policy keys command arguments by (command, arg).
- **Schema N-1.** Schema 1 is the first version, so no N-1 exists. The
  migration table is in place and empty: `migrate` passes schema 1 through
  and every other version is 2005. The version is read before any other
  field, so a newer manifest reports 2005, not 2000.
- **Read-only module** (for `audit = metadata`): every tool is class
  `read`, and there are no commands, no `verbs` and no secrets. Egress is
  allowed.
- **Uncleared arguments.** `Command::resolve` refuses (2003) unknown or
  missing required arguments, wrong types, values out of shape, NUL and
  dash values without `allow_dash`. A value its constraint does not clear is
  kept and listed in `ResolvedArgv::uncleared`, for policy to escalate.
  Integer and boolean arguments carry no constraint, so they are always
  uncleared.
- **Extra limits and grammars.** 64 parameters per verb, 64 env variables
  per command, 256 enum values, `max_output_bytes` at most 64 MiB (default
  1 MiB), integers within ±(2^53 - 1) (exact in RFC 8785), env names
  `[A-Z_][A-Z0-9_]*`, secret names in the id grammar, header and scheme
  `[A-Za-z][A-Za-z0-9-]{0,63}`, `scheme` optional. Egress hosts need two
  labels, and the top label must not be all digits (no IP literals).
  Two tools cannot share an `upstream` name, so one real tool cannot get
  two classes.
- **Canonical JSON is checked exactly.** `from_canonical_json` re-encodes
  the parsed manifest and refuses bytes that differ (whitespace, duplicate
  keys, order, missing defaults). Canonical input is limited to 1 MiB.
- **Verb names.** `run_command` and `mcp_call` are refused under `verbs`:
  command arguments and tool parameters are constrained where they are
  declared.
- **Proposal digest.** `CommandProposal::digest` is SHA-256 over
  `damavand-manifest/proposal/v1`, the base digest, the name and the
  command's canonical JSON, so an approval binds to one exact proposal.
- **No-weakening test.** `tests/no_weakening.rs` re-implements the policy
  constraint check (no policy dependency) and requires the same constraints
  and the same taint result for every parameter in the copied `cases.yaml`,
  plus the expected escalations and allows of those cases. The full
  decision comparison runs in policy once it depends on this crate.
- **Shared pattern corpus.** `tests/patterns.toml` is new; policy adopts
  the same bytes when it switches.
