# damavand-manifest: design

2026-11-02. Crate 3 of 8, Apache-2.0, repo `jamshidhq/damavand-manifest`.
Section 8 records the decisions on the open questions; section 9 records
where v0.1 differs from sections 0-7.

## 0. Decided (by owner or by earlier crates)

- One manifest per module, reviewed like code. Agents cannot widen it.
- jamshid keeps it in the core store, outside the worktree. Workers call `j_run {name, filter}`.
- The tool list is fixed per loop.
- Policy rules carry over unchanged: the action-id grammar `^[a-z][a-z0-9_.]*$`; one constraint per key (a non-empty enum or a pattern for a string; for an integer or a boolean an `allowed` list or, for an integer, a two-sided bound; see section 10); `compile_pattern` limits and forbidden set; an empty tainted value never clears; requests never carry constraints.
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
| `secrets` | list | `{name, host, port=443, header, scheme}`. Names only. (`host`, `port`) must be in `egress`. |
| `tools` | list | MCP tools (below). |
| `verbs` | table | Param constraints for built-in Cedar verbs. `project` kind only. |
| `commands` | table | Named commands (section 5). |

**Tool:** `id` (grammar), `upstream` (the real MCP name, any printable ASCII, max 128 bytes), `class` (ActionClass; omitted means `write.remote`), `params`.

**Param:** `type` (`string`, `integer`, `boolean`), `required`, shape limits (`max_len`, `min`, `max`), and an optional `constraint` (`enum` or `pattern`). Shape rejects bad values before policy. Only a constraint clears taint, so free text stays tainted: a string's `constraint`, or for an integer or a boolean a declared bound or `allowed` list (section 10). The same holds for command arguments, tool parameters and verb parameters. The crate generates MCP JSON Schema (`additionalProperties: false`); authors never write it.

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
- Values starting with `-` are refused unless `allow_option = true` (renamed from `allow_dash`, see section 9). `--` must precede the first placeholder unless `options_ok = true`.
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

Fields private, enums `#[non_exhaustive]`. Wire: capability `manifest` `{"digests": [...]}`; `manifest/get`, `manifest/list`, `manifest/validate` (no store write). (`manifest/propose` is out of v0.1; see section 9, review round 4.)

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
- Proptest: `resolve` never emits a `-`, `@` or `+` value without `allow_option`; every element is a literal or a constraint-checked value; digest ignores key order; parse never panics.
- Mutants: canonicaliser, digest, resolver, dash and `--` rules, limits, class rules.
- Order: manifest v0.1 is standalone (as policy v0.1 was), wire names and codes local, no git deps. After publish: proto, then manifest, then policy.

## 8. Decisions

The owner accepted every recommendation of the open questions.

1. **Missing-command approval.** An agent never gets a one-shot run. The
   accepted design was an agent proposal the user approves as a diff; it
   is out of v0.1 (section 9, review round 4). The user adds commands in a
   reviewed change.
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
  option-like values without `allow_option`, path escapes without
  `allow_path_escape`. A value its constraint does not clear is
  kept and listed in `ResolvedArgv::uncleared`, for policy to escalate.
  Integer and boolean arguments clear only inside a declared bound
  (review round 4).
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
- **No-weakening test.** `tests/no_weakening.rs` re-implements the policy
  constraint check (no policy dependency) and requires the same constraints
  and the same taint result for every parameter in the copied `cases.yaml`,
  plus the expected escalations and allows of those cases. The full
  decision comparison runs in policy once it depends on this crate.
- **Shared pattern corpus.** `tests/patterns.toml` is new; policy adopts
  the same bytes when it switches.

### Review round 1 (PR #1)

Rules added after the adversarial review of PR #1. Each refusal has
corpus entries in `tests/reject/`. Rules for agent proposals were removed
with proposals in round 4.

- **Never programs.** `NEVER_PROGRAMS` (one const in `schema.rs`:
  terraform, tofu, terragrunt, tfp, pulumi, cdk, cdktf, sam) holds the
  infrastructure apply tools that are Never by owner rule. A command whose
  `argv[0]` basename names one is refused at load, and again in
  `cross_check`. The match is on the
  lowercased basename, also with a variant suffix (`-1.9`, `_v2`, `.exe`)
  or a bare version of digits and dots (`3`, `1.5`). When `argv[0]` is a wrapper program, every word
  of every later literal is checked too, so `env A=1 tofu apply` and
  `sh -c "cd d && tofu apply"` are refused, and `resolve` refuses argument
  values that make a wrapper run one. **Limit:** the crate sees argv only.
  It cannot see through a script or build tool (`make apply`,
  `./deploy.sh`, `npx cdk`, `docker run <image>`); those are reviewed with
  the manifest, and the sandbox bounds them. `cdktf` is added to the owner
  list (the CDK for terraform); `cdk8s` is not matched.
- **Remote programs: class floor, not Never.** kubectl, helm, argocd,
  flux and ansible-playbook stay allowed (the DevOps agent runs read
  operations with them), as do aws, gcloud and az. A command whose program
  (`argv[0]`, or a literal word behind a wrapper) is in `REMOTE_PROGRAMS` has
  `Command::class() == write.remote`; every other command is
  `write.worktree` (`run_command`). The class is derived from argv and is
  not a manifest field, so it cannot be set lower; it is not in the
  canonical JSON (argv already binds it into the digest).
  `ResolvedArgv::class` raises it when a value behind a wrapper names a
  remote program.
- **Plain text where it runs.** argv literals, env values and `cwd` refuse
  C0 and C1 controls and DEL (tab, newline and carriage return included),
  Unicode `Cf`, `Zl` and `Zp` (via `pattern::is_forbidden_char`), and in
  v0.1 any non-ASCII character. Env names already follow
  `[A-Z_][A-Z0-9_]*`.
- **Denied env names.** `DENIED_ENV` (`LD_*`, `DYLD_*`, `PATH`,
  `BASH_ENV`, `ENV`, `*_OPTIONS`, `GIT_*`, `RUSTC`, `RUSTC_WRAPPER`,
  `CARGO_*_RUNNER`, `CARGO_BUILD_*`, `RUSTFLAGS`, `PYTHON*`, `NODE_*`,
  `PERL5*`, `IFS`, `SHELLOPTS`, plus `RUSTC_WORKSPACE_WRAPPER`, `RUSTDOC`,
  `RUSTDOCFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_*_LINKER`, `BASHOPTS`)
  is refused in every command.
- **Option injection.** `allow_dash` is renamed `allow_option` (0.x,
  unpublished, so no serde alias: one spelling). Values starting with `@`
  (response files) or `+` (rustup toolchains, `+opt`) are refused like `-`.
- **Path escape.** A value that is an absolute path or holds a `..`
  segment (split on `/` and `\`; each `=`-separated part is checked, and
  leading `-`, `@`, `+` are ignored for the absolute test, so `--out=/x`
  and `@/x` count) is refused unless the argument sets
  `allow_path_escape = true` (default false, command arguments only). A
  short option with a glued path (`-f/etc/x`) is not seen; constrain such
  an argument.
- **Tool class floor.** `class` may be omitted and then means
  `write.remote`; `read` must be written out. The class is the author's
  assertion, reviewed in git; agents cannot set it (ADR-1122). `Manifest::lints` lists every `read` tool.
- **Wrapper programs.** `WRAPPER_PROGRAMS` (shells, `env`, `xargs`,
  `find`, `nohup`, `timeout`, `nice`, `sudo`, `doas`, `su`, `busybox`,
  `python*`, `node`, `perl`, `ruby`) is a warning from `Manifest::lints` in
  a user-authored manifest, and makes the Never and class checks read every
  later word. It is a partial list: a lint, not a boundary.
- **Secrets bind (host, port).** A secret has a `port` (default 443) and
  (`host`, `port`) must be an egress entry, so a secret for port 443 is
  never sent to another port of the same host.
- **`Args::from_json_str`** parses raw JSON text and refuses a key given
  twice. `Args::from_json` takes a `Value`, in which serde_json has already
  kept the last duplicate, so it cannot refuse them.
- **Not done here.** A `cwd` symlink that leaves the worktree is the
  executor's job (`openat2` with `RESOLVE_BENEATH`); the crate checks text
  only.

### Review round 2 (PR #1)

- **Shells and interpreters are a class floor.** A command whose program
  (`argv[0]`, or a literal word behind a wrapper) is in
  `INTERPRETER_PROGRAMS` (the shells, busybox, `python*`, node, perl, ruby,
  deno, bun, lua, php, awk, gawk, mawk, nawk) is at least `write.remote`,
  like `REMOTE_PROGRAMS`.

The other rules of rounds 2 and 3 bounded agent proposals and were removed
with them (round 4).

### Review round 3 (PR #1)

- **`env` values.** When `argv[0]` is `env`, `resolve` refuses an argument
  value holding `=`: through `env` it would set a variable.

### Review round 4 (PR #1): owner rulings

- **Agent command proposals are out of v0.1.** `CommandProposal`, its
  diff and digest, `manifest/propose`, the proposal-only rules and
  constants (`CODE_FLAGS`, `CODE_FLAG_LETTERS`, `is_code_flag`,
  `PROPOSAL_FORBIDDEN_CHARS`, `PROPOSAL_ENV_ALLOW`) and the proposal corpus
  are removed. Why: after three rounds of fail-closed rules, a delta
  security review still found bypasses (`npx terraform apply`,
  `docker run hashicorp/terraform`, `git push --force` classed
  `write.worktree`, `git -c core.fsmonitor=...`,
  `cargo --config build.rustc-wrapper=...`, `make -f x.mk`, `npm exec`,
  literal paths such as `cat ~/.ssh/id_ed25519`). Vetting an
  agent-written argv cannot be made sound here: the executor sandbox is
  the boundary, and the manifest must not pretend to be one. A future
  form must be narrowing-only: it may only take authority away from a
  command the user already wrote (fewer argument values, a smaller
  timeout), never add a program, a literal, an argument or an env
  variable. Every rule for user-authored manifests is unchanged (the
  rejection corpus gives the same result on every file before and after).
  The `-p`/`-r` over-refusal was in `is_code_flag` only, so it is gone.
- **Integer and boolean arguments clear taint inside a declared bound.**
  Round 4 scoped this to command arguments; section 10 extends the same
  rules to tool parameters and verb parameters.
  - Integer: cleared when its `allowed` list holds the value, or, without
    a list, when both `min` and `max` are narrower than ±(2^53 - 1). A
    bound at that limit is no bound, whether written or not: the
    canonical form fills the default, so it cannot tell the two apart,
    and the stricter reading keeps TOML and canonical JSON equal
    (`Constraint::IntegerRange`, derived, not in the canonical form).
  - Boolean: cleared only when its `allowed` list holds the value
    (`Constraint::Booleans`). A boolean without a list stays tainted.
    (The looser option, a boolean always safe once declared, was not
    taken.)
  - `allowed`: 1-256 values of the argument's type, no duplicates,
    integers inside `min..=max`; sorted in the canonical form, and
    written there only when present, so existing digests do not change.
    `constraint` stays refused on integers and booleans.
  - A value outside `min..=max` is refused (2003), as before; a value
    outside `allowed` is kept and stays tainted, like a string outside its
    enum. `Manifest::constraints` lists the new constraints, so policy
    and `ResolvedArgv::uncleared` agree.

## 10. Integer and boolean taint scope (owner rulings 2026-11-14)

- **One rule everywhere.** Command arguments, tool parameters and verb
  parameters clear integer and boolean values the same way. An integer
  clears when its `allowed` list holds the value, or, without a list,
  when both `min` and `max` are narrower than ±(2^53 - 1). A boolean
  clears only through `allowed`. A one-sided bound never clears. The
  field keeps the name `allowed`.
- **Any finite declared bound narrower than ±(2^53 - 1) clears;
  narrowness is the author's call.** The crate does not judge whether
  `1..=1000000` is narrow enough. The reviewer of the manifest does.
- **Negative bounds and `allow_option`.** An integer command argument
  with `allow_option = true` and a negative `min` can clear values such
  as `-5`, which read as flags in argv. That is the author's opt-in:
  without `allow_option`, `resolve` refuses any value starting with `-`.
  The `-`/`@`/`+` and path-escape rules stay command-only; tool and verb
  values never reach an argv.
- **Tool parameters.** `allowed` is accepted, and a two-sided bound
  derives `Constraint::IntegerRange`. The MCP input schema keeps
  `minimum` and `maximum` and gets no `enum` for `allowed`: a value
  outside the list is kept and stays tainted, it is not a shape error.
  The `gh.issue_read.number` parameter of the `full.toml` fixture
  (`1..=1000000`) now clears; its digest is unchanged, because the range
  is derived and not written.
- **Verb parameters.** A verb parameter takes `type` (`string` when
  omitted), `constraint` (strings only), `min`, `max` and `allowed`.
  Nothing else: `required`, `max_len`, `allow_option` and
  `allow_path_escape` stay unknown fields. A verb entry exists only to
  clear taint, so an integer or boolean verb parameter that clears no
  value (one-sided bound, no bound, boolean without `allowed`) is refused
  at load, instead of being kept as an entry that does nothing.
- **Canonical form.** A string verb parameter is still written as
  `{"constraint": ...}` only, so the digest of every manifest that does
  not use the new forms is unchanged (pinned for the fixtures in
  `tests/taint_scope.rs`). An integer verb parameter writes `type`,
  `min` and `max` (defaults filled) and `allowed` when present; a boolean
  writes `type` and `allowed`. `allowed` is sorted. A string verb
  parameter with an explicit `"type": "string"` is not canonical.
- **No panic path.** Writing a constraint to JSON is one exhaustive
  match over every `Constraint` variant; the old `unreachable!` for verb
  constraints is gone.
- **For consumers.** damavand-policy must decide clearing by calling
  `Constraint::clears`, not by matching variants itself. `Constraint` and
  `ConstraintKey` are `#[non_exhaustive]`: a variant policy does not know
  must fail closed (value stays tainted).
