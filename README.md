# damavand-manifest

Module manifests for the damavand agent-safety crates. A manifest says what
one module (a jamshid project, a connector, a source, a loop, an executor)
may do: its MCP tools with their action class and parameters, its named
commands, its exact egress hosts and the secrets bound to them, and caps
that can only lower autonomy. Manifests are reviewed like code. Nothing an
agent sends can widen one.

[docs/design.md](docs/design.md) is the design, with the decisions taken.

## Stability

- **Rust API:** can change in any release before 1.0.
- `serde_json` (`Tool::input_schema`, `Args::from_json`) and `regex`
  (`pattern::compile_pattern`) are public dependencies.
- MSRV: Rust 1.89.
- No dependency on other damavand crates.

## Use

```rust
use damavand_manifest::{Args, Manifest};

let m = Manifest::parse_toml(&text)?; // strict; refuses anything unsafe
let digest = m.digest();              // SHA-256 over RFC 8785 JSON
for (key, constraint) in m.constraints() {
    // (verb | tool | command, parameter) -> enum or pattern that clears taint
}
let run = m.resolve("test", &Args::new().with("filter", "parse::limits"))?;
// run.argv, run.cwd, run.env, run.timeout_secs; no shell.
// run.class is the action class to check (write.worktree, or
// write.remote for a remote program).
// run.uncleared lists the arguments policy must escalate.
for warning in m.lints() {
    // wrapper programs and `read` tools, for the reviewer
}
```

## Manifest

```toml
schema = 1
id = "jamshid"              # [a-z][a-z0-9_.]*
kind = "project"            # project | connector | source | loop | executor
audit = "full"              # full (default) | metadata (read-only modules)

[identity]
aws_role = "arn:aws:iam::123456789012:role/jamshid-reader"

[autonomy]                  # class -> 0-3; only lowers the git cap
"write.remote" = 1

[[egress]]                  # exact lowercase host, HTTPS, no wildcards
host = "api.github.com"     # port = 443 by default

[[secrets]]                 # name only; (host, port) must be in egress
name = "github_token"
host = "api.github.com"     # port = 443 by default"
header = "Authorization"
scheme = "Bearer"

[[tools]]
id = "gh.issue_read"        # never a schema verb or a Never action
upstream = "get_issue"      # the real MCP tool name
class = "read"              # never "never"; omitted = "write.remote"
params.repo = { type = "string", required = true, max_len = 100, constraint = { pattern = "[a-z0-9_.-]+/[a-z0-9_.-]+" } }

[verbs.j_edit.mode]         # project manifests only
constraint = { enum = ["append", "replace"] }

[commands.test]
argv = ["cargo", "test", "--workspace", "--", "{filter}"]
env = { RUST_BACKTRACE = "1" }
output = "failures-only"
timeout_secs = 900          # required, at most 3600
args.filter = { type = "string", max_len = 200, constraint = { pattern = "[a-z0-9_:]+" } }
```

| Rule | |
| --- | --- |
| Parsing | Unknown fields, duplicate keys, floats, datetimes and integers beyond ±(2^53 - 1) are refused. |
| Limits | 256 KiB per file, 4 KiB per string or key, 256 tools, 64 parameters per tool, command or verb, 128 commands, 64 argv elements, 64 egress entries, 32 secrets, 64 env variables, 256 enum values. |
| Classes | A manifest sets a class only for its own tools; an omitted class is `write.remote`, so `read` is always written out (and listed by `lints`). The class is the author's assertion, reviewed in git; proposals never touch tools. `never`, schema verbs and Never actions are refused as tool ids; a verb never takes a class. A command's class is derived: `write.remote` when its program is in `REMOTE_PROGRAMS` (kubectl, helm, aws, ...), else `write.worktree`. |
| Constraints | One non-empty enum or one pattern. Patterns go through `pattern::compile_pattern` (anchored; refused if they can match the empty string, a character in `Cc`, `Cf`, `Zl` or `Zp`, or a shell metacharacter). An empty value never clears. Only a constraint clears taint. |
| Commands | argv only, no shell. `argv[0]` is a literal and never a Never program (`NEVER_PROGRAMS`, also behind a wrapper such as `env` or `sh -c`). A placeholder fills a whole element; an absent optional argument deletes its element. `--` must come before the first placeholder unless `options_ok = true`. A value starting with `-`, `@` or `+` is refused unless the argument has `allow_option = true`; an absolute path or a `..` segment unless it has `allow_path_escape = true`. argv literals, env values and `cwd` are printable ASCII. Fixed env without the names in `DENIED_ENV` (`LD_*`, `PATH`, `GIT_*`, ...), relative `cwd` without `..`. |
| Audit | `metadata` only when every tool is class `read` and there are no commands, verbs or secrets. |

## Canonical form and digest

`Manifest::canonical_json` is RFC 8785 JSON of the validated value with
defaults filled in and unordered lists sorted (egress, secrets, tools, enum
values). `Manifest::digest` is SHA-256 over the length-prefixed domain tag
`damavand-manifest/v1` and the length-prefixed canonical bytes. Comments,
layout and key order do not change it. `Manifest::from_canonical_json`
refuses bytes that are not exactly the canonical form.

## Missing commands

An agent never runs a command the manifest lacks. It can propose one:
`CommandProposal::parse` validates the addition against the base manifest,
`diff` renders it for the user (one field per line, every string quoted,
anything outside printable ASCII escaped as `\u{XXXX}`), and after the user
approves, the core calls `apply` (refused if the base moved on) and commits
the result as a user-authored revision with a new digest. A proposal is held to more than
a manifest: `argv[0]` is never a wrapper program (`WRAPPER_PROGRAMS`: shells,
`env`, `xargs`, `sudo`, interpreters), and it sets no `env`.

## Wire (damavand-proto)

Capability `manifest` (`{"digests": [...]}`); methods `manifest/get`,
`manifest/list`, `manifest/validate` (no store write), `manifest/propose`
(pending, never active); error codes 2000-2005 (`wire::codes`). Until this
crate depends on damavand-proto, the names live in the `wire` module.

## Not yet in the crate

- The manifest store, the approval flow and the `manifest/*` server.
- A schema N-1: schema 1 is the first version, so `migrate` passes it
  through and every other version is refused (2005).

## License

Apache-2.0. See [LICENSE](LICENSE).
