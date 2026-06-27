# hackamore usability: formalized catalogs, policy tooling, web UI, pluggable flavors

**Date:** 2026-06-12
**Status:** Approved — amended 2026-06-12 during phase-1 implementation: catalog/normalizer
agreement is enforced by invariant tests rather than a catalog-interpreting default
`normalize` (see §1); the pre-existing named-action `Catalog` in the gateway was renamed
`ActionCatalog` to free the name.

## Problem

hackamore is hard to use, in three connected ways:

1. **Policy authoring is not formalized.** The policy vocabulary (verbs, resource
   paths, resource kinds, conditionable fields) is implicitly defined by hand-written
   normalizer code in `gateway/src/normalize.rs`. A user writing a GitHub policy has
   no way to discover that `POST /repos/o/r/pulls` normalizes to verb `Create`,
   resource `repos/o/r/pulls`, kind `pull_request`, with fields `base`, `head`,
   `title`, … — they reverse-engineer the normalizer by trial and error.
2. **No validation or feedback.** Beyond JSON shape (and named-action catalog checks
   at mint time), nothing tells an author that a rule can never match, a glob is
   malformed, or a condition references a field that no operation produces. A bad
   policy silently never matches and everything is denied.
3. **Setup friction.** Configuring a host means pasting a real credential as a
   plaintext string into `config.json`.

Adding a new service flavor today means editing gateway internals — flavors are not
pluggable even for contributors, let alone discoverable for users.

## Goals

- A **machine-readable catalog** per flavor is the single source of truth for the
  policy vocabulary, and powers discovery (CLI + web UI), validation (lint), and
  debugging (offline dry-run).
- Policy authoring becomes **self-contained**: a user can list everything they can
  write a policy about, validate a policy, and test it against a hypothetical
  request — all offline, from the binary, with no server running.
- Flavors are **pluggable via a Rust trait + compile-time registry**, with the
  default normalization driven by the catalog so catalog and behavior cannot drift.
- A **toggleable web UI** lets users explore catalogs and compose policies
  interactively.
- Credentials can be referenced from the environment or files instead of inline
  plaintext, and `hackamore init` scaffolds a valid config.

## Non-goals

- Runtime-loadable flavors (WASM, external catalog files). Flavors are compiled in.
- A new policy authoring language or shorthand. The wire policy format is unchanged.
- Record-then-author ("learn mode" deriving policies from audit traffic) — explicit
  fast-follow, enabled by this work but out of scope.
- An audit/denial viewer in the web UI — future scope.
- A demo mode with mock upstreams.

## Design

### 1. The `Flavor` trait and registry (`hackamore-gateway`)

A flavor becomes a first-class abstraction, replacing the hand-rolled flavor `match`
in `normalize.rs`:

```rust
pub trait Flavor: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;
    fn catalog(&self) -> &Catalog;
    fn resource(&self, path: &str) -> Resource;
}
```

- Built-in flavors (`github`, `k8s`, `generic`) register in a static, compile-time
  registry. Config `"flavor": "github"` resolves through the registry; an unknown
  flavor name is a **startup error** (fail closed). Absent flavor = generic, as today.
- **Amended:** the flavor hook is `resource()` (path → kind), not a full `normalize`
  override — verb and field extraction are protocol concerns (`Protocol::Rest` /
  `AwsQuery` / `AwsJson`) shared by all flavors and they stay in `normalize.rs`.
  Resource derivation stays as flavor *code* (moved verbatim from `normalize.rs`,
  exact parity), and no-drift between catalog and normalizer is guaranteed by
  **invariant tests** instead of a catalog interpreter: every catalog operation's
  route template is instantiated with dummy segments and walked through the flavor's
  real `resource()` (kind must match) and through the real method→verb mapping (verb
  must match). A catalog entry that disagrees with the data plane cannot ship.
- Unmatched requests keep today's behavior unchanged — each flavor's `resource()`
  handles every path (fail-closed default-deny applies as before).
- The existing normalize unit tests serve as the parity pins; they were not modified
  beyond flavor-reference spelling.

### 2. `Catalog` schema (`hackamore-models`, fluorite)

Catalogs are served over the admin API to the web UI, so they are protocol types:
defined in `models/fluorite/catalog.fl`, generated like the rest of the contract.

```
Catalog   { flavor: String, operations: [Operation] }
Operation { id: String,              // "pulls.create"
            verb: Verb,              // reuses the existing Verb union
            route: Route,            // { method, path_template: "repos/{owner}/{repo}/pulls" }
            resource_kind: String,   // "pull_request"
            fields: [FieldSpec],     // { name: "base", source: Body|Query|Path, summary }
            summary: String }
```

Hand-written convenience methods (lookups by id, by route) go in `models/src/lib.rs`
per project convention. Catalogs are **not** persisted data; they are static data
compiled into flavors and serialized on demand.

### 3. CLI: self-contained discovery, validation, dry-run

All three commands work offline from the binary's compiled-in registry — no server.

- **`hackamore catalog list [--flavor <name>] [--json]`** — every flavor, operation,
  resource kind, path shape, and conditionable field. Human table by default,
  `--json` for tooling.
- **`hackamore policy lint <policy.json>`** — semantic validation. Lives in
  `hackamore-policy` as a pure function beside `decide`:

  ```rust
  pub fn lint(policy: &Policy, catalogs: &[Catalog]) -> Vec<Finding>
  // Finding { severity: Error | Warning, rule_index, message }
  ```

  Checks: resource globs that match no known operation route, conditions on fields
  no matching operation produces, rules fully shadowed by earlier rules, malformed
  globs, named-action verbs unknown to every catalog (subsumes today's mint-time
  `validate_catalog`). Errors exit nonzero; warnings print but pass. Rules scoped
  to a flavor with an empty catalog (e.g. `generic`) skip catalog-derived checks —
  structural checks (glob syntax, shadowing) still apply.
- **`hackamore policy test <policy.json> --flavor github --request "POST /repos/o/r/pulls" --field base=main`** —
  runs normalize + a traced decide offline. Prints the normalized `Action`, which
  rule (by index) matched or that none did, and the verdict. `decide_traced` in
  `hackamore-policy` returns the matched rule index alongside the `Verdict`; the
  gateway also includes this trace detail in deny audit events.
- **Mint-time lint:** the admin `/mint` endpoint runs `lint` and rejects policies
  with Error findings (replacing/absorbing the current named-action validation), so
  a bad policy fails fast at mint instead of silently never matching.

### 4. Web UI: catalog explorer + policy composer

- Served from the **admin listener** (already localhost-only) under `/ui`, behind a
  config flag `"web_ui": true | false`.
- Static assets embedded in the binary at compile time. A small, dependency-light
  single-page app — plain HTML/JS/CSS checked into the repo, no Node build step in
  `make build`.
- New admin endpoints, all thin wrappers over the same pure functions the CLI uses:
  - `GET  /catalogs` — serialized catalogs from the registry
  - `POST /policy/lint` — body: policy; returns findings
  - `POST /policy/test` — body: policy + synthetic request; returns Action, trace,
    verdict
  - existing `POST /mint`
- Composer flow: browse a service's operations → select operations to allow → add
  conditions with field autocomplete from the catalog → live lint feedback → export
  the policy JSON, or mint a token directly.

### 5. Setup: credential references and `hackamore init`

- Config credential values become a union: inline string (today, discouraged),
  `{"env": "GITHUB_TOKEN"}`, or `{"file": "/path/to/secret"}`. Resolution happens
  at startup in `hackamore-control`'s vault; resolved secrets keep the existing
  no-plain-`String` discipline. A missing env var or unreadable file is a startup
  error (fail closed).
- **`hackamore init`** — interactive scaffold: pick services from the flavor
  registry, choose a credential source per service, write a valid `config.json`.
  The generated config lints clean and points at env-var credentials by default.

## Error handling

- Unknown flavor in config → startup error, server refuses to start.
- Lint: Error findings reject at mint (403 with the findings); CLI exits nonzero.
- `policy test` with a request that matches no catalog route still normalizes via
  the fallback and reports the verdict — mirroring runtime behavior exactly.
- Credential reference resolution failure → startup error naming the credential id
  (never the secret value).
- Web UI disabled → `/ui` and the new endpoints return 404.

## Testing

- **Parity tests** for the flavor refactor: golden (request → Action) cases for
  github/k8s/generic asserted unchanged across the refactor.
- **Catalog invariant tests**: every operation's route template parses; ids unique;
  every built-in flavor's catalog non-empty.
- **Lint unit tests** in `hackamore-policy`: each finding type, plus a clean policy.
- **`decide_traced`** unit tests: trace agrees with `decide` on verdict for all cases.
- **e2e** (`hackamore-tests`): mint rejects a policy with lint errors; `/catalogs`,
  `/policy/lint`, `/policy/test` round-trip; web UI flag off → 404.
- **CLI snapshot tests** for `catalog list` and `policy test` output.

## Phasing

Each phase ships independently and is useful on its own:

1. **Catalog types + `Flavor` trait refactor** — pure refactor, parity tests, no
   behavior change.
2. **`hackamore catalog list`** — discovery.
3. **`policy lint` + `policy test` + mint-time lint** — validation and debugging.
4. **Admin endpoints + web UI** — explorer and composer.
5. **`hackamore init` + credential references** — setup.

## Future work (explicitly deferred)

- Record-then-author: derive a least-privilege policy from audit `Action` traffic.
- Audit/denial viewer in the web UI.
- Policy templates (`policy new --template github-reviewer`) validated by lint.
- Runtime-loadable catalog files for user-defined services without recompiling.
