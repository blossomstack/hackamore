# Policy Lint + Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Phase 3 of the usability spec: `hackamore policy lint`, `hackamore policy test` (offline dry-run with rule tracing), and mint-time lint — the validation + denial-debugging loop, built on the phase-1/2 catalogs.

**Architecture:** A `Finding` wire type (`models/fluorite/lint.fl`). `hackamore-policy` gains two pure functions beside `decide`: `decide_traced` (verdict + matched rule index) and `lint(&Policy, &BTreeMap<String, &Catalog>) -> Vec<Finding>` (the map keys are **target names** — the gateway maps configured service names to their flavor catalogs; the offline CLI matches rule target names against flavor names). Catalog-derived findings are **Warnings** (catalogs are curated, not exhaustive); can-never-match structural findings and opposite-effect shadowed rules are **Errors**. Mint rejects on Errors. The gateway's decide path switches to `decide_traced` so audit events carry the matched rule index.

**Tech Stack:** Same workspace; branch `policy-lint-test` stacked on `flavor-trait-catalog-list` (PR #11 still open); PR base = that branch.

**Branch:** `policy-lint-test` off `flavor-trait-catalog-list`.

---

### Task 1: `lint.fl` Finding wire type

**Files:** Create `models/fluorite/lint.fl`; Modify `models/src/lib.rs`.

- [ ] Schema: `package lint;` — `enum Severity { Error, Warning }`; `struct Finding { severity: Severity, rule_index: u64, message: String }` (u64 to match existing schema int usage). Doc comments: findings are transported (mint rejection body, future `/policy/lint` endpoint).
- [ ] `models/src/lib.rs`: module include + `Finding::error(rule_index, msg)` / `Finding::warning(rule_index, msg)` constructors + `Severity` re-derives. Serialization smoke test.
- [ ] `cargo test -p hackamore-models`; commit `models: lint Finding wire type`.

### Task 2: `decide_traced` in `hackamore-policy`

**Files:** Modify `policy/src/lib.rs`.

- [ ] ```rust
  /// A decision plus which rule produced it (`None` = default-deny fallthrough).
  pub struct Trace { pub verdict: Verdict, pub matched_rule: Option<usize> }
  pub fn decide_traced(action: &Action, policy: &Policy) -> Trace
  ```
  `decide` delegates: `decide_traced(action, policy).verdict`. Tests: matched index on allow/deny, `None` on fallthrough; existing tests untouched.
- [ ] `cargo test -p hackamore-policy`; commit `policy: decide_traced exposes the matched rule`.

### Task 3: `lint` in `hackamore-policy`

**Files:** Create `policy/src/lint.rs`; Modify `policy/src/lib.rs` (`pub mod lint;` + make `segments_match` available to lint via `pub(crate)`).

Checks (TDD: write the test per check first):
- [ ] **E1 unmatchable glob** (Error): resource glob with leading `/`, empty pattern, or empty segment (`//`) — action paths never have these shapes.
- [ ] **E2/W1 shadowed rule**: rule *j* shadows later rule *i* when every facet of *j* is at-least-as-general: targets (*j* empty or ⊇), verbs (*j* empty or ⊇), resources (*j* empty or every *i*-glob is subsumed by some *j*-glob via `glob_subsumes`), conditions (*j*'s conditions ⊆ *i*'s — fewer = broader). Opposite effects → **Error** ("unreachable: rule N is shadowed by rule M with opposite effect"); same effect → **Warning** ("redundant").
  `glob_subsumes(general, specific)`: segment-recursive pattern-vs-pattern — literal needs equal-literal/`*`/`**` in general; `*` needs `*`/`**`; `**` needs `**`.
- [ ] **W2 no catalogued operation**: per rule, applicable catalogs = all provided (empty targets) or the named targets' entries; skip rules whose applicable catalogs are absent/empty (raw). Each resource glob must intersect ≥1 operation route (`glob_intersects_route`: glob segments vs template segments where `{x}` = any-one, trailing `{x+}` = any-one-or-more; `**` consumes 0..; verb-filter when the rule names verbs) — else Warning "matches no catalogued operation of <targets>".
- [ ] **W3 unknown condition field**: collect the documented fields of the operations the rule can match (route intersects a rule glob — or all ops when the rule has no resource globs — and verb compatible). If ≥1 matched op documents ≥1 field and a condition's (first-segment) field name is in no matched op's field list → Warning. (Dotted paths: compare the first segment.)
- [ ] Public surface: `pub fn lint(policy: &Policy, catalogs: &BTreeMap<String, &Catalog>) -> Vec<Finding>`, findings ordered by rule index. Named-action verbs are NOT linted here (config-owned `ActionCatalog` mint validation already covers them; flavor catalogs are CRUD-only today).
- [ ] `cargo test -p hackamore-policy`; commit `policy: lint — structural + catalog-aware policy validation`.

### Task 4: mint-time lint + audit rule trace (gateway)

**Files:** Modify `gateway/src/core.rs`, `gateway/src/server.rs`.

- [ ] `mint_checked`: after `validate_catalog`, build `BTreeMap<String, &Catalog>` from `self.router.services()` (name → `flavor.catalog()`, skipping empty catalogs) and run lint; any Error finding → `Err(MintError::PolicyLint(findings))` (new variant carrying all findings; Display = "policy failed lint: <first error message> (+N more)").
- [ ] `server.rs` mint handler: `PolicyLint` → 403 JSON `{ "error": "policy failed lint", "findings": [...] }`; other errors unchanged.
- [ ] Decide path (`core.rs:423`): use `decide_traced`; deny detail `"ExplicitDeny (rule 2)"` / `"NotAllowed"`; allow detail gains `"; rule N"`.
- [ ] Unit tests in core.rs: mint rejects a policy with an unmatchable glob and a shadowed-opposite-effect pair; audit detail carries the rule index. `cargo test -p hackamore-gateway`; commit.

### Task 5: CLI `policy lint` + `policy test`

**Files:** Modify `cli/src/main.rs`, `cli/src/render.rs`.

- [ ] `Policy` subcommand: `Lint { file, json }` and `Test { file, flavor, target: Option<String> (default = flavor name), request: String ("METHOD /path?query"), field: Vec<String> (k=v, JSON-parsed values with string fallback) }`.
- [ ] `lint`: catalogs map = flavor-name → catalog for all registry flavors (offline convention: target names matching a flavor name get that catalog). Render findings (`render::findings_human` — "error rule 1: …" lines / `--json`); exit nonzero iff any Error.
- [ ] `test`: build `ProxyRequest` (parse method+path+query; body = JSON object from `--field`s), `canonicalize::path`, `normalize` with a synthetic `Service` of the flavor (name = target), `decide_traced`. Print the normalized Action (pretty JSON), then `decision: Allow (rule 0)` / `Deny NotAllowed (no rule matched)`. Exit 0 (the command succeeded; the verdict is output).
- [ ] Render tests for findings + verdict lines; manual smoke: lint `examples/policy.reviewer-bot.json`, test a matching and a non-matching request against it.
- [ ] `cargo test --workspace`; commit `cli: policy lint + policy test — offline validation and dry-run`.

### Task 6: e2e + docs + gate

**Files:** Modify `tests/tests/use_cases.rs` (or new `tests/tests/mint_lint.rs`), `README.md`.

- [ ] e2e: mint with a policy containing an unmatchable glob → HTTP 403 with `findings`; the reviewer-bot example policy still mints.
- [ ] README quickstart: lint + test lines after `catalog list`.
- [ ] `make check`; push; PR (base `flavor-trait-catalog-list`), no Claude attribution.

## Self-review notes
- Spec deltas recorded: named-action lint deferred (covered by existing ActionCatalog mint validation); catalog findings are Warnings because catalogs are curated subsets; `policy test` exits 0 on deny (verdict is output, not failure).
- Type thread: `Finding` (models) ← produced by `policy::lint` ← consumed by gateway `MintError::PolicyLint` and cli render. `Trace.matched_rule: Option<usize>`.
