# Flavor Trait + Catalog Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Phases 1–2 of the usability spec (`docs/superpowers/specs/2026-06-12-usability-catalogs-tooling-design.md`): make flavors pluggable behind a `Flavor` trait with a compile-time registry exposing a machine-readable `Catalog`, then ship `hackamore catalog list`.

**Architecture:** A new `Catalog` protocol type (fluorite, `models/fluorite/catalog.fl`) describes each flavor's operations (id, verb, route, resource kind, conditionable fields). A `Flavor` trait in `gateway/src/flavors/` owns resource derivation and exposes its catalog; built-in flavors (`github`, `k8s`, `generic`) register in a static registry resolved by name (unknown name in config → startup error, fail closed). **Design refinement vs spec:** resource derivation stays as flavor code (moved verbatim, exact parity) rather than being interpreted from the catalog; no-drift is guaranteed by *invariant tests* that walk every catalog operation through the flavor's real `resource()` and the method→verb mapping, asserting agreement. The spec is amended to record this. The existing named-action `Catalog` (a `BTreeSet` used for mint-time validation) is renamed `ActionCatalog` to free the name.

**Tech Stack:** Rust workspace, fluorite codegen (models/build.rs picks up new `.fl` files automatically), clap CLI, `make check` as the gate.

**Branch:** work on `flavor-trait-catalog-list` off `main` in the main checkout (nothing else in flight; keeps the build cache warm).

---

### Task 1: `catalog.fl` protocol type + convenience constructors

**Files:**
- Create: `models/fluorite/catalog.fl`
- Modify: `models/src/lib.rs` (new module include + convenience impls + tests)

- [ ] **Step 1: Write the schema** — `models/fluorite/catalog.fl`:

```
/// The machine-readable vocabulary of one flavor: every operation policies can be
/// written about, with its verb, route shape, resource kind, and the request fields
/// conditional rules can reference. Served to discovery tooling (`hackamore catalog
/// list`, the web UI) and consumed by policy lint — the single source of truth a
/// policy author works from.
package catalog;

use action.Verb;

/// The HTTP methods catalog routes are written against (the canonical operation
/// spellings; HEAD/OPTIONS normalize like GET and are not catalogued).
enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// Where a conditionable field comes from in the request.
enum FieldSource {
    /// Captured from a path template segment.
    Path,
    /// A query-string parameter.
    Query,
    /// A key in the JSON (or form) request body.
    Body,
}

/// One request attribute an operation exposes to conditional rules.
struct FieldSpec {
    /// The key as it appears in `Action.fields` (dotted paths allowed, e.g. "head.ref").
    name: String,
    source: FieldSource,
    /// One-line human description.
    summary: String,
}

/// The route shape of an operation: method + path template. Template segments are
/// literals or `{name}` captures; a trailing `{name+}` captures the path remainder.
struct Route {
    method: HttpMethod,
    /// Slash-joined, no leading slash, e.g. "repos/{owner}/{repo}/pulls".
    path_template: String,
}

/// One operation a policy can allow or deny: what the normalizer turns a matching
/// request into (verb + resource kind), and which fields it extracts.
struct Operation {
    /// Stable id, e.g. "pulls.create".
    id: String,
    /// The verb the normalizer produces for this operation.
    verb: Verb,
    route: Route,
    /// The `Resource.kind` the normalizer produces, e.g. "pull_request".
    resource_kind: String,
    /// Conditionable request fields this operation carries. Not exhaustive — the
    /// normalizer forwards every body/query key — but the documented, curated set.
    fields: Vec<FieldSpec>,
    /// One-line human description.
    summary: String,
}

/// A flavor's full vocabulary. An empty `operations` list means the flavor is raw /
/// undocumented (e.g. `generic`): discovery has nothing to show and lint skips
/// catalog-derived checks.
struct Catalog {
    /// The flavor name this catalog belongs to, e.g. "github".
    flavor: String,
    operations: Vec<Operation>,
}
```

- [ ] **Step 2: Add the module include** in `models/src/lib.rs` after the `provision` block:

```rust
#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod catalog {
    include!(concat!(env!("OUT_DIR"), "/catalog/mod.rs"));
}
```

- [ ] **Step 3: Add convenience impls + tests** in `models/src/lib.rs` (follow the `Action::of` pattern):

```rust
impl catalog::HttpMethod {
    /// The canonical uppercase method string, e.g. "POST".
    pub fn as_str(self) -> &'static str { /* match all five arms */ }
}

impl catalog::FieldSpec {
    pub fn of(name: impl Into<String>, source: catalog::FieldSource, summary: impl Into<String>) -> Self
}

impl catalog::Operation {
    /// Ergonomic constructor with no fields; chain `with_fields`.
    pub fn of(id, verb, method: catalog::HttpMethod, path_template, resource_kind, summary) -> Self
    #[must_use] pub fn with_fields(mut self, fields: Vec<catalog::FieldSpec>) -> Self
}

impl catalog::Catalog {
    pub fn of(flavor: impl Into<String>, operations: Vec<catalog::Operation>) -> Self
}
```

`HttpMethod` derives only the workspace set (no `Copy` from codegen) — check the generated derives; if `Copy` is absent, take `self` by value anyway (`Clone` is derived) or by reference, whichever compiles cleanly.

Unit test in a `#[cfg(test)]` module: build an `Operation` via `of(...).with_fields(...)`, serialize with `serde_json`, assert the JSON shape (tagged-union verb, enum method as string).

- [ ] **Step 4: Run** `cargo test -p hackamore-models` — expect PASS (codegen picks up the new package via `compile_with_options(options, &["fluorite"])`).

- [ ] **Step 5: Commit** `models: add catalog protocol types (flavor vocabulary)`

### Task 2: rename gateway `Catalog` → `ActionCatalog`

**Files:**
- Modify: `gateway/src/service.rs` (type def + impls + tests)
- Modify: `gateway/src/lib.rs:20` (re-export)
- Modify: `gateway/src/core.rs` (`with_catalogs`, `validate_catalog` sites)
- Modify: `cli/src/main.rs:12,124-135` (import + usage)

- [ ] **Step 1:** Mechanical rename everywhere (`grep -rn "Catalog" --include=\*.rs` excluding `target/`); keep doc comments, adjust them to say "named-action catalog". The re-export becomes `pub use service::{ActionCatalog, ...}`.
- [ ] **Step 2: Run** `cargo clippy --all-targets --all-features -- -D warnings && cargo test --workspace` — expect PASS, zero behavior change.
- [ ] **Step 3: Commit** `gateway: rename Catalog -> ActionCatalog, freeing the name for the flavor vocabulary`

### Task 3: the `Flavor` trait, built-in impls, registry

**Files:**
- Create: `gateway/src/flavors/mod.rs`, `gateway/src/flavors/github.rs`, `gateway/src/flavors/k8s.rs`, `gateway/src/flavors/generic.rs`
- Modify: `gateway/src/service.rs` (drop `Flavor` enum; `Service.flavor` becomes `&'static dyn Flavor`; manual `Default`)
- Modify: `gateway/src/normalize.rs` (resource derivation delegates to the flavor; move `github_resource`/`k8s_resource`/`generic_resource` into flavor files)
- Modify: `gateway/src/lib.rs` (module + re-exports)
- Modify call sites: `gateway/src/core.rs` (tests + provision `s.flavor.name()` — unchanged call), `cli/src/main.rs`, `tests/src/lib.rs:10,174`, `tests/tests/use_cases.rs`, `tests/tests/transports.rs`

- [ ] **Step 1: Write the trait + registry** (`flavors/mod.rs`):

```rust
//! Pluggable normalization flavors. A flavor owns how a request path becomes a
//! [`Resource`] and publishes its [`Catalog`] — the machine-readable vocabulary
//! policy tooling (discovery, lint, the web UI) works from. Built-in flavors live
//! here and register in [`registry`]; adding one = a new impl + one registry line.
//! Catalog/normalizer agreement is enforced by invariant tests, not shared code:
//! every catalog operation is walked through the flavor's real `resource()`.

mod generic;
mod github;
mod k8s;

pub use generic::GenericFlavor;
pub use github::GithubFlavor;
pub use k8s::K8sFlavor;

use hackamore_models::action::Resource;
use hackamore_models::catalog::Catalog;

/// How one service flavor turns request paths into resources, plus its published
/// vocabulary. `Debug` is a supertrait so `Service` can keep `#[derive(Debug)]`.
pub trait Flavor: Send + Sync + std::fmt::Debug {
    /// The canonical lowercase flavor name (what config's `"flavor"` field says).
    fn name(&self) -> &'static str;
    /// The flavor's operation vocabulary (empty = raw/undocumented).
    fn catalog(&self) -> &Catalog;
    /// Derive the resource (canonical path + kind) for a request path.
    fn resource(&self, path: &str) -> Resource;
}

pub static GENERIC: GenericFlavor = GenericFlavor;
pub static GITHUB: GithubFlavor = GithubFlavor;
pub static K8S: K8sFlavor = K8sFlavor;

/// Every built-in flavor, in `catalog list` display order.
pub fn registry() -> &'static [&'static dyn Flavor] {
    &[&GITHUB, &K8S, &GENERIC]
}

/// Look up a flavor by its canonical name (case-insensitive).
pub fn by_name(name: &str) -> Option<&'static dyn Flavor> {
    registry().iter().copied().find(|f| f.name().eq_ignore_ascii_case(name))
}

/// Resolve a config flavor name. Absent = generic; an unknown name is an error
/// (fail closed: a typo must not silently downgrade to generic parsing).
pub fn resolve(name: Option<&str>) -> Result<&'static dyn Flavor, UnknownFlavor> {
    match name {
        None => Ok(&GENERIC),
        Some(n) => by_name(n).ok_or_else(|| UnknownFlavor(n.to_string())),
    }
}

/// A config named a flavor no registered impl claims.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownFlavor(pub String);

impl std::fmt::Display for UnknownFlavor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let known: Vec<&str> = registry().iter().map(|f| f.name()).collect();
        write!(f, "unknown flavor '{}' (known: {})", self.0, known.join(", "))
    }
}
impl std::error::Error for UnknownFlavor {}
```

Each impl file: a unit struct deriving `Debug`, the moved `*_resource` function (verbatim, including `github_collection_kind`), `catalog()` returning a `&'static Catalog` via `std::sync::OnceLock` (empty `Catalog::of("generic", vec![])` for generic; github/k8s data lands in Task 4 — start them empty too so this task stays a pure move).

- [ ] **Step 2: Rewire `Service`** (`service.rs`): delete the `Flavor` enum (and its `parse`/`name` impls and the `flavor_parse_defaults_generic` test); `pub flavor: &'static dyn crate::flavors::Flavor`; replace `#[derive(... Default)]` with a manual `impl Default for Service` (flavor: `&crate::flavors::GENERIC`, rest `Default::default()`); `with_flavor(mut self, flavor: &'static dyn crate::flavors::Flavor)`.
- [ ] **Step 3: Rewire `normalize()`** (`normalize.rs:23-27`): the flavor match becomes `let resource = service.flavor.resource(path);`. Remove the moved functions + their imports. **Do not touch the existing tests' assertions** — they are the parity pins; update only their `Flavor::Github`-style references to `&flavors::GITHUB`.
- [ ] **Step 4: Update remaining call sites**: `Flavor::parse(s.flavor.as_deref())` in `cli/src/main.rs` → `hackamore_gateway::flavors::resolve(s.flavor.as_deref()).map_err(|e| format!("service '{}': {e}", s.name))?` — convert the `.map().collect()` services block into a `for` loop pushing into a `Vec` so `?` works. `tests/` crates: import `hackamore_gateway::flavors` and pass `&flavors::GITHUB` etc. `gateway/src/lib.rs`: add `pub mod flavors;`, re-export `pub use flavors::Flavor;`, drop `Flavor` from the `service` re-export list.
- [ ] **Step 5: Add registry tests** in `flavors/mod.rs`: `by_name("github")`/`("GitHub")` resolve to a flavor named "github"; `resolve(None)` is generic; `resolve(Some("nope"))` is `Err` and the message names the known flavors; registry names are unique.
- [ ] **Step 6: Run** `cargo clippy --all-targets --all-features -- -D warnings && cargo test --workspace` — expect PASS (normalize tests prove parity).
- [ ] **Step 7: Commit** `gateway: pluggable Flavor trait + compile-time registry; unknown flavor fails closed`

### Task 4: GitHub + K8s catalog data + invariant tests

**Files:**
- Modify: `gateway/src/flavors/github.rs`, `gateway/src/flavors/k8s.rs`
- Modify: `gateway/src/flavors/mod.rs` (shared invariant tests)

- [ ] **Step 1: GitHub catalog** (in `github.rs`, built inside the `OnceLock`). Operations (all `Verb::crud` — REST flavor; fields source `Body` unless said otherwise; ids/kinds must agree with `github_resource`):
  - `repo.get` — Get `repos/{owner}/{repo}` → kind `repo`
  - `pulls.list` — Get `repos/{owner}/{repo}/pulls` → `pull_request`; fields: `state`(Query), `base`(Query), `head`(Query)
  - `pulls.create` — Post `repos/{owner}/{repo}/pulls` → `pull_request`; fields: `title`, `head`, `base`, `body`, `draft`
  - `pulls.get` — Get `repos/{owner}/{repo}/pulls/{number}` → `pull_request`
  - `pulls.update` — Patch `repos/{owner}/{repo}/pulls/{number}` → `pull_request`; fields: `title`, `body`, `state`, `base`
  - `pulls.merge` — Put `repos/{owner}/{repo}/pulls/{number}/merge` → `pull_request`; fields: `merge_method`, `commit_title`
  - `issues.list` — Get `repos/{owner}/{repo}/issues` → `issue`; fields: `state`(Query), `labels`(Query)
  - `issues.create` — Post `repos/{owner}/{repo}/issues` → `issue`; fields: `title`, `body`, `labels`, `assignees`
  - `issues.get` — Get `repos/{owner}/{repo}/issues/{number}` → `issue`
  - `issues.update` — Patch `repos/{owner}/{repo}/issues/{number}` → `issue`; fields: `title`, `body`, `state`
  - `issues.comment` — Post `repos/{owner}/{repo}/issues/{number}/comments` → `issue`; fields: `body`
  - `contents.get` — Get `repos/{owner}/{repo}/contents/{path+}` → `contents`; fields: `ref`(Query)
  - `contents.put` — Put `repos/{owner}/{repo}/contents/{path+}` → `contents` (create *or* update a file; the method maps to verb Update); fields: `message`, `content`, `branch`, `sha`
  - `contents.delete` — Delete `repos/{owner}/{repo}/contents/{path+}` → `contents`; fields: `message`, `sha`, `branch`
  - `git.create_ref` — Post `repos/{owner}/{repo}/git/refs` → `git`; fields: `ref`, `sha`
  - `git.get_ref` — Get `repos/{owner}/{repo}/git/ref/{ref+}` → `git`
  - `actions.list_runs` — Get `repos/{owner}/{repo}/actions/runs` → `actions`
  - `hooks.list` — Get `repos/{owner}/{repo}/hooks` → `hook`
  - `hooks.create` — Post `repos/{owner}/{repo}/hooks` → `hook`; fields: `config`, `events`, `active`
  Every operation gets a one-line `summary`. Add `{owner}`/`{repo}` Path-source fields? No — path captures only exist when `extract.path_template` is configured; the catalog documents Body/Query fields only (YAGNI).
- [ ] **Step 2: K8s catalog** (`k8s.rs`): `pods.list` Get `api/v1/namespaces/{namespace}/pods` → `pods`; `pods.get` Get `.../pods/{name}` → `pods`; `pods.delete` Delete `.../pods/{name}` → `pods`; `pods.logs` Get `.../pods/{name}/log` → `pods`; `deployments.list` Get `apis/apps/v1/namespaces/{namespace}/deployments` → `deployments`; `deployments.get`/`deployments.create`(fields none)/`deployments.delete` likewise; `secrets.get` Get `api/v1/namespaces/{namespace}/secrets/{name}` → `secrets`. Wait — `pods.logs` route ends in `log`; `k8s_resource` gives segment after namespace = `pods` ✓.
- [ ] **Step 3: Invariant tests** in `flavors/mod.rs` `#[cfg(test)]`, run over `registry()` so future flavors are covered automatically:

```rust
/// Instantiate a route template with dummy concrete segments: `{name}` -> "x",
/// trailing `{name+}` -> "x/y", literals kept.
fn instantiate(template: &str) -> String { /* split('/'), map, join */ }

#[test]
fn catalog_kinds_agree_with_the_normalizer() {
    for flavor in registry() {
        for op in &flavor.catalog().operations {
            let path = instantiate(&op.route.path_template);
            assert_eq!(flavor.resource(&path).kind, op.resource_kind,
                "{}: op {} catalog kind drifted from resource()", flavor.name(), op.id);
        }
    }
}

#[test]
fn catalog_verbs_agree_with_the_method_mapping() { /* verb_for(http method from op.route.method.as_str()) == op.verb */ }

#[test]
fn catalog_ids_are_unique_and_flavor_names_match() { /* per flavor: BTreeSet of ids, len equal; catalog.flavor == flavor.name() */ }

#[test]
fn github_and_k8s_catalogs_are_non_empty() { ... }
```

`verb_for` lives in `normalize.rs` as a private fn — make it `pub(crate)` so the test can use it (the real mapping, not a copy).
- [ ] **Step 4: Run** `cargo test -p hackamore-gateway` — expect PASS.
- [ ] **Step 5: Commit** `gateway: publish github/k8s catalogs, invariant-tested against the normalizer`

### Task 5: `hackamore catalog list`

**Files:**
- Modify: `cli/src/lib.rs` (new `pub mod render;`) — Create: `cli/src/render.rs`
- Modify: `cli/src/main.rs` (subcommand)

- [ ] **Step 1: Rendering functions + tests first** (`cli/src/render.rs`):

```rust
//! Human/JSON rendering for `hackamore catalog list`. Pure string-building so it
//! unit-tests without a terminal.

use hackamore_models::action::Verb;
use hackamore_models::catalog::Catalog;

/// Render catalogs as an aligned human table, one section per flavor. Raw flavors
/// (empty catalogs) say so instead of printing an empty table.
pub fn catalogs_human(catalogs: &[Catalog]) -> String { ... }

/// Render catalogs as pretty JSON (the same shape `GET /catalogs` will serve).
pub fn catalogs_json(catalogs: &[Catalog]) -> Result<String, serde_json::Error> { ... }
```

Human format per flavor:

```
flavor: github (19 operations)
  OPERATION       VERB    ROUTE                                        KIND          FIELDS
  pulls.create    Create  POST repos/{owner}/{repo}/pulls              pull_request  title, head, base, body, draft
  ...
flavor: generic
  (raw: no catalog — paths normalize generically; policies use path globs)
```

Verb display: `Crud` arm → its kind (`Read`/`Create`/`Update`/`Delete`); `Action` arm → the id. Column widths computed from content (simple max-len padding). Tests: snapshot-assert a small hand-built catalog renders with aligned columns + the raw-flavor line; JSON round-trips via `serde_json::from_str::<Vec<Catalog>>`.

- [ ] **Step 2: Wire the subcommand** (`cli/src/main.rs`):

```rust
/// Inspect the policy vocabulary built into this binary.
Catalog {
    #[command(subcommand)]
    command: CatalogCommand,
},

#[derive(Subcommand)]
enum CatalogCommand {
    /// List every flavor's operations, resource kinds, and conditionable fields.
    List(CatalogListArgs),
}

#[derive(clap::Args)]
struct CatalogListArgs {
    /// Only this flavor (e.g. "github").
    #[arg(long)]
    flavor: Option<String>,
    /// Emit JSON instead of a table.
    #[arg(long)]
    json: bool,
}
```

Handler (sync — no server, no tokio needed; call it before/outside the async runtime or just from the async main, it's pure): collect `flavors::registry()`, filter by `--flavor` via `flavors::by_name` (unknown → `Err(UnknownFlavor)` propagates, nonzero exit), clone each `catalog()`, print `catalogs_json` or `catalogs_human`.

- [ ] **Step 3: Run** `cargo run -p cli --bin hackamore -- catalog list` and `-- catalog list --flavor github --json`; eyeball output. `-- catalog list --flavor nope` → exits nonzero with the known-flavors message.
- [ ] **Step 4: Run** `cargo test --workspace` — expect PASS.
- [ ] **Step 5: Commit** `cli: hackamore catalog list — self-contained vocabulary discovery`

### Task 6: docs

**Files:**
- Modify: `README.md` (quickstart: add `catalog list` line; crate table row for flavors if apt)
- Modify: `docs/superpowers/specs/2026-06-12-usability-catalogs-tooling-design.md` (amend §1: invariant-tested flavor code instead of catalog-interpreted normalize; note the `ActionCatalog` rename)
- Modify: `CLAUDE.md` only if the flavor module changes the architecture summary (it doesn't — skip)

- [ ] **Step 1:** README quickstart gains, after the `make run` line: `cargo run -p cli --bin hackamore -- catalog list   # discover what policies can say per flavor`. Policy-model section gains one sentence pointing at `catalog list`.
- [ ] **Step 2:** Spec §1 amendment + a one-line changelog note under **Status**.
- [ ] **Step 3: Commit** `docs: catalog discovery + spec amendment`

### Task 7: gate + PR

- [ ] **Step 1:** `make check` — expect all green.
- [ ] **Step 2:** Push branch, open PR titled `pluggable flavors + catalog discovery (spec phases 1-2)`; body: problem, what changed (trait/registry, ActionCatalog rename, catalogs, CLI), parity/invariant test story, follow-ups (lint/test/web UI = spec phases 3-5). **No Claude attribution anywhere** (user rule).

## Self-review notes

- Spec coverage: phase 1 (Tasks 1–4), phase 2 (Task 5); spec §1's "catalog-driven default normalize" intentionally refined → recorded in Task 6 amendment.
- Type consistency: `catalog::Catalog` (models) vs `ActionCatalog` (gateway) — distinct names everywhere; `Flavor` trait replaces the enum wholesale; `with_flavor` takes `&'static dyn Flavor` at every call site listed in Task 3 Step 4.
- `verb_for` exposure (`pub(crate)`) is required by Task 4 Step 3 and called out there.
