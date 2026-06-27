# Policy Studio redesign: three views, full-registry browse, self-contained reference

**Date:** 2026-06-13
**Status:** Approved
**Parent:** [`2026-06-12-usability-catalogs-tooling-design.md`](2026-06-12-usability-catalogs-tooling-design.md)
(§4, "Web UI: catalog explorer + policy composer")

## Problem

The web UI shipped in the parent spec works, but review feedback flagged four
usability gaps:

1. **Crowded.** Everything — catalog explorer, rule composer, lint, dry-run, mint —
   is stacked into one two-pane screen. There is no separation between *learning* the
   vocabulary, *authoring* a policy, and *understanding the server* you're authoring
   against.
2. **Only configured flavors are browsable.** The explorer renders
   `catalogs_response().catalogs`, which is deduped to the flavors of *configured*
   services. A user can't browse the github vocabulary on a server that only has k8s
   configured, even though that vocabulary is compiled in.
3. **Not self-contained.** The UI never surfaces what services are configured, what
   credential each injects, or what the domain terms (flavor, verb, resource,
   condition) mean. The author has to read the docs alongside the tool.
4. **Raw wire format in the user's face.** The policy JSON textarea is the de-facto
   editing surface, exposing the tagged-union verb shape
   (`{"type":"Crud","value":{"kind":"Read"}}`) and condition structs. The dry-run
   result dumps the raw normalized `Action`. Users end up reading and hand-editing the
   wire format the composer was supposed to hide.

This is a UI-layer redesign plus two small, additive backend changes. The policy
engine, lint, dry-run, and mint semantics are unchanged.

## Goals

- **Three focused views** — Explore, Compose, Server — one visible at a time, so each
  job has room to breathe.
- **Explore the full flavor registry**, not just configured flavors.
- **Self-contained**: the UI shows the configured services (with the credential *id*
  each injects), and a glossary of the domain vocabulary.
- **Never make the wire format the authoring surface.** Verbs, conditions, and verdicts
  are always human words; the policy JSON and raw `Action` are export/debug only,
  collapsed by default.

## Non-goals

- No change to the policy engine, lint rules, dry-run, or mint behavior.
- No JS framework or build step. The UI stays plain HTML/JS/CSS embedded in the binary.
- Phase 5 of the parent spec (`hackamore init` + credential references) — separate work.
- Audit/denial viewer, demo mode — still future scope.
- Runtime-loadable flavors — still out of scope.

## Design

### 1. Shell — three tabs (view A)

A top tab bar switches between three views; exactly one is visible at a time. Plain
JS show/hide keyed off the active tab — no router, no history integration. State (the
rule array, loaded catalogs/services) is module-global and shared across views, so
switching tabs never loses work.

Cross-view action: **`+ allow`** in Explore appends a rule (as today) and switches to
the Compose tab, surfacing a transient toast (`added rule for pulls.create`) so the
jump is legible.

### 2. Explore view — full registry

- A **flavor selector** lists every flavor from the registry (`github`, `k8s`,
  `generic`), independent of what's configured. Default to the first non-empty catalog.
- A **text filter** narrows the operations table by id / route / resource kind.
- Each operation row: `+ allow` · id · verb (color chip) · `METHOD path/template` ·
  resource kind · fields · one-line summary.
- A flavor with an empty catalog (generic) shows the existing "raw — use path globs"
  note instead of a table.
- `+ allow` builds the same allow rule as today (`routeToGlob` of the path template,
  the operation's verb, the target pre-filled to a configured service of that flavor if
  one exists, else blank) and jumps to Compose.

### 3. Compose view — friendly authoring, wire format tucked away

The composer's controls are unchanged in spirit; the layout gets room and the raw
format recedes:

- **Rule cards**: effect pill (Allow/Deny), target dropdown sourced from configured
  services, CRUD verb chips, resource-glob list editor, and a condition editor with
  **field autocomplete drawn from the selected target's catalog** (so the author picks
  `base` from a list rather than typing into the nested `value` struct).
- **Live lint** pill + findings list — unchanged engine, debounced `POST /policy/lint`.
- **Dry-run** leads with a human verdict line:
  `✓ Allow · matched rule 0 · normalized to Create pull_request · fields: base=main`.
  The raw normalized `Action` JSON is moved behind a collapsed `▸ raw Action` disclosure
  for debugging. Verb and resource-kind are rendered via the existing `verbLabel`
  mapping — never raw tagged-union JSON.
- **Mint**: ttl + button; a lint-rejection 403 still renders its structured findings
  inline.
- **Policy JSON** becomes a collapsed `▸ Policy JSON` disclosure: a read-only, copyable
  export plus a separate "paste & load" box for import. It is never open by default and
  never the primary editing surface.

### 4. Server view — self-contained reference

- **Configured services** table, one row per service: name · flavor · consumer address ·
  outbound auth. Auth renders as a human label — `passthrough`, `bearer`,
  `header X-API-Key`, `sigv4` — plus the vault **credential id** it injects (empty for
  passthrough). **Only the id is shown, never the secret.**
- **Glossary**: a compact definition list for the domain vocabulary the other two views
  assume — flavor, target/service, verb (CRUD + named), resource (kind + path),
  condition (field/operator), effect, default-deny, credential id, catalog/operation.
  Static content embedded in the UI.

### 5. Backend changes (additive)

Two changes, both to data the admin API already half-exposes:

- **`models/fluorite/catalog.fl`**: replace the thin `ServiceFlavor` with a richer
  `ServiceInfo { name, flavor, address, auth, credential }`, where `auth` is the human
  outbound label and `credential` is the vault id (empty string = passthrough / none).
  `CatalogsResponse` keeps two fields but their contract sharpens: `services:
  [ServiceInfo]` is the configured set; `catalogs: [Catalog]` becomes the **full
  registry** (every flavor), so Explore can browse all of them. Hand-written convenience
  constructors go in `models/src/lib.rs` per project convention.
- **`gateway/src/core.rs::catalogs_response()`**: build `catalogs` from
  `flavors::registry()` (all flavors) instead of the configured subset, and build
  `services` from each `Service`'s name, `flavor.name()`, `address`, a label derived
  from its `Outbound` variant, and `Outbound::credential_id()`. Update the doc comment.
- **`gateway/src/server.rs`**: refresh the `/catalogs` handler doc comment (semantics:
  full registry + enriched services). No new endpoints — lint/test/mint are reused.

Server-side lint and dry-run remain scoped to **configured** services (unchanged):
`gateway.lint()` and `gateway.dry_run()` are untouched. The full registry is a *display*
concern only.

**Security:** credential **ids** are vault keys, not secrets, and the audit log already
prints them. The admin listener is localhost-only operator surface. Exposing ids there
is consistent with the existing posture; no secret ever crosses the wire.

## Error handling

- `web_ui: false` → `/ui`, `/catalogs`, `/policy/lint`, `/policy/test` all still 404
  (unchanged).
- Explore selecting a flavor with no configured service: `+ allow` leaves the rule's
  target blank (the author picks one in Compose); lint will warn if the target is
  unknown, as today.
- Dry-run against a target with no configured service: the existing
  `DryRunError::UnknownTarget` path is unchanged; the target dropdown only offers
  configured services, so this is not reachable from the UI.
- Paste-and-load with invalid JSON: surfaced as an inline error on the import box, the
  rule array is left untouched.

## Testing

- **e2e** (`tests/tests/web_ui.rs`): with a single service configured, `GET /catalogs`
  returns **all** registered flavors in `catalogs` (github, k8s, generic) and a
  `services` entry carrying the configured service's `credential`, `auth`, and `address`.
  Re-assert `web_ui: false` → 404 for the UI and endpoints.
- **Model round-trip** (`models/src/lib.rs` tests): `ServiceInfo` and the updated
  `CatalogsResponse` serialize/deserialize with the expected field names.
- **No-drift** of the existing catalog invariant tests is unaffected (registry
  enumeration already used there).
- **Front-end**: plain JS, no build/test harness. Verified live against a running
  gateway (browser walkthrough of the three views: Explore browses all flavors, `+ allow`
  jumps to Compose, dry-run shows the friendly verdict, Server lists services +
  credential ids + glossary, wire JSON stays collapsed).
- `make check` (fmt + clippy `-D warnings` + `cargo test --workspace`) stays green.

## Implementation order

1. **Models** — `ServiceInfo` + `CatalogsResponse` contract + convenience methods +
   round-trip tests.
2. **Gateway** — `catalogs_response()` rebuilt (full registry + enriched services);
   handler doc comments.
3. **e2e** — extend `web_ui.rs` for the new response shape.
4. **Front-end** — rewrite `index.html` / `app.js` / `style.css` into the three views.
5. **Manual verification** + `make check`.
