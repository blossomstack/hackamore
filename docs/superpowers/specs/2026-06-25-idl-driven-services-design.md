# IDL-driven services: a fluorite IR fed by pluggable importers

**Date:** 2026-06-25
**Status:** Approved (proceed straight to plan + implementation)
**Supersedes:** the "generate flavor catalogs from OpenAPI" direction discussed on
[`2026-06-13-policy-studio-redesign-design.md`](2026-06-13-policy-studio-redesign-design.md);
revises that spec's Explore view (browses per-service models, not a hardcoded flavor
registry).

## Problem

Today a service's *vocabulary* — the operations, resource kinds, and conditionable
fields a policy can be written about — is hand-written Rust, one curated `Catalog` per
compiled-in flavor (`github`, `k8s`, `generic`). Adding or correcting a service means
editing gateway internals and recompiling. The catalogs are curated subsets, their
fields are unverified, and they can silently drift from the real upstream API.

What we want instead: **a service is defined by its own machine-readable API
description.** Point a service at an OpenAPI document (or an AWS Smithy/botocore model,
or some future description), supply its auth, and hackamore derives the whole vocabulary
from that description — comprehensively, with no per-service code and no special-casing
of any concrete service. New services are added at runtime, without recompiling.

## Goals

- **Descriptions are the source of truth.** A service's operations/resources/fields come
  from its API description, not hand-written Rust. Everything in the description is
  present.
- **Pluggable by description language, agnostic to it.** OpenAPI and Smithy/botocore are
  two concrete **IDLs**; more can be added. Exactly one component (an *Importer*) ever
  touches a raw IDL; everything else sees only hackamore's own model.
- **Agnostic to concrete services.** Nothing in the engine names "AWS," "GitHub," etc.
  AWS's RPC framing is expressed as generic configuration, not a special case.
- **A single internal representation (IR), defined in fluorite.** Importers target it;
  the engine, lint, discovery, and the studio consume only it.
- **Live registration.** A service can be added at runtime via the admin API — hackamore
  fetches the description, imports it, and begins routing and enforcing immediately.
- **Enforcement is unchanged and generic.** hackamore already normalizes any request and
  decides it against policy; the IR adds *vocabulary*, not a new enforcement engine.

## Non-goals

- A new policy language. The wire policy is unchanged.
- Resolving `$ref`/allOf composition beyond what each importer needs for operations and
  top-level field names (no full JSON-Schema evaluator).
- Persisting live-registered services across restarts (a fast-follow; see Future work).
- Replacing SigV4 / credential injection — those stay as they are.

## Two orthogonal axes (the core idea)

The design hinges on separating two things that were previously conflated:

- **IDL** — the *description source format*: OpenAPI, Smithy/botocore, … . Read by an
  **Importer**, then discarded. It never reaches the engine.
- **Protocol** — the *wire framing*: how a request encodes *which operation it is*. This
  is what the engine needs at request time. It is **generic** (mechanism-named), never
  service-named.

They are independent: a Smithy model can describe a REST service *or* an RPC one, so the
IDL does not determine the protocol — the description *declares* it, and the importer
records it in the IR.

```
 IDL document (OpenAPI / Smithy / …)
        │  Importer  (the only IDL-aware code)
        ▼
 ApiModel  (fluorite IR: protocol + resources + operations + fields)
        │
        ├─ normalize  (request → Action, using protocol)
        ├─ lint / dry-run
        └─ studio (Explore)
```

## The IR (fluorite, `models/fluorite/apimodel.fl`)

Generalizes today's REST-only `catalog.fl`. New package `apimodel`; `catalog.fl` is
removed and its consumers migrate. Sketch (final field set fixed in the plan):

```
package apimodel;
use action.Verb;

// How requests to a service name their operation. A MECHANISM, never a service name.
enum Protocol {
    Rest,                              // operation = HTTP method + path
    Parameter(NamedInParameter),       // operation name = value of a body/query field
    Header(NamedInHeader),             // operation name = (a suffix of) a header value
}
struct NamedInParameter { name: String }                 // AWS query  ⇒ name = "Action"
struct NamedInHeader   { name: String, suffix_after: String } // AWS json ⇒ name="x-amz-target", suffix_after="."

enum HttpMethod { Get, Post, Put, Patch, Delete }

// Where an operation lives in the request space — a REST route, or an operation name
// read per the service Protocol.
enum Selector {
    Rest(RestSelector),
    Named(NamedSelector),
}
struct RestSelector  { method: HttpMethod, path_template: String } // "repos/{owner}/{repo}/pulls"
struct NamedSelector { name: String }                              // "DescribeInstances"

enum FieldSource { Path, Query, Body, Header }   // Header added for RPC inputs
struct FieldSpec  { name: String, source: FieldSource, summary: String }

struct ResourceKind { name: String, summary: String }  // the service's resource taxonomy

struct Operation {
    id: String,                 // operationId / Action name
    verb: Verb,                 // CRUD (from method) or Named (the action)
    selector: Selector,
    resource_kind: String,      // references a ResourceKind.name ("" if none)
    fields: Vec<FieldSpec>,
    summary: String,
}

struct ApiModel {
    protocol: Protocol,
    resources: Vec<ResourceKind>,
    operations: Vec<Operation>,
}
```

Convenience constructors live in `models/src/lib.rs` per project convention. `ApiModel`
round-trips through JSON (it is served to the studio).

### How the IR maps the two kinds of service

- **REST (OpenAPI: GitHub, k8s, S3):** `protocol = Rest`; each operation a
  `Selector::Rest { method, path }`; `verb` from the method; `resource_kind` from the
  path; `fields` from path/query parameters + request-body top-level properties.
- **RPC (AWS query/json):** `protocol = Parameter{name:"Action"}` or
  `Header{name:"x-amz-target", suffix_after:"."}`; each operation a
  `Selector::Named { name }`; `verb` = `Named(name)`; `fields` from the input shape;
  `resource_kind` from the model's resource/shape if available, else "".

Nothing here is AWS-specific — "AWS query" is just `Parameter{"Action"}`.

## Importers (`hackamore-gateway`, `flavors/` becomes `import/`)

```
pub trait Importer {
    fn idl(&self) -> Idl;                                  // which IDL it parses
    fn import(&self, raw: &[u8]) -> Result<ApiModel, ImportError>;
}
pub enum Idl { OpenApi, Smithy }     // grows over time
```

- **`OpenApiImporter`** (phase 2): OpenAPI 3.x JSON/YAML → `ApiModel` with `protocol =
  Rest`. Walks `paths` × methods; `operationId` (fallback `METHOD path`); summary;
  parameters (`in: path|query` → FieldSource) and `requestBody` object property names →
  body fields; `verb_for(method)`; `resource_kind` via a path-derived rule (first
  meaningful segment, shared with the generic normalizer so catalog and data plane
  agree). Resolves local `$ref`s for parameters/request bodies; ignores unknown keywords.
- **`SmithyImporter`** (phase 6): botocore `service-2.json` / Smithy JSON AST →
  `ApiModel`. Reads the service `@protocol` trait → `Parameter`/`Header`; operations →
  `Selector::Named`; input shape members → fields; AWS resource shapes → `ResourceKind`s.

The importer is the *only* place an IDL's grammar is known. Both target the same
`ApiModel`, so adding an IDL never touches the engine.

## Generic Protocol normalization (`gateway/src/normalize.rs`)

The runtime already has a `Protocol` enum with `Rest` / `AwsQuery` / `AwsJson`. We
**generalize and retire the AWS-named arms** to mirror the IR:

- `AwsQuery` → `Parameter { name }` (read that body/query field; today's behavior is
  `Parameter{"Action"}`).
- `AwsJson` → `Header { name, suffix_after }` (read that header, optionally take the
  suffix after a delimiter; today's behavior is `Header{"x-amz-target", "."}`).

Normalization for a `Named`-protocol service reads the op name via the protocol and sets
`Verb::Named`. Existing AWS behavior is preserved exactly — the AWS-named tests become
parameterized generic ones. "AWS" survives only as config presets / importer output.

## Service definition and live registration

`Service` gains an optional **description**: `{ idl, source }` where `source` is a URL or
file path, plus its `Protocol` (declared by config or by the imported model). On register
(at startup from config, or live), hackamore:

1. fetches (URL) or reads (file) the raw description,
2. runs the matching `Importer` → `ApiModel`,
3. stores the model with the service and begins routing.

**Live registration (admin API):** the `ServiceRouter` becomes swappable
(`arc_swap::ArcSwap<Vec<Service>>`, copy-on-write — reads stay lock-free on the hot path).
New admin endpoints (localhost-only, like the rest of the admin surface):

- `POST /admin/services` — body `{ name, host, upstream_base, idl, source, outbound, … }`.
  hackamore imports and inserts the service, returns its `ApiModel` (or a structured
  import error). 4xx on fetch/parse failure (fail closed — a service that won't import is
  not added).
- `DELETE /admin/services/{name}` — remove a service.
- `GET /admin/services` — current registry (this subsumes the studio's `/catalogs`).

Config-declared services import at startup the same way; a startup import failure is a
startup error (fail closed).

## Studio impact

Explore browses **per-service `ApiModel`s** (one section per configured/registered
service) instead of a hardcoded flavor registry. The op row gains protocol-awareness:
REST rows show `METHOD path`; `Named` rows show the action name. The three-view shell,
Compose, and Server view are otherwise unchanged. A small "add a service" affordance in
the Server view can POST to `/admin/services` (optional, phase 7).

## Error handling

- Unknown IDL, unfetchable/unreadable source, or unparseable description → import error;
  config path fails startup, live path returns 4xx. Fail closed: the service is not
  added, so nothing routes to an un-described upstream by accident.
- An operation the importer can't model (no method/path, unknown protocol) is **skipped
  with a logged count**, never silently dropped wholesale (no-silent-caps).
- Enforcement is unaffected by import quality: an un-modeled request still normalizes
  generically and hits default-deny.

## Testing

- **IR round-trip** (`models`): `ApiModel` and each enum/union serialize with the
  expected tagged-union shape and round-trip.
- **OpenAPI importer** (`gateway`): table-driven over small fixture specs — a REST op with
  path+query+body fields maps to the right `Selector::Rest`, verb, fields; `operationId`
  fallback; `$ref` parameter resolution; a comprehensive multi-op fixture.
- **Protocol parity**: the generalized `Parameter`/`Header` normalization reproduces the
  retired AWS-named tests exactly (same Actions, same fields).
- **Smithy importer** (phase 6): fixtures for a query-protocol and a json-protocol service.
- **Live registration e2e** (`tests`): `POST /admin/services` with a fixture OpenAPI file
  → `GET /admin/services` shows it → `policy/test` against it decides correctly; a bad
  description → 4xx and no registry change; `DELETE` removes it.
- `make check` green at every phase.

## Phasing (each phase ships green and independently useful)

1. **Fluorite IR** (`apimodel`) + constructors + round-trip tests. Additive.
2. **`Importer` trait + `OpenApiImporter`** — pure, fixture-tested; not yet wired.
3. **Generic Protocol** — retire `AwsQuery`/`AwsJson`; parity tests; migrate
   `catalog.fl` consumers (lint, `catalogs_response`, CLI, studio) to `apimodel`; retire
   the hardcoded flavor catalogs (resource-kind derivation kept as a shared rule).
4. **Config-declared OpenAPI services** — service `{idl, source}`; import at startup;
   studio/lint/dry-run use per-service models. End-to-end: point a service at an OpenAPI
   file, author policy against it.
5. **Live registration** — swappable registry + `POST/DELETE/GET /admin/services`.
6. **`SmithyImporter`** — AWS via the same interface; reuse RPC normalization + SigV4.
7. **Studio Explore rework** + optional "add a service" affordance.

## Amendment (2026-06-26): faithful verbs, no derived kind

The verb is now the **literal thing the request states** — the HTTP method for REST, the
action name for RPC — not a derived category. The hardcoded method→CRUD mapping
(`CrudKind`/`CrudVerb`/`verb_for`'s table) is deleted; `action::Verb` is `Method(method:
String) | Action(id: String)`, carrying the method verbatim (so `PUT` ≠ `PATCH`, and any
method — `HEAD`, `TRACE`, `PROPFIND` — passes through unbucketed). The unused
`resource.kind` (a first-path-segment label no rule matched on) is removed; `Resource` is
just `{ path }`. The IR follows suit: `RestSelector.method` is a verbatim `String`, and the
redundant/derived fields are gone (`ApiOperation` is `{ id, selector, fields, summary }`,
`ApiModel` is `{ protocol, operations }` — no `verb`, `resource_kind`, `RestMethod`, or
`ResourceKind`). Guiding rule: **the model is a total, lossless projection of the
description — exhaustive and keyed by the operation's own identity; any coarse label
hackamore might add is advisory, never the identity, and the data plane reproduces it
exactly.** `docs/`/`README.md` still describe the old CRUD model and are a pending doc
update.

## As-built (2026-06-25)

Delivered green in this PR: the fluorite IR (`apimodel`), the OpenAPI **and** Smithy/botocore
importers behind one `Importer` trait, the generic wire `Protocol`
(`Rest`/`Parameter`/`Header`, with `aws-query`/`aws-json` as presets — no AWS-specific code
in the engine), per-service `ApiModel`, **live registration** (`POST`/`GET`/`DELETE
/admin/services` over a swappable `RwLock` registry; the imported model drives the wire
protocol), **config-time** description import (`description: { idl, file|url }`), and a
studio **Services** tab to add/list/remove runtime services and browse their models.

§Phasing step 3 is **complete**: the hardcoded `Flavor` system and `models/fluorite/catalog.fl`
were deleted; everything is unified on `apimodel::ApiModel`. Normalization now uses a single
generic first-segment resource rule (so resource *kinds* are coarser than the old per-flavor
kinds — `repos` not `pull_request` — but policy matches on path globs + verbs + fields, not
kind, so enforcement is unaffected). Policy lint runs against per-service `ApiModel`s; the
`/catalogs` endpoint and the CLI `catalog` command are gone; the studio dropped its Explore
tab and reads `/admin/services` for targets and field autocomplete. One transitional note:
`ProvisionService.flavor` now carries the service *name* as the agent's tool-config dispatch
hint (naming a service `github`/`k8s` selects the right consumer-side config writer).

## Future work (deferred)

- Rename `ProvisionService.flavor` → a `tool_hint` (it no longer names a flavor); or derive
  the agent's consumer-side config writer from the service's protocol/model instead.

- Persist live-registered services (config write-back or a small store).
- Richer resource model (hierarchy/identifiers/ARNs) if policy needs to match on it.
- `$ref` across files / remote refs; OpenAPI response-shape awareness.
- gRPC/GraphQL importers.
