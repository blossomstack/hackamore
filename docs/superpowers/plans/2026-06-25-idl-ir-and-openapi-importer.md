# IDL IR + OpenAPI Importer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add hackamore's fluorite internal representation (`apimodel`) and a pure OpenAPI→`ApiModel` importer — the foundation of [IDL-driven services](../specs/2026-06-25-idl-driven-services-design.md). Additive: nothing existing is removed or rewired in this plan.

**Architecture:** A new fluorite package `apimodel` defines the dialect-independent IR (a generic `Protocol` locator, `Selector`, `ResourceKind`, `Operation`, `ApiModel`). A new gateway module `import/` defines an `Importer` trait and a concrete `OpenApiImporter` that walks an OpenAPI 3.x document and produces an `ApiModel` with `protocol = Rest`. Resource-kind derivation reuses the generic first-segment rule so the catalog agrees with the data plane.

**Tech Stack:** Rust, fluorite codegen (`models/build.rs`), serde_json. No new dependencies.

---

## File structure

- Create `models/fluorite/apimodel.fl` — the IR schema (new fluorite package).
- Modify `models/src/lib.rs` — register the `apimodel` module + convenience constructors + round-trip test.
- Create `gateway/src/import/mod.rs` — `Importer` trait, `Idl` enum, `ImportError`.
- Create `gateway/src/import/openapi.rs` — `OpenApiImporter`.
- Modify `gateway/src/lib.rs` — `pub mod import;` and re-exports.
- Modify `gateway/src/normalize.rs` — make `verb_for` reusable by the importer (already `pub(crate)`; the importer is in-crate, so no change needed — verify only).

---

## Task 1: fluorite IR package `apimodel`

**Files:**
- Create: `models/fluorite/apimodel.fl`
- Modify: `models/src/lib.rs` (add `pub mod apimodel { include!… }`, constructors, test)

- [ ] **Step 1: Write the schema file**

`models/fluorite/apimodel.fl`:

```
/// hackamore's internal API representation (IR): the dialect-independent model every
/// importer (OpenAPI, Smithy, …) produces and the engine/lint/studio consume. Generic
/// over wire protocol so REST and RPC services share one shape; no concrete service or
/// description language is named here.
package apimodel;

use action.Verb;

/// How requests to a service name their operation — a mechanism, never a service name.
enum Protocol {
    /// Operation = HTTP method + path.
    Rest,
    /// Operation name = the value of a body/query parameter (AWS query: name = "Action").
    Parameter(NamedInParameter),
    /// Operation name = a suffix of a header value (AWS json: name = "x-amz-target").
    Header(NamedInHeader),
}

struct NamedInParameter { name: String }
/// `suffix_after` splits the header value and keeps the part after the last occurrence
/// (AWS json: "." turns "DynamoDB_20120810.PutItem" into "PutItem"). Empty = whole value.
struct NamedInHeader { name: String, suffix_after: String }

enum HttpMethod { Get, Post, Put, Patch, Delete }

/// Where an operation lives in the request space.
enum Selector {
    Rest(RestSelector),
    Named(NamedSelector),
}

struct RestSelector { method: HttpMethod, path_template: String }
struct NamedSelector { name: String }

/// Where a conditionable field is read from.
enum FieldSource { Path, Query, Body, Header }

struct FieldSpec { name: String, source: FieldSource, summary: String }

/// One resource kind a service exposes.
struct ResourceKind { name: String, summary: String }

struct Operation {
    id: String,
    verb: Verb,
    selector: Selector,
    resource_kind: String,
    fields: Vec<FieldSpec>,
    summary: String,
}

struct ApiModel {
    protocol: Protocol,
    resources: Vec<ResourceKind>,
    operations: Vec<Operation>,
}
```

- [ ] **Step 2: Register the module + add a round-trip test**

In `models/src/lib.rs`, add the module beside the others:

```rust
#[allow(clippy::doc_markdown, clippy::too_many_arguments)]
pub mod apimodel {
    include!(concat!(env!("OUT_DIR"), "/apimodel/mod.rs"));
}
```

Add to the `tests` module:

```rust
#[test]
fn api_model_round_trips_with_tagged_protocol_and_selector() {
    use super::action::{CrudKind, Verb};
    use super::apimodel::{
        ApiModel, FieldSource, FieldSpec, HttpMethod, NamedInParameter, Operation, Protocol,
        ResourceKind, RestSelector, Selector,
    };
    let rest_op = Operation {
        id: "pulls.create".into(),
        verb: Verb::crud(CrudKind::Create),
        selector: Selector::Rest(RestSelector {
            method: HttpMethod::Post,
            path_template: "repos/{owner}/{repo}/pulls".into(),
        }),
        resource_kind: "repos".into(),
        fields: vec![FieldSpec {
            name: "base".into(),
            source: FieldSource::Body,
            summary: "target branch".into(),
        }],
        summary: "Open a pull request".into(),
    };
    let model = ApiModel {
        protocol: Protocol::Rest,
        resources: vec![ResourceKind { name: "repos".into(), summary: String::new() }],
        operations: vec![rest_op],
    };
    let json = serde_json::to_value(&model).unwrap();
    assert_eq!(json["protocol"]["type"], "Rest");
    assert_eq!(json["operations"][0]["selector"]["type"], "Rest");
    assert_eq!(json["operations"][0]["selector"]["value"]["method"], "Post");
    assert_eq!(json["operations"][0]["fields"][0]["source"], "Body");
    let back: ApiModel = serde_json::from_value(json).unwrap();
    assert_eq!(model, back);

    // A Parameter-protocol (RPC) model round-trips too — "AWS" is just config.
    let rpc = ApiModel {
        protocol: Protocol::Parameter(NamedInParameter { name: "Action".into() }),
        resources: vec![],
        operations: vec![],
    };
    let j = serde_json::to_value(&rpc).unwrap();
    assert_eq!(j["protocol"]["type"], "Parameter");
    assert_eq!(j["protocol"]["value"]["name"], "Action");
    assert_eq!(serde_json::from_value::<ApiModel>(j).unwrap(), rpc);
}
```

- [ ] **Step 3: Run the test to verify it fails (schema not generated yet → compile error)**

Run: `cargo test -p hackamore-models api_model_round_trips`
Expected: FAIL — `unresolved import super::apimodel` / no `apimodel` until the schema compiles.

- [ ] **Step 4: (already done in Steps 1-2) build + run to green**

Run: `cargo test -p hackamore-models api_model_round_trips`
Expected: PASS. (fluorite codegen in `build.rs` picks up the new `.fl` automatically.)

- [ ] **Step 5: Commit**

```bash
git add models/fluorite/apimodel.fl models/src/lib.rs
git commit -m "models: apimodel IR — generic protocol locator, selector, resources"
```

---

## Task 2: `Importer` trait + `Idl` + `ImportError`

**Files:**
- Create: `gateway/src/import/mod.rs`
- Modify: `gateway/src/lib.rs` (`pub mod import;`)

- [ ] **Step 1: Write the module**

`gateway/src/import/mod.rs`:

```rust
//! Pluggable API-description import. An [`Importer`] parses one IDL (OpenAPI, Smithy, …)
//! into hackamore's dialect-independent [`ApiModel`]. The importer is the *only* code that
//! knows an IDL's grammar; everything downstream sees only the IR.

mod openapi;
pub use openapi::OpenApiImporter;

use hackamore_models::apimodel::ApiModel;

/// Which interface-description language an importer parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idl {
    OpenApi,
    Smithy,
}

/// Parse a raw API description into the IR. Implementations are pure (no I/O): fetching
/// the bytes is the caller's job, so importers stay trivially testable.
pub trait Importer {
    fn idl(&self) -> Idl;
    fn import(&self, raw: &[u8]) -> Result<ApiModel, ImportError>;
}

/// Why a description could not be turned into an [`ApiModel`].
#[derive(Debug)]
pub enum ImportError {
    /// The bytes were not the expected serialization (e.g. not JSON).
    Parse(String),
    /// The document was syntactically fine but had no usable operations.
    Empty,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Parse(m) => write!(f, "could not parse description: {m}"),
            ImportError::Empty => write!(f, "description declared no operations"),
        }
    }
}

impl std::error::Error for ImportError {}
```

- [ ] **Step 2: Wire the module in `gateway/src/lib.rs`**

Add `pub mod import;` next to the other `pub mod` lines, and (optional) re-export:

```rust
pub mod import;
pub use import::{Idl, Importer, OpenApiImporter};
```

- [ ] **Step 3: Run to verify it fails (openapi.rs missing)**

Run: `cargo build -p hackamore-gateway`
Expected: FAIL — `file not found for module openapi`. (Task 3 creates it.)

(No commit yet — Task 3 completes the module.)

---

## Task 3: `OpenApiImporter`

**Files:**
- Create: `gateway/src/import/openapi.rs`
- Test: inline `#[cfg(test)] mod tests` in the same file.

- [ ] **Step 1: Write the failing test first**

`gateway/src/import/openapi.rs` (start with the test + a stub):

```rust
//! OpenAPI 3.x → [`ApiModel`]. REST protocol: every `paths` × method becomes an operation
//! whose verb is the method's CRUD mapping, whose fields are the parameters + request-body
//! top-level properties, and whose resource kind is the path's first segment (the generic
//! normalizer's rule, so catalog and data plane agree).

use super::{Idl, ImportError, Importer};
use hackamore_models::apimodel::{
    ApiModel, FieldSource, FieldSpec, HttpMethod, Operation, Protocol, ResourceKind,
    RestSelector, Selector,
};
use serde_json::Value;

/// Imports OpenAPI 3.x JSON documents.
#[derive(Debug, Default)]
pub struct OpenApiImporter;

impl Importer for OpenApiImporter {
    fn idl(&self) -> Idl {
        Idl::OpenApi
    }
    fn import(&self, raw: &[u8]) -> Result<ApiModel, ImportError> {
        import_openapi(raw)
    }
}

fn import_openapi(_raw: &[u8]) -> Result<ApiModel, ImportError> {
    Err(ImportError::Empty) // replaced in Step 3
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hackamore_models::action::{CrudKind, Verb};

    fn spec() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/repos/{owner}/{repo}/pulls": {
                    "parameters": [
                        { "name": "owner", "in": "path", "description": "repo owner" }
                    ],
                    "get": {
                        "operationId": "pulls/list",
                        "summary": "List pull requests",
                        "parameters": [ { "name": "state", "in": "query", "description": "open/closed" } ]
                    },
                    "post": {
                        "operationId": "pulls/create",
                        "summary": "Open a pull request",
                        "requestBody": { "content": { "application/json": { "schema": {
                            "type": "object",
                            "properties": { "title": {}, "head": {}, "base": {} }
                        } } } }
                    }
                }
            }
        })).unwrap()
    }

    #[test]
    fn imports_rest_operations_verbs_fields_and_kind() {
        let model = OpenApiImporter.import(&spec()).unwrap();
        assert_eq!(model.protocol, Protocol::Rest);
        assert_eq!(model.operations.len(), 2);

        let create = model.operations.iter().find(|o| o.id == "pulls/create").unwrap();
        assert_eq!(create.verb, Verb::crud(CrudKind::Create));
        match &create.selector {
            Selector::Rest(r) => {
                assert_eq!(r.method, HttpMethod::Post);
                assert_eq!(r.path_template, "repos/{owner}/{repo}/pulls");
            }
            _ => panic!("expected Rest selector"),
        }
        assert_eq!(create.resource_kind, "repos");
        let body: Vec<&str> = create
            .fields
            .iter()
            .filter(|f| f.source == FieldSource::Body)
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(body, ["title", "head", "base"]);

        let list = model.operations.iter().find(|o| o.id == "pulls/list").unwrap();
        assert_eq!(list.verb, Verb::crud(CrudKind::Read));
        // path-item parameter (owner) + operation parameter (state) both surface.
        assert!(list.fields.iter().any(|f| f.name == "owner" && f.source == FieldSource::Path));
        assert!(list.fields.iter().any(|f| f.name == "state" && f.source == FieldSource::Query));

        assert!(model.resources.iter().any(|r| r.name == "repos"));
    }

    #[test]
    fn falls_back_to_method_path_id_and_rejects_non_json() {
        let no_id = serde_json::to_vec(&serde_json::json!({
            "paths": { "/x/y": { "get": {} } }
        })).unwrap();
        let m = OpenApiImporter.import(&no_id).unwrap();
        assert_eq!(m.operations[0].id, "GET /x/y");
        assert_eq!(m.operations[0].resource_kind, "x");

        assert!(matches!(OpenApiImporter.import(b"not json"), Err(ImportError::Parse(_))));
        assert!(matches!(
            OpenApiImporter.import(br#"{"paths":{}}"#),
            Err(ImportError::Empty)
        ));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hackamore-gateway import::openapi`
Expected: FAIL — both tests fail (stub returns `Empty`).

- [ ] **Step 3: Implement `import_openapi` + helpers (replace the stub)**

```rust
const METHODS: [(&str, HttpMethod); 5] = [
    ("get", HttpMethod::Get),
    ("put", HttpMethod::Put),
    ("post", HttpMethod::Post),
    ("delete", HttpMethod::Delete),
    ("patch", HttpMethod::Patch),
];

fn import_openapi(raw: &[u8]) -> Result<ApiModel, ImportError> {
    let spec: Value = serde_json::from_slice(raw).map_err(|e| ImportError::Parse(e.to_string()))?;
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(ImportError::Empty)?;

    let mut operations = Vec::new();
    for (path, item) in paths {
        let Some(item) = item.as_object() else { continue };
        let shared = item.get("parameters"); // path-item-level parameters
        for (method_key, method) in METHODS {
            let Some(op) = item.get(method_key).and_then(Value::as_object) else { continue };
            operations.push(operation(&spec, path, method_key, method, op, shared));
        }
    }
    if operations.is_empty() {
        return Err(ImportError::Empty);
    }
    let mut resources: Vec<ResourceKind> = Vec::new();
    for o in &operations {
        if !o.resource_kind.is_empty() && !resources.iter().any(|r| r.name == o.resource_kind) {
            resources.push(ResourceKind { name: o.resource_kind.clone(), summary: String::new() });
        }
    }
    Ok(ApiModel { protocol: Protocol::Rest, resources, operations })
}

fn operation(
    spec: &Value,
    path: &str,
    method_key: &str,
    method: HttpMethod,
    op: &serde_json::Map<String, Value>,
    shared_params: Option<&Value>,
) -> Operation {
    let template = path.trim_start_matches('/').to_string();
    let id = op
        .get("operationId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} {path}", method_key.to_ascii_uppercase()));
    let summary = op
        .get("summary")
        .or_else(|| op.get("description"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .to_string();

    let mut fields = Vec::new();
    for src in [shared_params, op.get("parameters")].into_iter().flatten() {
        if let Some(arr) = src.as_array() {
            for p in arr {
                if let Some(f) = parameter_field(spec, p) {
                    if !fields.iter().any(|x: &FieldSpec| x.name == f.name) {
                        fields.push(f);
                    }
                }
            }
        }
    }
    for name in body_property_names(spec, op) {
        if !fields.iter().any(|x| x.name == name) {
            fields.push(FieldSpec { name, source: FieldSource::Body, summary: String::new() });
        }
    }

    Operation {
        verb: crate::normalize::verb_for(&http_method(method_key)),
        id,
        selector: Selector::Rest(RestSelector { method, path_template: template.clone() }),
        resource_kind: first_segment(&template),
        fields,
        summary,
    }
}

/// The generic resource-kind rule: the first path segment (matches `GenericFlavor`).
fn first_segment(template: &str) -> String {
    template.split('/').next().unwrap_or("").to_string()
}

fn http_method(key: &str) -> http::Method {
    match key {
        "get" => http::Method::GET,
        "put" => http::Method::PUT,
        "post" => http::Method::POST,
        "delete" => http::Method::DELETE,
        "patch" => http::Method::PATCH,
        _ => http::Method::GET,
    }
}

/// Resolve a possibly-`$ref`'d parameter into a `FieldSpec`. Only path/query/header
/// parameters become conditionable fields; `in: cookie` and unknowns are dropped.
fn parameter_field(spec: &Value, param: &Value) -> Option<FieldSpec> {
    let param = deref(spec, param);
    let name = param.get("name")?.as_str()?.to_string();
    let source = match param.get("in").and_then(Value::as_str)? {
        "path" => FieldSource::Path,
        "query" => FieldSource::Query,
        "header" => FieldSource::Header,
        _ => return None,
    };
    let summary = param.get("description").and_then(Value::as_str).unwrap_or("").to_string();
    Some(FieldSpec { name, source, summary })
}

/// Top-level property names of the JSON request body schema (if any).
fn body_property_names(spec: &Value, op: &serde_json::Map<String, Value>) -> Vec<String> {
    let schema = op
        .get("requestBody")
        .map(|rb| deref(spec, rb))
        .and_then(|rb| rb.get("content").cloned())
        .and_then(|c| c.get("application/json").cloned())
        .and_then(|j| j.get("schema").cloned())
        .map(|s| deref(spec, &s));
    schema
        .as_ref()
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object)
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default()
}

/// One-level local `$ref` resolution (`#/components/...`). Non-refs pass through.
fn deref(spec: &Value, node: &Value) -> Value {
    let Some(reference) = node.get("$ref").and_then(Value::as_str) else {
        return node.clone();
    };
    reference
        .strip_prefix("#/")
        .map(|p| p.split('/').fold(spec, |acc, seg| acc.get(seg).unwrap_or(&Value::Null)))
        .cloned()
        .unwrap_or_else(|| node.clone())
}
```

- [ ] **Step 4: Run to verify both tests pass**

Run: `cargo test -p hackamore-gateway import::openapi`
Expected: PASS (2 tests).

- [ ] **Step 5: Full gate**

Run: `cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test --workspace`
Expected: green.

- [ ] **Step 6: Commit**

```bash
git add gateway/src/import/ gateway/src/lib.rs
git commit -m "gateway: Importer trait + OpenApiImporter (OpenAPI 3.x -> apimodel IR)"
```

---

## Remaining phases (separate plans)

Per the [spec](../specs/2026-06-25-idl-driven-services-design.md), these follow once the foundation lands and each gets its own bite-sized plan:

- **Phase 3 — generic Protocol + migration:** retire runtime `Protocol::AwsQuery/AwsJson` → `Parameter`/`Header` (parity tests); migrate `catalog.fl` consumers (lint, `catalogs_response`, CLI, studio) to `apimodel`; retire hardcoded flavor catalogs (keep the first-segment kind rule).
- **Phase 4 — config-declared OpenAPI services:** service `{ idl, source }`; import at startup; per-service `ApiModel` powers lint/dry-run/discovery. End-to-end usable.
- **Phase 5 — live registration:** swappable registry + `POST/DELETE/GET /admin/services`.
- **Phase 6 — `SmithyImporter`:** AWS via the same `Importer` interface; reuse RPC normalization + SigV4.
- **Phase 7 — studio Explore rework** + optional "add a service" affordance.

## Self-review

- **Spec coverage:** Tasks 1–3 cover spec §"The IR" (Task 1) and §"Importers → OpenApiImporter" (Tasks 2–3). Phases 3–7 are explicitly deferred to their own plans (spec §Phasing).
- **Placeholders:** none — every code step is complete.
- **Type consistency:** `ApiModel`/`Operation`/`Selector`/`Protocol`/`FieldSpec`/`ResourceKind`/`HttpMethod` field names match between Task 1 (schema), the Task 1 test, and Tasks 2–3 (importer). `verb_for` is the existing `pub(crate)` fn in `normalize.rs`. `Idl`/`Importer`/`ImportError` defined in Task 2 are used in Task 3.
