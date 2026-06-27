//! OpenAPI 3.x → [`ApiModel`]. REST protocol: every `paths` × method becomes an operation
//! whose selector is the literal method + path, and whose fields are the parameters +
//! request-body top-level properties.

use super::{Idl, ImportError, Importer};
use hackamore_models::apimodel::{ApiModel, ApiOperation, Field, FieldOrigin, Protocol, Selector};
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

/// The HTTP methods catalogued (the OpenAPI Path Item operations).
const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

fn import_openapi(raw: &[u8]) -> Result<ApiModel, ImportError> {
    let spec: Value = serde_json::from_slice(raw).map_err(|e| ImportError::Parse(e.to_string()))?;
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(ImportError::Empty)?;

    let mut operations = Vec::new();
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        let shared = item.get("parameters"); // path-item-level parameters apply to every method
        for key in METHODS {
            let Some(op) = item.get(key).and_then(Value::as_object) else {
                continue;
            };
            operations.push(operation(&spec, path, key, op, shared));
        }
    }
    if operations.is_empty() {
        return Err(ImportError::Empty);
    }

    Ok(ApiModel {
        protocol: Protocol::rest(),
        operations,
    })
}

fn operation(
    spec: &Value,
    path: &str,
    method_key: &str,
    op: &serde_json::Map<String, Value>,
    shared_params: Option<&Value>,
) -> ApiOperation {
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

    let mut fields: Vec<Field> = Vec::new();
    for src in [shared_params, op.get("parameters")].into_iter().flatten() {
        if let Some(arr) = src.as_array() {
            for p in arr {
                if let Some(f) = parameter_field(spec, p)
                    && !fields.iter().any(|x| x.name == f.name)
                {
                    fields.push(f);
                }
            }
        }
    }
    for name in body_property_names(spec, op) {
        if !fields.iter().any(|x| x.name == name) {
            fields.push(Field {
                name,
                source: FieldOrigin::Body,
                summary: String::new(),
            });
        }
    }

    ApiOperation {
        id,
        selector: Selector::route(method_key.to_ascii_uppercase(), template),
        fields,
        summary,
    }
}

/// Resolve a possibly-`$ref`'d parameter into a [`Field`]. Only path/query/header
/// parameters become conditionable fields; `in: cookie` and unknowns are dropped.
fn parameter_field(spec: &Value, param: &Value) -> Option<Field> {
    let param = deref(spec, param);
    let name = param.get("name")?.as_str()?.to_string();
    let source = match param.get("in").and_then(Value::as_str)? {
        "path" => FieldOrigin::Path,
        "query" => FieldOrigin::Query,
        "header" => FieldOrigin::Header,
        _ => return None,
    };
    let summary = param
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Some(Field {
        name,
        source,
        summary,
    })
}

/// Top-level property names of the JSON request body schema (if any).
fn body_property_names(spec: &Value, op: &serde_json::Map<String, Value>) -> Vec<String> {
    op.get("requestBody")
        .map(|rb| deref(spec, rb))
        .and_then(|rb| rb.get("content").cloned())
        .and_then(|c| c.get("application/json").cloned())
        .and_then(|j| j.get("schema").cloned())
        .map(|s| deref(spec, &s))
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
        .map(|p| {
            p.split('/')
                .fold(spec, |acc, seg| acc.get(seg).unwrap_or(&Value::Null))
        })
        .cloned()
        .unwrap_or_else(|| node.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
                    "head": {
                        "operationId": "pulls/head"
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
        }))
        .unwrap()
    }

    #[test]
    fn imports_rest_operations_with_literal_method_selectors_and_fields() {
        let model = OpenApiImporter.import(&spec()).unwrap();
        assert_eq!(model.protocol, Protocol::rest());
        assert_eq!(model.operations.len(), 3);

        let create = model
            .operations
            .iter()
            .find(|o| o.id == "pulls/create")
            .unwrap();
        match &create.selector {
            Selector::Route(r) => {
                assert_eq!(r.method, "POST");
                assert_eq!(r.path_template, "repos/{owner}/{repo}/pulls");
            }
            other => panic!("expected Route selector, got {other:?}"),
        }
        // Object key order isn't meaningful (serde_json sorts), so compare as a set.
        let mut body: Vec<&str> = create
            .fields
            .iter()
            .filter(|f| f.source == FieldOrigin::Body)
            .map(|f| f.name.as_str())
            .collect();
        body.sort_unstable();
        assert_eq!(body, ["base", "head", "title"]);

        let list = model
            .operations
            .iter()
            .find(|o| o.id == "pulls/list")
            .unwrap();
        match &list.selector {
            Selector::Route(r) => assert_eq!(r.method, "GET"),
            other => panic!("expected Route selector, got {other:?}"),
        }
        // The path-item parameter (owner) and the operation parameter (state) both surface.
        assert!(
            list.fields
                .iter()
                .any(|f| f.name == "owner" && f.source == FieldOrigin::Path)
        );
        assert!(
            list.fields
                .iter()
                .any(|f| f.name == "state" && f.source == FieldOrigin::Query)
        );

        // A `head` operation is now catalogued (one of the 8 OpenAPI methods).
        let head = model
            .operations
            .iter()
            .find(|o| o.id == "pulls/head")
            .unwrap();
        match &head.selector {
            Selector::Route(r) => assert_eq!(r.method, "HEAD"),
            other => panic!("expected Route selector, got {other:?}"),
        }
    }

    #[test]
    fn falls_back_to_method_path_id_and_rejects_bad_input() {
        let no_id = serde_json::to_vec(&serde_json::json!({
            "paths": { "/x/y": { "get": {} } }
        }))
        .unwrap();
        let m = OpenApiImporter.import(&no_id).unwrap();
        assert_eq!(m.operations[0].id, "GET /x/y");
        match &m.operations[0].selector {
            Selector::Route(r) => assert_eq!(r.method, "GET"),
            other => panic!("expected Route selector, got {other:?}"),
        }

        assert!(matches!(
            OpenApiImporter.import(b"not json"),
            Err(ImportError::Parse(_))
        ));
        assert!(matches!(
            OpenApiImporter.import(br#"{"paths":{}}"#),
            Err(ImportError::Empty)
        ));
    }

    #[test]
    fn resolves_ref_parameters() {
        let spec = serde_json::to_vec(&serde_json::json!({
            "paths": { "/things": { "get": {
                "operationId": "things/list",
                "parameters": [ { "$ref": "#/components/parameters/Page" } ]
            } } },
            "components": { "parameters": {
                "Page": { "name": "page", "in": "query", "description": "page number" }
            } }
        }))
        .unwrap();
        let m = OpenApiImporter.import(&spec).unwrap();
        assert!(
            m.operations[0]
                .fields
                .iter()
                .any(|f| f.name == "page" && f.source == FieldOrigin::Query)
        );
    }
}
