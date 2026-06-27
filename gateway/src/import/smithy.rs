//! botocore `service-2.json` (AWS's "Smithy"-derived model) → [`ApiModel`]. The
//! `metadata.protocol` decides the wire shape: `query`/`json` are RPC (operation name in a
//! parameter / header), `rest-json`/`rest-xml` are REST (method + path). Operations come
//! from `operations`; an operation's conditionable fields are its input shape's top-level
//! members.

use super::{Idl, ImportError, Importer};
use hackamore_models::apimodel::{ApiModel, ApiOperation, Field, FieldOrigin, Protocol, Selector};
use serde_json::Value;

/// Imports botocore `service-2.json` API models.
#[derive(Debug, Default)]
pub struct SmithyImporter;

impl Importer for SmithyImporter {
    fn idl(&self) -> Idl {
        Idl::Smithy
    }
    fn import(&self, raw: &[u8]) -> Result<ApiModel, ImportError> {
        import_smithy(raw)
    }
}

/// How an operation is selected under the service protocol. RPC protocols name the
/// operation directly; REST protocols read it off the method + request URI.
enum Wire {
    /// `query` / `json`: operation = a named action; selector = the operation name.
    Rpc,
    /// `rest-json` / `rest-xml`: operation = the literal method + path.
    Rest,
}

fn import_smithy(raw: &[u8]) -> Result<ApiModel, ImportError> {
    let spec: Value = serde_json::from_slice(raw).map_err(|e| ImportError::Parse(e.to_string()))?;
    let protocol_name = spec
        .get("metadata")
        .and_then(|m| m.get("protocol"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let (protocol, wire) = match protocol_name {
        // EC2's wire shape is query-RPC (operation name in the `Action` parameter, POST to
        // `/`); botocore labels it `ec2` only to flag a few list-serialization quirks the
        // engine doesn't care about. Treat it as `query`.
        "query" | "ec2" => (Protocol::parameter("Action"), Wire::Rpc),
        "json" => (Protocol::header("x-amz-target", "."), Wire::Rpc),
        "rest-json" | "rest-xml" => (Protocol::rest(), Wire::Rest),
        other => {
            return Err(ImportError::Parse(format!(
                "unsupported smithy protocol: {other}"
            )));
        }
    };

    let shapes = spec.get("shapes");
    let ops = spec
        .get("operations")
        .and_then(Value::as_object)
        .ok_or(ImportError::Empty)?;

    let mut operations = Vec::new();
    for (key, op) in ops {
        let Some(op) = op.as_object() else {
            continue;
        };
        operations.push(operation(key, op, &wire, shapes));
    }
    if operations.is_empty() {
        return Err(ImportError::Empty);
    }

    Ok(ApiModel {
        protocol,
        operations,
    })
}

fn operation(
    key: &str,
    op: &serde_json::Map<String, Value>,
    wire: &Wire,
    shapes: Option<&Value>,
) -> ApiOperation {
    let name = op
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(key)
        .to_string();
    let id = key.to_string();
    let summary = op
        .get("documentation")
        .and_then(Value::as_str)
        .map(strip_html)
        .unwrap_or_default();

    let selector = match wire {
        Wire::Rpc => Selector::named(name.clone()),
        Wire::Rest => {
            let method = op
                .get("http")
                .and_then(|h| h.get("method"))
                .and_then(Value::as_str)
                .map(|m| m.to_ascii_uppercase())
                .unwrap_or_else(|| "POST".to_string());
            let uri = op
                .get("http")
                .and_then(|h| h.get("requestUri"))
                .and_then(Value::as_str)
                .unwrap_or("/")
                .trim_start_matches('/')
                .to_string();
            Selector::route(method, uri)
        }
    };

    let fields = input_fields(op, shapes, wire);

    ApiOperation {
        id,
        selector,
        fields,
        summary,
    }
}

/// The operation's conditionable fields: the top-level members of its `input` shape. RPC
/// members are all `Body`; REST members honor an explicit `location` (uri/querystring/
/// header) and otherwise default to `Body`.
fn input_fields(
    op: &serde_json::Map<String, Value>,
    shapes: Option<&Value>,
    wire: &Wire,
) -> Vec<Field> {
    let Some(input_shape) = op
        .get("input")
        .and_then(|i| i.get("shape"))
        .and_then(Value::as_str)
    else {
        return Vec::new();
    };
    let Some(members) = shapes
        .and_then(|s| s.get(input_shape))
        .and_then(|s| s.get("members"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };

    members
        .iter()
        .map(|(name, member)| {
            let source = match wire {
                Wire::Rpc => FieldOrigin::Body,
                Wire::Rest => member
                    .get("location")
                    .and_then(Value::as_str)
                    .map(location_origin)
                    .unwrap_or(FieldOrigin::Body),
            };
            let summary = member_summary(member, shapes);
            Field {
                name: name.clone(),
                source,
                summary,
            }
        })
        .collect()
}

/// A REST member's `location` → where the field is read from. Unknown locations are body.
fn location_origin(location: &str) -> FieldOrigin {
    match location {
        "uri" => FieldOrigin::Path,
        "querystring" => FieldOrigin::Query,
        "header" | "headers" => FieldOrigin::Header,
        _ => FieldOrigin::Body,
    }
}

/// The member's referenced-shape documentation, stripped to its first line. Empty when not
/// readily available (no ref, or the ref carries no `documentation`).
fn member_summary(member: &Value, shapes: Option<&Value>) -> String {
    member
        .get("documentation")
        .and_then(Value::as_str)
        .map(strip_html)
        .or_else(|| {
            let shape = member.get("shape").and_then(Value::as_str)?;
            shapes
                .and_then(|s| s.get(shape))
                .and_then(|s| s.get("documentation"))
                .and_then(Value::as_str)
                .map(strip_html)
        })
        .unwrap_or_default()
}

/// Strip `<...>` tags from doc HTML and keep the first non-empty line — a terse, regex-free
/// summary (`<p>Describes instances.</p>` → "Describes instances.").
fn strip_html(doc: &str) -> String {
    let mut out = String::with_capacity(doc.len());
    let mut in_tag = false;
    for c in doc.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn bytes(v: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn query_protocol_is_rpc_with_named_selector_and_action_verb() {
        let raw = bytes(serde_json::json!({
            "metadata": { "protocol": "query", "targetPrefix": "ec2" },
            "operations": {
                "DescribeInstances": {
                    "name": "DescribeInstances",
                    "http": { "method": "POST", "requestUri": "/" },
                    "input": { "shape": "DescribeInstancesRequest" },
                    "documentation": "<p>Describes instances.</p>"
                }
            },
            "shapes": {
                "DescribeInstancesRequest": {
                    "type": "structure",
                    "members": {
                        "InstanceIds": { "shape": "StringList" },
                        "DryRun": { "shape": "Boolean" }
                    }
                }
            }
        }));
        let model = SmithyImporter.import(&raw).unwrap();
        assert_eq!(model.protocol, Protocol::parameter("Action"));
        assert_eq!(model.operations.len(), 1);

        let op = &model.operations[0];
        assert_eq!(op.id, "DescribeInstances");
        assert_eq!(op.summary, "Describes instances.");
        match &op.selector {
            Selector::Named(n) => assert_eq!(n.name, "DescribeInstances"),
            other => panic!("expected Named selector, got {other:?}"),
        }

        let mut body: Vec<&str> = op
            .fields
            .iter()
            .filter(|f| f.source == FieldOrigin::Body)
            .map(|f| f.name.as_str())
            .collect();
        body.sort_unstable();
        assert_eq!(body, ["DryRun", "InstanceIds"]);
    }

    #[test]
    fn ec2_protocol_is_treated_as_query_rpc() {
        // botocore labels EC2 with its own `ec2` protocol, but it is wire-identical to
        // `query` (operation name in the `Action` parameter), so the importer must accept it.
        let raw = bytes(serde_json::json!({
            "metadata": { "protocol": "ec2", "endpointPrefix": "ec2" },
            "operations": {
                "RunInstances": {
                    "name": "RunInstances",
                    "http": { "method": "POST", "requestUri": "/" },
                    "input": { "shape": "RunInstancesRequest" }
                }
            },
            "shapes": {
                "RunInstancesRequest": {
                    "type": "structure",
                    "members": { "ImageId": { "shape": "String" } }
                }
            }
        }));
        let model = SmithyImporter.import(&raw).unwrap();
        assert_eq!(model.protocol, Protocol::parameter("Action"));
        let op = &model.operations[0];
        assert_eq!(op.id, "RunInstances");
        match &op.selector {
            Selector::Named(n) => assert_eq!(n.name, "RunInstances"),
            other => panic!("expected Named selector, got {other:?}"),
        }
    }

    #[test]
    fn json_protocol_reads_target_header() {
        let raw = bytes(serde_json::json!({
            "metadata": { "protocol": "json", "targetPrefix": "DynamoDB_20120810" },
            "operations": {
                "PutItem": {
                    "name": "PutItem",
                    "http": { "method": "POST", "requestUri": "/" },
                    "input": { "shape": "PutItemInput" }
                }
            },
            "shapes": {
                "PutItemInput": {
                    "type": "structure",
                    "members": { "TableName": { "shape": "TableName" } }
                }
            }
        }));
        let model = SmithyImporter.import(&raw).unwrap();
        assert_eq!(model.protocol, Protocol::header("x-amz-target", "."));

        let op = &model.operations[0];
        match &op.selector {
            Selector::Named(n) => assert_eq!(n.name, "PutItem"),
            other => panic!("expected Named selector, got {other:?}"),
        }
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "TableName" && f.source == FieldOrigin::Body)
        );
    }

    #[test]
    fn rest_json_protocol_is_route_with_literal_method() {
        let raw = bytes(serde_json::json!({
            "metadata": { "protocol": "rest-json" },
            "operations": {
                "Invoke": {
                    "name": "Invoke",
                    "http": {
                        "method": "POST",
                        "requestUri": "/functions/{FunctionName}/invocations"
                    },
                    "input": { "shape": "InvocationRequest" }
                }
            },
            "shapes": {
                "InvocationRequest": {
                    "type": "structure",
                    "members": {
                        "FunctionName": { "shape": "NamespacedFunctionName", "location": "uri" },
                        "Payload": { "shape": "Blob" }
                    }
                }
            }
        }));
        let model = SmithyImporter.import(&raw).unwrap();
        assert_eq!(model.protocol, Protocol::rest());

        let op = &model.operations[0];
        match &op.selector {
            Selector::Route(r) => {
                assert_eq!(r.method, "POST");
                assert_eq!(r.path_template, "functions/{FunctionName}/invocations");
            }
            other => panic!("expected Route selector, got {other:?}"),
        }
        // The `location: uri` member surfaces as a Path field; the bare member is Body.
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "FunctionName" && f.source == FieldOrigin::Path)
        );
        assert!(
            op.fields
                .iter()
                .any(|f| f.name == "Payload" && f.source == FieldOrigin::Body)
        );
    }

    #[test]
    fn rejects_bad_input() {
        // Not JSON at all.
        assert!(matches!(
            SmithyImporter.import(b"not json"),
            Err(ImportError::Parse(_))
        ));
        // Valid JSON, a known protocol, but no operations.
        let no_ops = bytes(serde_json::json!({
            "metadata": { "protocol": "query" },
            "operations": {}
        }));
        assert!(matches!(
            SmithyImporter.import(&no_ops),
            Err(ImportError::Empty)
        ));
        // Unknown protocol fails closed with a Parse error.
        let bad_proto = bytes(serde_json::json!({
            "metadata": { "protocol": "graphql" },
            "operations": { "Foo": { "name": "Foo" } }
        }));
        assert!(matches!(
            SmithyImporter.import(&bad_proto),
            Err(ImportError::Parse(_))
        ));
        // Missing protocol also fails closed.
        let no_proto = bytes(serde_json::json!({
            "metadata": {},
            "operations": { "Foo": { "name": "Foo" } }
        }));
        assert!(matches!(
            SmithyImporter.import(&no_proto),
            Err(ImportError::Parse(_))
        ));
    }
}
