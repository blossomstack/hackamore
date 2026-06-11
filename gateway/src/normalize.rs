//! Request → [`Action`] normalization. This is the protocol adapter: it turns a raw
//! HTTP request into the engine's protocol-agnostic `Action`. RESTful by default
//! (method + path; a [`Flavor`] adds nicer resource kinds); RPC protocols
//! ([`Protocol::AwsQuery`]/[`Protocol::AwsJson`]) read the operation from the body/header
//! and set a named [`Verb`]. Extraction is **strict, fail-closed**: an RPC request whose
//! operation can't be parsed gets an unmatchable verb so no allow rule fires.

use crate::core::ProxyRequest;
use crate::service::{Flavor, Protocol, Service};
use models::action::{Action, CrudKind, Resource, Verb};
use serde_json::{Map, Value};

/// A fail-closed sentinel verb for RPC requests whose operation cannot be extracted. No
/// sane policy lists it, so it falls through to default-deny.
const UNPARSED: &str = "__unparsed__";

/// Normalize a request to `service` into an `Action`. `decoded_path` is the canonical,
/// percent-decoded, dot-resolved path (from [`crate::canonicalize`]) — matching the form a
/// policy glob is written against — so resource and field extraction see the same path the
/// engine will decide on.
pub fn normalize(service: &Service, req: &ProxyRequest, decoded_path: &str) -> Action {
    let path = decoded_path.trim_start_matches('/');
    let resource = match service.flavor {
        Flavor::Github => github_resource(path),
        Flavor::K8s => k8s_resource(path),
        Flavor::Generic => generic_resource(path),
    };
    let verb = verb_for_protocol(service.extract.protocol, req);
    let mut fields = merge_fields(&req.query, &req.body);
    if let Some(template) = &service.extract.path_template {
        capture_path_template(template, path, &mut fields);
    }
    Action::of(service.name.clone(), verb, resource).with_fields(fields)
}

/// The verb for a request under a wire protocol: a CRUD verb from the method (REST), or a
/// named action read from the body/header (AWS RPC).
fn verb_for_protocol(protocol: Protocol, req: &ProxyRequest) -> Verb {
    match protocol {
        Protocol::Rest => verb_for(&req.method),
        Protocol::AwsQuery => aws_query_action(req),
        Protocol::AwsJson => aws_json_action(req),
    }
}

/// Map an HTTP method to a coarse CRUD [`Verb`]. Unknown/odd methods map to `Read`, the
/// least-privileged verb, so they cannot accidentally satisfy a write rule.
fn verb_for(method: &http::Method) -> Verb {
    let kind = match *method {
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS => CrudKind::Read,
        http::Method::POST => CrudKind::Create,
        http::Method::PUT | http::Method::PATCH => CrudKind::Update,
        http::Method::DELETE => CrudKind::Delete,
        _ => CrudKind::Read,
    };
    Verb::crud(kind)
}

/// AWS query protocol: operation = `Action=<Op>` in the form body (or query string).
/// Fail-closed to [`UNPARSED`] when absent.
fn aws_query_action(req: &ProxyRequest) -> Verb {
    let find_action = |pairs: Vec<(String, String)>| {
        pairs
            .into_iter()
            .find(|(k, _)| k == "Action")
            .map(|(_, v)| v)
    };
    let from_body = std::str::from_utf8(&req.body)
        .ok()
        .and_then(|b| find_action(parse_query(b)));
    let op = from_body.or_else(|| find_action(parse_query(&req.query)));
    match op {
        Some(op) if !op.is_empty() => Verb::action(op),
        _ => Verb::action(UNPARSED),
    }
}

/// AWS JSON protocol: operation = the suffix of the `X-Amz-Target: <svc>.<Op>` header.
/// Fail-closed to [`UNPARSED`] when absent.
fn aws_json_action(req: &ProxyRequest) -> Verb {
    match req
        .headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .filter(|t| !t.is_empty())
    {
        Some(target) => Verb::action(target.rsplit('.').next().unwrap_or(target)),
        None => Verb::action(UNPARSED),
    }
}

/// Capture named segments from a path template (e.g. `/{bucket}/{key}`) into `fields`.
/// A trailing `{name+}` captures the remaining segments joined by `/`.
fn capture_path_template(template: &str, path: &str, fields: &mut Value) {
    let Value::Object(map) = fields else { return };
    let t: Vec<&str> = template.trim_start_matches('/').split('/').collect();
    let p: Vec<&str> = path.split('/').collect();
    for (i, seg) in t.iter().enumerate() {
        let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
            continue;
        };
        if let Some(rest_name) = name.strip_suffix('+') {
            let rest = p.get(i..).map(|s| s.join("/")).unwrap_or_default();
            if !rest.is_empty() {
                map.insert(rest_name.to_string(), Value::String(rest));
            }
        } else if let Some(v) = p.get(i) {
            map.insert(name.to_string(), Value::String((*v).to_string()));
        }
    }
}

/// Generic resource: the full path as the canonical id, with the first path segment as
/// a coarse `kind`. Works for any service.
fn generic_resource(path: &str) -> Resource {
    if path.is_empty() {
        return Resource::of("", "root");
    }
    let kind = path.split('/').next().unwrap_or("other");
    Resource::of(path, kind)
}

/// GitHub-aware resource parsing (the `github` flavor).
fn github_resource(path: &str) -> Resource {
    if path.is_empty() {
        return Resource::of("", "root");
    }
    let segments: Vec<&str> = path.split('/').collect();
    let kind = match segments.as_slice() {
        ["repos", _owner, _repo] => "repo",
        ["repos", _owner, _repo, collection, ..] => github_collection_kind(collection),
        [first, ..] => first,
        [] => "other",
    };
    Resource::of(path, kind)
}

/// Kubernetes-aware resource parsing: the resource kind is the collection after the
/// namespace name (`…/namespaces/dev/pods` → `pods`), else the last path segment.
fn k8s_resource(path: &str) -> Resource {
    if path.is_empty() {
        return Resource::of("", "root");
    }
    let segs: Vec<&str> = path.split('/').collect();
    let kind = segs
        .iter()
        .position(|s| *s == "namespaces")
        .and_then(|i| segs.get(i + 2))
        .or_else(|| segs.last())
        .copied()
        .unwrap_or("resource");
    Resource::of(path, kind)
}

fn github_collection_kind(collection: &str) -> &'static str {
    match collection {
        "pulls" => "pull_request",
        "issues" => "issue",
        "contents" => "contents",
        "git" => "git",
        "actions" => "actions",
        "hooks" => "hook",
        _ => "repo_subresource",
    }
}

/// Merge query-string params and the request body into one flat `fields` object for
/// conditional rules. Body keys win over query keys. A JSON object body contributes its
/// keys; otherwise a form-encoded body (one containing `=`, e.g. AWS query / HTML forms)
/// contributes its pairs. Any other body contributes nothing (its bytes still pass
/// through untouched when forwarded).
fn merge_fields(query: &str, body: &[u8]) -> Value {
    let mut map = Map::new();
    for (k, v) in parse_query(query) {
        map.insert(k, Value::String(v));
    }
    if let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(body) {
        for (k, v) in obj {
            map.insert(k, v);
        }
    } else if let Ok(text) = std::str::from_utf8(body) {
        // Form-encoded fallback — only when it actually looks like `k=v` pairs, so a
        // plain non-form body (e.g. "not json") contributes nothing.
        if text.contains('=') {
            for (k, v) in parse_query(text) {
                map.insert(k, Value::String(v));
            }
        }
    }
    Value::Object(map)
}

/// Minimal `a=b&c=d` parser. Keys and values are percent-decoded (and `+` → space) so a
/// condition like `base == "develop"` can't be evaded by sending `base=deve%6cop`; a
/// missing `=` yields an empty value.
fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return vec![];
    }
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (decode_field(k), decode_field(v)),
            None => (decode_field(pair), String::new()),
        })
        .collect()
}

/// Percent-decode a query/form token into a lossy string for matching.
fn decode_field(s: &str) -> String {
    String::from_utf8_lossy(&crate::sigv4::percent_decode(s)).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::HeaderMap;

    fn service(name: &str, flavor: Flavor) -> Service {
        Service::new(name, "*", "https://upstream.example").with_flavor(flavor)
    }

    fn req(method: http::Method, path: &str, query: &str, body: &str) -> ProxyRequest {
        ProxyRequest {
            method,
            path: path.to_string(),
            query: query.to_string(),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
        }
    }

    /// Normalize the way the data plane does: canonicalize the path first, then extract.
    fn norm(service: &Service, r: &ProxyRequest) -> Action {
        let canonical = crate::canonicalize::path(&r.path).expect("canonical path");
        normalize(service, r, &canonical.decoded)
    }

    #[test]
    fn github_flavor_parses_pull_request() {
        let r = req(
            http::Method::POST,
            "/repos/octocat/hello/pulls",
            "",
            r#"{"base":"main","title":"x"}"#,
        );
        let a = norm(&service("github", Flavor::Github), &r);
        assert_eq!(a.target, "github");
        assert_eq!(a.verb, Verb::crud(CrudKind::Create));
        assert_eq!(a.resource.path, "repos/octocat/hello/pulls");
        assert_eq!(a.resource.kind, "pull_request");
        assert_eq!(
            a.fields,
            serde_json::json!({ "base": "main", "title": "x" })
        );
    }

    #[test]
    fn generic_flavor_uses_first_segment_kind() {
        let a = norm(
            &service("openai", Flavor::Generic),
            &req(
                http::Method::POST,
                "/v1/chat/completions",
                "",
                r#"{"model":"gpt"}"#,
            ),
        );
        assert_eq!(a.target, "openai");
        assert_eq!(a.verb, Verb::crud(CrudKind::Create));
        assert_eq!(a.resource.path, "v1/chat/completions");
        assert_eq!(a.resource.kind, "v1");
        assert_eq!(a.fields, serde_json::json!({ "model": "gpt" }));
    }

    #[test]
    fn verbs_map_from_methods() {
        assert_eq!(
            verb_for(&http::Method::DELETE),
            Verb::crud(CrudKind::Delete)
        );
        assert_eq!(verb_for(&http::Method::PATCH), Verb::crud(CrudKind::Update));
        assert_eq!(verb_for(&http::Method::HEAD), Verb::crud(CrudKind::Read));
    }

    #[test]
    fn body_overrides_query_fields() {
        let a = norm(
            &service("svc", Flavor::Generic),
            &req(
                http::Method::POST,
                "/x",
                "base=main",
                r#"{"base":"develop"}"#,
            ),
        );
        assert_eq!(a.fields, serde_json::json!({ "base": "develop" }));
    }

    #[test]
    fn non_json_body_is_ignored_for_fields() {
        let a = norm(
            &service("svc", Flavor::Generic),
            &req(http::Method::POST, "/x", "", "not json"),
        );
        assert_eq!(a.fields, serde_json::json!({}));
    }

    #[test]
    fn aws_query_protocol_sets_named_verb_and_form_fields() {
        let mut svc = service("aws", Flavor::Generic);
        svc.extract.protocol = Protocol::AwsQuery;
        let a = norm(
            &svc,
            &req(
                http::Method::POST,
                "/",
                "",
                "Action=DescribeInstances&InstanceId=i-123",
            ),
        );
        assert_eq!(a.verb, Verb::action("DescribeInstances"));
        assert_eq!(
            a.fields,
            serde_json::json!({ "Action": "DescribeInstances", "InstanceId": "i-123" })
        );
    }

    #[test]
    fn aws_query_missing_action_fails_closed() {
        let mut svc = service("aws", Flavor::Generic);
        svc.extract.protocol = Protocol::AwsQuery;
        let a = norm(
            &svc,
            &req(http::Method::POST, "/", "", "Version=2016-11-15"),
        );
        assert_eq!(a.verb, Verb::action("__unparsed__"));
    }

    #[test]
    fn aws_json_protocol_reads_target_header() {
        let mut svc = service("ddb", Flavor::Generic);
        svc.extract.protocol = Protocol::AwsJson;
        let mut r = req(http::Method::POST, "/", "", r#"{"TableName":"dev"}"#);
        r.headers
            .insert("x-amz-target", "DynamoDB_20120810.PutItem".parse().unwrap());
        let a = norm(&svc, &r);
        assert_eq!(a.verb, Verb::action("PutItem"));
        assert_eq!(a.fields, serde_json::json!({ "TableName": "dev" }));
    }

    #[test]
    fn path_template_captures_named_segments() {
        let mut svc = service("s3", Flavor::Generic);
        svc.extract.path_template = Some("/{bucket}/{key+}".into());
        let a = norm(
            &svc,
            &req(http::Method::PUT, "/my-data/reports/q1.csv", "", ""),
        );
        assert_eq!(a.fields["bucket"], serde_json::json!("my-data"));
        assert_eq!(a.fields["key"], serde_json::json!("reports/q1.csv"));
    }
}
