//! Request → [`Action`] normalization. This is the protocol adapter: it turns a raw
//! HTTP request into the engine's protocol-agnostic `Action`. RESTful by default (the
//! verb is the literal HTTP method; the resource is the path); the generic RPC protocols
//! ([`Protocol::Parameter`]/[`Protocol::Header`]) read the operation name from a
//! body/query field or a header and set a named [`Verb`]. Extraction is **strict,
//! fail-closed**: an RPC request whose operation can't be parsed gets an unmatchable verb
//! so no allow rule fires.

use crate::core::ProxyRequest;
use crate::service::{Protocol, Service};
use hackamore_models::action::{Action, Resource, Verb};
use serde_json::{Map, Value};

/// A fail-closed sentinel verb for RPC requests whose operation cannot be extracted. No
/// sane policy lists it, so it falls through to default-deny.
const UNPARSED: &str = "__unparsed__";

/// Generic resource derivation: the full path is the canonical id (an empty path is the
/// service root). Works for any service.
pub fn resource(path: &str) -> Resource {
    Resource::of(path.to_string())
}

/// Normalize a request to `service` into an `Action`. `decoded_path` is the canonical,
/// percent-decoded, dot-resolved path (from [`crate::canonicalize`]) — matching the form a
/// policy glob is written against — so resource and field extraction see the same path the
/// engine will decide on.
pub fn normalize(service: &Service, req: &ProxyRequest, decoded_path: &str) -> Action {
    let path = decoded_path.trim_start_matches('/');
    // git Smart-HTTP derives *both* verb and resource from the request shape, so it bypasses
    // the generic path-resource / method-verb derivation entirely (a fetch/push must never
    // look like a plain GET/POST on the canonical path). The other protocols take the
    // generic path resource and read their verb per their own mechanism.
    let protocol = &service.extract.protocol;
    let (verb, resource) = match protocol {
        Protocol::Git => git_action(path, &req.query, &req.method),
        Protocol::Rest | Protocol::Parameter { .. } | Protocol::Header { .. } => {
            (verb_for_protocol(protocol, req), resource(path))
        }
    };
    let mut fields = merge_fields(&req.query, &req.body);
    if let Some(template) = &service.extract.path_template {
        capture_path_template(template, path, &mut fields);
    }
    Action::of(service.name.clone(), verb, resource).with_fields(fields)
}

/// The two git Smart-HTTP service names; also the literal verbs hackamore emits (no
/// invented "push"/"fetch" translation — the verb is the thing the request states).
const GIT_UPLOAD_PACK: &str = "git-upload-pack";
const GIT_RECEIVE_PACK: &str = "git-receive-pack";

/// Derive `(verb, resource)` for a git Smart-HTTP request. Recognizes the four shapes:
/// `GET {repo}/info/refs?service=git-{upload,receive}-pack` (the verb is the `?service=`
/// value) and `POST {repo}/git-{upload,receive}-pack` (the verb is the path suffix). The
/// resource is always `{owner}/{repo}`: the path with the matched suffix and a trailing
/// `.git` stripped. Any request matching none of the four shapes **fails closed** to the
/// literal method + canonical path, so a fetch/push allow rule can't fire on it.
fn git_action(path: &str, query: &str, method: &http::Method) -> (Verb, Resource) {
    if method == http::Method::GET {
        if let Some(repo) = path.strip_suffix("/info/refs") {
            let service = git_service_param(query);
            if service == GIT_UPLOAD_PACK || service == GIT_RECEIVE_PACK {
                return (Verb::action(service), resource(strip_dot_git(repo)));
            }
        }
    } else if method == http::Method::POST {
        for service in [GIT_UPLOAD_PACK, GIT_RECEIVE_PACK] {
            if let Some(repo) = path.strip_suffix(&format!("/{service}")) {
                return (Verb::action(service), resource(strip_dot_git(repo)));
            }
        }
    }
    // Unrecognized shape: fail closed to the generic method + path (no git verb).
    (verb_for(method), resource(path))
}

/// The value of the `service` query parameter (the git Smart-HTTP info/refs handshake), or
/// `""` when absent.
fn git_service_param(query: &str) -> String {
    parse_query(query)
        .into_iter()
        .find(|(k, _)| k == "service")
        .map(|(_, v)| v)
        .unwrap_or_default()
}

/// Strip a trailing `.git` from a git repo path (`acme/widgets.git` → `acme/widgets`); a
/// path without the suffix is returned unchanged.
fn strip_dot_git(repo: &str) -> &str {
    repo.strip_suffix(".git").unwrap_or(repo)
}

/// The verb for a request under a wire protocol: the literal HTTP method (REST), or a
/// named action read from a body/query field or a header (the generic RPC mechanisms).
fn verb_for_protocol(protocol: &Protocol, req: &ProxyRequest) -> Verb {
    match protocol {
        Protocol::Rest => verb_for(&req.method),
        Protocol::Parameter { name } => named_from_parameter(req, name),
        Protocol::Header { name, suffix_after } => named_from_header(req, name, suffix_after),
        // git is normalized by `git_action` (it derives the resource too), so it never
        // reaches here; fail closed if it ever does.
        Protocol::Git => Verb::action(UNPARSED),
    }
}

/// The REST verb for a request: the literal HTTP method, verbatim (uppercase as `http`
/// gives it), e.g. "GET", "PATCH", "PROPFIND". `pub(crate)` so other call sites can read
/// a method into the same verb.
pub(crate) fn verb_for(method: &http::Method) -> Verb {
    Verb::method(method.as_str())
}

/// Operation name = the value of the `name` field in the form body (or query string).
/// Fail-closed to [`UNPARSED`] when absent (AWS query is `name = "Action"`).
fn named_from_parameter(req: &ProxyRequest, name: &str) -> Verb {
    let find =
        |pairs: Vec<(String, String)>| pairs.into_iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let from_body = std::str::from_utf8(&req.body)
        .ok()
        .and_then(|b| find(parse_query(b)));
    let op = from_body.or_else(|| find(parse_query(&req.query)));
    match op {
        Some(op) if !op.is_empty() => Verb::action(op),
        _ => Verb::action(UNPARSED),
    }
}

/// Operation name = the `name` header value, keeping the part after the last
/// `suffix_after` (empty = the whole value). Fail-closed to [`UNPARSED`] when absent (AWS
/// json is `name = "x-amz-target"`, `suffix_after = "."`).
fn named_from_header(req: &ProxyRequest, name: &str, suffix_after: &str) -> Verb {
    match req
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|t| !t.is_empty())
    {
        Some(value) if suffix_after.is_empty() => Verb::action(value),
        Some(value) => Verb::action(value.rsplit(suffix_after).next().unwrap_or(value)),
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

    fn service(name: &str) -> Service {
        Service::new(name, "*", "https://upstream.example")
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
    fn method_verb_and_path_for_a_nested_path() {
        let r = req(
            http::Method::POST,
            "/repos/octocat/hello/pulls",
            "",
            r#"{"base":"main","title":"x"}"#,
        );
        let a = norm(&service("github"), &r);
        assert_eq!(a.target, "github");
        assert_eq!(a.verb, Verb::method("POST"));
        assert_eq!(a.resource.path, "repos/octocat/hello/pulls");
        assert_eq!(
            a.fields,
            serde_json::json!({ "base": "main", "title": "x" })
        );
    }

    #[test]
    fn generic_path_is_the_resource() {
        let a = norm(
            &service("openai"),
            &req(
                http::Method::POST,
                "/v1/chat/completions",
                "",
                r#"{"model":"gpt"}"#,
            ),
        );
        assert_eq!(a.target, "openai");
        assert_eq!(a.verb, Verb::method("POST"));
        assert_eq!(a.resource.path, "v1/chat/completions");
        assert_eq!(a.fields, serde_json::json!({ "model": "gpt" }));
    }

    #[test]
    fn verbs_are_the_literal_method() {
        assert_eq!(verb_for(&http::Method::GET), Verb::method("GET"));
        assert_eq!(verb_for(&http::Method::DELETE), Verb::method("DELETE"));
        // PUT and PATCH are now distinct (no longer collapsed to one CRUD verb).
        assert_eq!(verb_for(&http::Method::PUT), Verb::method("PUT"));
        assert_eq!(verb_for(&http::Method::PATCH), Verb::method("PATCH"));
        assert_ne!(verb_for(&http::Method::PUT), verb_for(&http::Method::PATCH));
        assert_eq!(verb_for(&http::Method::HEAD), Verb::method("HEAD"));
    }

    #[test]
    fn body_overrides_query_fields() {
        let a = norm(
            &service("svc"),
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
            &service("svc"),
            &req(http::Method::POST, "/x", "", "not json"),
        );
        assert_eq!(a.fields, serde_json::json!({}));
    }

    #[test]
    fn aws_query_protocol_sets_named_verb_and_form_fields() {
        let mut svc = service("aws");
        svc.extract.protocol = Protocol::parse(Some("aws-query"));
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
        let mut svc = service("aws");
        svc.extract.protocol = Protocol::parse(Some("aws-query"));
        let a = norm(
            &svc,
            &req(http::Method::POST, "/", "", "Version=2016-11-15"),
        );
        assert_eq!(a.verb, Verb::action("__unparsed__"));
    }

    #[test]
    fn aws_json_protocol_reads_target_header() {
        let mut svc = service("ddb");
        svc.extract.protocol = Protocol::parse(Some("aws-json"));
        let mut r = req(http::Method::POST, "/", "", r#"{"TableName":"dev"}"#);
        r.headers
            .insert("x-amz-target", "DynamoDB_20120810.PutItem".parse().unwrap());
        let a = norm(&svc, &r);
        assert_eq!(a.verb, Verb::action("PutItem"));
        assert_eq!(a.fields, serde_json::json!({ "TableName": "dev" }));
    }

    /// A git-http service.
    fn git_service(name: &str) -> Service {
        let mut svc = service(name);
        svc.extract.protocol = Protocol::parse(Some("git-http"));
        svc
    }

    #[test]
    fn git_fetch_info_refs_sets_named_verb_and_owner_repo_resource() {
        // `git fetch`/`clone`: GET …/info/refs?service=git-upload-pack.
        let a = norm(
            &git_service("github"),
            &req(
                http::Method::GET,
                "/acme/widgets.git/info/refs",
                "service=git-upload-pack",
                "",
            ),
        );
        assert_eq!(a.verb, Verb::action("git-upload-pack"));
        assert_eq!(a.resource.path, "acme/widgets");
    }

    #[test]
    fn git_push_info_refs_sets_named_verb_and_owner_repo_resource() {
        // `git push` discovery: GET …/info/refs?service=git-receive-pack.
        let a = norm(
            &git_service("github"),
            &req(
                http::Method::GET,
                "/acme/widgets.git/info/refs",
                "service=git-receive-pack",
                "",
            ),
        );
        assert_eq!(a.verb, Verb::action("git-receive-pack"));
        assert_eq!(a.resource.path, "acme/widgets");
    }

    #[test]
    fn git_upload_pack_post_sets_fetch_verb_from_path_suffix() {
        // The fetch RPC itself: POST …/git-upload-pack.
        let a = norm(
            &git_service("github"),
            &req(
                http::Method::POST,
                "/acme/widgets.git/git-upload-pack",
                "",
                "",
            ),
        );
        assert_eq!(a.verb, Verb::action("git-upload-pack"));
        assert_eq!(a.resource.path, "acme/widgets");
    }

    #[test]
    fn git_receive_pack_post_sets_push_verb_from_path_suffix() {
        // The push RPC itself: POST …/git-receive-pack.
        let a = norm(
            &git_service("github"),
            &req(
                http::Method::POST,
                "/acme/widgets.git/git-receive-pack",
                "",
                "",
            ),
        );
        assert_eq!(a.verb, Verb::action("git-receive-pack"));
        assert_eq!(a.resource.path, "acme/widgets");
    }

    #[test]
    fn git_unrecognized_shape_fails_closed_to_method_and_path() {
        // A request that matches none of the four Smart-HTTP shapes must not look like a
        // fetch/push: the verb is the literal method and the resource is the canonical path,
        // so no `git-upload-pack`/`git-receive-pack` allow rule fires.
        let a = norm(
            &git_service("github"),
            &req(http::Method::GET, "/acme/widgets.git/objects/abc", "", ""),
        );
        assert_eq!(a.verb, Verb::method("GET"));
        assert_eq!(a.resource.path, "acme/widgets.git/objects/abc");
        assert_ne!(a.verb, Verb::action("git-upload-pack"));
        assert_ne!(a.verb, Verb::action("git-receive-pack"));
    }

    #[test]
    fn git_resource_handles_repo_without_dot_git_suffix() {
        // Some hosts omit `.git`; the suffix strip still yields owner/repo.
        let a = norm(
            &git_service("github"),
            &req(
                http::Method::GET,
                "/acme/widgets/info/refs",
                "service=git-upload-pack",
                "",
            ),
        );
        assert_eq!(a.verb, Verb::action("git-upload-pack"));
        assert_eq!(a.resource.path, "acme/widgets");
    }

    #[test]
    fn path_template_captures_named_segments() {
        let mut svc = service("s3");
        svc.extract.path_template = Some("/{bucket}/{key+}".into());
        let a = norm(
            &svc,
            &req(http::Method::PUT, "/my-data/reports/q1.csv", "", ""),
        );
        assert_eq!(a.fields["bucket"], serde_json::json!("my-data"));
        assert_eq!(a.fields["key"], serde_json::json!("reports/q1.csv"));
    }
}
