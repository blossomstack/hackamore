//! e2e for live service registration: `POST /admin/services` imports an OpenAPI description
//! and registers a service at runtime; `GET /admin/services` lists it with its imported
//! model; the dry-run path enforces against it; `DELETE` removes it — all with no restart.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hackamore_gateway::{Outbound, Service};
use hackamore_tests::{start_hackamore_services, start_mock_upstream};

const OPENAPI: &str = r#"{
  "openapi": "3.0.0",
  "paths": {
    "/widgets/{id}": {
      "get": { "operationId": "widgets/get", "summary": "Get a widget" },
      "delete": { "operationId": "widgets/delete", "summary": "Delete a widget" }
    }
  }
}"#;

#[tokio::test]
async fn register_list_enforce_remove_a_service_at_runtime() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    let dir = tempfile::tempdir().unwrap();
    let spec_path = dir.path().join("widgets.json");
    std::fs::write(&spec_path, OPENAPI).unwrap();

    // POST: register live from the OpenAPI file. 201 Created with the imported model.
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "widgets",
            "host": "api.widgets.test",
            "upstreamBase": "https://api.widgets.test",
            "idl": "openapi",
            "sourceFile": spec_path.to_str().unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "widgets");
    let ops: Vec<&str> = body["model"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert!(ops.contains(&"widgets/get"), "imported ops: {ops:?}");

    // GET: the service is in the live registry with its model.
    let listed: serde_json::Value = client
        .get(format!("{}/admin/services", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "widgets")
        .expect("widgets listed");
    assert_eq!(svc["model"]["operations"].as_array().unwrap().len(), 2);

    // Enforce: a read-only policy allows GET and denies DELETE on the just-registered service.
    let read_only = serde_json::json!({ "rules": [{ "effect": "Allow", "matches": {
        "targets": [], "resources": [], "conditions": [],
        "verbs": [{ "type": "Method", "value": { "method": "GET" } }] } }] });
    let test = |method: &str| {
        serde_json::json!({
            "policy": read_only, "target": "widgets", "method": method,
            "path": "/widgets/123", "query": "", "fields": {}
        })
    };
    let allow: serde_json::Value = client
        .post(format!("{}/policy/test", h.admin_url))
        .json(&test("GET"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(allow["verdict"]["type"], "Allow");
    // Generic normalization: the resource is the canonical path.
    assert_eq!(allow["action"]["resource"]["path"], "widgets/123");

    let deny: serde_json::Value = client
        .post(format!("{}/policy/test", h.admin_url))
        .json(&test("DELETE"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deny["verdict"]["type"], "Deny");

    // DELETE: remove it from the live registry.
    let del: serde_json::Value = client
        .delete(format!("{}/admin/services/widgets", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del["removed"], true);
    let after: serde_json::Value = client
        .get(format!("{}/admin/services", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        after
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["name"] != "widgets")
    );
}

#[tokio::test]
async fn register_with_inline_spec_imports_the_ops() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    // A tiny inline OpenAPI carried in `specInline` — imported server-side, same path as a file.
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "inline-svc",
            "upstreamBase": "https://api.inline.test",
            "idl": "openapi",
            "specInline": OPENAPI,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let ops: Vec<&str> = body["model"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert!(ops.contains(&"widgets/get"), "imported ops: {ops:?}");
    assert!(ops.contains(&"widgets/delete"), "imported ops: {ops:?}");
}

#[tokio::test]
async fn register_with_inline_model_skips_import() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    // A pre-built ApiModel (the IR) carried in `modelInline` — deserialized directly, no idl.
    let model = serde_json::json!({
        "protocol": { "type": "Rest", "value": {} },
        "operations": [{
            "id": "things/get",
            "selector": { "type": "Route", "value": { "method": "GET", "pathTemplate": "things/{id}" } },
            "fields": [],
            "summary": "Get a thing"
        }]
    });
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "model-svc",
            "upstreamBase": "https://api.model.test",
            "modelInline": model,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let ops: Vec<&str> = body["model"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert_eq!(ops, ["things/get"]);
}

#[tokio::test]
async fn register_rejects_multiple_model_sources() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    // Both an inline spec and a model → 400 (mutually exclusive); nothing registered.
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "two-sources",
            "upstreamBase": "https://api.x.test",
            "idl": "openapi",
            "specInline": OPENAPI,
            "modelInline": { "protocol": { "type": "Rest", "value": {} }, "operations": [] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn git_http_service_auto_attaches_the_git_model() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    // A git-http service with no model/spec still lists the two git ops (server attaches them).
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "git-auto",
            "host": "github.com",
            "upstreamBase": "https://github.com",
            "protocol": "git-http",
            "outbound": { "kind": "basic", "username": "x-access-token", "secret": "ghp_x" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let ops: Vec<&str> = body["model"]["operations"]
        .as_array()
        .expect("git model auto-attached")
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert_eq!(ops, ["git-upload-pack", "git-receive-pack"]);
}

#[tokio::test]
async fn register_rejects_a_bad_description() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "not json").unwrap();

    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "bad", "host": "x", "upstreamBase": "https://x",
            "idl": "openapi", "sourceFile": bad.to_str().unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    // Nothing was registered.
    let listed: serde_json::Value = client
        .get(format!("{}/admin/services", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(listed.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn register_with_inline_secret_and_default_host() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();
    let dir = tempfile::tempdir().unwrap();
    let spec_path = dir.path().join("svc.json");
    std::fs::write(&spec_path, OPENAPI).unwrap();

    // No `host` (defaults to upstreamBase's hostname); bearer auth with the secret inline.
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "widgets2",
            "upstreamBase": "https://api.widgets.test:8443/v1",
            "idl": "openapi",
            "sourceFile": spec_path.to_str().unwrap(),
            "outbound": { "kind": "bearer", "secret": "ghs_live_token" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    let listed: serde_json::Value = client
        .get(format!("{}/admin/services", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "widgets2")
        .expect("widgets2 listed");
    // host defaulted to the upstream hostname (scheme, port, and path stripped).
    assert_eq!(svc["host"], "api.widgets.test");
    // bearer auth; the inline secret was vaulted under the service name.
    assert_eq!(svc["auth"], "bearer");
    assert_eq!(svc["credential"], "widgets2");
}

#[tokio::test]
async fn register_credential_then_reference_it_from_a_service() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();
    let dir = tempfile::tempdir().unwrap();
    let spec_path = dir.path().join("svc.json");
    std::fs::write(&spec_path, OPENAPI).unwrap();

    // Register a credential from a `static` source. 201 with the id only — never the secret.
    let cred = client
        .post(format!("{}/admin/credentials", h.admin_url))
        .json(&serde_json::json!({
            "id": "gh-login",
            "source": { "kind": "static", "secret": "ghp_supersecret" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(cred.status(), reqwest::StatusCode::CREATED);
    let cred_body: serde_json::Value = cred.json().await.unwrap();
    assert_eq!(cred_body["id"], "gh-login");
    // The response carries no secret value anywhere.
    assert!(!cred_body.to_string().contains("ghp_supersecret"));

    // GET /admin/credentials lists the id, and never a secret value.
    let listed: serde_json::Value = client
        .get(format!("{}/admin/credentials", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = listed["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(ids.contains(&"gh-login"), "ids: {ids:?}");
    assert!(!listed.to_string().contains("ghp_supersecret"));

    // Register a service whose outbound references the credential *by id* (no inline secret).
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "github-git",
            "upstreamBase": "https://github.com",
            "idl": "openapi",
            "sourceFile": spec_path.to_str().unwrap(),
            "outbound": { "kind": "basic", "username": "x-access-token", "credential": "gh-login" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    let services: serde_json::Value = client
        .get(format!("{}/admin/services", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc = services
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "github-git")
        .expect("github-git listed");
    // The service references the existing credential id; the auth label names the mechanism.
    assert_eq!(svc["credential"], "gh-login");
    assert_eq!(svc["auth"], "basic x-access-token");
}

#[tokio::test]
async fn register_service_rejects_secret_and_credential_together() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();
    let dir = tempfile::tempdir().unwrap();
    let spec_path = dir.path().join("svc.json");
    std::fs::write(&spec_path, OPENAPI).unwrap();

    // Both an inline secret and a credential reference for an injecting stance → 400.
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "ambiguous",
            "upstreamBase": "https://api.widgets.test",
            "idl": "openapi",
            "sourceFile": spec_path.to_str().unwrap(),
            "outbound": { "kind": "bearer", "secret": "inline", "credential": "an-id" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // Neither a secret nor a credential for an injecting stance → 400.
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "empty-auth",
            "upstreamBase": "https://api.widgets.test",
            "idl": "openapi",
            "sourceFile": spec_path.to_str().unwrap(),
            "outbound": { "kind": "bearer" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn credential_source_command_resolves_stdout() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    // A `command` source runs argv and trims stdout. `echo` is portable enough for the test.
    let resp = client
        .post(format!("{}/admin/credentials", h.admin_url))
        .json(&serde_json::json!({
            "id": "cmd-cred",
            "source": { "kind": "command", "argv": ["echo", "cmd-token-value"] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let listed: serde_json::Value = client
        .get(format!("{}/admin/credentials", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listed["ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "cmd-cred")
    );
    // A failing command (non-zero exit) is a 400; nothing is vaulted.
    let bad = client
        .post(format!("{}/admin/credentials", h.admin_url))
        .json(&serde_json::json!({
            "id": "bad-cmd",
            "source": { "kind": "command", "argv": ["false"] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// Basic injection end-to-end: a service that injects HTTP Basic auth forwards
/// `Authorization: Basic base64(<username>:<real secret>)`, and the agent's token / the real
/// secret never leak into the forwarded header.
#[tokio::test]
async fn basic_injection_forwards_base64_authorization() {
    let upstream = start_mock_upstream().await;
    let h = start_hackamore_services(vec![
        Service::new("git", "*", &upstream.base_url).with_outbound(Outbound::Basic {
            username: "x-access-token".into(),
            credential: "gh-login".into(),
        }),
    ])
    .await;
    h.add_credential("gh-login", "ghp_realtoken");

    let pol = serde_json::from_str(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "verbs": [], "resources": [], "conditions": [] } } ] }"#,
    )
    .unwrap();
    let token = h.mint_token(&pol, 3600).await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/octocat/hello.git/info/refs?service=git-upload-pack",
            h.proxy_url
        ))
        .header("X-Hackamore-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let got = upstream.requests();
    let expected = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode("x-access-token:ghp_realtoken")
    };
    assert_eq!(
        got[0].authorization.as_deref(),
        Some(format!("Basic {expected}").as_str())
    );
    // Neither the launch token nor the real secret leaks into the forwarded Authorization.
    let auth = got[0].authorization.clone().unwrap();
    assert!(!auth.contains(&token));
    assert!(!auth.contains("ghp_realtoken"));
}
