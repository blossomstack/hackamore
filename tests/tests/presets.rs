//! e2e for the CLI service presets (P4a). The preset **expansion** is pure
//! (`preset::resolve(...).to_service_json(...)`), so these tests build the same admin JSON the
//! CLI sends and drive it against a live `start_hackamore_services` admin API — exercising the
//! full server-side path: `specInline` import, git-model auto-attach, and the inline Smithy
//! import. A pre-registered credential id is referenced (the `--credential` path); the
//! `--auth-source` convenience is unit-tested in the cli crate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hackamore_cli::preset::{self, CredentialChoice, DEFAULT_AWS_REGION};
use hackamore_tests::start_hackamore_services;

/// Expand a preset to its admin JSON, threading in the referenced credential id (the
/// `--credential <id>` path).
fn expand(name: &str, region: &str, credential: &str) -> serde_json::Value {
    let p = preset::resolve(name, region)
        .unwrap()
        .unwrap_or_else(|| panic!("{name} should be a known preset"));
    let resolved = p
        .resolve_credential(&CredentialChoice::Credential(credential.to_string()))
        .unwrap();
    assert!(
        resolved.register.is_none(),
        "--credential registers nothing"
    );
    p.to_service_json(&resolved.id)
}

/// Register a `static`/`aws-static` credential up front so a preset's outbound can reference
/// it by id.
async fn register_credential(admin_url: &str, body: serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{admin_url}/admin/credentials"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "credential registered"
    );
}

/// `github-git` preset → registers a git-http service whose model the server auto-attaches,
/// and a fetch is allowed / a push denied by a read-only git policy via the dry-run path
/// (the P2 git assertion).
#[tokio::test]
async fn github_git_preset_registers_and_enforces_git_verbs() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();
    register_credential(
        &h.admin_url,
        serde_json::json!({ "id": "gh-login", "source": { "kind": "static", "secret": "ghp_x" } }),
    )
    .await;

    let body = expand("github-git", DEFAULT_AWS_REGION, "gh-login");
    // The preset sends no model — the server attaches the hardcoded git model.
    assert!(body.get("specInline").is_none());
    assert_eq!(body["protocol"], "git-http");

    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let reg: serde_json::Value = resp.json().await.unwrap();
    // The server auto-attached the git model: its two ops appear.
    let ops: Vec<&str> = reg["model"]["operations"]
        .as_array()
        .expect("git model attached")
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert!(ops.contains(&"git-upload-pack"), "ops: {ops:?}");
    assert!(ops.contains(&"git-receive-pack"), "ops: {ops:?}");

    // Read-only git policy: allow only the fetch verb.
    let read_only = serde_json::json!({ "rules": [{ "effect": "Allow", "matches": {
        "targets": [], "resources": [], "conditions": [],
        "verbs": [{ "type": "Action", "value": { "id": "git-upload-pack" } }] } }] });
    let test = |service: &str| {
        serde_json::json!({
            "policy": read_only, "target": "github-git", "method": "GET",
            "path": "/acme/widgets.git/info/refs", "query": format!("service={service}"),
            "fields": {}
        })
    };

    let fetch: serde_json::Value = client
        .post(format!("{}/policy/test", h.admin_url))
        .json(&test("git-upload-pack"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetch["verdict"]["type"], "Allow");
    assert_eq!(fetch["action"]["resource"]["path"], "acme/widgets");

    let push: serde_json::Value = client
        .post(format!("{}/policy/test", h.admin_url))
        .json(&test("git-receive-pack"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(push["verdict"]["type"], "Deny");
}

/// `github-api` preset → imports the bundled GitHub OpenAPI inline and registers with a
/// non-zero op count, including a known op (`pulls/create`).
#[tokio::test]
async fn github_api_preset_imports_inline_openapi() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();
    register_credential(
        &h.admin_url,
        serde_json::json!({ "id": "gh-login", "source": { "kind": "static", "secret": "ghp_x" } }),
    )
    .await;

    let body = expand("github-api", DEFAULT_AWS_REGION, "gh-login");
    assert!(body["specInline"].as_str().unwrap().contains("\"openapi\""));

    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let reg: serde_json::Value = resp.json().await.unwrap();
    let ops = reg["model"]["operations"].as_array().expect("imported ops");
    assert!(!ops.is_empty(), "github-api imported a non-zero op count");
    let ids: std::collections::HashSet<&str> =
        ops.iter().filter_map(|o| o["id"].as_str()).collect();
    assert!(
        ids.contains("pulls/create"),
        "expected pulls/create among {} ops",
        ids.len()
    );

    // Listed with bearer outbound referencing the credential.
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
        .find(|s| s["name"] == "github-api")
        .expect("github-api listed");
    assert_eq!(svc["host"], "api.github.com");
    assert_eq!(svc["auth"], "bearer");
    assert_eq!(svc["credential"], "gh-login");
}

/// `aws:ec2` preset → imports the bundled EC2 Smithy model inline (`RunInstances` present) and
/// registers a `sigv4` outbound referencing a pre-registered AWS bundle.
#[tokio::test]
async fn aws_ec2_preset_imports_smithy_and_signs_with_sigv4() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();
    register_credential(
        &h.admin_url,
        serde_json::json!({
            "id": "aws-prod",
            "source": {
                "kind": "aws-static",
                "access_key_id": "AKIAEXAMPLE",
                "secret_access_key": "secret-key"
            }
        }),
    )
    .await;

    let body = expand("aws:ec2", DEFAULT_AWS_REGION, "aws-prod");
    assert_eq!(body["outbound"]["kind"], "sigv4");
    assert_eq!(body["outbound"]["service"], "ec2");
    assert_eq!(body["outbound"]["region"], "us-east-1");

    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let reg: serde_json::Value = resp.json().await.unwrap();
    // The EC2 Smithy model imported (ec2 protocol → query RPC), with RunInstances present.
    let ids: std::collections::HashSet<&str> = reg["model"]["operations"]
        .as_array()
        .expect("imported ops")
        .iter()
        .filter_map(|o| o["id"].as_str())
        .collect();
    assert!(
        ids.contains("RunInstances"),
        "expected RunInstances among {} ops",
        ids.len()
    );

    // The service lists a sigv4 outbound referencing the bundle by id.
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
        .find(|s| s["name"] == "aws-ec2")
        .expect("aws-ec2 listed");
    assert_eq!(svc["host"], "ec2.us-east-1.amazonaws.com");
    assert_eq!(svc["auth"], "sigv4");
    assert_eq!(svc["credential"], "aws-prod");
}
