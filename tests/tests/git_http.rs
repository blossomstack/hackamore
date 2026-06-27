//! e2e for the `git-http` protocol: register a git-http service with `"protocol":
//! "git-http"` and no spec (the server auto-attaches the hardcoded git model), then dry-run
//! (`POST /policy/test`) shows a read-only git policy (allow the `git-upload-pack` verb)
//! **allows** a fetch and **denies** a push — and that the normalizer yields the
//! `{owner}/{repo}` resource and the literal named git verb under the same method+path,
//! distinguished only by the `?service=` query.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hackamore_tests::start_hackamore_services;

#[tokio::test]
async fn git_http_service_allows_fetch_and_denies_push() {
    let h = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    // Register a model-less git-http service (no idl, no source — just the protocol).
    let resp = client
        .post(format!("{}/admin/services", h.admin_url))
        .json(&serde_json::json!({
            "name": "github-git",
            "host": "github.com",
            "upstreamBase": "https://github.com",
            "protocol": "git-http",
            "outbound": { "kind": "basic", "username": "x-access-token", "secret": "ghp_realtoken" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    // A git-http service registered with no model gets the hardcoded git model auto-attached
    // (its two ops) so lint / discovery / the studio have vocabulary to enumerate.
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "github-git");
    let ops: Vec<&str> = body["model"]["operations"]
        .as_array()
        .expect("git model auto-attached")
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert_eq!(ops, ["git-upload-pack", "git-receive-pack"]);

    // A read-only git policy: allow only the fetch verb (git-upload-pack).
    let read_only = serde_json::json!({ "rules": [{ "effect": "Allow", "matches": {
        "targets": [], "resources": [], "conditions": [],
        "verbs": [{ "type": "Action", "value": { "id": "git-upload-pack" } }] } }] });

    // Both requests are GET …/info/refs on the same path; only `?service=` differs.
    let test = |service: &str| {
        serde_json::json!({
            "policy": read_only, "target": "github-git", "method": "GET",
            "path": "/acme/widgets.git/info/refs", "query": format!("service={service}"),
            "fields": {}
        })
    };

    // Fetch is allowed; normalize yields the named git verb and the {owner}/{repo} resource.
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
    assert_eq!(fetch["action"]["verb"]["type"], "Action");
    assert_eq!(fetch["action"]["verb"]["value"]["id"], "git-upload-pack");

    // Push (same method+path, different ?service=) is denied — the read-only policy lists
    // only the fetch verb.
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
    assert_eq!(push["action"]["resource"]["path"], "acme/widgets");
    assert_eq!(push["action"]["verb"]["value"]["id"], "git-receive-pack");
}
