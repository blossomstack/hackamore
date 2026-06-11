//! Full-stack e2e tests: a real halter server (reverse proxy + admin API) in front of a
//! mock GitHub upstream, driven over HTTP exactly as a sandboxed agent's `gh`/`git`
//! would drive it. Each test asserts one user story end to end.

use models::policy::Policy;
use tests::{start_halter, start_mock_upstream};

fn policy_from(json: &str) -> Policy {
    serde_json::from_str(json).expect("valid policy json")
}

/// Allow only reads. The target's credential is injected by the service config, not the
/// policy. (`verb` is the open tagged union — a CRUD verb here.)
const READ_ONLY: &str = r#"{
    "rules": [
        { "effect": "Allow",
          "matches": {
              "targets": [],
              "verbs": [ { "type": "Crud", "value": { "kind": "Read" } } ],
              "resources": [], "conditions": []
          } }
    ]
}"#;

/// Allow opening PRs only against base branch "develop".
const PR_TO_DEVELOP_ONLY: &str = r#"{
    "rules": [
        { "effect": "Allow",
          "matches": {
              "targets": [],
              "verbs": [ { "type": "Crud", "value": { "kind": "Create" } } ],
              "resources": ["repos/*/*/pulls"],
              "conditions": [ { "type": "Equals", "value": { "field": "base", "value": "develop" } } ]
          } }
    ]
}"#;

/// User story: finer-than-native control — PRs allowed only against an approved base.
/// (Basic read-inject and denied-write are covered by `use_cases::github_use_case`; this
/// keeps the body-condition gating that the use-case suite doesn't exercise.)
#[tokio::test]
async fn pr_create_gated_by_base_branch() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter
        .mint_token(&policy_from(PR_TO_DEVELOP_ONLY), 3600)
        .await;
    let client = reqwest::Client::new();

    // Allowed: base = develop.
    let ok = client
        .post(format!("{}/repos/octocat/hello/pulls", halter.proxy_url))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "base": "develop", "title": "feature" }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Denied: base = main.
    let denied = client
        .post(format!("{}/repos/octocat/hello/pulls", halter.proxy_url))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "base": "main", "title": "sneaky" }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    // Only the allowed PR was forwarded.
    let got = upstream.requests();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].method, "POST");
    assert_eq!(got[0].path, "/repos/octocat/hello/pulls");
}

/// Allow reads only under octocat's repos. The canonicalizer must stop a disguised path
/// from escaping this scope.
const OCTOCAT_READS: &str = r#"{
    "rules": [
        { "effect": "Allow",
          "matches": {
              "targets": [], "conditions": [],
              "verbs": [ { "type": "Crud", "value": { "kind": "Read" } } ],
              "resources": ["repos/octocat/**"]
          } }
    ]
}"#;

/// User story: a path that *spells* its way out of scope (`..`, encoded dots) is folded to
/// its canonical form before the policy decision, so it cannot evade a resource glob.
#[tokio::test]
async fn path_traversal_cannot_escape_resource_scope() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter.mint_token(&policy_from(OCTOCAT_READS), 3600).await;
    let client = reqwest::Client::new();

    // In-scope read is allowed and forwarded.
    let ok = client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // `..` traversal out of octocat's repos → canonicalizes to /repos/evil/secret → denied.
    let traversal = client
        .get(format!("{}/repos/octocat/../evil/secret", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(traversal.status(), 403);

    // Percent-encoded dots are decoded first, so this is the same escape → denied.
    let encoded = client
        .get(format!(
            "{}/repos/octocat/%2e%2e/evil/secret",
            halter.proxy_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(encoded.status(), 403);

    // Only the one in-scope read reached the upstream.
    assert_eq!(upstream.requests().len(), 1);
}

/// User story: an unauthenticated or invalid token is rejected before any forwarding.
#[tokio::test]
async fn missing_or_invalid_token_is_unauthorized() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let client = reqwest::Client::new();

    let no_auth = client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .send()
        .await
        .unwrap();
    assert_eq!(no_auth.status(), 401);

    let bad_auth = client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth("not-a-real-token")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_auth.status(), 401);

    assert!(!upstream.was_called());
}

/// User story: a token can be revoked before its TTL, and immediately stops working.
#[tokio::test]
async fn revoked_token_is_rejected() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter.mint_token(&policy_from(READ_ONLY), 3600).await;
    let client = reqwest::Client::new();

    // Works before revocation.
    let ok = client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Revoke via the admin API.
    let revoke = client
        .post(format!("{}/revoke", halter.admin_url))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 200);
    assert_eq!(
        revoke.json::<serde_json::Value>().await.unwrap()["revoked"],
        true
    );

    // The same token is now unauthorized.
    let after = client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), 401);

    // Revoking an unknown token reports `revoked: false`.
    let again = client
        .post(format!("{}/revoke", halter.admin_url))
        .json(&serde_json::json!({ "token": "never-existed" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        again.json::<serde_json::Value>().await.unwrap()["revoked"],
        false
    );

    // Only the pre-revocation read reached the upstream.
    assert_eq!(upstream.requests().len(), 1);
}

/// User story: with tenants configured, a tenant may only mint tokens for targets it owns.
#[tokio::test]
async fn tenant_mint_is_scoped_to_owned_targets() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    // The single catch-all service is named "github"; tenant-a owns only it.
    halter
        .control
        .tenants
        .insert("tenant-a", ["github".to_string()]);
    let client = reqwest::Client::new();

    let mint = |tenant: Option<&str>, target: &str| {
        let body = serde_json::json!({
            "policy": { "rules": [ { "effect": "Allow", "matches": {
                "targets": [target], "verbs": [], "resources": [], "conditions": [] } } ] },
            "ttlSeconds": 60,
        });
        let mut r = client
            .post(format!("{}/mint", halter.admin_url))
            .json(&body);
        if let Some(t) = tenant {
            r = r.header("X-Halter-Tenant", t);
        }
        r.send()
    };

    // Owned target → 200.
    assert_eq!(
        mint(Some("tenant-a"), "github").await.unwrap().status(),
        200
    );
    // Unowned target → 403.
    assert_eq!(
        mint(Some("tenant-a"), "openai").await.unwrap().status(),
        403
    );
    // Missing tenant credential (tenants configured) → 403.
    assert_eq!(mint(None, "github").await.unwrap().status(), 403);
    // Unknown tenant → 403.
    assert_eq!(mint(Some("ghost"), "github").await.unwrap().status(), 403);
}

/// User story: a consumer fetches its setup bundle from `/provision` with its token.
#[tokio::test]
async fn provision_returns_setup_bundle() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter.mint_token(&policy_from(READ_ONLY), 3600).await;

    let resp = reqwest::Client::new()
        .get(format!("{}/provision", halter.admin_url))
        .header("X-Halter-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let doc: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(doc["halterToken"], token);
    // The github service (allow-all-targets policy) is surfaced, in inject mode, and no
    // real secret leaks into the doc.
    let services = doc["services"].as_array().unwrap();
    assert!(services.iter().any(|s| s["target"] == "github"));
    assert!(!resp_text_contains(&doc, "real-secret-token"));

    // No token → 401.
    let unauth = reqwest::Client::new()
        .get(format!("{}/provision", halter.admin_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);
}

fn resp_text_contains(doc: &serde_json::Value, needle: &str) -> bool {
    doc.to_string().contains(needle)
}

/// User story: any structurally valid policy mints a token (no agent identity).
#[tokio::test]
async fn admin_mint_accepts_any_valid_policy() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    let resp = halter.mint(&policy_from(READ_ONLY), 3600).await;
    assert!(resp.status().is_success());
    let value: serde_json::Value = resp.json().await.unwrap();
    assert!(value["token"].as_str().is_some());
}

/// User story: every decision is journaled — allow and deny alike.
#[tokio::test]
async fn decisions_are_audited() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter(&upstream.base_url).await;
    halter.add_credential("github-app", "real-secret-token");
    let token = halter.mint_token(&policy_from(READ_ONLY), 3600).await;
    let client = reqwest::Client::new();

    client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    client
        .delete(format!("{}/repos/octocat/hello", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    let events = halter.audit.events();
    assert_eq!(events.len(), 2, "one audit record per decision");
    assert_eq!(events[0].decision, models::audit::Decision::Allow);
    assert_eq!(events[1].decision, models::audit::Decision::Deny);
}
