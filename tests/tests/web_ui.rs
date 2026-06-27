//! e2e for the admin web-UI surface: the embedded SPA loads, `GET /admin/services` lists
//! the configured services, `POST /policy/lint` and `POST /policy/test` round-trip, and a
//! request with a non-matching path dry-runs to a default-deny.

use hackamore_gateway::{Outbound, Service};
use hackamore_tests::{start_hackamore_services, start_hackamore_services_opts};

fn github_and_openai() -> Vec<Service> {
    vec![
        Service::new("github", "api.github.com", "https://api.github.com").with_outbound(
            Outbound::Bearer {
                credential: "github-app".into(),
            },
        ),
        Service::new("openai", "api.openai.com", "https://api.openai.com"),
    ]
}

#[tokio::test]
async fn ui_assets_and_services_endpoint() {
    let h = start_hackamore_services(github_and_openai()).await;
    let client = reqwest::Client::new();

    let ui = client
        .get(format!("{}/ui", h.admin_url))
        .send()
        .await
        .unwrap();
    assert!(ui.status().is_success());
    let html = ui.text().await.unwrap();
    assert!(html.contains("policy studio"));
    assert!(html.contains("/ui/app.js"));

    let js = client
        .get(format!("{}/ui/app.js", h.admin_url))
        .send()
        .await
        .unwrap();
    assert!(js.status().is_success());

    // The studio's target dropdown and Server view read the live registry.
    let services: serde_json::Value = client
        .get(format!("{}/admin/services", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let services = services.as_array().unwrap();
    assert_eq!(services.len(), 2);
    // Each service is projected with its outbound auth stance: the credential *id* it
    // injects (never the secret) and a human auth label.
    let github = services
        .iter()
        .find(|s| s["name"] == "github")
        .expect("github service listed");
    assert_eq!(github["auth"], "bearer");
    assert_eq!(github["credential"], "github-app");
    let openai = services
        .iter()
        .find(|s| s["name"] == "openai")
        .expect("openai service listed");
    assert_eq!(openai["auth"], "passthrough");
    assert_eq!(openai["credential"], ""); // passthrough injects no vault credential
}

#[tokio::test]
async fn lint_and_test_endpoints_round_trip() {
    let h = start_hackamore_services(github_and_openai()).await;
    let client = reqwest::Client::new();

    // Lint flags an unmatchable glob.
    let findings: serde_json::Value = client
        .post(format!("{}/policy/lint", h.admin_url))
        .json(&serde_json::json!({
            "rules": [{ "effect": "Allow", "matches": {
                "targets": [], "verbs": [], "resources": ["/leading"], "conditions": [] } }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        findings
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["severity"] == "Error")
    );

    // Test: a read-only policy allows a GET and denies a DELETE on the same path.
    let read_only = serde_json::json!({
        "rules": [{ "effect": "Allow", "matches": {
            "targets": [], "resources": [], "conditions": [],
            "verbs": [{ "type": "Method", "value": { "method": "GET" } }] } }]
    });
    let body = |method: &str| {
        serde_json::json!({
            "policy": read_only, "target": "github", "method": method,
            "path": "/repos/o/r", "query": "", "fields": {}
        })
    };

    let allow: serde_json::Value = client
        .post(format!("{}/policy/test", h.admin_url))
        .json(&body("GET"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(allow["verdict"]["type"], "Allow");
    assert_eq!(allow["matched"]["type"], "Rule");
    // Generic normalization: the resource is the canonical path.
    assert_eq!(allow["action"]["resource"]["path"], "repos/o/r");

    let deny: serde_json::Value = client
        .post(format!("{}/policy/test", h.admin_url))
        .json(&body("DELETE"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deny["verdict"]["type"], "Deny");
    assert_eq!(deny["matched"]["type"], "NoMatch");
}

#[tokio::test]
async fn ui_and_endpoints_are_404_when_disabled() {
    let h = start_hackamore_services_opts(github_and_openai(), false).await;
    let client = reqwest::Client::new();
    for (method, path) in [("GET", "/ui")] {
        let resp = client
            .request(method.parse().unwrap(), format!("{}{}", h.admin_url, path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND, "{path}");
    }
    // Mint still works with the UI off — it is not part of the authoring surface.
    let resp = client
        .post(format!("{}/policy/lint", h.admin_url))
        .json(&serde_json::json!({ "rules": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_endpoint_rejects_unknown_target() {
    let h = start_hackamore_services(github_and_openai()).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/policy/test", h.admin_url))
        .json(&serde_json::json!({
            "policy": { "rules": [] }, "target": "nope", "method": "GET",
            "path": "/x", "query": "", "fields": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}
