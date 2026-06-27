//! e2e: the admin `/mint` endpoint lints policies — structural Error findings (e.g. an
//! unreachable rule) reject with structured findings in the body, warnings alone still
//! mint.

use hackamore_gateway::{Outbound, Service};
use hackamore_models::policy::Policy;
use hackamore_tests::{start_hackamore_services, start_mock_upstream};

fn policy(json: &str) -> Policy {
    serde_json::from_str(json).expect("valid policy json")
}

#[tokio::test]
async fn mint_rejects_lint_errors_with_findings() {
    let upstream = start_mock_upstream().await;
    let hackamore = start_hackamore_services(vec![
        Service::new("github", "*", &upstream.base_url).with_outbound(Outbound::Bearer {
            credential: "github-app".into(),
        }),
    ])
    .await;

    // Rule 1 is unreachable: rule 0 allows everything it would deny.
    let shadowed = policy(
        r#"{ "rules": [
            { "effect": "Allow", "matches": { "targets": [], "verbs": [], "resources": [], "conditions": [] } },
            { "effect": "Deny", "matches": { "targets": [], "verbs": [], "resources": ["/leading/slash"], "conditions": [] } }
        ] }"#,
    );
    let resp = hackamore.mint(&shadowed, 3600).await;
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"], "policy failed lint");
    let findings = body["findings"].as_array().expect("findings array");
    assert!(findings.iter().any(|f| f["severity"] == "Error"), "{body}");

    // The reviewer-bot example policy (warnings at most) still mints.
    let example = policy(include_str!("../../examples/policy.reviewer-bot.json"));
    let token = hackamore.mint_token(&example, 3600).await;
    assert!(!token.is_empty());
}
