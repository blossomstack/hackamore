//! Integration test for the GitHub-App credential provider's HTTP exchange: a mock GitHub
//! `access_tokens` endpoint stands in for api.github.com, and we assert the provider signs
//! an app JWT, presents it, and returns the minted installation token. (The EKS presigner,
//! the JWT signing, and the caching/rotation logic are unit-tested in `hackamore_control::providers`.)

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use hackamore_control::{CredentialProvider, GitHubAppProvider, pkcs8_from_pem};
use std::sync::{Arc, Mutex};

/// The bearer JWT the mock received, captured so the test can assert the provider presented
/// a well-formed app token.
#[derive(Default)]
struct Captured {
    authorization: Mutex<Option<String>>,
}

async fn access_tokens(
    State(captured): State<Arc<Captured>>,
    Path(installation_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    *captured.authorization.lock().unwrap() = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    Json(serde_json::json!({
        "token": format!("ghs_installation_token_for_{installation_id}"),
        "expires_at": "2099-01-01T00:00:00Z",
    }))
}

#[tokio::test]
async fn github_app_provider_mints_installation_token() {
    let captured = Arc::new(Captured::default());
    let app = Router::new()
        .route(
            "/app/installations/:installation_id/access_tokens",
            post(access_tokens),
        )
        .with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let pem = include_str!("../../control/testdata/github_app_key.pem");
    let provider = GitHubAppProvider {
        app_id: "123456".into(),
        installation_id: "789".into(),
        private_key_pkcs8_der: pkcs8_from_pem(pem).unwrap(),
        api_base: base,
        client: reqwest::Client::new(),
    };

    let now = 1_700_000_000_000;
    let minted = provider.mint(now).await.expect("mint succeeds");
    assert_eq!(
        minted.secret.expose(),
        "ghs_installation_token_for_789",
        "the installation token from the exchange is the minted secret"
    );
    assert!(minted.expires_at_ms > now);

    // The provider presented a Bearer app JWT (header.claims.signature).
    let auth = captured.authorization.lock().unwrap().clone().unwrap();
    let jwt = auth.strip_prefix("Bearer ").expect("bearer scheme");
    assert_eq!(jwt.split('.').count(), 3, "a three-part JWT");
}
