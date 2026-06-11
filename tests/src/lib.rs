//! Test harness for halter's full-stack e2e tests: a mock GitHub upstream that records
//! what it receives, and a live halter server (reverse proxy + admin API) wired to it.
//!
//! Not a production crate — helpers `unwrap` freely and this crate intentionally does
//! not enable the workspace restriction lints.

use axum::Router;
use axum::extract::State;
use control::{ControlPlane, InMemoryAudit, InMemoryCredentials, Secret};
use gateway::{Flavor, Gateway, Outbound, ServerState, Service, ServiceRouter};
use models::policy::Policy;
use std::sync::{Arc, Mutex};

/// One request the mock upstream received.
#[derive(Clone, Debug)]
pub struct Received {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

/// A mock GitHub API that records every request and returns a fixed JSON body.
pub struct MockUpstream {
    pub base_url: String,
    requests: Arc<Mutex<Vec<Received>>>,
}

impl MockUpstream {
    /// Snapshot of all requests the upstream has received.
    pub fn requests(&self) -> Vec<Received> {
        self.requests.lock().unwrap().clone()
    }

    /// Whether the upstream was ever contacted.
    pub fn was_called(&self) -> bool {
        !self.requests.lock().unwrap().is_empty()
    }
}

/// Start the mock upstream on an ephemeral port.
pub async fn start_mock_upstream() -> MockUpstream {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(record_handler)
        .with_state(requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    MockUpstream { base_url, requests }
}

async fn record_handler(
    State(requests): State<Arc<Mutex<Vec<Received>>>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let (mut parts, body) = request.into_parts();

    // Upgrade branch: echo bytes back over the upgraded connection, so tests can verify
    // halter tunnels `Connection: Upgrade` (WebSocket/SPDY: kubectl exec/port-forward) end
    // to end. We record the request, return 101, and splice the upgraded stream to itself.
    let is_upgrade = parts
        .headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        && parts.headers.contains_key(http::header::UPGRADE);
    if is_upgrade {
        requests.lock().unwrap().push(Received {
            method: parts.method.to_string(),
            path: parts.uri.path().to_string(),
            authorization: parts
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            body: Vec::new(),
        });
        if let Some(on_upgrade) = parts.extensions.remove::<hyper::upgrade::OnUpgrade>() {
            tokio::spawn(async move {
                if let Ok(upgraded) = on_upgrade.await {
                    let io = hyper_util::rt::TokioIo::new(upgraded);
                    let (mut r, mut w) = tokio::io::split(io);
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                }
            });
        }
        return axum::response::Response::builder()
            .status(101)
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::CONNECTION, "Upgrade")
            .body(axum::body::Body::empty())
            .unwrap();
    }

    let body = axum::body::to_bytes(body, 25 * 1024 * 1024)
        .await
        .unwrap_or_default();
    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    requests.lock().unwrap().push(Received {
        method: parts.method.to_string(),
        path: parts.uri.path().to_string(),
        authorization,
        body: body.to_vec(),
    });
    // SSE branch: any path containing "stream" returns a Server-Sent Events body, so
    // tests can verify halter relays event streams (transport) end to end.
    if parts.uri.path().contains("stream") {
        let events = "data: one\n\ndata: two\n\ndata: three\n\n";
        return axum::response::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .body(axum::body::Body::from(events))
            .unwrap();
    }

    let payload = serde_json::json!({ "ok": true, "path": parts.uri.path() }).to_string();
    axum::response::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(payload))
        .unwrap()
}

/// A live halter server plus handles to seed and inspect its control plane.
pub struct Harness {
    pub control: Arc<ControlPlane>,
    pub audit: Arc<InMemoryAudit>,
    pub credentials: Arc<InMemoryCredentials>,
    pub proxy_url: String,
    pub admin_url: String,
}

impl Harness {
    /// Seed a credential into the vault.
    pub fn add_credential(&self, id: &str, secret: &str) {
        self.credentials.insert(id, Secret::new(secret));
    }

    /// Mint a launch token bound to `policy` via the admin API (exercising that endpoint
    /// too).
    pub async fn mint(&self, policy: &Policy, ttl_seconds: u64) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/mint", self.admin_url))
            .json(&serde_json::json!({ "policy": policy, "ttlSeconds": ttl_seconds }))
            .send()
            .await
            .unwrap()
    }

    /// Mint and return just the token string (asserts success).
    pub async fn mint_token(&self, policy: &Policy, ttl_seconds: u64) -> String {
        let resp = self.mint(policy, ttl_seconds).await;
        assert!(resp.status().is_success(), "mint failed: {}", resp.status());
        let value: serde_json::Value = resp.json().await.unwrap();
        value["token"].as_str().unwrap().to_string()
    }
}

/// Start a halter server with a single catch-all GitHub-flavored service pointing at
/// `upstream_base` (the common case for most tests).
pub async fn start_halter(upstream_base: &str) -> Harness {
    start_halter_services(vec![
        Service::new("github", "*", upstream_base)
            .with_flavor(Flavor::Github)
            .with_outbound(Outbound::Bearer {
                credential: "github-app".to_string(),
            }),
    ])
    .await
}

/// Start a halter server whose agent-facing proxy terminates TLS with `tls`, on ephemeral
/// ports. The provision doc carries `tls.ca_pem` as `halter_ca`; the admin API stays
/// plaintext. The returned `proxy_url` is `https://…`.
pub async fn start_halter_tls_services(
    services: Vec<Service>,
    tls: gateway::TlsMaterial,
) -> Harness {
    let credentials = Arc::new(InMemoryCredentials::new());
    let audit = Arc::new(InMemoryAudit::new());
    let control = Arc::new(ControlPlane::new(credentials.clone(), audit.clone()));
    let config = tls.server_config().expect("valid tls material");
    let gateway = Gateway::new(control.clone(), ServiceRouter::new(services)).with_ca(tls.ca_pem);
    let state = Arc::new(ServerState::new(gateway));

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("https://{}", proxy_listener.local_addr().unwrap());
    let admin_url = format!("http://{}", admin_listener.local_addr().unwrap());

    let proxy_state = state.clone();
    tokio::spawn(async move {
        let _ = gateway::server::serve_proxy_tls(
            proxy_listener,
            gateway::proxy_router(proxy_state),
            config,
        )
        .await;
    });
    tokio::spawn(async move {
        let _ = axum::serve(admin_listener, gateway::admin_router(state)).await;
    });

    Harness {
        control,
        audit,
        credentials,
        proxy_url,
        admin_url,
    }
}

/// Start a halter server with an explicit service allowlist, on ephemeral ports.
pub async fn start_halter_services(services: Vec<Service>) -> Harness {
    let credentials = Arc::new(InMemoryCredentials::new());
    let audit = Arc::new(InMemoryAudit::new());
    let control = Arc::new(ControlPlane::new(credentials.clone(), audit.clone()));
    let gateway = Gateway::new(control.clone(), ServiceRouter::new(services));
    let state = Arc::new(ServerState::new(gateway));

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy_listener.local_addr().unwrap());
    let admin_url = format!("http://{}", admin_listener.local_addr().unwrap());

    let proxy_state = state.clone();
    tokio::spawn(async move {
        let _ = axum::serve(proxy_listener, gateway::proxy_router(proxy_state)).await;
    });
    tokio::spawn(async move {
        let _ = axum::serve(admin_listener, gateway::admin_router(state)).await;
    });

    Harness {
        control,
        audit,
        credentials,
        proxy_url,
        admin_url,
    }
}
