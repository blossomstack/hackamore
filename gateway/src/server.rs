//! The HTTP data plane: an axum reverse proxy that drives [`Gateway`], plus a small
//! admin API for minting tokens.
//!
//! halter runs as a reverse proxy, not a transparent MITM: the agent is configured to
//! address halter directly and the sandbox (nono/Seatbelt/Landlock + netns) guarantees
//! halter is the *only* reachable destination, so the agent cannot bypass it. The agent
//! presents its halter token, never the real credential.
//!
//! By default the agent-facing listener is plaintext (the confined sandbox makes
//! interception a non-issue). When a deployment wants the consumer to terminate TLS at
//! halter and trust its certificate, [`serve`] takes an optional rustls config and the
//! proxy listener speaks HTTPS ([`serve_proxy_tls`]); the CA the consumer must trust rides
//! out in the provision doc as `halter_ca`. The admin API stays plaintext on its
//! localhost-only listener either way.

use crate::core::{ForwardPlan, Gateway, Outcome, ProxyRequest, Rejection};
use axum::Router;
use axum::body::Body;
use axum::extract::{Json, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::StatusCode;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use models::control::{MintRequest, RevokeRequest, RevokeResponse};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

/// Maximum request body halter will buffer (25 MiB). Larger requests are rejected.
const MAX_BODY: usize = 25 * 1024 * 1024;

/// How often the background sweeper reclaims expired token-table entries.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Shared state for both routers: the decision engine and the outbound HTTP client.
pub struct ServerState {
    gateway: Gateway,
    client: reqwest::Client,
}

impl ServerState {
    pub fn new(gateway: Gateway) -> Self {
        Self {
            gateway,
            client: reqwest::Client::new(),
        }
    }
}

/// The proxy router: every method and path is captured and run through the gateway.
pub fn proxy_router(state: Arc<ServerState>) -> Router {
    Router::new().fallback(proxy_handler).with_state(state)
}

/// The admin router: `POST /mint` issues a launch token for a submitted policy. Bind
/// this on a separate, localhost-only listener — it is operator/orchestrator surface,
/// not agent surface.
pub fn admin_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/mint", post(mint_handler))
        .route("/revoke", post(revoke_handler))
        .route("/provision", get(provision_handler))
        .with_state(state)
}

/// Serve both routers until shutdown: the proxy on `proxy_addr`, the admin API on
/// `admin_addr`. When `tls` is `Some`, the agent-facing proxy listener terminates TLS with
/// that rustls config (the consumer-trusts-halter's-cert model); the admin API always
/// stays plaintext on its localhost-only listener.
pub async fn serve(
    proxy_addr: std::net::SocketAddr,
    admin_addr: std::net::SocketAddr,
    gateway: Gateway,
    tls: Option<Arc<ServerConfig>>,
) -> std::io::Result<()> {
    let state = Arc::new(ServerState::new(gateway));
    let proxy_listener = tokio::net::TcpListener::bind(proxy_addr).await?;
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!(%proxy_addr, %admin_addr, proxy_scheme = scheme, "halter listening");

    spawn_sweeper(state.clone());

    let admin = axum::serve(admin_listener, admin_router(state.clone()));
    let proxy_app = proxy_router(state);
    match tls {
        Some(config) => {
            tokio::try_join!(
                serve_proxy_tls(proxy_listener, proxy_app, config),
                async move { admin.await }
            )?;
        }
        None => {
            let proxy = axum::serve(proxy_listener, proxy_app);
            tokio::try_join!(async move { proxy.await }, async move { admin.await })?;
        }
    }
    Ok(())
}

/// Serve `app` over TLS on `listener`: accept TCP, complete the rustls handshake, then drive
/// the connection with hyper's auto (HTTP/1+2) builder — `with_upgrades` so the
/// `Connection: Upgrade` relay (WebSocket/SPDY) still works under TLS. A failed handshake
/// drops that one connection; the accept loop continues. Public so the e2e harness can
/// drive a TLS proxy on an ephemeral listener.
pub async fn serve_proxy_tls(
    listener: tokio::net::TcpListener,
    app: Router,
    config: Arc<ServerConfig>,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("tls handshake failed: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            if let Err(e) = ConnBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!("tls connection error: {e}");
            }
        });
    }
}

/// Spawn the background token-table sweeper: every [`SWEEP_INTERVAL`] it evicts expired
/// entries so the table tracks live capacity, not all-time mint volume.
fn spawn_sweeper(state: Arc<ServerState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        // The immediate first tick is a no-op (empty table); skip straight to the cadence.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let reclaimed = state.gateway.sweep_expired();
            if reclaimed > 0 {
                tracing::debug!(reclaimed, "swept expired tokens");
            }
        }
    });
}

async fn proxy_handler(
    State(state): State<Arc<ServerState>>,
    request: axum::extract::Request,
) -> Response {
    let (mut parts, body) = request.into_parts();
    // Capture the pending client upgrade (and the hop-by-hop upgrade headers) before the
    // request is decomposed, so an allowed `kubectl exec`/`watch` can be tunneled.
    let upgrade = crate::upgrade::is_upgrade(&parts.headers);
    let on_upgrade = if upgrade {
        parts.extensions.remove::<hyper::upgrade::OnUpgrade>()
    } else {
        None
    };
    let original_headers = upgrade.then(|| parts.headers.clone());

    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    let proxy_req = ProxyRequest {
        method: parts.method,
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or_default().to_string(),
        headers: parts.headers,
        body,
    };
    match state.gateway.handle(proxy_req) {
        Outcome::Reject(rejection) => rejection_response(&rejection),
        Outcome::Forward(mut plan) => match (on_upgrade, original_headers) {
            // Allowed upgrade: re-add the hop-by-hop upgrade headers to the injected plan
            // and tunnel both ends.
            (Some(on_up), Some(orig)) => {
                crate::upgrade::carry_upgrade_headers(&orig, &mut plan.headers);
                crate::upgrade::tunnel(plan, on_up).await
            }
            _ => forward(&state.client, plan).await,
        },
    }
}

async fn mint_handler(
    State(state): State<Arc<ServerState>>,
    headers: http::HeaderMap,
    Json(req): Json<MintRequest>,
) -> Response {
    // No agent identity: a structurally valid policy mints a token. When tenants are
    // configured, the `X-Halter-Tenant` credential must own every target the policy names
    // (fail closed); single-trust-domain deployments leave tenancy unconfigured (open).
    let tenant = headers
        .get("x-halter-tenant")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty());
    match state
        .gateway
        .mint_checked(req.policy, req.ttl_seconds, tenant)
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => error_response(StatusCode::FORBIDDEN, &err.to_string()),
    }
}

/// `POST /revoke` — invalidate a token immediately, before its TTL. Operator/holder
/// surface on the admin listener; presenting the token is sufficient to revoke it.
async fn revoke_handler(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<RevokeRequest>,
) -> Response {
    let revoked = state.gateway.revoke(&req.token);
    (StatusCode::OK, Json(RevokeResponse { revoked })).into_response()
}

/// `GET /provision` — return the consumer-setup bundle for the presented halter token
/// (in `X-Halter-Token` or `Authorization`). The doc carries no real upstream secrets.
async fn provision_handler(
    State(state): State<Arc<ServerState>>,
    headers: http::HeaderMap,
) -> Response {
    let Some(token) = crate::core::token_from_headers(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "missing halter token");
    };
    match state.gateway.provision(&token) {
        Some(doc) => (StatusCode::OK, Json(doc)).into_response(),
        None => error_response(StatusCode::UNAUTHORIZED, "unknown or expired halter token"),
    }
}

/// Execute the planned upstream request and relay the response back to the agent.
///
/// The response body is **streamed**, never buffered, so Server-Sent Events, chunked
/// responses, and long-polls flow through halter transparently. (The request body is
/// buffered earlier because policy conditions may inspect it; responses have no such
/// need.)
async fn forward(client: &reqwest::Client, plan: ForwardPlan) -> Response {
    let mut builder = client.request(plan.method, &plan.url).headers(plan.headers);
    if !plan.body.is_empty() {
        builder = builder.body(plan.body);
    }
    let upstream = match builder.send().await {
        Ok(resp) => resp,
        Err(e) => return error_response(StatusCode::BAD_GATEWAY, &format!("upstream error: {e}")),
    };

    let status = upstream.status();
    let headers = filter_response_headers(upstream.headers());
    let body = Body::from_stream(upstream.bytes_stream());

    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// Copy upstream response headers, dropping hop-by-hop and length/encoding headers that
/// the server layer recomputes.
fn filter_response_headers(headers: &http::HeaderMap) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in headers {
        let n = name.as_str().to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "content-length"
                | "te"
                | "trailers"
                | "upgrade"
        ) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn rejection_response(rejection: &Rejection) -> Response {
    let body = serde_json::json!({
        "error": rejection.message,
        "reason": format!("{:?}", rejection.reason),
    })
    .to_string();
    (
        rejection.status,
        [(http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "error": message }).to_string();
    (
        status,
        [(http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}
