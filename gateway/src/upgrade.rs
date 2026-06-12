//! HTTP `Upgrade` relay — the transport that lets `kubectl exec` / `port-forward` /
//! `logs -f` / `watch` (WebSocket / SPDY) work through hackamore.
//!
//! A normal request is decided, the credential injected, and the response *streamed*
//! ([`crate::server::forward`]). An upgrade is different: after the policy allows it, hackamore
//! must open its own connection to the upstream, replay the upgrade, and — once both ends
//! return `101 Switching Protocols` — tunnel raw bytes in both directions for the life of
//! the connection. The policy decision still happens first on the normalized request, so an
//! `exec` into a disallowed namespace is denied before any tunnel is built.
//!
//! Upgrade/`Connection`/`Sec-WebSocket-*` headers are hop-by-hop and are normally stripped;
//! [`carry_upgrade_headers`] re-adds them to the (credential-injected) forward plan because
//! hackamore is the next hop establishing the upgrade with the upstream.

use crate::core::ForwardPlan;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

/// Hop-by-hop headers an upgrade needs forwarded to the upstream (hackamore is the next hop).
const UPGRADE_HEADERS: [&str; 6] = [
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
];

/// Whether `headers` describe an HTTP Upgrade request (`Connection: Upgrade` + an
/// `Upgrade:` token). Token match is case-insensitive and tolerant of a header list.
pub fn is_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        });
    connection_upgrade && headers.contains_key(http::header::UPGRADE)
}

/// Copy the upgrade hop-by-hop headers from the original request into the forward plan's
/// (sanitized, credential-injected) header set, so the upstream sees a complete upgrade.
pub fn carry_upgrade_headers(original: &HeaderMap, plan: &mut HeaderMap) {
    for name in UPGRADE_HEADERS {
        if let Some(value) = original.get(name)
            && let Ok(hn) = http::HeaderName::from_bytes(name.as_bytes())
        {
            plan.insert(hn, value.clone());
        }
    }
}

/// Relay an allowed upgrade: connect to the upstream, replay the request, and on `101`
/// tunnel bytes both ways between the client and the upstream. A non-101 upstream response
/// is relayed back verbatim (no tunnel). `client_on_upgrade` is the client connection's
/// pending upgrade, taken from the inbound request's extensions.
pub async fn tunnel(plan: ForwardPlan, client_on_upgrade: OnUpgrade) -> Response {
    let Some(target) = UpstreamTarget::parse(&plan.url) else {
        return bad("invalid upstream url for upgrade");
    };
    let mut sender = match connect(&target).await {
        Ok(s) => s,
        Err(e) => return bad(&format!("upstream connect failed: {e}")),
    };

    let req = match build_request(&plan, &target) {
        Ok(r) => r,
        Err(e) => return bad(&e),
    };
    let upstream_resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => return bad(&format!("upstream upgrade request failed: {e}")),
    };

    if upstream_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Upstream declined the upgrade — relay its response as an ordinary one.
        let status = upstream_resp.status();
        let headers = upstream_resp.headers().clone();
        let mut response = Response::new(axum::body::Body::new(upstream_resp.into_body()));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return response;
    }

    // Both sides will switch protocols. Capture the upstream upgrade and the 101 headers,
    // then splice the two upgraded streams together for the life of the connection.
    let status = upstream_resp.status();
    let headers = upstream_resp.headers().clone();
    let upstream_on_upgrade = hyper::upgrade::on(upstream_resp);
    tokio::spawn(async move {
        match tokio::try_join!(client_on_upgrade, upstream_on_upgrade) {
            Ok((client, upstream)) => {
                let mut client = TokioIo::new(client);
                let mut upstream = TokioIo::new(upstream);
                if let Err(e) = copy_bidirectional(&mut client, &mut upstream).await {
                    tracing::debug!("upgrade tunnel closed: {e}");
                }
            }
            Err(e) => tracing::debug!("upgrade handshake failed: {e}"),
        }
    });

    // Hand the client its 101 with the upstream's switching headers; once it is written, the
    // client's `OnUpgrade` resolves and the spawned tunnel begins.
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// A parsed upstream URL: where to connect and what to put on the request line.
struct UpstreamTarget {
    tls: bool,
    host: String,
    port: u16,
    path_and_query: String,
}

impl UpstreamTarget {
    fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let tls = match scheme {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), if tls { 443 } else { 80 }),
        };
        Some(Self {
            tls,
            host,
            port,
            path_and_query: if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            },
        })
    }

    fn authority(&self) -> String {
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// An HTTP/1 request sender over the upstream connection, with the connection task driving
/// upgrades in the background.
type Sender = hyper::client::conn::http1::SendRequest<axum::body::Body>;

/// Open an HTTP/1 connection to the upstream (TLS when `https`) and spawn its connection
/// task with upgrades enabled.
async fn connect(target: &UpstreamTarget) -> Result<Sender, String> {
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| e.to_string())?;
    if target.tls {
        let connector = TlsConnector::from(tls_client_config());
        let server_name = ServerName::try_from(target.host.clone())
            .map_err(|_| "invalid upstream server name".to_string())?;
        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        handshake(TokioIo::new(stream)).await
    } else {
        handshake(TokioIo::new(tcp)).await
    }
}

async fn handshake<I>(io: I) -> Result<Sender, String>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| e.to_string())?;
    // The connection future must be polled for the request/response and the upgrade to
    // progress; `with_upgrades` keeps the socket alive after the 101 for the tunnel.
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!("upstream upgrade connection ended: {e}");
        }
    });
    Ok(sender)
}

/// Build the upstream upgrade request (origin-form URI, explicit `Host`, empty body).
fn build_request(
    plan: &ForwardPlan,
    target: &UpstreamTarget,
) -> Result<http::Request<axum::body::Body>, String> {
    let mut builder = http::Request::builder()
        .method(plan.method.clone())
        .uri(&target.path_and_query);
    for (name, value) in &plan.headers {
        builder = builder.header(name, value);
    }
    // http/1 client conn needs an explicit Host (the inbound one was stripped).
    builder = builder.header(http::header::HOST, target.authority());
    builder
        .body(axum::body::Body::empty())
        .map_err(|e| e.to_string())
}

/// A rustls client config trusting the webpki root set, built once and shared.
// `with_safe_default_protocol_versions` returns a `Result` only to surface a misconfigured
// provider; with the ring provider and the built-in default versions it is infallible, so
// the localized `expect` cannot fire in practice.
#[allow(clippy::expect_used)]
fn tls_client_config() -> Arc<ClientConfig> {
    use std::sync::OnceLock;
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring provider supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

fn bad(message: &str) -> Response {
    (StatusCode::BAD_GATEWAY, message.to_string()).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn detects_upgrade_requests() {
        assert!(is_upgrade(&headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket")
        ])));
        // Header lists and casing are tolerated.
        assert!(is_upgrade(&headers(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket")
        ])));
        // Missing either half → not an upgrade.
        assert!(!is_upgrade(&headers(&[("upgrade", "websocket")])));
        assert!(!is_upgrade(&headers(&[("connection", "upgrade")])));
        assert!(!is_upgrade(&headers(&[("connection", "keep-alive")])));
    }

    #[test]
    fn carry_upgrade_headers_copies_hop_by_hop_set() {
        let original = headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-key", "abc"),
            ("x-other", "ignored"),
        ]);
        let mut plan = headers(&[("authorization", "Bearer real")]);
        carry_upgrade_headers(&original, &mut plan);
        assert_eq!(plan.get("upgrade").unwrap(), "websocket");
        assert_eq!(plan.get("connection").unwrap(), "Upgrade");
        assert_eq!(plan.get("sec-websocket-key").unwrap(), "abc");
        // The injected credential is retained; unrelated headers aren't copied here.
        assert_eq!(plan.get("authorization").unwrap(), "Bearer real");
        assert!(plan.get("x-other").is_none());
    }

    #[test]
    fn parses_upstream_targets() {
        let t = UpstreamTarget::parse("https://api.k8s.example/api/v1/x?watch=1").unwrap();
        assert!(t.tls);
        assert_eq!(t.host, "api.k8s.example");
        assert_eq!(t.port, 443);
        assert_eq!(t.path_and_query, "/api/v1/x?watch=1");
        assert_eq!(t.authority(), "api.k8s.example");

        let t = UpstreamTarget::parse("http://127.0.0.1:8080/exec").unwrap();
        assert!(!t.tls);
        assert_eq!(t.port, 8080);
        assert_eq!(t.authority(), "127.0.0.1:8080");

        assert!(UpstreamTarget::parse("ftp://nope").is_none());
    }
}
