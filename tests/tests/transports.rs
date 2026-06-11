//! e2e tests for transport + routing capabilities that the per-use-case suite doesn't
//! exercise: SSE streaming relay and fail-closed Host routing. (Per-service injection and
//! AWS-query action gating live in `use_cases.rs`.)

use gateway::{Flavor, Outbound, Service};
use models::policy::Policy;
use tests::{start_halter_services, start_halter_tls_services, start_mock_upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn allow_all() -> Policy {
    serde_json::from_str(
        r#"{ "rules": [ { "effect": "Allow",
            "matches": { "targets": [], "verbs": [], "resources": [], "conditions": [] } } ] }"#,
    )
    .expect("valid policy")
}

fn service(name: &str, host: &str, flavor: Flavor, credential: &str, upstream: &str) -> Service {
    Service::new(name, host, upstream)
        .with_flavor(flavor)
        .with_outbound(Outbound::Bearer {
            credential: credential.into(),
        })
}

/// SSE transport: an event-stream response is relayed through halter with its
/// `text/event-stream` content type and full payload intact.
#[tokio::test]
async fn sse_stream_is_relayed() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![service(
        "events",
        "*",
        Flavor::Generic,
        "svc-key",
        &upstream.base_url,
    )])
    .await;
    halter.add_credential("svc-key", "real");
    let token = halter.mint_token(&allow_all(), 3600).await;

    let resp = reqwest::Client::new()
        .get(format!("{}/v1/stream", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("data: one"));
    assert!(body.contains("data: three"));
}

/// TLS termination: when halter is configured with a serving cert, the agent-facing proxy
/// speaks HTTPS, a consumer that trusts the CA can drive a request through it end to end,
/// and the provision doc carries that CA as `halter_ca`.
#[tokio::test]
async fn tls_terminated_proxy_serves_https_and_publishes_ca() {
    let upstream = start_mock_upstream().await;
    let ca = include_str!("../../gateway/testdata/tls_ca.pem");
    let tls = gateway::TlsMaterial {
        cert_pem: include_str!("../../gateway/testdata/tls_cert.pem").to_string(),
        key_pem: include_str!("../../gateway/testdata/tls_key.pem").to_string(),
        ca_pem: ca.to_string(),
    };
    let halter = start_halter_tls_services(
        vec![service(
            "svc",
            "*",
            Flavor::Generic,
            "svc-key",
            &upstream.base_url,
        )],
        tls,
    )
    .await;
    halter.add_credential("svc-key", "real");
    let token = halter.mint_token(&allow_all(), 3600).await;

    // A client that trusts halter's CA completes the TLS handshake and the request succeeds.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    let resp = client
        .get(format!("{}/v1/x", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(halter.proxy_url.starts_with("https://"));

    // The provision doc surfaces the CA the consumer must trust.
    let doc: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/provision", halter.admin_url))
        .header("X-Halter-Token", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        doc["halterCa"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
}

/// HTTP Upgrade transport: an allowed `Connection: Upgrade` request (the shape of `kubectl
/// exec`/`port-forward`/`watch`) is tunneled through halter to the upstream, which switches
/// protocols and echoes bytes back over the spliced connection — with the real credential
/// injected, not the halter token.
#[tokio::test]
async fn allowed_upgrade_is_tunneled_to_upstream() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![service(
        "svc",
        "*",
        Flavor::Generic,
        "svc-key",
        &upstream.base_url,
    )])
    .await;
    halter.add_credential("svc-key", "real");
    let token = halter.mint_token(&allow_all(), 3600).await;

    let addr = halter.proxy_url.trim_start_matches("http://").to_string();
    let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let req = format!(
        "GET /exec HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
         Authorization: Bearer {token}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    // Read response headers up to the blank line; expect 101 Switching Protocols.
    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "connection closed before upgrade");
        head.extend_from_slice(&tmp[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.contains("101"),
        "expected 101 Switching Protocols, got:\n{head}"
    );

    // The tunnel is live: bytes we send are echoed back by the upstream through halter.
    stream.write_all(b"ping-through-halter").await.unwrap();
    let mut echo = vec![0u8; b"ping-through-halter".len()];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping-through-halter");

    // The upstream saw the injected credential, not the halter token.
    let got = upstream.requests();
    assert_eq!(got[0].path, "/exec");
    assert_eq!(got[0].authorization.as_deref(), Some("Bearer real"));
}

/// Fail closed: a request whose Host matches no configured service is denied and never
/// forwarded — even with a valid token and an allow-all policy.
#[tokio::test]
async fn unrouted_host_is_denied() {
    let upstream = start_mock_upstream().await;
    // Only "api.github.com" is configured; the test client's Host (127.0.0.1) won't match.
    let halter = start_halter_services(vec![service(
        "github",
        "api.github.com",
        Flavor::Github,
        "github-app",
        &upstream.base_url,
    )])
    .await;
    halter.add_credential("github-app", "real");
    let token = halter.mint_token(&allow_all(), 3600).await;

    let resp = reqwest::Client::new()
        .get(format!("{}/repos/o/r", halter.proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(
        !upstream.was_called(),
        "unrouted host must not be forwarded"
    );
}
