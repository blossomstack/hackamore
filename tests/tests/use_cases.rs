//! Per-use-case full-stack e2e: for each of github, generic, k8s, and aws, a mock
//! upstream + a real halter server + the real `halter-agent` config writers (into an
//! isolated temp HOME, so the host's `~/.kube`/`~/.aws`/git config are never touched).
//! Each test mints a token, provisions + writes native config, then drives the request
//! the way the tool would and asserts the mock upstream received the injected/re-signed
//! call.

use gateway::{Extract, Flavor, Outbound, Protocol, Service};
use models::policy::Policy;
use tests::{Harness, start_halter_services, start_mock_upstream};

fn policy(json: &str) -> Policy {
    serde_json::from_str(json).expect("valid policy json")
}

/// A catch-all service (host `*`) of the given flavor + outbound, pointing at `upstream`.
fn service(name: &str, flavor: Flavor, outbound: Outbound, upstream: &str) -> Service {
    Service::new(name, "*", upstream)
        .with_flavor(flavor)
        .with_outbound(outbound)
}

/// Mint a token, fetch the provision doc, and run the real halter-agent config writers
/// into `home`. Returns the token and the provision doc.
async fn provision_agent(
    halter: &Harness,
    pol: &Policy,
    home: &std::path::Path,
) -> (String, models::provision::ProvisionDoc) {
    let token = halter.mint_token(pol, 3600).await;
    let doc = cli::agent::fetch_provision(&halter.admin_url, &token)
        .await
        .expect("provision");
    cli::agent::write_configs(home, &doc).expect("write configs");
    (token, doc)
}

/// The host:port a client/SDK addresses halter at (and signs into, for SigV4).
fn proxy_host(halter: &Harness) -> String {
    halter
        .proxy_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string()
}

/// **GitHub use case** — bearer inject. halter-agent writes git credentials; a `git`/`gh`
/// style request is injected with the real GitHub-App token.
#[tokio::test]
async fn github_use_case() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![service(
        "github",
        Flavor::Github,
        Outbound::Bearer {
            credential: "github-app".into(),
        },
        &upstream.base_url,
    )])
    .await;
    halter.add_credential("github-app", "ghs-real-token");
    let home = tempfile::tempdir().unwrap();

    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "resources": ["repos/octocat/**"], "conditions": [],
            "verbs": [ { "type": "Crud", "value": { "kind": "Read" } } ] } } ] }"#,
    );
    let (token, _doc) = provision_agent(&halter, &pol, home.path()).await;

    // halter-agent wrote git credentials with the token — only under the isolated home.
    let creds = std::fs::read_to_string(home.path().join(".git-credentials")).unwrap();
    assert!(
        creds.contains(&token),
        "git credentials carry the halter token"
    );

    // Drive a read the way gh/git would (token via X-Halter-Token).
    let client = reqwest::Client::new();
    let ok = client
        .get(format!("{}/repos/octocat/hello", halter.proxy_url))
        .header("X-Halter-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let got = upstream.requests();
    assert_eq!(got[0].path, "/repos/octocat/hello");
    assert_eq!(
        got[0].authorization.as_deref(),
        Some("Bearer ghs-real-token")
    );

    // A write outside the read scope is denied and never forwarded.
    let denied = client
        .delete(format!("{}/repos/octocat/hello", halter.proxy_url))
        .header("X-Halter-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(upstream.requests().len(), 1);
}

/// **Generic HTTPS use case** — bearer inject for any SDK. halter-agent writes `halter.env`.
#[tokio::test]
async fn generic_use_case() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![service(
        "openai",
        Flavor::Generic,
        Outbound::Bearer {
            credential: "openai-key".into(),
        },
        &upstream.base_url,
    )])
    .await;
    halter.add_credential("openai-key", "sk-real-key");
    let home = tempfile::tempdir().unwrap();

    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
        "targets": [], "verbs": [], "resources": [], "conditions": [] } } ] }"#,
    );
    let (token, _doc) = provision_agent(&halter, &pol, home.path()).await;

    // halter-agent wrote the env file with the token (generic SDKs read base-url + token).
    let env = std::fs::read_to_string(home.path().join("halter.env")).unwrap();
    assert!(env.contains(&token));

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", halter.proxy_url))
        .header("X-Halter-Token", &token)
        .json(&serde_json::json!({ "model": "gpt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let got = upstream.requests();
    assert_eq!(got[0].path, "/v1/chat/completions");
    assert_eq!(got[0].authorization.as_deref(), Some("Bearer sk-real-key"));
}

/// **Kubernetes use case** — bearer inject (static-token kubeconfig). halter-agent writes
/// a kubeconfig; a `kubectl` style request is injected with the real cluster token.
#[tokio::test]
async fn k8s_use_case() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![service(
        "eks-prod",
        Flavor::K8s,
        Outbound::Bearer {
            credential: "eks-token".into(),
        },
        &upstream.base_url,
    )])
    .await;
    halter.add_credential("eks-token", "k8s-aws-v1.real");
    let home = tempfile::tempdir().unwrap();

    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "resources": ["api/v1/namespaces/dev/**"], "conditions": [],
            "verbs": [ { "type": "Crud", "value": { "kind": "Read" } } ] } } ] }"#,
    );
    let (token, _doc) = provision_agent(&halter, &pol, home.path()).await;

    // halter-agent wrote a kubeconfig with the static token.
    let kube = std::fs::read_to_string(home.path().join(".kube").join("config")).unwrap();
    assert!(kube.contains("kind: Config"));
    assert!(kube.contains(&format!("token: {token}")));

    let client = reqwest::Client::new();
    let ok = client
        .get(format!("{}/api/v1/namespaces/dev/pods", halter.proxy_url))
        .header("X-Halter-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let got = upstream.requests();
    assert_eq!(got[0].path, "/api/v1/namespaces/dev/pods");
    assert_eq!(
        got[0].authorization.as_deref(),
        Some("Bearer k8s-aws-v1.real")
    );

    // A different namespace is outside scope → denied.
    let denied = client
        .get(format!("{}/api/v1/namespaces/prod/pods", halter.proxy_url))
        .header("X-Halter-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(upstream.requests().len(), 1);
}

/// **AWS use case** — SigV4 in/out. halter-agent writes `~/.aws` (dummy credential); the
/// consumer signs with the dummy cred (exactly as the `aws` CLI does, via halter's signer),
/// halter verifies it and re-signs the forwarded request with the real account credential.
#[tokio::test]
async fn aws_use_case() {
    let upstream = start_mock_upstream().await;
    let halter = start_halter_services(vec![
        Service::new("ec2", "*", upstream.base_url.clone())
            .with_outbound(Outbound::SigV4 {
                credential: "aws-secret".into(),
                access_key_id: "REALAKID".into(),
                region: "us-east-1".into(),
                service: "ec2".into(),
            })
            .with_extract(Extract {
                protocol: Protocol::AwsQuery,
                path_template: None,
            }),
    ])
    .await;
    halter.add_credential("aws-secret", "real-secret-key");
    let home = tempfile::tempdir().unwrap();

    // Allow only DescribeInstances (a named action verb).
    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "resources": [], "conditions": [],
            "verbs": [ { "type": "Action", "value": { "id": "DescribeInstances" } } ] } } ] }"#,
    );
    let (_token, doc) = provision_agent(&halter, &pol, home.path()).await;

    // halter-agent wrote ~/.aws/credentials with a dummy key pair (not the real secret).
    let creds = std::fs::read_to_string(home.path().join(".aws").join("credentials")).unwrap();
    assert!(creds.contains("aws_access_key_id = AKIAHALTER"));
    assert!(!creds.contains("real-secret-key"));

    // Pull the dummy credential the consumer signs with from the provision doc.
    let auth = &doc
        .services
        .iter()
        .find(|s| s.target == "ec2")
        .unwrap()
        .auth;
    let models::provision::ProvisionAuth::SigV4(dummy) = auth else {
        panic!("expected SigV4 provision auth");
    };

    let host = proxy_host(&halter);
    let client = reqwest::Client::new();
    // Sign at the current wall-clock time — halter checks the request's freshness against
    // its own clock, exactly as it would for a live `aws` CLI invocation.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Helper: sign a body with the dummy cred (what the aws CLI does) and send it.
    let send = |body: &'static [u8]| {
        let signed = gateway::sigv4::sign(
            &gateway::sigv4::Creds {
                access_key_id: &dummy.access_key_id,
                secret_access_key: &dummy.secret_access_key,
            },
            "us-east-1",
            "ec2",
            "POST",
            &host,
            "/",
            "",
            body,
            now_ms,
        );
        client
            .post(format!("{}/", halter.proxy_url))
            .header(reqwest::header::AUTHORIZATION, signed.authorization)
            .header("x-amz-date", signed.amz_date)
            .header("x-amz-content-sha256", signed.content_sha256)
            .body(body)
            .send()
    };

    // Allowed: DescribeInstances → re-signed with the REAL access key id upstream.
    let ok = send(b"Action=DescribeInstances&Version=2016-11-15")
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let got = upstream.requests();
    let upstream_auth = got[0].authorization.as_deref().unwrap();
    assert!(upstream_auth.starts_with("AWS4-HMAC-SHA256 Credential=REALAKID/"));
    assert!(!upstream_auth.contains(&dummy.access_key_id));

    // Denied: TerminateInstances is outside the policy → 403, never forwarded.
    let denied = send(b"Action=TerminateInstances&InstanceId=i-123")
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(upstream.requests().len(), 1);
}
