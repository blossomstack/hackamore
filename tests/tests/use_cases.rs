//! Per-use-case full-stack e2e: for each of github, generic, k8s, and aws, a mock
//! upstream + a real hackamore server + the real `hackamore-agent` config writers (into an
//! isolated temp HOME, so the host's `~/.kube`/`~/.aws`/git config are never touched).
//! Each test mints a token, provisions + writes native config, then drives the request
//! the way the tool would and asserts the mock upstream received the injected/re-signed
//! call.

use hackamore_gateway::{Extract, Outbound, Protocol, Service};
use hackamore_models::policy::Policy;
use hackamore_tests::{Harness, start_hackamore_services, start_mock_upstream};

fn policy(json: &str) -> Policy {
    serde_json::from_str(json).expect("valid policy json")
}

/// A catch-all service (host `*`) with the given outbound, pointing at `upstream`. Defaults
/// to the `generic` tool hint (override with `.with_tool_hint`).
fn service(name: &str, outbound: Outbound, upstream: &str) -> Service {
    Service::new(name, "*", upstream).with_outbound(outbound)
}

/// Mint a token, fetch the provision doc, and run the real hackamore-agent config writers
/// into `home`. Returns the token and the provision doc.
async fn provision_agent(
    hackamore: &Harness,
    pol: &Policy,
    home: &std::path::Path,
) -> (String, hackamore_models::provision::ProvisionDoc) {
    let token = hackamore.mint_token(pol, 3600).await;
    // Provision the way a sandboxed consumer does: via the proxy listener's reserved
    // `/.hackamore/provision` path (the admin API is unreachable from a sandbox).
    let doc = hackamore_agent::fetch_provision(&hackamore.proxy_url, &token)
        .await
        .expect("provision");
    hackamore_agent::write_configs(home, &doc).expect("write configs");
    (token, doc)
}

/// The host:port a client/SDK addresses hackamore at (and signs into, for SigV4).
fn proxy_host(hackamore: &Harness) -> String {
    hackamore
        .proxy_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string()
}

/// **GitHub REST use case** — bearer inject, `tool_hint: github`. hackamore-agent writes the
/// `gh` hosts.yml (NOT git credentials — that is the separate `git` hint); a `gh`-style REST
/// request is injected with the real GitHub-App token.
#[tokio::test]
async fn github_use_case() {
    let upstream = start_mock_upstream().await;
    let hackamore = start_hackamore_services(vec![
        service(
            "github-api",
            Outbound::Bearer {
                credential: "github-app".into(),
            },
            &upstream.base_url,
        )
        .with_tool_hint("github"),
    ])
    .await;
    hackamore.add_credential("github-app", "ghs-real-token");
    let home = tempfile::tempdir().unwrap();

    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "resources": ["repos/octocat/**"], "conditions": [],
            "verbs": [ { "type": "Method", "value": { "method": "GET" } } ] } } ] }"#,
    );
    let (token, _doc) = provision_agent(&hackamore, &pol, home.path()).await;

    // hackamore-agent wrote the `gh` hosts.yml with the token — only under the isolated home.
    let gh =
        std::fs::read_to_string(home.path().join(".config").join("gh").join("hosts.yml")).unwrap();
    assert!(
        gh.contains(&token),
        "gh hosts.yml carries the hackamore token"
    );
    // The `github` hint writes no git credential store (that is the `git` hint's job).
    assert!(!home.path().join(".git-credentials").exists());

    // Drive a read the way gh/git would (token via X-Hackamore-Token).
    let client = reqwest::Client::new();
    let ok = client
        .get(format!("{}/repos/octocat/hello", hackamore.proxy_url))
        .header("X-Hackamore-Token", &token)
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
        .delete(format!("{}/repos/octocat/hello", hackamore.proxy_url))
        .header("X-Hackamore-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(upstream.requests().len(), 1);
}

/// **Generic HTTPS use case** — bearer inject for any SDK. hackamore-agent writes `hackamore.env`.
#[tokio::test]
async fn generic_use_case() {
    let upstream = start_mock_upstream().await;
    let hackamore = start_hackamore_services(vec![service(
        "openai",
        Outbound::Bearer {
            credential: "openai-key".into(),
        },
        &upstream.base_url,
    )])
    .await;
    hackamore.add_credential("openai-key", "sk-real-key");
    let home = tempfile::tempdir().unwrap();

    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
        "targets": [], "verbs": [], "resources": [], "conditions": [] } } ] }"#,
    );
    let (token, _doc) = provision_agent(&hackamore, &pol, home.path()).await;

    // hackamore-agent wrote the env file with the token (generic SDKs read base-url + token).
    let env = std::fs::read_to_string(home.path().join("hackamore.env")).unwrap();
    assert!(env.contains(&token));

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", hackamore.proxy_url))
        .header("X-Hackamore-Token", &token)
        .json(&serde_json::json!({ "model": "gpt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let got = upstream.requests();
    assert_eq!(got[0].path, "/v1/chat/completions");
    assert_eq!(got[0].authorization.as_deref(), Some("Bearer sk-real-key"));
}

/// **Kubernetes use case** — bearer inject (static-token kubeconfig). hackamore-agent writes
/// a kubeconfig; a `kubectl` style request is injected with the real cluster token.
#[tokio::test]
async fn k8s_use_case() {
    let upstream = start_mock_upstream().await;
    // `tool_hint: kubernetes` is the agent's cue to write a kubeconfig (not the service name).
    let hackamore = start_hackamore_services(vec![
        service(
            "k8s",
            Outbound::Bearer {
                credential: "eks-token".into(),
            },
            &upstream.base_url,
        )
        .with_tool_hint("kubernetes"),
    ])
    .await;
    hackamore.add_credential("eks-token", "k8s-aws-v1.real");
    let home = tempfile::tempdir().unwrap();

    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "resources": ["api/v1/namespaces/dev/**"], "conditions": [],
            "verbs": [ { "type": "Method", "value": { "method": "GET" } } ] } } ] }"#,
    );
    let (token, _doc) = provision_agent(&hackamore, &pol, home.path()).await;

    // hackamore-agent wrote a kubeconfig with the static token.
    let kube = std::fs::read_to_string(home.path().join(".kube").join("config")).unwrap();
    assert!(kube.contains("kind: Config"));
    assert!(kube.contains(&format!("token: {token}")));

    let client = reqwest::Client::new();
    let ok = client
        .get(format!(
            "{}/api/v1/namespaces/dev/pods",
            hackamore.proxy_url
        ))
        .header("X-Hackamore-Token", &token)
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
        .get(format!(
            "{}/api/v1/namespaces/prod/pods",
            hackamore.proxy_url
        ))
        .header("X-Hackamore-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(upstream.requests().len(), 1);
}

/// **AWS use case** — SigV4 in/out. hackamore-agent writes `~/.aws` (dummy credential); the
/// consumer signs with the dummy cred (exactly as the `aws` CLI does, via hackamore's signer),
/// hackamore verifies it and re-signs the forwarded request with the real account credential.
#[tokio::test]
async fn aws_use_case() {
    let upstream = start_mock_upstream().await;
    let hackamore = start_hackamore_services(vec![
        Service::new("ec2", "*", upstream.base_url.clone())
            .with_outbound(Outbound::SigV4 {
                credential: "aws-secret".into(),
                region: "us-east-1".into(),
                service: "ec2".into(),
            })
            .with_tool_hint("aws")
            .with_extract(Extract {
                protocol: Protocol::parse(Some("aws-query")),
                path_template: None,
            }),
    ])
    .await;
    // The akid now comes from the resolved AWS bundle (no inline akid on the service).
    hackamore.credentials.insert_aws(
        "aws-secret",
        hackamore_control::AwsCredential {
            access_key_id: "REALAKID".into(),
            secret_access_key: hackamore_control::Secret::new("real-secret-key"),
            session_token: None,
            expires_at_ms: None,
        },
    );
    let home = tempfile::tempdir().unwrap();

    // Allow only DescribeInstances (a named action verb).
    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "resources": [], "conditions": [],
            "verbs": [ { "type": "Action", "value": { "id": "DescribeInstances" } } ] } } ] }"#,
    );
    let (_token, doc) = provision_agent(&hackamore, &pol, home.path()).await;

    // hackamore-agent wrote ~/.aws/credentials with a dummy key pair (not the real secret).
    let creds = std::fs::read_to_string(home.path().join(".aws").join("credentials")).unwrap();
    assert!(creds.contains("aws_access_key_id = AKIAHACKAMORE"));
    assert!(!creds.contains("real-secret-key"));

    // Pull the dummy credential the consumer signs with from the provision doc.
    let auth = &doc
        .services
        .iter()
        .find(|s| s.target == "ec2")
        .unwrap()
        .auth;
    let hackamore_models::provision::ProvisionAuth::SigV4(dummy) = auth else {
        panic!("expected SigV4 provision auth");
    };

    let host = proxy_host(&hackamore);
    let client = reqwest::Client::new();
    // Sign at the current wall-clock time — hackamore checks the request's freshness against
    // its own clock, exactly as it would for a live `aws` CLI invocation.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Helper: sign a body with the dummy cred (what the aws CLI does) and send it.
    let send = |body: &'static [u8]| {
        let signed = hackamore_gateway::sigv4::sign(
            &hackamore_gateway::sigv4::Creds {
                access_key_id: &dummy.access_key_id,
                secret_access_key: &dummy.secret_access_key,
                session_token: None,
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
            .post(format!("{}/", hackamore.proxy_url))
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

/// **AWS bundle use case (P3)** — register an `aws-static` credential *with a session token*
/// and a `sigv4` service entirely through the admin API, then drive a SigV4-signed request
/// and assert hackamore re-signs it with the real bundle and rides the session token out in
/// `X-Amz-Security-Token` (part of the SigV4 signed header set).
#[tokio::test]
async fn aws_bundle_session_token_use_case() {
    let upstream = start_mock_upstream().await;
    // Start with no services; we register the sigv4 service live via the admin API.
    let hackamore = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    // 1. Register the AWS bundle (akid + secret + session token) via POST /admin/credentials.
    let cred_resp = client
        .post(format!("{}/admin/credentials", hackamore.admin_url))
        .json(&serde_json::json!({
            "id": "aws-prod",
            "source": {
                "kind": "aws-static",
                "access_key_id": "REALAKID",
                "secret_access_key": "real-secret-key",
                "session_token": "real-session-token"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(cred_resp.status(), 201, "credential registered");
    // The response never echoes any secret.
    let cred_body = cred_resp.text().await.unwrap();
    assert!(!cred_body.contains("real-secret-key"));
    assert!(!cred_body.contains("real-session-token"));

    // 2. Register a model-less `sigv4` service referencing the bundle by id.
    let svc_resp = client
        .post(format!("{}/admin/services", hackamore.admin_url))
        .json(&serde_json::json!({
            "name": "ec2",
            "upstreamBase": upstream.base_url,
            "protocol": "aws-query",
            "outbound": {
                "kind": "sigv4",
                "credential": "aws-prod",
                "region": "us-east-1",
                "service": "ec2"
            }
        }))
        .send()
        .await
        .unwrap();
    assert!(svc_resp.status().is_success(), "service registered");

    // 3. Mint a token bound to a policy allowing DescribeInstances, and a dummy AWS cred the
    //    consumer signs with (the SigV4 inbound flow).
    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": [], "resources": [], "conditions": [],
            "verbs": [ { "type": "Action", "value": { "id": "DescribeInstances" } } ] } } ] }"#,
    );
    let _token = hackamore.mint_token(&pol, 3600).await;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let dummy = hackamore
        .control
        .tokens
        .mint_sigv4(pol.clone(), 3600, now_ms);

    // 4. Sign a request with the dummy cred (what the aws CLI does) and send it.
    let host = proxy_host(&hackamore);
    let body = b"Action=DescribeInstances&Version=2016-11-15";
    let signed = hackamore_gateway::sigv4::sign(
        &hackamore_gateway::sigv4::Creds {
            access_key_id: &dummy.access_key_id,
            secret_access_key: &dummy.secret_access_key,
            session_token: None,
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
    let resp = client
        .post(format!("{}/", hackamore.proxy_url))
        .header(reqwest::header::AUTHORIZATION, signed.authorization)
        .header("x-amz-date", signed.amz_date)
        .header("x-amz-content-sha256", signed.content_sha256)
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 5. The forwarded request is re-signed with the REAL bundle and carries the session token.
    let got = upstream.requests();
    assert_eq!(got.len(), 1);
    let upstream_auth = got[0].authorization.as_deref().unwrap();
    assert!(upstream_auth.starts_with("AWS4-HMAC-SHA256 Credential=REALAKID/"));
    // x-amz-security-token is part of the signed header set...
    assert!(upstream_auth.contains("x-amz-security-token"));
    // ...and rides out as a header carrying the real session token.
    assert_eq!(
        got[0].header("x-amz-security-token"),
        Some("real-session-token")
    );
    // No real secret leaks (only the session token, which is meant to ride out, appears).
    assert!(!upstream_auth.contains("real-secret-key"));

    // A non-allowed action is denied and never forwarded.
    let body2 = b"Action=TerminateInstances&InstanceId=i-123";
    let signed2 = hackamore_gateway::sigv4::sign(
        &hackamore_gateway::sigv4::Creds {
            access_key_id: &dummy.access_key_id,
            secret_access_key: &dummy.secret_access_key,
            session_token: None,
        },
        "us-east-1",
        "ec2",
        "POST",
        &host,
        "/",
        "",
        body2,
        now_ms,
    );
    let denied = client
        .post(format!("{}/", hackamore.proxy_url))
        .header(reqwest::header::AUTHORIZATION, signed2.authorization)
        .header("x-amz-date", signed2.amz_date)
        .header("x-amz-content-sha256", signed2.content_sha256)
        .body(body2.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(upstream.requests().len(), 1);
}

/// **Tool-hint routing (P5)** — register three preset-style services *live via the admin API*
/// with distinct `toolHint`s (`github` REST, `git` git-http, `aws` sigv4), mint a token,
/// fetch the provision doc, and run `write_configs`. Assert each hint produces exactly its
/// own native files (and only those): `gh` hosts.yml for `github`, `.git-credentials` +
/// `.gitconfig` for `git`, the AWS profile for `aws`. The git credential line is the
/// Basic-inbound shape hackamore (P2) accepts (`https://x-access-token:<token>@host`). This
/// exercises the full `toolHint` plumbing: admin request → `Service.tool_hint` →
/// `ProvisionService.tool_hint` → the agent's split dispatch.
#[tokio::test]
async fn tool_hint_drives_agent_native_config() {
    let upstream = start_mock_upstream().await;
    let hackamore = start_hackamore_services(vec![]).await;
    let client = reqwest::Client::new();

    // 1. github-api (REST) → toolHint github → the agent should write the gh hosts.yml only.
    let resp = client
        .post(format!("{}/admin/services", hackamore.admin_url))
        .json(&serde_json::json!({
            "name": "github-api",
            "host": "*",
            "upstreamBase": upstream.base_url,
            "toolHint": "github",
            "outbound": { "kind": "bearer", "secret": "ghs-real-token" }
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "github-api registered");

    // 2. github-git (git-http) → toolHint git → the agent should write the git files only.
    let resp = client
        .post(format!("{}/admin/services", hackamore.admin_url))
        .json(&serde_json::json!({
            "name": "github-git",
            "host": "github.example",
            "upstreamBase": "https://github.example",
            "protocol": "git-http",
            "toolHint": "git",
            // The consumer-facing endpoint the agent points git at (becomes the credential host).
            "address": "https://github.example",
            "outbound": { "kind": "basic", "username": "x-access-token", "secret": "ghp_realtoken" }
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "github-git registered");

    // 3. an aws sigv4 service → toolHint aws → the agent should write the AWS profile.
    client
        .post(format!("{}/admin/credentials", hackamore.admin_url))
        .json(&serde_json::json!({
            "id": "aws-prod",
            "source": { "kind": "aws-static", "access_key_id": "REALAKID",
                        "secret_access_key": "real-secret-key" }
        }))
        .send()
        .await
        .unwrap();
    let resp = client
        .post(format!("{}/admin/services", hackamore.admin_url))
        .json(&serde_json::json!({
            "name": "aws-ec2",
            "host": "ec2.example",
            "upstreamBase": "https://ec2.example",
            "protocol": "aws-query",
            "toolHint": "aws",
            "outbound": { "kind": "sigv4", "credential": "aws-prod",
                          "region": "us-east-1", "service": "ec2" }
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "aws-ec2 registered");

    // Mint a token granting all three named services, provision + write native config.
    let pol = policy(
        r#"{ "rules": [ { "effect": "Allow", "matches": {
            "targets": ["github-api", "github-git", "aws-ec2"],
            "verbs": [], "resources": [], "conditions": [] } } ] }"#,
    );
    let home = tempfile::tempdir().unwrap();
    let (token, doc) = provision_agent(&hackamore, &pol, home.path()).await;
    // The provision doc carries each service's tool_hint (not its name).
    let hint = |target: &str| {
        doc.services
            .iter()
            .find(|s| s.target == target)
            .map(|s| s.tool_hint.as_str())
    };
    assert_eq!(hint("github-api"), Some("github"));
    assert_eq!(hint("github-git"), Some("git"));
    assert_eq!(hint("aws-ec2"), Some("aws"));

    // `github` hint → gh hosts.yml carries the launch token.
    let gh =
        std::fs::read_to_string(home.path().join(".config").join("gh").join("hosts.yml")).unwrap();
    assert!(gh.contains(&token), "gh hosts.yml carries the token");

    // `git` hint → git-credentials in the Basic-inbound shape hackamore accepts, + .gitconfig.
    let git_creds = std::fs::read_to_string(home.path().join(".git-credentials")).unwrap();
    assert!(
        git_creds.contains(&format!("https://x-access-token:{token}@github.example")),
        "git credentials use the Basic-inbound x-access-token shape"
    );
    let gitconfig = std::fs::read_to_string(home.path().join(".gitconfig")).unwrap();
    assert!(gitconfig.contains("helper = store"));

    // `aws` hint → AWS profile with the dummy creds + endpoint (never the real secret).
    let aws_creds = std::fs::read_to_string(home.path().join(".aws").join("credentials")).unwrap();
    assert!(aws_creds.contains("aws_access_key_id = AKIAHACKAMORE"));
    assert!(!aws_creds.contains("real-secret-key"));

    // Drive a github-api read the way gh would — the real GitHub token is injected.
    let ok = client
        .get(format!("{}/repos/octocat/hello", hackamore.proxy_url))
        .header("X-Hackamore-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let got = upstream.requests();
    assert_eq!(
        got[0].authorization.as_deref(),
        Some("Bearer ghs-real-token")
    );
}
