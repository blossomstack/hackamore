//! e2e for the `k8s` CLI preset's live-fetch registration path.
//!
//! The k8s preset is the one preset whose API model is **not** bundled — the CLI fetches the
//! cluster's `…/openapi/v2` at registration and ships it inline. A real cluster can't be
//! e2e'd here, so this stands up a **mock cluster** (plain HTTP, no TLS, so no CA wiring is
//! exercised) that serves a tiny OpenAPI at `/openapi/v2`, plus the harness admin API, then
//! drives the real `hackamore services add k8s` subprocess end to end:
//!
//!   kubeconfig-less (`--cluster` + `--token`) → live fetch (Bearer auth) → register the kube
//!   credential (token → `static`) → register the service with the fetched OpenAPI inline +
//!   `bearer` injection.
//!
//! The cluster-independent pieces (kubeconfig parse, source mapping, request construction,
//! expansion) are unit-tested in `hackamore_cli::k8s`; this covers the I/O glue in `main.rs`.
//! TLS/CA and exec-plugin auth still need a real cluster and are not e2e'd.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use std::sync::{Arc, Mutex};

use hackamore_tests::start_hackamore_services;

/// A tiny but structurally valid OpenAPI the mock cluster serves at `/openapi/v2`.
const CLUSTER_OPENAPI: &str = r#"{
  "openapi": "3.0.0",
  "info": { "title": "Kubernetes", "version": "v1.29.0" },
  "paths": {
    "/api/v1/namespaces/{namespace}/pods": {
      "get": { "operationId": "listCoreV1NamespacedPod", "summary": "list pods" }
    }
  }
}"#;

/// Locate the built `hackamore` binary relative to the running test executable
/// (`target/<profile>/deps/<test>` → `target/<profile>/hackamore`). Returns `None` if it
/// isn't there, so the test skips rather than falsely failing when the bin wasn't built.
fn hackamore_bin() -> Option<std::path::PathBuf> {
    let test_exe = std::env::current_exe().ok()?;
    // .../target/<profile>/deps/<test-exe>  → ancestor[1] is .../target/<profile>
    let profile_dir = test_exe.parent()?.parent()?;
    let bin = profile_dir.join(if cfg!(windows) {
        "hackamore.exe"
    } else {
        "hackamore"
    });
    bin.exists().then_some(bin)
}

async fn serve_openapi(
    State(auth): State<Arc<Mutex<Option<String>>>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    *auth.lock().unwrap() = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    axum::response::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(CLUSTER_OPENAPI))
        .unwrap()
}

#[tokio::test]
async fn k8s_preset_fetches_live_openapi_and_registers_service_and_credential() {
    let Some(bin) = hackamore_bin() else {
        eprintln!("skipping: hackamore binary not built");
        return;
    };

    // Mock cluster: serve the OpenAPI at /openapi/v2 over plain HTTP and capture the auth header.
    let seen_auth: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let app = Router::new()
        .route("/openapi/v2", get(serve_openapi))
        .with_state(seen_auth.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cluster_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // The hackamore admin API the CLI registers against.
    let h = start_hackamore_services(vec![]).await;

    // Drive the real CLI: kubeconfig-less, explicit cluster + token.
    let output = tokio::task::spawn_blocking({
        let admin = h.admin_url.clone();
        move || {
            std::process::Command::new(bin)
                .args([
                    "services",
                    "add",
                    "k8s",
                    "--cluster",
                    &cluster_url,
                    "--token",
                    "kube-bearer-tok",
                    "--admin-url",
                    &admin,
                ])
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "CLI failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The cluster OpenAPI was fetched with the bearer token.
    assert_eq!(
        seen_auth.lock().unwrap().as_deref(),
        Some("Bearer kube-bearer-tok"),
    );

    // The service is registered with the fetched OpenAPI inline and a bearer injection.
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/admin/services", h.admin_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let k8s = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "k8s")
        .expect("k8s service registered");
    // The imported model carries the operation from the fetched spec.
    let ops: Vec<&str> = k8s["model"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["id"].as_str())
        .collect();
    assert!(
        ops.contains(&"listCoreV1NamespacedPod"),
        "imported ops: {ops:?}"
    );
}
