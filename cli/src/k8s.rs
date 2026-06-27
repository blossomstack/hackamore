//! The `k8s` CLI preset — the one preset whose API model is **not** bundled.
//!
//! Every other preset ([`crate::preset`]) pins a model it ships in the binary. A Kubernetes
//! cluster's vocabulary is the cluster's own (versioned, CRD-extended) OpenAPI, so the CLI
//! fetches it live from `<server>/openapi/v2` at registration and ships it inline. That makes
//! the preset two-step: an impure fetch (in the command handler) feeds a pure expansion (here).
//!
//! Everything in this module is **pure and unit-testable** — kubeconfig parsing, the
//! user-auth → credential-source mapping, the OpenAPI fetch *request construction* (url +
//! headers + CA, separate from the actual `send()`), and the service-JSON expansion given an
//! already-fetched spec. The command handler in `main.rs` performs the I/O (read the
//! kubeconfig file, decode/read the CA, `send()` the request, register credential + service).
//!
//! **v1 auth: bearer token or exec-plugin only.** A `user.token` becomes a `static` credential
//! source; a `user.exec` becomes a `command` source (argv = `[command, ...args]`) so hackamore
//! re-runs it and the token rotates. mTLS client-cert auth is deferred (see the design spec);
//! exec `env` entries are **not yet threaded** into the command source (a v1 limitation noted
//! at [`ExecAuth`]).

use base64::Engine;

/// The default kube credential id (and service name) the preset registers under.
pub const DEFAULT_K8S_NAME: &str = "k8s";

/// The cluster's OpenAPI path the CLI fetches the model from.
pub const OPENAPI_V2_PATH: &str = "/openapi/v2";

/// A kubeconfig user's auth material, narrowed to what v1 supports (bearer token or
/// exec-plugin). mTLS client-cert is deferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAuth {
    /// A static bearer token (`user.token`).
    Token(String),
    /// An exec credential plugin (`user.exec`). hackamore re-runs it to rotate the token.
    Exec(ExecAuth),
}

/// A kubeconfig exec credential plugin. The argv hackamore re-runs is `[command, ...args]`.
///
/// **v1 limitation:** `env` is parsed for completeness but **not yet threaded** into the
/// hackamore `command` source (the source has no env field). exec plugins that depend on
/// extra env beyond the inherited process environment are unsupported until that lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecAuth {
    /// The plugin binary, e.g. `aws` or `kubelogin`.
    pub command: String,
    /// Arguments passed to the binary.
    pub args: Vec<String>,
    /// `(name, value)` env pairs declared in the kubeconfig. Not yet threaded (see above).
    pub env: Vec<(String, String)>,
}

/// Where a cluster's CA certificate comes from. The CLI trusts this CA when fetching the
/// OpenAPI over TLS (unless `insecure` is set on the resolved context).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterCa {
    /// Inline base64-encoded PEM (`cluster.certificate-authority-data`).
    Data(String),
    /// A path to a PEM file on disk (`cluster.certificate-authority`).
    Path(String),
    /// No CA pinned — rely on the system trust store.
    None,
}

/// A kubeconfig context resolved to exactly the connection parameters the k8s preset needs.
/// The product of the **pure** [`parse_kubeconfig`]; no files or network touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedContext {
    /// `cluster.server` — the API server URL.
    pub server: String,
    /// The cluster CA, if any.
    pub ca: ClusterCa,
    /// Whether `cluster.insecure-skip-tls-verify` is set (disables CA verification).
    pub insecure: bool,
    /// The user's auth material.
    pub auth: UserAuth,
}

/// Parse a kubeconfig document and resolve a single context to its connection parameters.
///
/// `context` selects the context by name; `None` uses the file's `current-context`. Pure: the
/// caller hands in the kubeconfig **text**, so this is testable without files or a cluster.
/// Fails closed — a missing context, cluster, user, or supported auth is an error, never a
/// silent default.
pub fn parse_kubeconfig(text: &str, context: Option<&str>) -> Result<ResolvedContext, String> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| format!("parse kubeconfig: {e}"))?;

    let context_name = match context {
        Some(name) => name.to_string(),
        None => doc
            .get("current-context")
            .and_then(|v| v.as_str())
            .ok_or("kubeconfig has no current-context and no --context was given")?
            .to_string(),
    };

    let context_entry = find_named(&doc, "contexts", &context_name)
        .ok_or_else(|| format!("kubeconfig has no context named '{context_name}'"))?;
    let context_body = context_entry
        .get("context")
        .ok_or_else(|| format!("context '{context_name}' has no `context` body"))?;
    let cluster_name = context_body
        .get("cluster")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("context '{context_name}' names no cluster"))?;
    let user_name = context_body
        .get("user")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("context '{context_name}' names no user"))?;

    let cluster = find_named(&doc, "clusters", cluster_name)
        .ok_or_else(|| format!("kubeconfig has no cluster named '{cluster_name}'"))?
        .get("cluster")
        .ok_or_else(|| format!("cluster '{cluster_name}' has no `cluster` body"))?;
    let user = find_named(&doc, "users", user_name)
        .ok_or_else(|| format!("kubeconfig has no user named '{user_name}'"))?
        .get("user")
        .ok_or_else(|| format!("user '{user_name}' has no `user` body"))?;

    let server = cluster
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("cluster '{cluster_name}' has no `server` URL"))?
        .to_string();
    let ca = parse_cluster_ca(cluster);
    let insecure = cluster
        .get("insecure-skip-tls-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let auth = parse_user_auth(user, user_name)?;

    Ok(ResolvedContext {
        server,
        ca,
        insecure,
        auth,
    })
}

/// Find the entry named `name` in a kubeconfig list section (`clusters`/`contexts`/`users`).
/// Each entry is `{ name: …, <kind>: { … } }`.
fn find_named<'a>(
    doc: &'a serde_yaml::Value,
    section: &str,
    name: &str,
) -> Option<&'a serde_yaml::Value> {
    doc.get(section)?
        .as_sequence()?
        .iter()
        .find(|entry| entry.get("name").and_then(|v| v.as_str()) == Some(name))
}

/// Read a cluster's CA: prefer inline `certificate-authority-data`, else a
/// `certificate-authority` path, else none.
fn parse_cluster_ca(cluster: &serde_yaml::Value) -> ClusterCa {
    if let Some(data) = cluster
        .get("certificate-authority-data")
        .and_then(|v| v.as_str())
    {
        return ClusterCa::Data(data.to_string());
    }
    if let Some(path) = cluster
        .get("certificate-authority")
        .and_then(|v| v.as_str())
    {
        return ClusterCa::Path(path.to_string());
    }
    ClusterCa::None
}

/// Resolve a user's auth to the one supported v1 shape (bearer token or exec-plugin). Fails
/// closed: a user with neither (e.g. client-cert mTLS only) is unsupported in v1.
fn parse_user_auth(user: &serde_yaml::Value, user_name: &str) -> Result<UserAuth, String> {
    if let Some(token) = user.get("token").and_then(|v| v.as_str()) {
        if token.is_empty() {
            return Err(format!("user '{user_name}' has an empty token"));
        }
        return Ok(UserAuth::Token(token.to_string()));
    }
    if let Some(exec) = user.get("exec") {
        let command = exec
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("user '{user_name}' exec has no `command`"))?
            .to_string();
        let args = exec
            .get("args")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let env = exec
            .get("env")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|e| {
                        let name = e.get("name").and_then(|v| v.as_str())?;
                        let value = e.get("value").and_then(|v| v.as_str())?;
                        Some((name.to_string(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        return Ok(UserAuth::Exec(ExecAuth { command, args, env }));
    }
    Err(format!(
        "user '{user_name}' has no supported auth: v1 needs a bearer `token` or an `exec` \
         plugin (client-cert mTLS is deferred)"
    ))
}

/// Map a resolved user auth to a `POST /admin/credentials` source JSON.
///
/// - [`UserAuth::Token`] → a `static` source carrying the token verbatim.
/// - [`UserAuth::Exec`] → a `command` source with argv `[command, ...args]`, so hackamore
///   re-runs the plugin and the token rotates. exec `env` is **not** threaded (v1 limitation;
///   see [`ExecAuth`]).
///
/// Pure — never echoes the token to a log.
pub fn auth_to_source_json(auth: &UserAuth) -> serde_json::Value {
    match auth {
        UserAuth::Token(token) => serde_json::json!({ "kind": "static", "secret": token }),
        UserAuth::Exec(exec) => {
            let mut argv = Vec::with_capacity(1 + exec.args.len());
            argv.push(exec.command.clone());
            argv.extend(exec.args.iter().cloned());
            serde_json::json!({ "kind": "command", "argv": argv })
        }
    }
}

/// The constituent parts of the live OpenAPI fetch request — built **purely** so the url,
/// auth header, and CA wiring are unit-testable without performing the request. The command
/// handler turns this into a `reqwest` call and `send()`s it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiRequest {
    /// The full URL: `<server>/openapi/v2`.
    pub url: String,
    /// The `Authorization` header value (`Bearer <token>`).
    pub authorization: String,
    /// PEM bytes of the CA to trust, if the context pins one (already decoded/read).
    pub ca_pem: Option<Vec<u8>>,
    /// Whether to skip TLS verification (context `insecure-skip-tls-verify` or `--insecure…`).
    pub insecure: bool,
}

/// Construct the OpenAPI fetch request from the resolved server URL, the bearer token to
/// authenticate with, the (already-resolved) CA PEM bytes, and the insecure flag. Pure: no
/// `send()`. Trailing slashes on `server` are trimmed so the path joins cleanly.
pub fn build_openapi_request(
    server: &str,
    token: &str,
    ca_pem: Option<Vec<u8>>,
    insecure: bool,
) -> OpenApiRequest {
    OpenApiRequest {
        url: format!("{}{}", server.trim_end_matches('/'), OPENAPI_V2_PATH),
        authorization: format!("Bearer {token}"),
        ca_pem,
        insecure,
    }
}

/// Decode a base64 `certificate-authority-data` value to PEM bytes. Pure and testable.
pub fn decode_ca_data(data: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|e| format!("decode certificate-authority-data: {e}"))
}

/// Expand the k8s preset into the generic `POST /admin/services` JSON, given the
/// **already-fetched** OpenAPI `spec`. Pure (mirrors [`crate::preset::Preset::to_service_json`],
/// but the model is supplied by the live fetch rather than bundled).
///
/// `server` is the cluster API URL (`upstreamBase`); `host` is its host component (inbound
/// routing); `credential` is the kube credential id the bearer injection references.
pub fn expand_service_json(
    name: &str,
    host: &str,
    server: &str,
    spec: &str,
    credential: &str,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "host": host,
        "upstreamBase": server,
        "protocol": "rest",
        "idl": "openapi",
        // The agent tool-config hint: a k8s service makes the agent write a kubeconfig.
        "toolHint": "kubernetes",
        "specInline": spec,
        "outbound": { "kind": "bearer", "credential": credential },
    })
}

/// The host component of a cluster server URL (for inbound `Host` routing). Strips scheme and
/// path; keeps the port if present. Fails closed on a URL with no host.
pub fn server_host(server: &str) -> Result<String, String> {
    let after_scheme = server
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if host.is_empty() {
        return Err(format!("cluster URL '{server}' has no host"));
    }
    Ok(host.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const TOKEN_KUBECONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: prod
clusters:
  - name: prod-cluster
    cluster:
      server: https://prod.example.com:6443
      certificate-authority-data: cHJvZC1jYQ==
  - name: dev-cluster
    cluster:
      server: https://dev.example.com:6443
      insecure-skip-tls-verify: true
contexts:
  - name: prod
    context:
      cluster: prod-cluster
      user: prod-user
  - name: dev
    context:
      cluster: dev-cluster
      user: dev-user
users:
  - name: prod-user
    user:
      token: prod-bearer-token
  - name: dev-user
    user:
      exec:
        command: aws
        args:
          - eks
          - get-token
          - --cluster-name
          - dev
        env:
          - name: AWS_PROFILE
            value: dev
"#;

    #[test]
    fn current_context_resolves_a_token_user_with_inline_ca() {
        let ctx = parse_kubeconfig(TOKEN_KUBECONFIG, None).unwrap();
        assert_eq!(ctx.server, "https://prod.example.com:6443");
        assert_eq!(ctx.ca, ClusterCa::Data("cHJvZC1jYQ==".to_string()));
        assert!(!ctx.insecure);
        assert_eq!(ctx.auth, UserAuth::Token("prod-bearer-token".to_string()));
    }

    #[test]
    fn certificate_authority_data_base64_decodes() {
        let ctx = parse_kubeconfig(TOKEN_KUBECONFIG, None).unwrap();
        let ClusterCa::Data(data) = &ctx.ca else {
            panic!("expected inline CA data");
        };
        assert_eq!(decode_ca_data(data).unwrap(), b"prod-ca");
    }

    #[test]
    fn non_default_context_selects_an_exec_user_and_insecure() {
        let ctx = parse_kubeconfig(TOKEN_KUBECONFIG, Some("dev")).unwrap();
        assert_eq!(ctx.server, "https://dev.example.com:6443");
        assert!(ctx.insecure);
        assert_eq!(ctx.ca, ClusterCa::None);
        assert_eq!(
            ctx.auth,
            UserAuth::Exec(ExecAuth {
                command: "aws".to_string(),
                args: vec![
                    "eks".to_string(),
                    "get-token".to_string(),
                    "--cluster-name".to_string(),
                    "dev".to_string(),
                ],
                env: vec![("AWS_PROFILE".to_string(), "dev".to_string())],
            })
        );
    }

    #[test]
    fn missing_context_fails_closed() {
        let err = parse_kubeconfig(TOKEN_KUBECONFIG, Some("nope")).unwrap_err();
        assert!(err.contains("no context named 'nope'"), "{err}");
    }

    #[test]
    fn no_current_context_and_no_override_fails_closed() {
        let kc = r#"
apiVersion: v1
kind: Config
clusters: []
contexts: []
users: []
"#;
        let err = parse_kubeconfig(kc, None).unwrap_err();
        assert!(err.contains("no current-context"), "{err}");
    }

    #[test]
    fn certificate_authority_path_is_read_when_no_inline_data() {
        let kc = r#"
current-context: c
clusters:
  - name: cl
    cluster:
      server: https://x:6443
      certificate-authority: /etc/ca.pem
contexts:
  - name: c
    context: { cluster: cl, user: u }
users:
  - name: u
    user: { token: t }
"#;
        let ctx = parse_kubeconfig(kc, None).unwrap();
        assert_eq!(ctx.ca, ClusterCa::Path("/etc/ca.pem".to_string()));
    }

    #[test]
    fn user_with_no_supported_auth_fails_closed() {
        // client-cert mTLS only — deferred in v1.
        let kc = r#"
current-context: c
clusters:
  - name: cl
    cluster: { server: https://x:6443 }
contexts:
  - name: c
    context: { cluster: cl, user: u }
users:
  - name: u
    user:
      client-certificate-data: Zm9v
      client-key-data: YmFy
"#;
        let err = parse_kubeconfig(kc, None).unwrap_err();
        assert!(err.contains("no supported auth"), "{err}");
    }

    #[test]
    fn token_auth_maps_to_a_static_source() {
        let source = auth_to_source_json(&UserAuth::Token("abc".to_string()));
        assert_eq!(source["kind"], "static");
        assert_eq!(source["secret"], "abc");
    }

    #[test]
    fn exec_auth_maps_to_a_command_source_with_command_first_in_argv() {
        let source = auth_to_source_json(&UserAuth::Exec(ExecAuth {
            command: "aws".to_string(),
            args: vec!["eks".to_string(), "get-token".to_string()],
            // env is intentionally dropped (v1 limitation).
            env: vec![("AWS_PROFILE".to_string(), "dev".to_string())],
        }));
        assert_eq!(source["kind"], "command");
        assert_eq!(source["argv"][0], "aws");
        assert_eq!(source["argv"][1], "eks");
        assert_eq!(source["argv"][2], "get-token");
        // env is not threaded into the source.
        assert!(source.get("env").is_none());
        assert_eq!(source["argv"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn openapi_request_targets_v2_with_bearer_and_ca() {
        let req = build_openapi_request(
            "https://prod.example.com:6443/",
            "the-token",
            Some(b"-----BEGIN CERTIFICATE-----".to_vec()),
            false,
        );
        // Trailing slash trimmed, /openapi/v2 appended exactly once.
        assert_eq!(req.url, "https://prod.example.com:6443/openapi/v2");
        assert_eq!(req.authorization, "Bearer the-token");
        assert_eq!(
            req.ca_pem.as_deref(),
            Some(&b"-----BEGIN CERTIFICATE-----"[..])
        );
        assert!(!req.insecure);
    }

    #[test]
    fn openapi_request_carries_insecure_flag_and_no_ca() {
        let req = build_openapi_request("https://x:6443", "t", None, true);
        assert_eq!(req.url, "https://x:6443/openapi/v2");
        assert!(req.insecure);
        assert!(req.ca_pem.is_none());
    }

    #[test]
    fn server_host_strips_scheme_and_path_keeps_port() {
        assert_eq!(
            server_host("https://prod.example.com:6443/api").unwrap(),
            "prod.example.com:6443"
        );
        assert_eq!(server_host("https://x").unwrap(), "x");
        assert!(server_host("https://").is_err());
    }

    #[test]
    fn expansion_pins_rest_openapi_bearer_and_inlines_the_fetched_spec() {
        let spec = r#"{"openapi":"3.0.0","paths":{"/api/v1/namespaces/{namespace}/pods":{}}}"#;
        let json = expand_service_json(
            "k8s",
            "prod.example.com:6443",
            "https://prod.example.com:6443",
            spec,
            "k8s",
        );
        assert_eq!(json["name"], "k8s");
        assert_eq!(json["host"], "prod.example.com:6443");
        assert_eq!(json["upstreamBase"], "https://prod.example.com:6443");
        assert_eq!(json["protocol"], "rest");
        assert_eq!(json["idl"], "openapi");
        // The k8s preset hints `kubernetes` (the agent writes a kubeconfig).
        assert_eq!(json["toolHint"], "kubernetes");
        assert_eq!(json["outbound"]["kind"], "bearer");
        assert_eq!(json["outbound"]["credential"], "k8s");
        // The fetched spec rides inline.
        let inlined = json["specInline"].as_str().unwrap();
        assert!(inlined.contains("/api/v1/namespaces/{namespace}/pods"));
    }
}
