//! The HTTP data plane: an axum reverse proxy that drives [`Gateway`], plus a small
//! admin API for minting tokens.
//!
//! hackamore runs as a reverse proxy, not a transparent MITM: the agent is configured to
//! address hackamore directly and the sandbox (nono/Seatbelt/Landlock + netns) guarantees
//! hackamore is the *only* reachable destination, so the agent cannot bypass it. The agent
//! presents its hackamore token, never the real credential.
//!
//! By default the agent-facing listener is plaintext (the confined sandbox makes
//! interception a non-issue). When a deployment wants the consumer to terminate TLS at
//! hackamore and trust its certificate, [`serve`] takes an optional rustls config and the
//! proxy listener speaks HTTPS ([`serve_proxy_tls`]); the CA the consumer must trust rides
//! out in the provision doc as `hackamore_ca`. The admin API stays plaintext on its
//! localhost-only listener either way.

use crate::core::{ForwardPlan, Gateway, Outcome, ProxyRequest, Rejection};
use crate::import::{Importer, OpenApiImporter, SmithyImporter};
use crate::service::{Outbound, Protocol, Service};
use axum::Router;
use axum::body::Body;
use axum::extract::{Json, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use hackamore_models::apimodel::ApiModel;
use hackamore_models::control::{MintRequest, RevokeRequest, RevokeResponse};
use http::StatusCode;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

/// Maximum request body hackamore will buffer (25 MiB). Larger requests are rejected.
const MAX_BODY: usize = 25 * 1024 * 1024;

/// Maximum admin-API request body (64 MiB). The admin listener is operator/orchestrator
/// surface, not agent surface, and `POST /admin/services` carries inline API descriptions
/// (`specInline`) — the bundled GitHub OpenAPI alone is ~12 MiB — so the admin router needs a
/// far higher limit than axum's 2 MiB `Json` default.
const ADMIN_MAX_BODY: usize = 64 * 1024 * 1024;

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

/// The proxy router: every method and path is captured and run through the gateway,
/// except the reserved `/.hackamore/` prefix, which hackamore claims for its own
/// consumer-facing endpoints before Host-based service routing runs.
///
/// `GET /.hackamore/provision` serves the token-authenticated provision doc on the
/// agent-facing listener, so a sandboxed consumer whose *only* network egress is this
/// proxy can self-provision. It lives here and **only** here: the admin listener also
/// serves the unauthenticated `/mint`, so it must never be reachable from a sandbox.
/// Documented tradeoff: a hypothetical upstream path beginning with `/.hackamore/` is
/// shadowed by this reservation.
pub fn proxy_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/.hackamore/provision", get(provision_handler))
        .fallback(proxy_handler)
        .with_state(state)
}

/// The admin router: `POST /mint` issues a launch token for a submitted policy. Bind
/// this on a separate, localhost-only listener — it is operator/orchestrator surface,
/// not agent surface. Provisioning is served only from `/.hackamore/provision` on the
/// proxy listener (see [`proxy_router`]).
///
/// When the gateway's web UI is enabled (the default) the router also serves the
/// authoring surface: the embedded single-page UI under `/ui` and its endpoints —
/// `POST /policy/lint`, `POST /policy/test`. All of it returns 404 when disabled.
pub fn admin_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/mint", post(mint_handler))
        .route("/revoke", post(revoke_handler))
        .route("/policy/lint", post(policy_lint_handler))
        .route("/policy/test", post(policy_test_handler))
        .route(
            "/admin/services",
            get(list_services_handler).post(register_service_handler),
        )
        .route("/admin/services/:name", delete(remove_service_handler))
        .route(
            "/admin/credentials",
            get(list_credentials_handler).post(register_credential_handler),
        )
        .route("/ui", get(ui_index_handler))
        .route("/ui/app.js", get(ui_js_handler))
        .route("/ui/style.css", get(ui_css_handler))
        // Inline API descriptions (`specInline`) can be large (the bundled GitHub OpenAPI is
        // ~12 MiB); raise the admin body limit well above axum's 2 MiB `Json` default.
        .layer(axum::extract::DefaultBodyLimit::max(ADMIN_MAX_BODY))
        .with_state(state)
}

/// `POST /policy/lint` — lint a policy document against the configured services'
/// imported models (the same check minting enforces). Always 200 with the findings array.
async fn policy_lint_handler(
    State(state): State<Arc<ServerState>>,
    Json(policy): Json<hackamore_models::policy::Policy>,
) -> Response {
    if !state.gateway.web_ui() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(state.gateway.lint(&policy)).into_response()
}

/// `POST /policy/test` — dry-run one synthetic request through normalize + decide.
async fn policy_test_handler(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<hackamore_models::dryrun::TestRequest>,
) -> Response {
    if !state.gateway.web_ui() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.gateway.dry_run(&req) {
        Ok(resp) => Json(resp).into_response(),
        Err(err) => error_response(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

// --- live service registration (admin) ------------------------------------

/// Body of `POST /admin/services` — register a service from an API description (an OpenAPI
/// or Smithy doc), supplied as a URL or a file path, plus its outbound auth. hackamore
/// imports the description into an [`ApiModel`], derives the wire protocol from it, and adds
/// the service to the live routing table.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterServiceRequest {
    name: String,
    /// Inbound `Host`-header routing pattern. Optional — defaults to the hostname of
    /// `upstream_base` (the common case where the agent addresses the real upstream host).
    #[serde(default)]
    host: Option<String>,
    upstream_base: String,
    /// "openapi" | "smithy". Optional: a model-less service (e.g. a `git-http` service whose
    /// vocabulary is the custom normalizer, not an imported spec) supplies a `protocol`
    /// instead and omits both `idl` and any source.
    #[serde(default)]
    idl: Option<String>,
    /// The description location — exactly one when `idl` is present.
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    source_file: Option<String>,
    /// Raw description **text supplied inline** (the bytes themselves), imported with the
    /// `idl` importer — the same code path as `source_file`, just bytes-in-hand. CLI presets
    /// send their bundled spec this way. Mutually exclusive with `source_file`/`source_url`.
    #[serde(default)]
    spec_inline: Option<String>,
    /// A pre-built [`ApiModel`] supplied inline as JSON — deserialized directly, no import.
    /// CLI presets that hardcode their vocabulary (e.g. `github-git`) send the model this way.
    /// Mutually exclusive with every other source and with `idl`.
    #[serde(default)]
    model_inline: Option<ApiModel>,
    /// The wire protocol name for a model-less service, e.g. "git-http" (also "rest" /
    /// "aws-query" / "aws-json"). Ignored when `idl` is present — the imported model declares
    /// its own protocol. Absent + no model defaults to `rest`.
    #[serde(default)]
    protocol: Option<String>,
    /// Consumer-facing address surfaced in the provision doc (optional).
    #[serde(default)]
    address: Option<String>,
    /// The agent tool-config hint surfaced in the provision doc (`github` | `git` | `aws` |
    /// `kubernetes` | `generic`) — which native tool config the agent writes for this service.
    /// Optional; absent defaults to `generic` (no native tool files). The CLI presets set it.
    #[serde(default)]
    tool_hint: Option<String>,
    /// Outbound auth stance (default passthrough).
    #[serde(default)]
    outbound: OutboundSpec,
}

/// The outbound auth stance for `POST /admin/services` — every stance hackamore supports.
/// Each injecting stance resolves its credential one of two mutually exclusive ways: an
/// inline `secret` (the **actual** token / key, vaulted under the service's name, stored as
/// a `Secret` and never echoed back) **or** a `credential` reference (the id of a credential
/// already in the vault, registered separately via `POST /admin/credentials`). Supplying
/// both or neither for an injecting stance is rejected (fail closed). `passthrough` takes
/// neither.
#[derive(serde::Deserialize, Default)]
#[serde(tag = "kind")]
enum OutboundSpec {
    #[default]
    #[serde(rename = "passthrough")]
    Passthrough,
    #[serde(rename = "bearer")]
    Bearer {
        #[serde(default)]
        secret: Option<String>,
        #[serde(default)]
        credential: Option<String>,
    },
    #[serde(rename = "header")]
    Header {
        name: String,
        #[serde(default)]
        secret: Option<String>,
        #[serde(default)]
        credential: Option<String>,
    },
    #[serde(rename = "basic")]
    Basic {
        username: String,
        #[serde(default)]
        secret: Option<String>,
        #[serde(default)]
        credential: Option<String>,
    },
    /// SigV4 references an AWS *bundle* (akid + secret + optional session token), which can't
    /// be pasted as one inline string, so it takes a `credential` reference only — register
    /// the bundle via `POST /admin/credentials` (an `aws-static`/`assume-role`/`instance`
    /// source) first. The access key id rides in the bundle, not here.
    #[serde(rename = "sigv4")]
    Sigv4 {
        credential: String,
        region: String,
        service: String,
    },
}

/// Resolve an injecting stance's credential id: vault the inline `secret` under `cred_id`,
/// or reference an existing `credential` id directly. Exactly one of the two is required —
/// both or neither is a configuration error (fail closed). Vaulting can also fail when the
/// store rejects runtime secrets (a minting/static store).
fn resolve_credential(
    secret: Option<String>,
    credential: Option<String>,
    cred_id: &str,
    gateway: &Gateway,
) -> Result<String, String> {
    match (secret, credential) {
        (Some(_), Some(_)) => Err(
            "supply exactly one of `secret` (inline) or `credential` (an existing vault id), \
             not both"
                .to_string(),
        ),
        (None, None) => Err(
            "an injecting outbound stance needs either an inline `secret` or a `credential` \
             reference"
                .to_string(),
        ),
        (Some(secret), None) => {
            if gateway.vault_secret(cred_id.to_string(), hackamore_control::Secret::new(secret)) {
                Ok(cred_id.to_string())
            } else {
                Err(
                    "this server's credential store does not accept secrets at runtime; \
                     register the credential via POST /admin/credentials and reference it by id"
                        .to_string(),
                )
            }
        }
        (None, Some(reference)) => {
            if reference.trim().is_empty() {
                Err("`credential` reference must not be empty".to_string())
            } else {
                Ok(reference)
            }
        }
    }
}

/// Turn an [`OutboundSpec`] into an [`Outbound`], resolving each injecting stance's
/// credential (inline-and-vaulted under `cred_id`, or an existing vault id reference).
fn outbound_from_spec(
    spec: OutboundSpec,
    cred_id: &str,
    gateway: &Gateway,
) -> Result<Outbound, String> {
    Ok(match spec {
        OutboundSpec::Passthrough => Outbound::Passthrough,
        OutboundSpec::Bearer { secret, credential } => Outbound::Bearer {
            credential: resolve_credential(secret, credential, cred_id, gateway)?,
        },
        OutboundSpec::Header {
            name,
            secret,
            credential,
        } => Outbound::Header {
            name,
            credential: resolve_credential(secret, credential, cred_id, gateway)?,
        },
        OutboundSpec::Basic {
            username,
            secret,
            credential,
        } => Outbound::Basic {
            username,
            credential: resolve_credential(secret, credential, cred_id, gateway)?,
        },
        OutboundSpec::Sigv4 {
            credential,
            region,
            service,
        } => {
            if credential.trim().is_empty() {
                return Err("`credential` reference must not be empty".to_string());
            }
            Outbound::SigV4 {
                credential,
                region,
                service,
            }
        }
    })
}

// --- credential registration (admin) --------------------------------------

/// Body of `POST /admin/credentials` — register a credential under `id`, resolved from a
/// **source** (the Source axis: where hackamore obtains the real material). The resolved
/// secret is stored in the vault under `id`; services reference it by id via their outbound
/// stance. The secret is never echoed back.
#[derive(serde::Deserialize)]
struct RegisterCredentialRequest {
    id: String,
    source: CredentialSource,
}

/// The base AWS credential an `assume-role`/`instance` source signs with: an explicit
/// static key pair, or the hackamore host's environment chain
/// (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`). Tagged by `kind`.
#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum AwsBase {
    /// An explicit static base key pair (optionally a session token).
    Static {
        access_key_id: String,
        secret_access_key: String,
        #[serde(default)]
        session_token: Option<String>,
    },
    /// Read the base from the hackamore host's `AWS_*` environment variables.
    Env,
}

impl AwsBase {
    /// Resolve to a base [`AwsCredential`], or an error (fail closed). The base has no expiry
    /// (it only signs the AssumeRole request).
    fn resolve(self) -> Result<hackamore_control::AwsCredential, String> {
        match self {
            AwsBase::Static {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                if access_key_id.is_empty() || secret_access_key.is_empty() {
                    return Err("static base needs access_key_id and secret_access_key".into());
                }
                Ok(hackamore_control::AwsCredential {
                    access_key_id,
                    secret_access_key: hackamore_control::Secret::new(secret_access_key),
                    session_token: session_token.map(hackamore_control::Secret::new),
                    expires_at_ms: None,
                })
            }
            AwsBase::Env => {
                let akid = std::env::var("AWS_ACCESS_KEY_ID")
                    .map_err(|_| "AWS_ACCESS_KEY_ID is not set".to_string())?;
                let sak = std::env::var("AWS_SECRET_ACCESS_KEY")
                    .map_err(|_| "AWS_SECRET_ACCESS_KEY is not set".to_string())?;
                if akid.is_empty() || sak.is_empty() {
                    return Err("AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are empty".into());
                }
                let token = std::env::var("AWS_SESSION_TOKEN")
                    .ok()
                    .filter(|t| !t.is_empty());
                Ok(hackamore_control::AwsCredential {
                    access_key_id: akid,
                    secret_access_key: hackamore_control::Secret::new(sak),
                    session_token: token.map(hackamore_control::Secret::new),
                    expires_at_ms: None,
                })
            }
        }
    }
}

/// A credential source. Tagged by `kind`. Token-shaped sources (`static`/`env`/`file`/
/// `command`) resolve to one [`Secret`]; AWS sources resolve to an [`AwsCredential`] bundle
/// (`aws-static`) or register an AWS-bundle minting provider (`assume-role`/`instance`).
///
/// [`Secret`]: hackamore_control::Secret
/// [`AwsCredential`]: hackamore_control::AwsCredential
#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CredentialSource {
    /// A pasted secret, vaulted as-is.
    Static { secret: String },
    /// An environment variable on the hackamore host.
    Env { var: String },
    /// A file path on the hackamore host; its trimmed contents are the secret.
    File { path: String },
    /// A command run on the hackamore host; its trimmed stdout is the secret (e.g.
    /// `["gh", "auth", "token"]`).
    Command { argv: Vec<String> },
    /// A static AWS credential bundle (akid + secret + optional session token), vaulted as an
    /// AWS bundle. For static IAM-user keys, omit the session token.
    AwsStatic {
        access_key_id: String,
        secret_access_key: String,
        #[serde(default)]
        session_token: Option<String>,
    },
    /// STS `AssumeRole`: an AWS-bundle minting provider signed with `base`.
    AssumeRole {
        role_arn: String,
        region: String,
        #[serde(default)]
        role_session_name: Option<String>,
        /// The STS endpoint host; defaults to `sts.amazonaws.com`.
        #[serde(default)]
        sts_endpoint: Option<String>,
        base: AwsBase,
    },
    /// The host AWS credential chain. v1 reads the `AWS_*` environment variables and vaults a
    /// static bundle from them (IMDS/profile resolution is deferred).
    Instance,
}

/// What a resolved [`CredentialSource`] produces: a token-shaped secret, a static AWS bundle,
/// or an AWS-bundle minting provider. Keeps each kind's vaulting path distinct in the handler.
enum Resolved {
    Token(String),
    Aws(hackamore_control::AwsCredential),
    AwsProvider(Arc<dyn hackamore_control::AwsCredentialProvider>),
}

impl CredentialSource {
    /// Resolve this source to its material (fail closed on any error). Token sources read the
    /// host (env/file/command) or echo the pasted value; `aws-static`/`instance` build a
    /// bundle; `assume-role` builds a minting provider.
    fn resolve(self) -> Result<Resolved, String> {
        match self {
            CredentialSource::Static { secret } => {
                if secret.is_empty() {
                    Err("static source `secret` must not be empty".to_string())
                } else {
                    Ok(Resolved::Token(secret))
                }
            }
            CredentialSource::Env { var } => {
                let value =
                    std::env::var(&var).map_err(|_| format!("env var '{var}' is not set"))?;
                if value.is_empty() {
                    Err(format!("env var '{var}' is empty"))
                } else {
                    Ok(Resolved::Token(value))
                }
            }
            CredentialSource::File { path } => {
                let contents = std::fs::read_to_string(&path)
                    .map_err(|e| format!("read credential file '{path}': {e}"))?;
                let trimmed = contents.trim();
                if trimmed.is_empty() {
                    Err(format!("credential file '{path}' is empty"))
                } else {
                    Ok(Resolved::Token(trimmed.to_string()))
                }
            }
            CredentialSource::Command { argv } => {
                let Some((program, args)) = argv.split_first() else {
                    return Err("command source `argv` must not be empty".to_string());
                };
                let output = std::process::Command::new(program)
                    .args(args)
                    .output()
                    .map_err(|e| format!("run command '{program}': {e}"))?;
                if !output.status.success() {
                    return Err(format!("command '{program}' exited with {}", output.status));
                }
                let stdout = String::from_utf8(output.stdout)
                    .map_err(|e| format!("command '{program}' produced non-UTF-8 output: {e}"))?;
                let trimmed = stdout.trim();
                if trimmed.is_empty() {
                    Err(format!("command '{program}' produced no output"))
                } else {
                    Ok(Resolved::Token(trimmed.to_string()))
                }
            }
            CredentialSource::AwsStatic {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                if access_key_id.is_empty() || secret_access_key.is_empty() {
                    return Err(
                        "aws-static needs `access_key_id` and `secret_access_key`".to_string()
                    );
                }
                Ok(Resolved::Aws(hackamore_control::AwsCredential {
                    access_key_id,
                    secret_access_key: hackamore_control::Secret::new(secret_access_key),
                    session_token: session_token.map(hackamore_control::Secret::new),
                    expires_at_ms: None,
                }))
            }
            CredentialSource::AssumeRole {
                role_arn,
                region,
                role_session_name,
                sts_endpoint,
                base,
            } => {
                if role_arn.is_empty() || region.is_empty() {
                    return Err("assume-role needs `role_arn` and `region`".to_string());
                }
                let base = base.resolve()?;
                let provider = hackamore_control::AssumeRoleProvider {
                    base,
                    role_arn,
                    role_session_name: role_session_name.unwrap_or_else(|| "hackamore".to_string()),
                    region,
                    sts_endpoint: sts_endpoint.unwrap_or_else(|| "sts.amazonaws.com".to_string()),
                    client: reqwest::Client::new(),
                };
                Ok(Resolved::AwsProvider(Arc::new(provider)))
            }
            CredentialSource::Instance => {
                // v1: the instance chain is the host `AWS_*` environment, vaulted static.
                Ok(Resolved::Aws(AwsBase::Env.resolve()?))
            }
        }
    }
}

/// `POST /admin/credentials` — resolve a source to a secret and vault it under `id`. Returns
/// 201 with `{ "id": "..." }` (never the secret). A source that won't resolve is a 400; a
/// store that doesn't accept runtime insertion is a 409. Fail closed on any error.
async fn register_credential_handler(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<RegisterCredentialRequest>,
) -> Response {
    if req.id.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "credential `id` must not be empty");
    }
    let id = req.id.clone();
    let resolved = match req.source.resolve() {
        Ok(r) => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
    };
    // Each kind has its own runtime-vaulting path. A store that rejects the kind (a static
    // `InMemoryCredentials` can't host an AWS *provider*) answers 409 — fail closed, and never
    // echo any secret.
    let stored = match resolved {
        Resolved::Token(secret) => state
            .gateway
            .vault_secret(id.clone(), hackamore_control::Secret::new(secret)),
        Resolved::Aws(cred) => state.gateway.vault_aws(id.clone(), cred),
        Resolved::AwsProvider(provider) => {
            state.gateway.register_aws_provider(id.clone(), provider)
        }
    };
    if stored {
        (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response()
    } else {
        error_response(
            StatusCode::CONFLICT,
            "this server's credential store does not accept this credential source at runtime; \
             an assume-role/instance source requires a minting-capable store",
        )
    }
}

/// `GET /admin/credentials` — list the known credential ids (never secrets).
async fn list_credentials_handler(State(state): State<Arc<ServerState>>) -> Response {
    Json(serde_json::json!({ "ids": state.gateway.credential_ids() })).into_response()
}

/// The inbound `Host` routing pattern for a service: an explicit `host`, else the hostname
/// of `upstream_base` (scheme + path + port stripped).
fn host_or_default(host: Option<String>, upstream_base: &str) -> String {
    match host {
        Some(h) if !h.trim().is_empty() => h,
        _ => {
            let after_scheme = upstream_base.split("://").nth(1).unwrap_or(upstream_base);
            let host = after_scheme.split('/').next().unwrap_or(after_scheme);
            host.split(':').next().unwrap_or(host).to_string()
        }
    }
}

/// Read an API description from a URL or a file path (exactly one required).
async fn fetch_description(
    client: &reqwest::Client,
    url: Option<&str>,
    file: Option<&str>,
) -> Result<Vec<u8>, String> {
    match (url, file) {
        (Some(u), None) => {
            let resp = client
                .get(u)
                .send()
                .await
                .map_err(|e| format!("fetch {u}: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("fetch {u}: HTTP {}", resp.status()));
            }
            resp.bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| format!("read {u}: {e}"))
        }
        (None, Some(f)) => tokio::fs::read(f)
            .await
            .map_err(|e| format!("read {f}: {e}")),
        _ => Err("exactly one of sourceUrl or sourceFile is required".to_string()),
    }
}

/// Resolve a service's [`ApiModel`] from the request's mutually-exclusive sources (fail
/// closed). At most one source may be supplied:
/// - `model_inline` — a pre-built model, deserialized directly (no import, no `idl`).
/// - an imported description (`source_file` / `source_url` / `spec_inline`) with `idl` — the
///   bytes are fetched/read/taken inline and run through the matching importer.
/// - none — a model-less service (its `protocol` field drives normalization).
///
/// More than one source, or `idl` without a description (or a description without `idl`), is a
/// configuration error.
async fn resolve_model(
    client: &reqwest::Client,
    req: &RegisterServiceRequest,
) -> Result<Option<ApiModel>, String> {
    let description_sources = usize::from(req.source_file.is_some())
        + usize::from(req.source_url.is_some())
        + usize::from(req.spec_inline.is_some());
    let total_sources = description_sources + usize::from(req.model_inline.is_some());
    if total_sources > 1 {
        return Err(
            "supply at most one model source: sourceFile, sourceUrl, specInline, or modelInline"
                .to_string(),
        );
    }
    if let Some(model) = &req.model_inline {
        if req.idl.is_some() {
            return Err("modelInline is a pre-built model; do not also pass `idl`".to_string());
        }
        return Ok(Some(model.clone()));
    }
    match (req.idl.as_deref(), description_sources) {
        (Some(idl), 1) => {
            // Inline text needs no fetch; file/URL go through the shared reader.
            let raw = match &req.spec_inline {
                Some(text) => text.clone().into_bytes(),
                None => {
                    fetch_description(
                        client,
                        req.source_url.as_deref(),
                        req.source_file.as_deref(),
                    )
                    .await?
                }
            };
            import_description(idl, &raw).map(Some)
        }
        (Some(_), 0) => {
            Err("`idl` needs a description: sourceFile, sourceUrl, or specInline".to_string())
        }
        (None, 1) => {
            Err("a description (sourceFile/sourceUrl/specInline) needs an `idl`".to_string())
        }
        // No idl and no description → a model-less service.
        (None, _) => Ok(None),
        // `idl` is set but somehow >1 description survived the earlier guard — unreachable.
        (Some(_), _) => Err("at most one description source is allowed".to_string()),
    }
}

/// Import raw description bytes with the importer for `idl`.
fn import_description(idl: &str, raw: &[u8]) -> Result<ApiModel, String> {
    let result = match idl.to_ascii_lowercase().as_str() {
        "openapi" => OpenApiImporter.import(raw),
        "smithy" => SmithyImporter.import(raw),
        other => return Err(format!("unknown idl '{other}' (known: openapi, smithy)")),
    };
    result.map_err(|e| e.to_string())
}

/// `POST /admin/services` — fetch + import a description and register the service live. Fail
/// closed: a description that won't fetch or import is a 400 and nothing is registered. The
/// imported model drives the wire protocol, so RPC services (AWS) normalize correctly with
/// no extra config.
async fn register_service_handler(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<RegisterServiceRequest>,
) -> Response {
    // Resolve the service's vocabulary from at most one source: an imported description
    // (fetched URL / read file / inline text, via the `idl` importer) or a pre-built model
    // supplied inline. A model-less service declares a `protocol` directly (e.g. git-http,
    // whose vocabulary is the custom normalizer, not an importable spec).
    let model = match resolve_model(&state.client, &req).await {
        Ok(m) => m,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
    };
    let name = req.name.clone();
    // A model declares its own protocol; a model-less service takes the explicit `protocol`
    // field (defaulting to rest).
    let protocol = match &model {
        Some(m) => Protocol::from(m),
        None => Protocol::parse(req.protocol.as_deref()),
    };
    // A git-http service with no model still gets the hardcoded git vocabulary (its two ops +
    // the `repo` resource) so lint / discovery / the studio have something to enumerate — the
    // request→Action mapping remains the custom normalizer, the model is advisory.
    let model = match model {
        None if protocol == Protocol::Git => Some(crate::import::git_model()),
        other => other,
    };
    let host = host_or_default(req.host, &req.upstream_base);
    let outbound = match outbound_from_spec(req.outbound, &name, &state.gateway) {
        Ok(o) => o,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
    };
    let mut service = Service::new(req.name, host, req.upstream_base).with_outbound(outbound);
    if let Some(m) = model.clone() {
        service = service.with_model(m);
    }
    if let Some(addr) = req.address {
        service = service.with_address(addr);
    }
    if let Some(hint) = req.tool_hint {
        service = service.with_tool_hint(hint);
    }
    service.extract.protocol = protocol;
    let replaced = state.gateway.register_service(service);
    let status = if replaced {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (
        status,
        Json(serde_json::json!({ "name": name, "replaced": replaced, "model": model })),
    )
        .into_response()
}

/// `GET /admin/services` — the live service registry, each with its imported model.
async fn list_services_handler(State(state): State<Arc<ServerState>>) -> Response {
    Json(state.gateway.registered_services()).into_response()
}

/// `DELETE /admin/services/:name` — remove a registered service from the live registry.
async fn remove_service_handler(
    State(state): State<Arc<ServerState>>,
    Path(name): Path<String>,
) -> Response {
    let removed = state.gateway.remove_service(&name);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "removed": removed })),
    )
        .into_response()
}

/// The embedded web UI: a dependency-light single-page app compiled into the binary,
/// so `hackamore serve` needs no asset directory.
async fn ui_index_handler(State(state): State<Arc<ServerState>>) -> Response {
    ui_asset(&state, "text/html; charset=utf-8", WEBUI_INDEX)
}

async fn ui_js_handler(State(state): State<Arc<ServerState>>) -> Response {
    ui_asset(&state, "application/javascript; charset=utf-8", WEBUI_JS)
}

async fn ui_css_handler(State(state): State<Arc<ServerState>>) -> Response {
    ui_asset(&state, "text/css; charset=utf-8", WEBUI_CSS)
}

fn ui_asset(state: &ServerState, content_type: &'static str, body: &'static str) -> Response {
    if !state.gateway.web_ui() {
        return StatusCode::NOT_FOUND.into_response();
    }
    ([(http::header::CONTENT_TYPE, content_type)], body).into_response()
}

const WEBUI_INDEX: &str = include_str!("webui/index.html");
const WEBUI_JS: &str = include_str!("webui/app.js");
const WEBUI_CSS: &str = include_str!("webui/style.css");

/// Serve both routers until shutdown: the proxy on `proxy_addr`, the admin API on
/// `admin_addr`. When `tls` is `Some`, the agent-facing proxy listener terminates TLS with
/// that rustls config (the consumer-trusts-hackamore's-cert model); the admin API always
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
    tracing::info!(%proxy_addr, %admin_addr, proxy_scheme = scheme, "hackamore listening");

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
    // configured, the `X-Hackamore-Tenant` credential must own every target the policy names
    // (fail closed); single-trust-domain deployments leave tenancy unconfigured (open).
    let tenant = headers
        .get("x-hackamore-tenant")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty());
    match state
        .gateway
        .mint_checked(req.policy, req.ttl_seconds, tenant)
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        // A lint rejection carries structured findings so the author (or the web UI) can
        // see every problem at once, not just the first.
        Err(crate::core::MintError::PolicyLint(findings)) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "policy failed lint",
                "findings": findings,
            })),
        )
            .into_response(),
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

/// The provision endpoint — return the consumer-setup bundle for the presented hackamore
/// token (in `X-Hackamore-Token` or `Authorization`). The doc carries no real upstream
/// secrets, and the handler authenticates purely from headers. It is mounted only on
/// the proxy listener at `GET /.hackamore/provision` — the one address a sandbox can reach.
async fn provision_handler(
    State(state): State<Arc<ServerState>>,
    headers: http::HeaderMap,
) -> Response {
    let Some(token) = crate::core::token_from_headers(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "missing hackamore token");
    };
    match state.gateway.provision(&token) {
        Some(doc) => (StatusCode::OK, Json(doc)).into_response(),
        None => error_response(
            StatusCode::UNAUTHORIZED,
            "unknown or expired hackamore token",
        ),
    }
}

/// Execute the planned upstream request and relay the response back to the agent.
///
/// The response body is **streamed**, never buffered, so Server-Sent Events, chunked
/// responses, and long-polls flow through hackamore transparently. (The request body is
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
