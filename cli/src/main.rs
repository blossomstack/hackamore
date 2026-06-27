//! `hackamore` — the CLI entry point.
//!
//! `hackamore serve --config <file>` starts the reverse proxy + admin API from a config
//! file. `hackamore mint --admin-url <url> --policy <file> --ttl <secs>` calls a running
//! server's admin API to issue a launch token bound to that policy (handy for manual
//! testing; in production the orchestrator calls the admin API directly).

use clap::{Parser, Subcommand};
use hackamore_cli::config::{Config, DescriptionConfig, OutboundConfig};
use hackamore_control::{ControlPlane, InMemoryCredentials, Secret, TracingAudit};
use hackamore_gateway::{
    ActionCatalog, Extract, Gateway, Importer, OpenApiImporter, Outbound, Protocol, Service,
    ServiceRouter, SmithyImporter, TlsMaterial,
};
use hackamore_models::control::{MintRequest, MintResponse};
use hackamore_models::policy::Policy;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "hackamore",
    about = "JIT, policy-scoped access for untrusted agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the reverse proxy and admin API.
    Serve(ServeArgs),
    /// Mint a launch token bound to a policy file, via a running server's admin API.
    Mint(MintArgs),
    /// Validate and dry-run policy documents offline (no server needed).
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Register and inspect credentials on a running server's admin API (the Source axis).
    Credentials {
        #[command(subcommand)]
        command: CredentialsCommand,
    },
    /// Register services on a running server's admin API (the Injection axis).
    Services {
        #[command(subcommand)]
        command: ServicesCommand,
    },
}

#[derive(Subcommand)]
enum CredentialsCommand {
    /// Register a credential under `id`, resolved from a source, via `POST /admin/credentials`.
    Add(Box<CredentialsAddArgs>),
}

#[derive(Subcommand)]
enum ServicesCommand {
    /// Register a service from an API description, via `POST /admin/services`. Its outbound
    /// stance may reference an existing credential id (`--credential`) or carry an inline
    /// secret (`--secret`).
    Add(Box<ServicesAddArgs>),
}

/// How a credential's real material is sourced.
///
/// Token-shaped sources are a single mutually-exclusive flag (`--secret`/`--env`/`--file`/
/// `--command`). AWS sources are selected with `--source <aws-static|assume-role|instance>`
/// and carry their own parameter flags. Exactly one source overall is required.
#[derive(clap::Args)]
struct SourceArgs {
    /// A pasted secret, vaulted as-is.
    #[arg(long)]
    secret: Option<String>,
    /// An environment variable on the hackamore host.
    #[arg(long)]
    env: Option<String>,
    /// A file on the hackamore host; its trimmed contents are the secret.
    #[arg(long)]
    file: Option<String>,
    /// A command on the hackamore host; its trimmed stdout is the secret. Pass the whole
    /// command as one string, split on whitespace (e.g. `--command "gh auth token"`).
    #[arg(long)]
    command: Option<String>,
    /// An AWS source kind: `aws-static`, `assume-role`, or `instance`.
    #[arg(long)]
    source: Option<String>,
    /// AWS access key id (for `--source aws-static`).
    #[arg(long)]
    access_key_id: Option<String>,
    /// AWS secret access key (for `--source aws-static`).
    #[arg(long)]
    secret_access_key: Option<String>,
    /// AWS session token (optional, for `--source aws-static`).
    #[arg(long)]
    session_token: Option<String>,
    /// Role ARN to assume (for `--source assume-role`).
    #[arg(long)]
    role_arn: Option<String>,
    /// AWS region (for `--source assume-role`).
    #[arg(long)]
    region: Option<String>,
    /// Base credential for `--source assume-role`: `env` (host `AWS_*` vars) or `instance`
    /// (alias of `env`). Defaults to `env`.
    #[arg(long, default_value = "env")]
    base: String,
}

impl SourceArgs {
    /// Build the `source` JSON for `POST /admin/credentials` from whichever flag was given.
    /// Exactly one source must be supplied across the token flags and `--source`.
    fn to_source_json(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let token_flags = [&self.secret, &self.env, &self.file, &self.command]
            .iter()
            .filter(|f| f.is_some())
            .count();
        if token_flags + usize::from(self.source.is_some()) != 1 {
            return Err(
                "exactly one source is required: one of --secret/--env/--file/--command or \
                 --source <aws-static|assume-role|instance>"
                    .into(),
            );
        }
        if let Some(source) = &self.source {
            return self.to_aws_source_json(source);
        }
        match (&self.secret, &self.env, &self.file, &self.command) {
            (Some(secret), None, None, None) => {
                Ok(serde_json::json!({ "kind": "static", "secret": secret }))
            }
            (None, Some(var), None, None) => Ok(serde_json::json!({ "kind": "env", "var": var })),
            (None, None, Some(path), None) => {
                Ok(serde_json::json!({ "kind": "file", "path": path }))
            }
            (None, None, None, Some(command)) => {
                let argv: Vec<&str> = command.split_whitespace().collect();
                if argv.is_empty() {
                    return Err("--command must not be empty".into());
                }
                Ok(serde_json::json!({ "kind": "command", "argv": argv }))
            }
            _ => Err("exactly one of --secret/--env/--file/--command is required".into()),
        }
    }

    /// Build the `source` JSON for an AWS `--source <kind>`.
    fn to_aws_source_json(
        &self,
        kind: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        match kind {
            "aws-static" => {
                let akid = self
                    .access_key_id
                    .clone()
                    .ok_or("--source aws-static needs --access-key-id")?;
                let sak = self
                    .secret_access_key
                    .clone()
                    .ok_or("--source aws-static needs --secret-access-key")?;
                let mut spec = serde_json::json!({
                    "kind": "aws-static",
                    "access_key_id": akid,
                    "secret_access_key": sak,
                });
                if let Some(token) = &self.session_token {
                    spec["session_token"] = serde_json::Value::String(token.clone());
                }
                Ok(spec)
            }
            "assume-role" => {
                let role_arn = self
                    .role_arn
                    .clone()
                    .ok_or("--source assume-role needs --role-arn")?;
                let region = self
                    .region
                    .clone()
                    .ok_or("--source assume-role needs --region")?;
                // `instance` is an alias for the host env chain as the signing base.
                let base = match self.base.as_str() {
                    "env" | "instance" => serde_json::json!({ "kind": "env" }),
                    other => return Err(format!("unknown --base '{other}' (env|instance)").into()),
                };
                Ok(serde_json::json!({
                    "kind": "assume-role",
                    "role_arn": role_arn,
                    "region": region,
                    "base": base,
                }))
            }
            "instance" => Ok(serde_json::json!({ "kind": "instance" })),
            other => {
                Err(format!("unknown --source '{other}' (aws-static|assume-role|instance)").into())
            }
        }
    }
}

#[derive(clap::Args)]
struct CredentialsAddArgs {
    /// Base URL of the admin API, e.g. http://127.0.0.1:9091
    #[arg(long)]
    admin_url: String,
    /// The credential id to register the resolved secret under.
    id: String,
    #[command(flatten)]
    source: SourceArgs,
}

#[derive(clap::Args)]
struct ServicesAddArgs {
    /// Base URL of the admin API, e.g. http://127.0.0.1:9091
    #[arg(long)]
    admin_url: String,
    /// A preset name (`github-api`, `github-git`, `aws:<svc>`) or a logical service name for a
    /// generic registration. A preset pins host/upstream/protocol/model/injection; you supply
    /// only the credential (`--credential` or `--auth-source`). A non-preset name falls through
    /// to the generic registration (`--upstream-base` + `--openapi`/`--smithy` + `--inject`).
    name: String,
    /// Upstream base URL, e.g. https://api.github.com (generic registration; pinned by presets).
    #[arg(long)]
    upstream_base: Option<String>,
    /// Inbound Host routing pattern (defaults to the upstream host).
    #[arg(long)]
    host: Option<String>,
    /// "openapi" | "smithy".
    #[arg(long, default_value = "openapi")]
    idl: String,
    /// Path to the API description file.
    #[arg(long)]
    source_file: Option<String>,
    /// URL to fetch the API description from.
    #[arg(long)]
    source_url: Option<String>,
    /// Consumer-facing address surfaced in the provision doc.
    #[arg(long)]
    address: Option<String>,
    /// Outbound injection: passthrough | bearer | header | basic | sigv4.
    #[arg(long, default_value = "passthrough")]
    inject: String,
    /// Reference an existing vault credential id. For a preset, the credential the service
    /// references (mutually exclusive with --auth-source); generically, mutually exclusive
    /// with --secret.
    #[arg(long)]
    credential: Option<String>,
    /// Inline secret to vault under the service name (generic; mutually exclusive with
    /// --credential).
    #[arg(long)]
    secret: Option<String>,
    /// Header name for `--inject header`.
    #[arg(long, default_value = "X-API-Key")]
    header_name: String,
    /// Username for `--inject basic`.
    #[arg(long, default_value = "x-access-token")]
    username: String,
    /// AWS access key id for `--inject sigv4`.
    #[arg(long)]
    access_key_id: Option<String>,
    /// AWS region. For an `aws:<svc>` preset this pins the host + signature region (defaults to
    /// us-east-1); generically it is the `--inject sigv4` region.
    #[arg(long)]
    region: Option<String>,
    /// AWS service for `--inject sigv4`.
    #[arg(long)]
    service: Option<String>,
    /// For a preset: register a credential from a source first (id defaults to the preset
    /// name), then reference it. The convenience over `--credential`. Names a source kind:
    /// `gh-token` (github → `gh auth token`), or any `POST /admin/credentials` kind
    /// (`static`/`env`/`file`/`command`/`aws-static`/`assume-role`/`instance`). Mutually
    /// exclusive with `--credential`.
    #[arg(long)]
    auth_source: Option<String>,
    /// Override the credential id `--auth-source` registers under (defaults to the preset name).
    #[arg(long)]
    auth_id: Option<String>,
    #[command(flatten)]
    source_params: SourceParams,
    #[command(flatten)]
    k8s: K8sArgs,
}

/// Connection parameters for the `k8s` preset. The cluster URL / token / CA are resolved with
/// explicit flags overriding the kubeconfig; the kubeconfig path + context locate the rest.
/// Only read when `name == "k8s"`; ignored by every other preset and the generic path.
#[derive(clap::Args)]
struct K8sArgs {
    /// Cluster API server URL (overrides the kubeconfig `cluster.server`).
    #[arg(long)]
    cluster: Option<String>,
    /// Path to the kubeconfig (defaults to `$KUBECONFIG`, else `~/.kube/config`).
    #[arg(long)]
    kubeconfig: Option<String>,
    /// kubeconfig context name (defaults to the file's `current-context`).
    #[arg(long)]
    context: Option<String>,
    /// Bearer token to authenticate the OpenAPI fetch (overrides the kubeconfig user auth).
    #[arg(long)]
    token: Option<String>,
    /// Path to the cluster CA PEM (overrides the kubeconfig `certificate-authority[-data]`).
    #[arg(long)]
    ca: Option<String>,
    /// Skip TLS verification when fetching the OpenAPI (insecure; also read from the context).
    #[arg(long)]
    insecure_skip_tls_verify: bool,
}

/// Parameters carried by `--auth-source <kind>` for a preset, mirroring the credential source
/// flags. Only the fields the chosen kind needs are read; unused flags are ignored.
#[derive(clap::Args)]
struct SourceParams {
    /// Secret for `--auth-source static`.
    #[arg(long = "auth-secret")]
    auth_secret: Option<String>,
    /// Env var for `--auth-source env`.
    #[arg(long = "auth-env")]
    auth_env: Option<String>,
    /// File path for `--auth-source file`.
    #[arg(long = "auth-file")]
    auth_file: Option<String>,
    /// Command (whitespace-split) for `--auth-source command`.
    #[arg(long = "auth-command")]
    auth_command: Option<String>,
    /// Secret access key for `--auth-source aws-static` (akid comes from `--access-key-id`).
    #[arg(long)]
    secret_access_key: Option<String>,
    /// Session token for `--auth-source aws-static` (optional).
    #[arg(long)]
    session_token: Option<String>,
    /// Role ARN for `--auth-source assume-role`.
    #[arg(long)]
    role_arn: Option<String>,
    /// Base credential for `--auth-source assume-role` (`env`|`instance`). Defaults to `env`.
    #[arg(long, default_value = "env")]
    role_base: String,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Lint a policy file: structural errors (rules that can never match or never fire)
    /// and catalog-derived warnings. Exits nonzero on errors.
    Lint(PolicyLintArgs),
    /// Dry-run one request through normalize + decide, showing the normalized action,
    /// which rule matched, and the verdict.
    Test(PolicyTestArgs),
}

#[derive(clap::Args)]
struct PolicyLintArgs {
    /// Path to the JSON policy document.
    policy: std::path::PathBuf,
    /// Emit findings as JSON instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct PolicyTestArgs {
    /// Path to the JSON policy document.
    policy: std::path::PathBuf,
    /// Target (service instance) name the synthetic action carries.
    #[arg(long, default_value = "target")]
    target: String,
    /// The request to test, as "METHOD /path[?query]", e.g. "POST /repos/o/r/pulls".
    #[arg(long)]
    request: String,
    /// Body field as key=value (repeatable). Values parse as JSON when possible
    /// (`--field draft=true` is a boolean), else as strings.
    #[arg(long = "field")]
    fields: Vec<String>,
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Path to the JSON config file.
    #[arg(long)]
    config: std::path::PathBuf,
}

#[derive(clap::Args)]
struct MintArgs {
    /// Base URL of the admin API, e.g. http://127.0.0.1:9091
    #[arg(long)]
    admin_url: String,
    /// Path to a JSON policy document to bind the token to.
    #[arg(long)]
    policy: std::path::PathBuf,
    /// Token lifetime in seconds.
    #[arg(long, default_value_t = 3600)]
    ttl: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Mint(args) => mint(args).await,
        Command::Policy { command } => match command {
            PolicyCommand::Lint(args) => policy_lint(&args),
            PolicyCommand::Test(args) => policy_test(&args),
        },
        Command::Credentials { command } => match command {
            CredentialsCommand::Add(args) => credentials_add(args).await,
        },
        Command::Services { command } => match command {
            ServicesCommand::Add(args) => services_add(args).await,
        },
    }
}

/// Register a credential on a running server's admin API, resolving it from a source.
async fn credentials_add(args: Box<CredentialsAddArgs>) -> Result<(), Box<dyn std::error::Error>> {
    let source = args.source.to_source_json()?;
    let url = format!("{}/admin/credentials", args.admin_url.trim_end_matches('/'));
    let body = serde_json::json!({ "id": args.id, "source": source });
    let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
    let status = resp.status();
    let payload: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = payload["error"].as_str().unwrap_or("unknown error");
        return Err(format!("register credential failed: HTTP {status}: {msg}").into());
    }
    // The response carries the id only — never the secret.
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

/// Register a service on a running server's admin API. Dispatches by name: a known **preset**
/// (`github-api`/`github-git`/`aws:<svc>`) expands to the generic admin call with everything
/// but the credential pinned; any other name falls through to a fully generic registration.
async fn services_add(args: Box<ServicesAddArgs>) -> Result<(), Box<dyn std::error::Error>> {
    use hackamore_cli::preset;
    // The k8s preset can't be a pure `resolve` like the bundled ones — its model is fetched
    // live from the cluster at registration — so it gets its own handler.
    if args.name == "k8s" {
        return services_add_k8s(&args).await;
    }
    let region = args
        .region
        .clone()
        .unwrap_or_else(|| preset::DEFAULT_AWS_REGION.to_string());
    match preset::resolve(&args.name, &region)? {
        Some(p) => services_add_preset(&args, p).await,
        None => services_add_generic(&args).await,
    }
}

/// Expand a preset to the generic `POST /admin/services` body and register it, first
/// registering the credential when `--auth-source` is used. The credential is required:
/// exactly one of `--credential` / `--auth-source` (clear error otherwise).
async fn services_add_preset(
    args: &ServicesAddArgs,
    preset: hackamore_cli::preset::Preset,
) -> Result<(), Box<dyn std::error::Error>> {
    let choice = credential_choice(args)?;
    let resolved = preset.resolve_credential(&choice)?;
    let admin = args.admin_url.trim_end_matches('/');
    let client = reqwest::Client::new();

    // `--auth-source` registers the credential first so the service can reference it by id.
    if let Some(register) = &resolved.register {
        let cred_url = format!("{admin}/admin/credentials");
        let resp = client.post(&cred_url).json(register).send().await?;
        let status = resp.status();
        let payload: serde_json::Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            let msg = payload["error"].as_str().unwrap_or("unknown error");
            return Err(format!("register credential failed: HTTP {status}: {msg}").into());
        }
    }

    let mut body = preset.to_service_json(&resolved.id);
    // A preset pins host/upstream, but `--host`/`--address` may still override/augment.
    if let Some(obj) = body.as_object_mut() {
        if let Some(h) = &args.host {
            obj.insert("host".into(), serde_json::Value::String(h.clone()));
        }
        if let Some(a) = &args.address {
            obj.insert("address".into(), serde_json::Value::String(a.clone()));
        }
    }
    post_service(&client, admin, &body).await
}

/// The `k8s` preset. Unlike the bundled presets it needs a **live** model: read the kubeconfig
/// (explicit flags override), fetch the cluster's `/openapi/v2` over TLS trusting the cluster
/// CA, register the kube credential (token → `static`, exec → `command`), and register the
/// service with the fetched OpenAPI inline + a `bearer` injection. Fails closed: any
/// resolution or fetch failure registers nothing.
///
/// Bearer-token / exec-plugin auth only in v1 (mTLS client-cert is deferred). This can't be
/// e2e'd without a real cluster, so its pieces (parse, source mapping, request construction,
/// expansion) are unit-tested in [`hackamore_cli::k8s`].
async fn services_add_k8s(args: &ServicesAddArgs) -> Result<(), Box<dyn std::error::Error>> {
    use hackamore_cli::k8s;

    // Resolve the kubeconfig context only when a flag doesn't already supply everything we'd
    // read from it (server, token, CA). With both --cluster and --token given, a kubeconfig is
    // read only if we still need its CA — but --ca / --insecure cover that, so it may be skipped
    // entirely. We parse it whenever any of the three is missing.
    let k = &args.k8s;
    let need_kubeconfig = k.cluster.is_none() || (k.token.is_none() && args.credential.is_none());
    let resolved = if need_kubeconfig {
        let text = read_kubeconfig(k.kubeconfig.as_deref())?;
        Some(k8s::parse_kubeconfig(&text, k.context.as_deref())?)
    } else {
        None
    };

    // Server URL: --cluster overrides the kubeconfig.
    let server = match (&k.cluster, &resolved) {
        (Some(c), _) => c.clone(),
        (None, Some(r)) => r.server.clone(),
        (None, None) => {
            return Err("k8s needs a cluster URL: pass --cluster or a kubeconfig".into());
        }
    };
    let host = k8s::server_host(&server)?;

    // The bearer token used **for the fetch**: --token overrides the kubeconfig user auth.
    // When the user auth is an exec plugin we run it to get a token to authenticate the fetch.
    let fetch_token = match &k.token {
        Some(t) => t.clone(),
        None => match resolved.as_ref().map(|r| &r.auth) {
            Some(k8s::UserAuth::Token(t)) => t.clone(),
            Some(k8s::UserAuth::Exec(exec)) => run_exec_for_token(exec)?,
            None => {
                return Err(
                    "k8s needs a token to fetch the cluster OpenAPI: pass --token or a kubeconfig \
                     user with a token/exec auth"
                        .into(),
                );
            }
        },
    };

    // CA + insecure: --ca / --insecure-skip-tls-verify override the kubeconfig.
    let insecure = k.insecure_skip_tls_verify || resolved.as_ref().is_some_and(|r| r.insecure);
    let ca_pem = resolve_ca(k.ca.as_deref(), resolved.as_ref().map(|r| &r.ca))?;

    // Fetch the OpenAPI live (construction is pure; only the send() is here).
    let request = k8s::build_openapi_request(&server, &fetch_token, ca_pem, insecure);
    let spec = fetch_openapi(&request).await?;

    let admin = args.admin_url.trim_end_matches('/');
    let client = reqwest::Client::new();

    // The credential the service references. With --credential we reference it verbatim (no
    // registration); otherwise we register a kube credential from the resolved user auth (id
    // defaults to "k8s", overridable with --auth-id).
    let credential_id = match &args.credential {
        Some(id) => {
            if id.trim().is_empty() {
                return Err("--credential must not be empty".into());
            }
            id.clone()
        }
        None => {
            let auth = match (&k.token, resolved.as_ref().map(|r| &r.auth)) {
                // An explicit --token registers a static credential carrying it.
                (Some(t), _) => k8s::UserAuth::Token(t.clone()),
                (None, Some(a)) => a.clone(),
                (None, None) => {
                    return Err(
                        "k8s needs a credential: pass --credential <id>, --token, or a kubeconfig \
                         user with token/exec auth"
                            .into(),
                    );
                }
            };
            let id = args
                .auth_id
                .clone()
                .unwrap_or_else(|| k8s::DEFAULT_K8S_NAME.to_string());
            let source = k8s::auth_to_source_json(&auth);
            let register = serde_json::json!({ "id": id, "source": source });
            let cred_url = format!("{admin}/admin/credentials");
            let resp = client.post(&cred_url).json(&register).send().await?;
            let status = resp.status();
            let payload: serde_json::Value = resp.json().await.unwrap_or_default();
            if !status.is_success() {
                let msg = payload["error"].as_str().unwrap_or("unknown error");
                return Err(format!("register credential failed: HTTP {status}: {msg}").into());
            }
            id
        }
    };

    let mut body =
        k8s::expand_service_json(k8s::DEFAULT_K8S_NAME, &host, &server, &spec, &credential_id);
    // --host / --address may still override/augment the pinned routing.
    if let Some(obj) = body.as_object_mut() {
        if let Some(h) = &args.host {
            obj.insert("host".into(), serde_json::Value::String(h.clone()));
        }
        if let Some(a) = &args.address {
            obj.insert("address".into(), serde_json::Value::String(a.clone()));
        }
    }
    post_service(&client, admin, &body).await
}

/// Read the kubeconfig file: `--kubeconfig`, else `$KUBECONFIG`, else `~/.kube/config`.
fn read_kubeconfig(flag: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    let path = match flag {
        Some(p) => std::path::PathBuf::from(p),
        None => match std::env::var_os("KUBECONFIG") {
            // KUBECONFIG may be a colon-separated list; v1 uses the first entry.
            Some(v) => {
                let raw = v.to_string_lossy().to_string();
                let first = raw.split(':').next().unwrap_or(&raw);
                if first.is_empty() {
                    return Err("KUBECONFIG is set but empty".into());
                }
                std::path::PathBuf::from(first)
            }
            None => {
                let home = std::env::var_os("HOME").ok_or(
                    "cannot locate kubeconfig: neither --kubeconfig, $KUBECONFIG, nor $HOME is set",
                )?;
                std::path::Path::new(&home).join(".kube").join("config")
            }
        },
    };
    std::fs::read_to_string(&path)
        .map_err(|e| format!("read kubeconfig {}: {e}", path.display()).into())
}

/// Resolve the cluster CA to PEM bytes: `--ca <file>` overrides the kubeconfig's inline data /
/// path. `None` means trust the system store (or skip verification when insecure).
fn resolve_ca(
    flag: Option<&str>,
    kube_ca: Option<&hackamore_cli::k8s::ClusterCa>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    use hackamore_cli::k8s::ClusterCa;
    if let Some(path) = flag {
        return Ok(Some(
            std::fs::read(path).map_err(|e| format!("read --ca {path}: {e}"))?,
        ));
    }
    match kube_ca {
        Some(ClusterCa::Data(data)) => Ok(Some(hackamore_cli::k8s::decode_ca_data(data)?)),
        Some(ClusterCa::Path(path)) => {
            Ok(Some(std::fs::read(path).map_err(|e| {
                format!("read certificate-authority {path}: {e}")
            })?))
        }
        Some(ClusterCa::None) | None => Ok(None),
    }
}

/// Run a kubeconfig exec plugin once to obtain a bearer token for the OpenAPI fetch. The
/// plugin emits an `ExecCredential` JSON on stdout; we read `.status.token`. (For the
/// registered credential the plugin is re-run by hackamore via the `command` source.)
fn run_exec_for_token(
    exec: &hackamore_cli::k8s::ExecAuth,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = std::process::Command::new(&exec.command)
        .args(&exec.args)
        .output()
        .map_err(|e| format!("run exec plugin '{}': {e}", exec.command))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("exec plugin '{}' failed: {stderr}", exec.command).into());
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("exec plugin '{}' output is not JSON: {e}", exec.command))?;
    parsed["status"]["token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("exec plugin '{}' returned no .status.token", exec.command).into())
}

/// Send the (purely constructed) OpenAPI fetch request and return the response body text. TLS
/// trusts the cluster CA when one is pinned; `insecure` disables verification. Fails closed on
/// any error (unreachable, non-200, empty body).
async fn fetch_openapi(
    request: &hackamore_cli::k8s::OpenApiRequest,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut builder = reqwest::Client::builder();
    if let Some(ca) = &request.ca_pem {
        let cert =
            reqwest::Certificate::from_pem(ca).map_err(|e| format!("parse cluster CA PEM: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    if request.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder
        .build()
        .map_err(|e| format!("build TLS client: {e}"))?;
    let resp = client
        .get(&request.url)
        .header(http::header::AUTHORIZATION, &request.authorization)
        .send()
        .await
        .map_err(|e| format!("fetch cluster OpenAPI from {}: {e}", request.url))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("read cluster OpenAPI body: {e}"))?;
    if !status.is_success() {
        return Err(format!("fetch cluster OpenAPI: HTTP {status}").into());
    }
    // Validate it's JSON (fail closed on an HTML error page etc.).
    serde_json::from_str::<serde_json::Value>(&text)
        .map_err(|e| format!("cluster OpenAPI is not JSON: {e}"))?;
    Ok(text)
}

/// The operator's credential choice for a preset: exactly one of `--credential` or
/// `--auth-source` (fail closed). `--auth-source` carries its kind + the matching `--auth-*` /
/// AWS params, normalized into a `POST /admin/credentials` source.
fn credential_choice(
    args: &ServicesAddArgs,
) -> Result<hackamore_cli::preset::CredentialChoice, Box<dyn std::error::Error>> {
    use hackamore_cli::preset::CredentialChoice;
    match (&args.credential, &args.auth_source) {
        (Some(_), Some(_)) => {
            Err("a preset needs exactly one of --credential or --auth-source, not both".into())
        }
        (None, None) => Err(
            "a preset needs a credential: pass --credential <id> or --auth-source <kind>".into(),
        ),
        (Some(id), None) => Ok(CredentialChoice::Credential(id.clone())),
        (None, Some(kind)) => Ok(CredentialChoice::AuthSource {
            id: args.auth_id.clone(),
            source: auth_source_json(kind, args)?,
        }),
    }
}

/// Build the `POST /admin/credentials` source JSON for a preset's `--auth-source <kind>`. The
/// friendly `gh-token` is left as a marker `{ "kind": "gh-token" }` for the preset to map to
/// the `gh auth token` command; every other kind is materialized from its `--auth-*` / AWS
/// params here.
fn auth_source_json(
    kind: &str,
    args: &ServicesAddArgs,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let p = &args.source_params;
    match kind {
        // The preset rewrites this marker into the concrete `gh auth token` command source.
        "gh-token" => Ok(serde_json::json!({ "kind": "gh-token" })),
        "static" => {
            let secret = p
                .auth_secret
                .clone()
                .ok_or("--auth-source static needs --auth-secret")?;
            Ok(serde_json::json!({ "kind": "static", "secret": secret }))
        }
        "env" => {
            let var = p
                .auth_env
                .clone()
                .ok_or("--auth-source env needs --auth-env")?;
            Ok(serde_json::json!({ "kind": "env", "var": var }))
        }
        "file" => {
            let path = p
                .auth_file
                .clone()
                .ok_or("--auth-source file needs --auth-file")?;
            Ok(serde_json::json!({ "kind": "file", "path": path }))
        }
        "command" => {
            let command = p
                .auth_command
                .clone()
                .ok_or("--auth-source command needs --auth-command")?;
            let argv: Vec<&str> = command.split_whitespace().collect();
            if argv.is_empty() {
                return Err("--auth-command must not be empty".into());
            }
            Ok(serde_json::json!({ "kind": "command", "argv": argv }))
        }
        "aws-static" => {
            let akid = args
                .access_key_id
                .clone()
                .ok_or("--auth-source aws-static needs --access-key-id")?;
            let sak = p
                .secret_access_key
                .clone()
                .ok_or("--auth-source aws-static needs --secret-access-key")?;
            let mut spec = serde_json::json!({
                "kind": "aws-static", "access_key_id": akid, "secret_access_key": sak,
            });
            if let Some(token) = &p.session_token {
                spec["session_token"] = serde_json::Value::String(token.clone());
            }
            Ok(spec)
        }
        "assume-role" => {
            let role_arn = p
                .role_arn
                .clone()
                .ok_or("--auth-source assume-role needs --role-arn")?;
            let region = args
                .region
                .clone()
                .ok_or("--auth-source assume-role needs --region")?;
            let base = match p.role_base.as_str() {
                "env" | "instance" => serde_json::json!({ "kind": "env" }),
                other => return Err(format!("unknown --role-base '{other}' (env|instance)").into()),
            };
            Ok(serde_json::json!({
                "kind": "assume-role", "role_arn": role_arn, "region": region, "base": base,
            }))
        }
        "instance" => Ok(serde_json::json!({ "kind": "instance" })),
        other => Err(format!(
            "unknown --auth-source '{other}' \
             (gh-token|static|env|file|command|aws-static|assume-role|instance)"
        )
        .into()),
    }
}

/// A fully generic service registration: the operator supplies upstream/idl/source/inject.
async fn services_add_generic(args: &ServicesAddArgs) -> Result<(), Box<dyn std::error::Error>> {
    let outbound = build_outbound_json(args)?;
    let upstream_base = args
        .upstream_base
        .clone()
        .ok_or("--upstream-base is required for a generic service registration")?;
    let mut body = serde_json::json!({
        "name": args.name,
        "upstreamBase": upstream_base,
        "idl": args.idl,
        "outbound": outbound,
    });
    let obj = body
        .as_object_mut()
        .ok_or("internal: body is not an object")?;
    match (&args.source_file, &args.source_url) {
        (Some(f), None) => {
            obj.insert("sourceFile".into(), serde_json::Value::String(f.clone()));
        }
        (None, Some(u)) => {
            obj.insert("sourceUrl".into(), serde_json::Value::String(u.clone()));
        }
        _ => return Err("exactly one of --source-file or --source-url is required".into()),
    }
    if let Some(h) = &args.host {
        obj.insert("host".into(), serde_json::Value::String(h.clone()));
    }
    if let Some(a) = &args.address {
        obj.insert("address".into(), serde_json::Value::String(a.clone()));
    }
    post_service(
        &reqwest::Client::new(),
        args.admin_url.trim_end_matches('/'),
        &body,
    )
    .await
}

/// `POST /admin/services` with `body`, printing `{ "name": … }` on success or surfacing the
/// server's error message.
async fn post_service(
    client: &reqwest::Client,
    admin: &str,
    body: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{admin}/admin/services");
    let resp = client.post(&url).json(body).send().await?;
    let status = resp.status();
    let payload: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = payload["error"].as_str().unwrap_or("unknown error");
        return Err(format!("register service failed: HTTP {status}: {msg}").into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({ "name": payload["name"] }))?
    );
    Ok(())
}

/// Build the `outbound` JSON for an `--inject` choice. Injecting stances require exactly one
/// of `--credential`/`--secret`; passthrough takes neither.
fn build_outbound_json(
    args: &ServicesAddArgs,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let inject = args.inject.to_ascii_lowercase();
    if inject == "passthrough" {
        return Ok(serde_json::json!({ "kind": "passthrough" }));
    }
    // The injecting stances need a credential reference or an inline secret (not both).
    let mut spec = serde_json::Map::new();
    match (&args.credential, &args.secret) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(
                "an injecting --inject needs exactly one of --credential or --secret".into(),
            );
        }
        (Some(c), None) => {
            spec.insert("credential".into(), serde_json::Value::String(c.clone()));
        }
        (None, Some(s)) => {
            spec.insert("secret".into(), serde_json::Value::String(s.clone()));
        }
    }
    match inject.as_str() {
        "bearer" => {
            spec.insert("kind".into(), "bearer".into());
        }
        "header" => {
            spec.insert("kind".into(), "header".into());
            spec.insert("name".into(), args.header_name.clone().into());
        }
        "basic" => {
            spec.insert("kind".into(), "basic".into());
            spec.insert("username".into(), args.username.clone().into());
        }
        "sigv4" => {
            // The access key id now rides in the referenced AWS bundle (an aws-static /
            // assume-role / instance credential), so `--inject sigv4` needs only a
            // `--credential` reference plus region/service — no inline akid.
            spec.insert("kind".into(), "sigv4".into());
            spec.insert(
                "region".into(),
                args.region
                    .clone()
                    .ok_or("--inject sigv4 needs --region")?
                    .into(),
            );
            spec.insert(
                "service".into(),
                args.service
                    .clone()
                    .ok_or("--inject sigv4 needs --service")?
                    .into(),
            );
        }
        other => return Err(format!("unknown --inject '{other}'").into()),
    }
    Ok(serde_json::Value::Object(spec))
}

/// Read and parse a policy document.
fn load_policy(path: &std::path::Path) -> Result<Policy, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read policy {}: {e}", path.display()))?;
    Ok(serde_json::from_str(&text).map_err(|e| format!("parse policy {}: {e}", path.display()))?)
}

/// Lint a policy offline. With no service models available offline, this runs the
/// structural checks only (unmatchable globs, shadowed/unreachable rules); a running
/// server lints against its configured services' imported models. Exits nonzero iff any
/// Error finding.
fn policy_lint(args: &PolicyLintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let policy = load_policy(&args.policy)?;
    let models: std::collections::BTreeMap<String, &hackamore_models::apimodel::ApiModel> =
        std::collections::BTreeMap::new();
    let findings = hackamore_policy::lint::lint(&policy, &models);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        print!("{}", hackamore_cli::render::findings_human(&findings));
    }
    if findings.iter().any(|f| f.is_error()) {
        std::process::exit(1);
    }
    Ok(())
}

/// Dry-run one synthetic request through the real normalize + decide path and print the
/// normalized action, the matched rule, and the verdict. Exits 0 whatever the verdict —
/// the decision is the output, not a failure.
fn policy_test(args: &PolicyTestArgs) -> Result<(), Box<dyn std::error::Error>> {
    let policy = load_policy(&args.policy)?;
    let target = args.target.clone();

    let (method, path_query) = args
        .request
        .split_once(' ')
        .ok_or("--request must be \"METHOD /path[?query]\"")?;
    let method = http::Method::from_bytes(method.trim().as_bytes())
        .map_err(|_| format!("invalid method '{method}'"))?;
    let (path, query) = match path_query.trim().split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (path_query.trim().to_string(), String::new()),
    };

    let mut body = serde_json::Map::new();
    for field in &args.fields {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| format!("--field '{field}' must be key=value"))?;
        // JSON value when it parses (numbers, booleans, null, quoted strings), else a
        // plain string — so `--field draft=true` means boolean true.
        let value = serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));
        body.insert(key.to_string(), value);
    }
    let body_bytes = if body.is_empty() {
        bytes::Bytes::new()
    } else {
        bytes::Bytes::from(serde_json::to_vec(&body)?)
    };

    let service = Service::new(target, "*", "https://upstream.example");
    let req = hackamore_gateway::ProxyRequest {
        method,
        path: path.clone(),
        query,
        headers: http::HeaderMap::new(),
        body: body_bytes,
    };
    let canonical = hackamore_gateway::canonicalize::path(&req.path)
        .map_err(|e| format!("non-canonical request path '{path}': {e:?}"))?;
    let action = hackamore_gateway::normalize::normalize(&service, &req, &canonical.decoded);
    let trace = hackamore_policy::decide_traced(&action, &policy);
    print!("{}", hackamore_cli::render::trace_human(&action, &trace)?);
    Ok(())
}

/// Build the control plane and gateway from config, then serve until shutdown.
async fn serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(&args.config)?;

    let credentials = build_credentials(&cfg).await?;
    let audit = build_audit(&cfg)?;
    let control = Arc::new(ControlPlane::new(credentials, audit));
    for (key, targets) in &cfg.tenants {
        control.tenants.insert(key.clone(), targets.iter().cloned());
    }
    let mut services: Vec<Service> = Vec::with_capacity(cfg.services.len());
    for s in &cfg.services {
        // A described service imports its vocabulary at startup; the imported model also
        // declares the wire protocol (so RPC/AWS services need no separate config). Fail
        // closed: a description that won't import refuses startup.
        let model = match &s.description {
            Some(d) => Some(
                import_service_description(d)
                    .await
                    .map_err(|e| format!("service '{}': {e}", s.name))?,
            ),
            None => None,
        };
        let protocol = match &model {
            Some(m) => Protocol::from(m),
            None => Protocol::parse(s.protocol.as_deref()),
        };
        services.push(Service {
            name: s.name.clone(),
            host: s.host.clone(),
            upstream_base: s.upstream_base.clone(),
            outbound: match &s.outbound {
                OutboundConfig::Passthrough => Outbound::Passthrough,
                OutboundConfig::Bearer(id) => Outbound::Bearer {
                    credential: id.clone(),
                },
                OutboundConfig::Header { name, credential } => Outbound::Header {
                    name: name.clone(),
                    credential: credential.clone(),
                },
                OutboundConfig::Sigv4 {
                    credential,
                    region,
                    service,
                } => Outbound::SigV4 {
                    credential: credential.clone(),
                    region: region.clone(),
                    service: service.clone(),
                },
            },
            address: s.consumer_address.clone().unwrap_or_default(),
            tool_hint: s
                .tool_hint
                .clone()
                .unwrap_or_else(|| hackamore_gateway::GENERIC_TOOL_HINT.to_string()),
            extract: Extract {
                protocol,
                path_template: s.path_template.clone(),
            },
            model: model.map(std::sync::Arc::new),
        });
    }
    tracing::info!(
        credentials = cfg.credentials.len(),
        services = services.len(),
        "loaded config"
    );

    let mut catalogs: HashMap<String, ActionCatalog> = HashMap::new();
    for s in &cfg.services {
        if let Some(path) = &s.catalog_openapi {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("read openapi {}: {e}", path.display()))?;
            let spec: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("parse openapi {}: {e}", path.display()))?;
            catalogs.insert(s.name.clone(), ActionCatalog::from_openapi(&spec));
        } else if !s.catalog.is_empty() {
            catalogs.insert(s.name.clone(), ActionCatalog::of(s.catalog.iter().cloned()));
        }
    }

    // Optional TLS termination: load the PEM material, derive the rustls config, and surface
    // the CA in the provision doc so consumers can trust hackamore's cert.
    let (tls_config, ca_pem) = match &cfg.tls {
        Some(t) => {
            let cert_pem = std::fs::read_to_string(&t.cert)
                .map_err(|e| format!("read tls cert {}: {e}", t.cert.display()))?;
            let key_pem = std::fs::read_to_string(&t.key)
                .map_err(|e| format!("read tls key {}: {e}", t.key.display()))?;
            let ca_pem = match &t.ca {
                Some(p) => std::fs::read_to_string(p)
                    .map_err(|e| format!("read tls ca {}: {e}", p.display()))?,
                None => cert_pem.clone(),
            };
            let material = TlsMaterial {
                cert_pem,
                key_pem,
                ca_pem: ca_pem.clone(),
            };
            let config = material.server_config()?;
            tracing::info!("tls termination enabled on the proxy listener");
            (Some(config), ca_pem)
        }
        None => (None, String::new()),
    };

    let gateway = Gateway::new(control, ServiceRouter::new(services))
        .with_catalogs(catalogs)
        .with_ca(ca_pem)
        .with_web_ui(cfg.web_ui);
    if cfg.web_ui {
        tracing::info!(url = %format!("http://{}/ui", cfg.admin_addr), "policy studio web UI enabled");
    }

    let proxy_addr = cfg.proxy_addr.parse()?;
    let admin_addr = cfg.admin_addr.parse()?;
    hackamore_gateway::serve(proxy_addr, admin_addr, gateway, tls_config).await?;
    Ok(())
}

/// Import a service's API description (OpenAPI or Smithy) from a file or URL into an
/// `ApiModel`. Exactly one of `file`/`url` must be set; an unimportable description is a
/// startup error (fail closed).
async fn import_service_description(
    d: &DescriptionConfig,
) -> Result<hackamore_models::apimodel::ApiModel, Box<dyn std::error::Error>> {
    let raw = match (&d.file, &d.url) {
        (Some(f), None) => {
            std::fs::read(f).map_err(|e| format!("read description {}: {e}", f.display()))?
        }
        (None, Some(u)) => reqwest::Client::new()
            .get(u)
            .send()
            .await?
            .bytes()
            .await?
            .to_vec(),
        _ => return Err("description needs exactly one of `file` or `url`".into()),
    };
    let model = match d.idl.to_ascii_lowercase().as_str() {
        "openapi" => OpenApiImporter.import(&raw),
        "smithy" => SmithyImporter.import(&raw),
        other => return Err(format!("unknown idl '{other}' (known: openapi, smithy)").into()),
    };
    model.map_err(|e| e.to_string().into())
}

/// Select the audit sink: a durable JSONL [`FileAudit`] when `audit_log` is configured,
/// otherwise the `tracing`-only sink.
fn build_audit(
    cfg: &Config,
) -> Result<Arc<dyn hackamore_control::AuditSink>, Box<dyn std::error::Error>> {
    match &cfg.audit_log {
        Some(path) => {
            let sink = hackamore_control::FileAudit::open(path)
                .map_err(|e| format!("open audit log {}: {e}", path.display()))?;
            tracing::info!(path = %path.display(), "durable audit log enabled");
            Ok(Arc::new(sink))
        }
        None => Ok(Arc::new(TracingAudit)),
    }
}

/// Build the credential store from config. With no minting providers it is the static
/// in-memory vault; with providers it is a [`CachingCredentials`] seeded with the static
/// secrets, primed once, and kept fresh by a background refresher.
async fn build_credentials(
    cfg: &Config,
) -> Result<Arc<dyn hackamore_control::CredentialStore>, Box<dyn std::error::Error>> {
    use hackamore_cli::config::ProviderConfig;

    if cfg.providers.is_empty() {
        let vault = InMemoryCredentials::new();
        for (id, secret) in &cfg.credentials {
            vault.insert(id.clone(), Secret::new(secret.clone()));
        }
        return Ok(Arc::new(vault));
    }

    let mut statics = HashMap::new();
    for (id, secret) in &cfg.credentials {
        statics.insert(id.clone(), Secret::new(secret.clone()));
    }
    let mut providers: HashMap<String, Arc<dyn hackamore_control::CredentialProvider>> =
        HashMap::new();
    for (id, p) in &cfg.providers {
        let provider: Arc<dyn hackamore_control::CredentialProvider> = match p {
            ProviderConfig::Eks {
                access_key_id,
                secret_access_key,
                region,
                cluster_name,
            } => Arc::new(hackamore_control::EksGetTokenProvider {
                access_key_id: access_key_id.clone(),
                secret_access_key: Secret::new(secret_access_key.clone()),
                region: region.clone(),
                cluster_name: cluster_name.clone(),
            }),
            ProviderConfig::GithubApp {
                app_id,
                installation_id,
                private_key_path,
                api_base,
            } => {
                let pem = std::fs::read_to_string(private_key_path)
                    .map_err(|e| format!("read app key {}: {e}", private_key_path.display()))?;
                Arc::new(hackamore_control::GitHubAppProvider {
                    app_id: app_id.clone(),
                    installation_id: installation_id.clone(),
                    private_key_pkcs8_der: hackamore_control::pkcs8_from_pem(&pem)?,
                    api_base: api_base
                        .clone()
                        .unwrap_or_else(|| "https://api.github.com".to_string()),
                    client: reqwest::Client::new(),
                })
            }
        };
        providers.insert(id.clone(), provider);
    }

    let caching = Arc::new(hackamore_control::CachingCredentials::new(
        statics, providers,
    ));
    // Prime so the first request can resolve a minted secret; then rotate in the background
    // ahead of expiry.
    let primed = caching.refresh_due(hackamore_control::now_ms()).await;
    tracing::info!(primed = primed.len(), "minted initial provider credentials");
    hackamore_control::spawn_refresher(
        caching.clone(),
        Arc::new(hackamore_control::now_ms),
        std::time::Duration::from_secs(60),
    );
    Ok(caching)
}

/// Call a running server's admin API to mint a token bound to a policy file, and print
/// the response as JSON.
async fn mint(args: MintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(&args.policy)
        .map_err(|e| format!("read policy {}: {e}", args.policy.display()))?;
    let policy: Policy = serde_json::from_str(&text)
        .map_err(|e| format!("parse policy {}: {e}", args.policy.display()))?;
    let url = format!("{}/mint", args.admin_url.trim_end_matches('/'));
    let body = MintRequest {
        policy,
        ttl_seconds: args.ttl,
    };
    let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
    if !resp.status().is_success() {
        return Err(format!("mint failed: HTTP {}", resp.status()).into());
    }
    let minted: MintResponse = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&minted)?);
    Ok(())
}
