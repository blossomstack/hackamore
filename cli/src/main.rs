//! `halter` — the CLI entry point.
//!
//! `halter serve --config <file>` starts the reverse proxy + admin API from a config
//! file. `halter mint --admin-url <url> --policy <file> --ttl <secs>` calls a running
//! server's admin API to issue a launch token bound to that policy (handy for manual
//! testing; in production the orchestrator calls the admin API directly).

use clap::{Parser, Subcommand};
use cli::config::{Config, OutboundConfig};
use control::{ControlPlane, InMemoryCredentials, Secret, TracingAudit};
use gateway::{
    Catalog, Extract, Flavor, Gateway, Outbound, Protocol, Service, ServiceRouter, TlsMaterial,
};
use models::control::{MintRequest, MintResponse};
use models::policy::Policy;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "halter",
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
    }
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
    let services: Vec<Service> = cfg
        .services
        .iter()
        .map(|s| Service {
            name: s.name.clone(),
            host: s.host.clone(),
            upstream_base: s.upstream_base.clone(),
            flavor: Flavor::parse(s.flavor.as_deref()),
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
                    access_key_id,
                    region,
                    service,
                } => Outbound::SigV4 {
                    credential: credential.clone(),
                    access_key_id: access_key_id.clone(),
                    region: region.clone(),
                    service: service.clone(),
                },
            },
            address: s.consumer_address.clone().unwrap_or_default(),
            extract: Extract {
                protocol: Protocol::parse(s.protocol.as_deref()),
                path_template: s.path_template.clone(),
            },
        })
        .collect();
    tracing::info!(
        credentials = cfg.credentials.len(),
        services = services.len(),
        "loaded config"
    );

    let mut catalogs: HashMap<String, Catalog> = HashMap::new();
    for s in &cfg.services {
        if let Some(path) = &s.catalog_openapi {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("read openapi {}: {e}", path.display()))?;
            let spec: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("parse openapi {}: {e}", path.display()))?;
            catalogs.insert(s.name.clone(), Catalog::from_openapi(&spec));
        } else if !s.catalog.is_empty() {
            catalogs.insert(s.name.clone(), Catalog::of(s.catalog.iter().cloned()));
        }
    }

    // Optional TLS termination: load the PEM material, derive the rustls config, and surface
    // the CA in the provision doc so consumers can trust halter's cert.
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
        .with_ca(ca_pem);

    let proxy_addr = cfg.proxy_addr.parse()?;
    let admin_addr = cfg.admin_addr.parse()?;
    gateway::serve(proxy_addr, admin_addr, gateway, tls_config).await?;
    Ok(())
}

/// Select the audit sink: a durable JSONL [`FileAudit`] when `audit_log` is configured,
/// otherwise the `tracing`-only sink.
fn build_audit(cfg: &Config) -> Result<Arc<dyn control::AuditSink>, Box<dyn std::error::Error>> {
    match &cfg.audit_log {
        Some(path) => {
            let sink = control::FileAudit::open(path)
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
) -> Result<Arc<dyn control::CredentialStore>, Box<dyn std::error::Error>> {
    use cli::config::ProviderConfig;

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
    let mut providers: HashMap<String, Arc<dyn control::CredentialProvider>> = HashMap::new();
    for (id, p) in &cfg.providers {
        let provider: Arc<dyn control::CredentialProvider> = match p {
            ProviderConfig::Eks {
                access_key_id,
                secret_access_key,
                region,
                cluster_name,
            } => Arc::new(control::EksGetTokenProvider {
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
                Arc::new(control::GitHubAppProvider {
                    app_id: app_id.clone(),
                    installation_id: installation_id.clone(),
                    private_key_pkcs8_der: control::pkcs8_from_pem(&pem)?,
                    api_base: api_base
                        .clone()
                        .unwrap_or_else(|| "https://api.github.com".to_string()),
                    client: reqwest::Client::new(),
                })
            }
        };
        providers.insert(id.clone(), provider);
    }

    let caching = Arc::new(control::CachingCredentials::new(statics, providers));
    // Prime so the first request can resolve a minted secret; then rotate in the background
    // ahead of expiry.
    let primed = caching.refresh_due(control::now_ms()).await;
    tracing::info!(primed = primed.len(), "minted initial provider credentials");
    control::spawn_refresher(
        caching.clone(),
        Arc::new(control::now_ms),
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
