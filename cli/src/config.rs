//! hackamore server configuration. This is application/storage config — hand-written and
//! deliberately *not* a fluorite type — so it can evolve independently of the wire
//! protocol. It seeds the gateway's service allowlist (with each service's outbound auth
//! stance) and the credential vault at startup. There are no agents: tokens are minted
//! per-policy via the admin API.

use serde::Deserialize;
use std::collections::HashMap;

/// Top-level server config, loaded from JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Address the agent-facing reverse proxy listens on, e.g. `127.0.0.1:9090`.
    pub proxy_addr: String,
    /// Address the operator/orchestrator admin API listens on, e.g. `127.0.0.1:9091`.
    pub admin_addr: String,
    /// The upstream HTTPS services hackamore will proxy to (the allowlist). Routed by Host.
    pub services: Vec<ServiceConfig>,
    /// Logical credential id → real secret. Provisioned out of band; never exposed to
    /// consumers.
    #[serde(default)]
    pub credentials: HashMap<String, String>,
    /// Logical credential id → a minting provider that produces short-lived, rotated
    /// secrets (EKS get-token, GitHub-App installation token). A provider id shadows a
    /// static `credentials` entry of the same name.
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    /// Multi-tenant mint authorization: tenant credential → the target names it owns.
    /// Empty = single trust domain (open minting on the localhost admin API).
    #[serde(default)]
    pub tenants: HashMap<String, Vec<String>>,
    /// Optional TLS termination for the agent-facing proxy listener. Absent = plaintext
    /// (the sandbox-confined model); present = consumers terminate TLS at hackamore and trust
    /// its certificate.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Optional path to a durable JSONL audit log. Absent = `tracing`-only audit (events
    /// go to the log stream, nothing queryable); present = every decision is also appended
    /// as one JSON line to this file.
    #[serde(default)]
    pub audit_log: Option<std::path::PathBuf>,
}

/// Paths to the PEM material for TLS termination. Storage/config type.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Path to the serving certificate chain (PEM).
    pub cert: std::path::PathBuf,
    /// Path to the serving private key (PEM; PKCS#8, PKCS#1, or SEC1).
    pub key: std::path::PathBuf,
    /// Path to the CA bundle consumers must trust (PEM). Defaults to the cert itself (the
    /// self-signed case) when omitted.
    #[serde(default)]
    pub ca: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    /// Logical instance name; becomes `Action.target` and what policy rules scope to.
    pub name: String,
    /// Host pattern matched against the request `Host`: exact, `*.suffix`, or `*`.
    pub host: String,
    /// Upstream base URL, e.g. `https://api.github.com`.
    pub upstream_base: String,
    /// Normalization flavor: "github" or "generic" (default).
    #[serde(default)]
    pub flavor: Option<String>,
    /// Consumer-facing address the agent points its tool at to reach this service through
    /// hackamore (surfaced in the provision doc). Optional.
    #[serde(default)]
    pub consumer_address: Option<String>,
    /// Wire protocol for extraction: "rest" (default), "aws-query", or "aws-json".
    #[serde(default)]
    pub protocol: Option<String>,
    /// Optional path template capturing named segments into fields, e.g. `/{bucket}/{key+}`.
    #[serde(default)]
    pub path_template: Option<String>,
    /// Optional action catalog: known named-action ids (e.g. "ec2:DescribeInstances") used
    /// to validate policies at mint time. Empty = unvalidated (raw).
    #[serde(default)]
    pub catalog: Vec<String>,
    /// Optional path to an OpenAPI v3 JSON spec; its operations are ingested into the action
    /// catalog (operationId, or `"<METHOD> <path>"`). Takes precedence over `catalog`.
    #[serde(default)]
    pub catalog_openapi: Option<std::path::PathBuf>,
    /// What hackamore does with upstream auth on allow: `"passthrough"` (default) forwards
    /// the consumer's own credential; `{ "bearer": "<cred-id>" }` injects it as a Bearer
    /// token; `{ "header": { "name": "X-API-Key", "credential": "<cred-id>" } }` injects
    /// it as a custom header.
    #[serde(default)]
    pub outbound: OutboundConfig,
}

/// A minting credential provider. Tagged by `kind`: `"eks"` presigns an STS get-token,
/// `"github-app"` exchanges an app JWT for an installation token. Storage/config type.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProviderConfig {
    /// AWS EKS `get-token`: a presigned STS `GetCallerIdentity` URL scoped to a cluster.
    Eks {
        access_key_id: String,
        secret_access_key: String,
        region: String,
        cluster_name: String,
    },
    /// GitHub-App installation token, minted from the app's RSA private key.
    GithubApp {
        app_id: String,
        installation_id: String,
        /// Path to the app's PKCS#8 private key PEM.
        private_key_path: std::path::PathBuf,
        /// API base; defaults to `https://api.github.com`.
        #[serde(default)]
        api_base: Option<String>,
    },
}

/// The configured outbound auth stance for a service (see [`ServiceConfig::outbound`]).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundConfig {
    /// Forward the consumer's own credential unchanged (filter-only).
    #[default]
    Passthrough,
    /// Inject the named vault credential as `Authorization: Bearer <secret>`.
    Bearer(String),
    /// Inject the named vault credential as a custom header.
    Header { name: String, credential: String },
    /// Re-sign the request with AWS SigV4 using the real account credential (the vault
    /// `credential` is the secret access key).
    Sigv4 {
        credential: String,
        access_key_id: String,
        region: String,
        service: String,
    },
}

impl Config {
    /// Load and parse a config file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read config {}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("parse config {}: {e}", path.display()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_config() {
        let json = r#"{
            "proxy_addr": "127.0.0.1:9090",
            "admin_addr": "127.0.0.1:9091",
            "services": [
                { "name": "github", "host": "api.github.com", "upstream_base": "https://api.github.com",
                  "flavor": "github", "outbound": { "bearer": "github-app" } },
                { "name": "openai", "host": "api.openai.com", "upstream_base": "https://api.openai.com",
                  "flavor": "generic", "outbound": "passthrough" },
                { "name": "keyed", "host": "api.keyed.com", "upstream_base": "https://api.keyed.com",
                  "outbound": { "header": { "name": "X-API-Key", "credential": "keyed-key" } } }
            ],
            "credentials": { "github-app": "secret" }
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.proxy_addr, "127.0.0.1:9090");
        assert_eq!(cfg.services.len(), 3);
        assert!(matches!(
            cfg.services[0].outbound,
            OutboundConfig::Bearer(ref id) if id == "github-app"
        ));
        assert!(matches!(
            cfg.services[1].outbound,
            OutboundConfig::Passthrough
        ));
        assert!(matches!(
            cfg.services[2].outbound,
            OutboundConfig::Header { ref name, ref credential }
                if name == "X-API-Key" && credential == "keyed-key"
        ));
        assert_eq!(
            cfg.credentials.get("github-app").map(String::as_str),
            Some("secret")
        );
    }

    #[test]
    fn outbound_defaults_to_passthrough() {
        let json = r#"{
            "proxy_addr": "127.0.0.1:9090",
            "admin_addr": "127.0.0.1:9091",
            "services": [
                { "name": "svc", "host": "*", "upstream_base": "https://up.example" }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(matches!(
            cfg.services[0].outbound,
            OutboundConfig::Passthrough
        ));
    }
}
