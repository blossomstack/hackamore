//! Service routing. hackamore forwards to any number of configured upstream HTTPS services,
//! chosen by the request's `Host` header. The configured set is an allowlist: a request
//! whose host matches no service is denied (fail closed). Each service names how its
//! requests are normalized into an `Action` (its [`Extract`] config).

use hackamore_models::apimodel::ApiModel;
use std::sync::Arc;

/// The wire protocol that decides *where the operation lives* in a request — the only
/// real branch in extraction. Named by **mechanism**, never by a concrete service: `Rest`
/// reads the HTTP method + path; `Parameter` reads the operation name from a body/query
/// field; `Header` reads it from a request header. "AWS" is just a configuration of these
/// (`aws-query` = `Parameter{"Action"}`, `aws-json` = `Header{"x-amz-target", "."}`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Protocol {
    /// Operation = HTTP method + URL path (RESTful: GitHub, k8s, S3, most APIs).
    #[default]
    Rest,
    /// Operation name = the value of a named body/query field (form-RPC).
    Parameter { name: String },
    /// Operation name = a named header value, keeping the part after the last
    /// `suffix_after` (empty = the whole value).
    Header { name: String, suffix_after: String },
    /// git Smart-HTTP: the verb (`git-upload-pack`/`git-receive-pack`) and resource
    /// (`{owner}/{repo}`) are derived by the custom git-http normalizer, not from a field.
    Git,
}

impl From<&ApiModel> for Protocol {
    /// An imported model declares its own wire protocol; mirror it into the runtime enum so
    /// normalization extracts operations the way the description says (no separate config).
    fn from(model: &ApiModel) -> Self {
        use hackamore_models::apimodel::Protocol as P;
        match &model.protocol {
            P::Rest(_) => Protocol::Rest,
            P::Parameter(p) => Protocol::Parameter {
                name: p.name.clone(),
            },
            P::Header(h) => Protocol::Header {
                name: h.name.clone(),
                suffix_after: h.suffix_after.clone(),
            },
            P::Git(_) => Protocol::Git,
        }
    }
}

impl Protocol {
    /// Parse a protocol name. `aws-query`/`aws-json` are presets over the generic
    /// mechanisms; unknown/absent values default to [`Protocol::Rest`].
    pub fn parse(name: Option<&str>) -> Self {
        match name {
            Some(n) if n.eq_ignore_ascii_case("aws-query") => Protocol::Parameter {
                name: "Action".to_string(),
            },
            Some(n) if n.eq_ignore_ascii_case("aws-json") => Protocol::Header {
                name: "x-amz-target".to_string(),
                suffix_after: ".".to_string(),
            },
            Some(n) if n.eq_ignore_ascii_case("git-http") => Protocol::Git,
            _ => Protocol::Rest,
        }
    }
}

/// Per-service normalization config — how a raw request becomes an `Action`. Grouped so
/// extraction knobs can grow without touching every `Service` site. Defaults to plain
/// RESTful method+path extraction (Tier 0).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extract {
    /// The wire protocol (operation location).
    pub protocol: Protocol,
    /// Optional path template capturing named segments into `fields`, e.g.
    /// `/{bucket}/{key}`. `None` = no capture (Tier 0 path glob).
    pub path_template: Option<String>,
}

/// A per-target **named-action** vocabulary used to validate policies at mint time
/// (distinct from the richer `hackamore_models::apimodel::ApiModel` that powers discovery
/// and lint). Empty = no catalog (raw / unvalidated, structural checks only). Populated
/// from a static config list today; an OpenAPI / k8s-discovery / AWS-SAR ingester
/// produces the same set, so validation never changes when a richer source is added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActionCatalog {
    actions: std::collections::BTreeSet<String>,
}

impl ActionCatalog {
    /// Build a catalog from a set of known named-action ids (e.g. "ec2:DescribeInstances").
    /// This is the static-config ingester; richer ingesters ([`ActionCatalog::from_openapi`], and
    /// future k8s-discovery / AWS-SAR sources) produce the same `ActionCatalog`, so policy
    /// validation never changes when a source is swapped in.
    pub fn of(actions: impl IntoIterator<Item = String>) -> Self {
        Self {
            actions: actions.into_iter().collect(),
        }
    }

    /// Ingest an OpenAPI v3 document (as parsed JSON) into a catalog: every operation's
    /// `operationId` becomes a known action, falling back to `"<METHOD> <path>"` (e.g.
    /// `"GET /pets/{id}"`) when an operation declares none. A spec with no operations yields
    /// an empty (raw) catalog.
    pub fn from_openapi(spec: &serde_json::Value) -> Self {
        const METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];
        let mut actions = std::collections::BTreeSet::new();
        let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) else {
            return Self::default();
        };
        for (path, item) in paths {
            let Some(item) = item.as_object() else {
                continue;
            };
            for method in METHODS {
                let Some(op) = item.get(method) else { continue };
                let action = op
                    .get("operationId")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("{} {path}", method.to_ascii_uppercase()));
                actions.insert(action);
            }
        }
        Self { actions }
    }

    /// Whether this catalog is absent (no semantic validation — raw).
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Whether `action` is a known catalog action.
    pub fn knows(&self, action: &str) -> bool {
        self.actions.contains(action)
    }
}

/// What hackamore does with upstream auth when a request is allowed — a closed mechanism
/// library, selected per service instance. This is the **hybrid** stance: filter-only by
/// default (`Passthrough`), credential-hiding via one of the inject mechanisms. The
/// credential is a property of the service instance, never named in policy. (SigV4 — a
/// request *transform* rather than a header set — is added as its own arm later.)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Outbound {
    /// Forward the consumer's own credential unchanged (filter-only).
    #[default]
    Passthrough,
    /// Inject the vault credential as `Authorization: Bearer <secret>`.
    Bearer { credential: String },
    /// Inject the vault credential as a custom header `<name>: <secret>` (e.g.
    /// `X-API-Key`).
    Header { name: String, credential: String },
    /// Inject the vault credential as HTTP Basic auth: `Authorization: Basic
    /// base64(<username>:<secret>)`. `username` is non-secret configuration (e.g.
    /// `x-access-token` for git-over-HTTPS); the secret is the password half.
    Basic {
        username: String,
        credential: String,
    },
    /// Re-sign the request with AWS SigV4 using the real account credential — the vault
    /// `credential` is an [`AwsCredential`] bundle (access key id + secret access key + an
    /// optional session token), so the access key id comes from the resolved bundle, not from
    /// the service config. `region` and `service` (the AWS service, e.g. "ec2") parameterize
    /// the signature.
    ///
    /// [`AwsCredential`]: hackamore_control::AwsCredential
    SigV4 {
        credential: String,
        region: String,
        service: String,
    },
}

impl Outbound {
    /// The vault credential id this stance injects/signs with, if any (`None` for
    /// passthrough).
    pub fn credential_id(&self) -> Option<&str> {
        match self {
            Outbound::Passthrough => None,
            Outbound::Bearer { credential }
            | Outbound::Header { credential, .. }
            | Outbound::Basic { credential, .. }
            | Outbound::SigV4 { credential, .. } => Some(credential),
        }
    }

    /// A human label for this outbound stance, for discovery surfaces (the Server view in
    /// the web UI). Names the mechanism, never the secret — the header arm includes the
    /// header name, which is configuration, not a credential.
    pub fn auth_label(&self) -> String {
        match self {
            Outbound::Passthrough => "passthrough".to_string(),
            Outbound::Bearer { .. } => "bearer".to_string(),
            Outbound::Header { name, .. } => format!("header {name}"),
            Outbound::Basic { username, .. } => format!("basic {username}"),
            Outbound::SigV4 { .. } => "sigv4".to_string(),
        }
    }
}

/// One configured upstream service instance. Build with [`Service::new`] + the `with_*`
/// setters rather than filling all fields positionally; everything but the name, host, and
/// upstream base has a sensible default (passthrough outbound, no consumer address, Tier-0
/// extraction, no model, the `generic` tool hint).
#[derive(Clone, Debug)]
pub struct Service {
    /// Logical instance name; becomes `Action.target` and what policy rules scope to.
    pub name: String,
    /// Host pattern matched against the request `Host` header: an exact host, a
    /// `*.suffix` wildcard, or `*` (catch-all).
    pub host: String,
    /// Upstream base URL without a trailing slash, e.g. `https://api.github.com`.
    pub upstream_base: String,
    /// What hackamore does with upstream auth on allow.
    pub outbound: Outbound,
    /// Consumer-facing address the agent points its tool at to reach this service
    /// through hackamore (the provision doc surfaces this). Empty if not configured.
    pub address: String,
    /// How requests are normalized into an `Action` (protocol + field extraction).
    pub extract: Extract,
    /// The agent tool-config hint surfaced as `ProvisionService.tool_hint`: which native
    /// tool config the agent should write for this service — one of `github` | `git` |
    /// `aws` | `kubernetes` | `generic`. Set by the CLI presets; `generic` (the default)
    /// means no tool files beyond the token + endpoint. Decoupled from the service *name*
    /// so a service named `github-api`/`aws:ec2` still routes correctly.
    pub tool_hint: String,
    /// The service's imported vocabulary (from an OpenAPI/Smithy description), if any —
    /// powers discovery, lint, and dry-run. `None` for raw, generically-normalized
    /// services. Behind an `Arc` so cloning a `Service` on the routing hot path stays
    /// cheap.
    pub model: Option<Arc<ApiModel>>,
}

/// The default tool-config hint for a service the operator didn't pin (`generic`): the agent
/// writes only the token + endpoint, no native tool config.
pub const GENERIC_TOOL_HINT: &str = "generic";

impl Default for Service {
    fn default() -> Self {
        Self {
            name: String::new(),
            host: String::new(),
            upstream_base: String::new(),
            outbound: Outbound::default(),
            address: String::new(),
            extract: Extract::default(),
            tool_hint: GENERIC_TOOL_HINT.to_string(),
            model: None,
        }
    }
}

impl Service {
    /// Start a service with the three required fields; outbound/address/extract/model take
    /// their defaults. Chain the `with_*` setters to override.
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        upstream_base: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            upstream_base: upstream_base.into(),
            ..Self::default()
        }
    }

    /// Set the outbound auth stance.
    #[must_use]
    pub fn with_outbound(mut self, outbound: Outbound) -> Self {
        self.outbound = outbound;
        self
    }

    /// Set the consumer-facing address surfaced in the provision doc.
    #[must_use]
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = address.into();
        self
    }

    /// Set the extraction config (protocol + field capture).
    #[must_use]
    pub fn with_extract(mut self, extract: Extract) -> Self {
        self.extract = extract;
        self
    }

    /// Set the agent tool-config hint (`github` | `git` | `aws` | `kubernetes` | `generic`)
    /// surfaced in the provision doc. Builder; defaults to `generic`.
    #[must_use]
    pub fn with_tool_hint(mut self, tool_hint: impl Into<String>) -> Self {
        self.tool_hint = tool_hint.into();
        self
    }

    /// Attach an imported API model (the service's vocabulary). Builder.
    #[must_use]
    pub fn with_model(mut self, model: ApiModel) -> Self {
        self.model = Some(Arc::new(model));
        self
    }
}

/// Routes an inbound request to a service by its `Host`. First match wins, so put more
/// specific patterns before catch-alls.
pub struct ServiceRouter {
    services: Vec<Service>,
}

impl ServiceRouter {
    pub fn new(services: Vec<Service>) -> Self {
        Self { services }
    }

    /// The service whose host pattern matches `host`, or `None` (→ deny).
    pub fn route(&self, host: &str) -> Option<&Service> {
        let host = normalize_host(host);
        self.services.iter().find(|s| host_matches(&s.host, &host))
    }

    /// Add a service, replacing any existing one with the same name (live registration).
    /// Returns whether an existing service was replaced.
    pub fn upsert(&mut self, service: Service) -> bool {
        match self.services.iter().position(|s| s.name == service.name) {
            Some(i) => {
                self.services[i] = service;
                true
            }
            None => {
                self.services.push(service);
                false
            }
        }
    }

    /// Remove the service named `name`; returns whether one was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.services.len();
        self.services.retain(|s| s.name != name);
        self.services.len() != before
    }

    /// All configured services (used to project a provision doc).
    pub fn services(&self) -> &[Service] {
        &self.services
    }
}

/// Lowercase and strip a trailing `:port` for matching.
fn normalize_host(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            h.to_string()
        }
        _ => host,
    }
}

/// Match a (lowercased, port-stripped) host against a pattern: `*` matches anything,
/// `*.suffix` matches `suffix` and any subdomain of it, otherwise an exact match.
fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    pattern == host
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn svc(name: &str, host: &str) -> Service {
        Service::new(name, host, format!("https://{name}.example"))
    }

    #[test]
    fn routes_by_exact_host_and_strips_port() {
        let r = ServiceRouter::new(vec![svc("github", "api.github.com")]);
        assert_eq!(
            r.route("api.github.com").map(|s| s.name.as_str()),
            Some("github")
        );
        assert_eq!(
            r.route("api.github.com:443").map(|s| s.name.as_str()),
            Some("github")
        );
        assert!(r.route("api.openai.com").is_none());
    }

    #[test]
    fn wildcard_suffix_and_catch_all() {
        let r = ServiceRouter::new(vec![svc("oai", "*.openai.com"), svc("any", "*")]);
        assert_eq!(
            r.route("api.openai.com").map(|s| s.name.as_str()),
            Some("oai")
        );
        assert_eq!(r.route("openai.com").map(|s| s.name.as_str()), Some("oai"));
        // Falls through to catch-all.
        assert_eq!(r.route("example.org").map(|s| s.name.as_str()), Some("any"));
    }

    #[test]
    fn first_match_wins() {
        let r = ServiceRouter::new(vec![svc("specific", "api.github.com"), svc("catch", "*")]);
        assert_eq!(
            r.route("api.github.com").map(|s| s.name.as_str()),
            Some("specific")
        );
    }

    #[test]
    fn parse_maps_git_http_to_git_protocol() {
        assert_eq!(Protocol::parse(Some("git-http")), Protocol::Git);
        assert_eq!(Protocol::parse(Some("GIT-HTTP")), Protocol::Git);
        // An imported model that declares the git protocol maps to the runtime Git arm.
        assert_eq!(
            Protocol::from(&ApiModel {
                protocol: hackamore_models::apimodel::Protocol::git(),
                operations: vec![],
            }),
            Protocol::Git
        );
        // Unknown/absent still defaults to Rest (fail-safe to the generic normalizer).
        assert_eq!(Protocol::parse(Some("nope")), Protocol::Rest);
    }

    #[test]
    fn service_defaults_to_generic_tool_hint_and_setter_overrides() {
        // A service built without a hint defaults to `generic` (no native tool files).
        let s = Service::new("svc", "*", "https://up.example");
        assert_eq!(s.tool_hint, GENERIC_TOOL_HINT);
        assert_eq!(s.tool_hint, "generic");
        // The setter pins the hint independent of the (different) service name.
        let gh = Service::new("github-api", "*", "https://api.github.com").with_tool_hint("github");
        assert_eq!(gh.tool_hint, "github");
        assert_ne!(gh.tool_hint, gh.name);
    }

    #[test]
    fn basic_outbound_credential_id_and_label() {
        let basic = Outbound::Basic {
            username: "x-access-token".into(),
            credential: "gh-login".into(),
        };
        assert_eq!(basic.credential_id(), Some("gh-login"));
        // The label names the mechanism + the non-secret username, never the credential.
        assert_eq!(basic.auth_label(), "basic x-access-token");
        assert!(!basic.auth_label().contains("gh-login"));
    }

    #[test]
    fn openapi_ingester_collects_operation_ids_with_fallback() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/pets": {
                    "get": { "operationId": "listPets" },
                    "post": { "operationId": "createPet" }
                },
                // No operationId → falls back to "<METHOD> <path>".
                "/pets/{id}": { "get": {} }
            }
        });
        let catalog = ActionCatalog::from_openapi(&spec);
        assert!(!catalog.is_empty());
        assert!(catalog.knows("listPets"));
        assert!(catalog.knows("createPet"));
        assert!(catalog.knows("GET /pets/{id}"));
        assert!(!catalog.knows("deletePet"));
        // A spec with no paths is a raw (empty) catalog.
        assert!(ActionCatalog::from_openapi(&serde_json::json!({})).is_empty());
    }
}
