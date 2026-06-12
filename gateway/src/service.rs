//! Service routing. hackamore forwards to any number of configured upstream HTTPS services,
//! chosen by the request's `Host` header. The configured set is an allowlist: a request
//! whose host matches no service is denied (fail closed). Each service names how its
//! requests are normalized into an `Action` (its [`Flavor`]).

/// How a service's requests are normalized into an `Action`. Also a tool hint the
/// provision doc surfaces so `hackamore-agent` writes the right native config.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Flavor {
    /// GitHub-aware resource parsing (repo/pull_request/issue kinds).
    Github,
    /// Kubernetes-aware resource parsing (namespace + resource kind).
    K8s,
    /// Path-based generic parsing — works for any HTTP/JSON or SSE service.
    #[default]
    Generic,
}

/// The wire protocol that decides *where the operation lives* in a request — the only
/// real branch in extraction. `Rest` (the default) reads the HTTP method + path; the AWS
/// RPC protocols read the operation from the body/header (the path is constant).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Protocol {
    /// Operation = HTTP method + URL path (RESTful: GitHub, k8s, S3, most APIs).
    #[default]
    Rest,
    /// AWS query protocol: `Action=<Op>` in a form-encoded body (EC2, IAM, …).
    AwsQuery,
    /// AWS JSON protocol: `X-Amz-Target: <svc>.<Op>` header (DynamoDB, …).
    AwsJson,
}

impl Protocol {
    /// Parse a protocol name; unknown/absent values default to [`Protocol::Rest`].
    pub fn parse(name: Option<&str>) -> Self {
        match name {
            Some(n) if n.eq_ignore_ascii_case("aws-query") => Protocol::AwsQuery,
            Some(n) if n.eq_ignore_ascii_case("aws-json") => Protocol::AwsJson,
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

/// A per-target action vocabulary used to validate policies at mint time. Empty = no
/// catalog (raw / unvalidated, structural checks only). Populated from a static config
/// list today; an OpenAPI / k8s-discovery / AWS-SAR ingester produces the same set, so
/// validation never changes when a richer source is added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    actions: std::collections::BTreeSet<String>,
}

impl Catalog {
    /// Build a catalog from a set of known named-action ids (e.g. "ec2:DescribeInstances").
    /// This is the static-config ingester; richer ingesters ([`Catalog::from_openapi`], and
    /// future k8s-discovery / AWS-SAR sources) produce the same `Catalog`, so policy
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

impl Flavor {
    /// Parse a flavor name; unknown/absent values default to [`Flavor::Generic`].
    pub fn parse(name: Option<&str>) -> Self {
        match name {
            Some(n) if n.eq_ignore_ascii_case("github") => Flavor::Github,
            Some(n) if n.eq_ignore_ascii_case("k8s") => Flavor::K8s,
            _ => Flavor::Generic,
        }
    }

    /// The canonical lowercase flavor name (the inverse of [`Flavor::parse`]).
    pub fn name(self) -> &'static str {
        match self {
            Flavor::Github => "github",
            Flavor::K8s => "k8s",
            Flavor::Generic => "generic",
        }
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
    /// Re-sign the request with AWS SigV4 using the real account credential — the vault
    /// `credential` is the secret access key; `access_key_id`, `region`, and `service`
    /// (the AWS service, e.g. "ec2") parameterize the signature.
    SigV4 {
        credential: String,
        access_key_id: String,
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
            | Outbound::SigV4 { credential, .. } => Some(credential),
        }
    }
}

/// One configured upstream service instance. Build with [`Service::new`] + the `with_*`
/// setters rather than filling all seven fields positionally; everything but the name,
/// host, and upstream base has a sensible default (generic flavor, passthrough outbound,
/// no consumer address, Tier-0 extraction).
#[derive(Clone, Debug, Default)]
pub struct Service {
    /// Logical instance name; becomes `Action.target` and what policy rules scope to.
    pub name: String,
    /// Host pattern matched against the request `Host` header: an exact host, a
    /// `*.suffix` wildcard, or `*` (catch-all).
    pub host: String,
    /// Upstream base URL without a trailing slash, e.g. `https://api.github.com`.
    pub upstream_base: String,
    /// How requests to this service are normalized.
    pub flavor: Flavor,
    /// What hackamore does with upstream auth on allow.
    pub outbound: Outbound,
    /// Consumer-facing address the agent points its tool at to reach this service
    /// through hackamore (the provision doc surfaces this). Empty if not configured.
    pub address: String,
    /// How requests are normalized into an `Action` (protocol + field extraction).
    pub extract: Extract,
}

impl Service {
    /// Start a service with the three required fields; flavor/outbound/address/extract take
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

    /// Set the normalization flavor.
    #[must_use]
    pub fn with_flavor(mut self, flavor: Flavor) -> Self {
        self.flavor = flavor;
        self
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
        let catalog = Catalog::from_openapi(&spec);
        assert!(!catalog.is_empty());
        assert!(catalog.knows("listPets"));
        assert!(catalog.knows("createPet"));
        assert!(catalog.knows("GET /pets/{id}"));
        assert!(!catalog.knows("deletePet"));
        // A spec with no paths is a raw (empty) catalog.
        assert!(Catalog::from_openapi(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn flavor_parse_defaults_generic() {
        assert_eq!(Flavor::parse(Some("github")), Flavor::Github);
        assert_eq!(Flavor::parse(Some("GitHub")), Flavor::Github);
        assert_eq!(Flavor::parse(Some("rest")), Flavor::Generic);
        assert_eq!(Flavor::parse(None), Flavor::Generic);
    }
}
