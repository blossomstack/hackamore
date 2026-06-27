//! The gateway core: the transport-agnostic decision + enforcement path.
//!
//! [`Gateway::handle`] takes a normalized [`ProxyRequest`], authenticates the hackamore
//! token and resolves its bound policy, normalizes the request into an `Action`, calls
//! the pure [`hackamore_policy::decide`], records an audit event, and returns an [`Outcome`] —
//! either a [`ForwardPlan`] (with the matched service's outbound stance applied) or a
//! [`Rejection`]. It performs no network I/O itself; the server module executes the
//! forward. Keeping this layer free of HTTP plumbing makes the whole decision path
//! deterministically testable.

use crate::service::{ActionCatalog, Outbound, Service, ServiceRouter};
use crate::{canonicalize, normalize};
use base64::Engine;
use hackamore_control::{ControlPlane, now_ms};
use hackamore_models::action::Action;
use hackamore_models::audit::{AuditEvent, Decision};
use hackamore_models::verdict::{DenyReason, Verdict};
use std::collections::HashMap;
use std::sync::Arc;

/// A normalized inbound request, independent of any HTTP library.
pub struct ProxyRequest {
    pub method: http::Method,
    /// Request path including the leading `/`, e.g. `/repos/o/r/pulls`.
    pub path: String,
    /// Raw query string without the `?`, possibly empty.
    pub query: String,
    pub headers: http::HeaderMap,
    pub body: bytes::Bytes,
}

/// What the data plane should do with a request.
pub enum Outcome {
    /// Forward upstream after applying the plan (credential injected, token stripped).
    Forward(ForwardPlan),
    /// Reject without contacting the upstream.
    Reject(Rejection),
}

/// A concrete upstream request to execute.
pub struct ForwardPlan {
    pub url: String,
    pub method: http::Method,
    pub headers: http::HeaderMap,
    pub body: bytes::Bytes,
}

/// A denied request, ready to render as an HTTP error.
pub struct Rejection {
    pub status: http::StatusCode,
    pub reason: DenyReason,
    pub message: String,
}

/// One registered service projected for the admin API (`GET /admin/services`): its
/// routing/auth summary plus its imported model. Serialized to the studio; credential is
/// the vault *id*, never the secret.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredService {
    pub name: String,
    pub host: String,
    pub upstream_base: String,
    pub address: String,
    pub auth: String,
    pub credential: String,
    pub model: Option<hackamore_models::apimodel::ApiModel>,
}

/// A source of wall-clock time, injectable for tests.
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The data-plane decision engine. Holds the control plane and the service routing
/// table (any number of configured upstream HTTPS services).
pub struct Gateway {
    control: Arc<ControlPlane>,
    /// The service allowlist, behind an `RwLock` so services can be registered/removed at
    /// runtime via the admin API (live registration). Reads (routing, projections) take a
    /// read lock; register/remove take the write lock.
    router: std::sync::RwLock<ServiceRouter>,
    clock: Clock,
    /// Per-target action catalogs used to validate policies at mint time. A target with
    /// no entry (or an empty catalog) is unvalidated (raw).
    catalogs: HashMap<String, ActionCatalog>,
    /// The CA bundle a consumer must trust to validate hackamore's TLS, surfaced in the
    /// provision doc. Empty when hackamore terminates plaintext (the sandbox-confined model).
    hackamore_ca: String,
    /// Whether the admin listener serves the web UI and its authoring endpoints
    /// (`/ui`, `POST /policy/lint`, `POST /policy/test`). On by default — the admin
    /// listener is operator-only — and switchable off in config.
    web_ui: bool,
}

impl Gateway {
    /// Build a gateway over `control` routing to `router`'s services, using the wall
    /// clock.
    pub fn new(control: Arc<ControlPlane>, router: ServiceRouter) -> Self {
        Self {
            control,
            router: std::sync::RwLock::new(router),
            clock: Arc::new(now_ms),
            catalogs: HashMap::new(),
            hackamore_ca: String::new(),
            web_ui: true,
        }
    }

    /// Build a gateway with an injected clock (tests).
    pub fn with_clock(control: Arc<ControlPlane>, router: ServiceRouter, clock: Clock) -> Self {
        Self {
            control,
            router: std::sync::RwLock::new(router),
            clock,
            catalogs: HashMap::new(),
            hackamore_ca: String::new(),
            web_ui: true,
        }
    }

    /// Enable/disable the admin web UI and its authoring endpoints. Builder.
    #[must_use]
    pub fn with_web_ui(mut self, enabled: bool) -> Self {
        self.web_ui = enabled;
        self
    }

    /// Whether the admin listener serves the web UI and authoring endpoints.
    pub fn web_ui(&self) -> bool {
        self.web_ui
    }

    /// Attach per-target action catalogs (for mint-time policy validation). Builder.
    #[must_use]
    pub fn with_catalogs(mut self, catalogs: HashMap<String, ActionCatalog>) -> Self {
        self.catalogs = catalogs;
        self
    }

    /// Set the CA bundle consumers must trust to validate hackamore's TLS (surfaced as
    /// `hackamore_ca` in the provision doc). Builder; empty means plaintext.
    #[must_use]
    pub fn with_ca(mut self, ca_pem: impl Into<String>) -> Self {
        self.hackamore_ca = ca_pem.into();
        self
    }

    /// Mint a launch token bound to `policy`. This is the control-plane verb the
    /// orchestrator calls at launch. Any valid policy mints a token — there is no agent
    /// identity (multi-tenant caller-authorization, when added, gates this earlier).
    pub fn mint(
        &self,
        policy: hackamore_models::policy::Policy,
        ttl_seconds: u64,
    ) -> hackamore_models::control::MintResponse {
        self.control
            .tokens
            .mint(policy, ttl_seconds, (self.clock)())
    }

    /// Mint with multi-tenant authorization. When no tenants are configured (single trust
    /// domain) this is open and equals [`Gateway::mint`]. Otherwise a valid `tenant`
    /// credential is required and the policy may only name targets that tenant owns —
    /// fail closed, closing the credential-laundering hole.
    pub fn mint_checked(
        &self,
        policy: hackamore_models::policy::Policy,
        ttl_seconds: u64,
        tenant: Option<&str>,
    ) -> Result<hackamore_models::control::MintResponse, MintError> {
        if !self.control.tenants.is_empty() {
            let key = tenant.ok_or(MintError::MissingTenant)?;
            let owned = self
                .control
                .tenants
                .owned(key)
                .ok_or(MintError::UnknownTenant)?;
            validate_tenant_policy(&policy, &owned)?;
        }
        self.validate_catalog(&policy)?;
        self.lint_policy(&policy)?;
        Ok(self.mint(policy, ttl_seconds))
    }

    /// Run the model-aware policy lint with each configured service's imported model.
    /// Error findings reject the mint (fail fast: a policy with a rule that can never do
    /// what its author meant must not silently mint and then deny everything); warnings
    /// are returned to the caller in logs only.
    fn lint_policy(&self, policy: &hackamore_models::policy::Policy) -> Result<(), MintError> {
        let findings = self.lint(policy);
        for finding in findings.iter().filter(|f| !f.is_error()) {
            tracing::warn!(
                rule = finding.rule_index,
                "policy lint warning: {}",
                finding.message
            );
        }
        if findings
            .iter()
            .any(hackamore_models::lint::Finding::is_error)
        {
            return Err(MintError::PolicyLint(findings));
        }
        Ok(())
    }

    /// A poison-tolerant read lock on the service router. A panicked writer can't leave the
    /// routing table half-updated (services are replaced wholesale), so recovering the inner
    /// value keeps the data plane available rather than propagating the panic.
    fn router_read(&self) -> std::sync::RwLockReadGuard<'_, ServiceRouter> {
        self.router
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a service at runtime (live registration), replacing any of the same name.
    /// Returns whether an existing service was replaced.
    pub fn register_service(&self, service: Service) -> bool {
        self.router
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upsert(service)
    }

    /// Remove a registered service by name; returns whether one was removed.
    pub fn remove_service(&self, name: &str) -> bool {
        self.router
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(name)
    }

    /// Vault a secret supplied at runtime — a live-registered service's inline credential.
    /// Returns whether the credential store accepted it (a static/minting store may not).
    pub fn vault_secret(&self, id: String, secret: hackamore_control::Secret) -> bool {
        self.control.credentials.insert_runtime(id, secret)
    }

    /// Vault an AWS credential *bundle* supplied at runtime — an `aws-static` credential
    /// registered via the admin API. Returns whether the store accepted it.
    pub fn vault_aws(&self, id: String, cred: hackamore_control::AwsCredential) -> bool {
        self.control.credentials.insert_aws_runtime(id, cred)
    }

    /// Register an AWS-bundle minting provider (assume-role / instance) supplied at runtime.
    /// Returns whether the store supports AWS providers — only a minting `CachingCredentials`
    /// does; a static store returns `false` and the admin API answers 409 (fail closed). The
    /// provider is type-erased across the `CredentialStore` boundary (see
    /// [`hackamore_control::CredentialStore::register_aws_provider`]).
    pub fn register_aws_provider(
        &self,
        id: String,
        provider: Arc<dyn hackamore_control::AwsCredentialProvider>,
    ) -> bool {
        self.control
            .credentials
            .register_aws_provider(id, Box::new(provider))
    }

    /// The set of credential **ids** the vault knows about (for `GET /admin/credentials`).
    /// Ids only — never the secrets.
    pub fn credential_ids(&self) -> Vec<String> {
        self.control.credentials.ids()
    }

    /// Snapshot of registered services for the admin API (`GET /admin/services`): each
    /// instance's routing/auth projection plus its imported [`ApiModel`] (if any). Owned, so
    /// the router lock isn't held by the caller.
    pub fn registered_services(&self) -> Vec<RegisteredService> {
        self.router_read()
            .services()
            .iter()
            .map(|s| RegisteredService {
                name: s.name.clone(),
                host: s.host.clone(),
                upstream_base: s.upstream_base.clone(),
                address: s.address.clone(),
                auth: s.outbound.auth_label(),
                credential: s.outbound.credential_id().unwrap_or_default().to_string(),
                model: s.model.as_deref().cloned(),
            })
            .collect()
    }

    /// Lint a policy against the configured services' imported models (the same check
    /// minting enforces; also served as `POST /policy/lint` on the admin API). Only
    /// services with a model contribute model-derived checks; structural checks always run.
    pub fn lint(
        &self,
        policy: &hackamore_models::policy::Policy,
    ) -> Vec<hackamore_models::lint::Finding> {
        let router = self.router_read();
        let models: std::collections::BTreeMap<String, &hackamore_models::apimodel::ApiModel> =
            router
                .services()
                .iter()
                .filter_map(|s| s.model.as_deref().map(|m| (s.name.clone(), m)))
                .collect();
        hackamore_policy::lint::lint(policy, &models)
    }

    /// Dry-run one synthetic request through the real canonicalize → normalize →
    /// decide path under a not-yet-minted policy (served as `POST /policy/test`). No
    /// token, no forwarding, no audit: this is an authoring tool, not an enforcement
    /// path.
    pub fn dry_run(
        &self,
        req: &hackamore_models::dryrun::TestRequest,
    ) -> Result<hackamore_models::dryrun::TestResponse, DryRunError> {
        use hackamore_models::dryrun::{MatchedRule, TestResponse};
        let router = self.router_read();
        let service = router
            .services()
            .iter()
            .find(|s| s.name == req.target)
            .ok_or_else(|| DryRunError::UnknownTarget(req.target.clone()))?;
        let method = http::Method::from_bytes(req.method.as_bytes())
            .map_err(|_| DryRunError::InvalidMethod(req.method.clone()))?;
        let body = if req.fields.as_object().is_some_and(|o| !o.is_empty()) {
            serde_json::to_vec(&req.fields)
                .map(bytes::Bytes::from)
                .unwrap_or_default()
        } else {
            bytes::Bytes::new()
        };
        let proxy_req = ProxyRequest {
            method,
            path: req.path.clone(),
            query: req.query.clone(),
            headers: http::HeaderMap::new(),
            body,
        };
        let canonical = canonicalize::path(&proxy_req.path)
            .map_err(|_| DryRunError::NonCanonicalPath(req.path.clone()))?;
        let action = normalize::normalize(service, &proxy_req, &canonical.decoded);
        let trace = hackamore_policy::decide_traced(&action, &req.policy);
        Ok(TestResponse {
            action,
            verdict: trace.verdict,
            matched: MatchedRule::of(trace.matched_rule),
        })
    }

    /// Validate a policy's named-action verbs against the catalogs. A target with no catalog
    /// is unvalidated (raw); a known action passes; an unknown action **rejects the mint**
    /// (fail closed) — catching typos and stale assumptions before a token exists. CRUD
    /// verbs are always valid (Tier 0).
    ///
    /// Both rule shapes are covered: a rule that names explicit targets is checked against
    /// each named target's catalog; an **empty-target** (any-service) allow rule — which the
    /// old check skipped entirely — must have its named action known by *at least one*
    /// configured catalog, so a typo can't slip through on the broadest rule of all.
    fn validate_catalog(&self, policy: &hackamore_models::policy::Policy) -> Result<(), MintError> {
        use hackamore_models::action::Verb;
        use hackamore_models::policy::Effect;
        let nonempty: Vec<&ActionCatalog> =
            self.catalogs.values().filter(|c| !c.is_empty()).collect();
        for rule in &policy.rules {
            if rule.effect != Effect::Allow {
                continue;
            }
            for verb in &rule.matches.verbs {
                let Verb::Action(named) = verb else {
                    continue;
                };
                if rule.matches.targets.is_empty() {
                    // Any-service rule: require the action to be known by some catalog (when
                    // any catalogs are configured); skip when everything is raw.
                    if !nonempty.is_empty() && !nonempty.iter().any(|c| c.knows(&named.id)) {
                        return Err(MintError::UnknownAction {
                            target: "*".to_string(),
                            action: named.id.clone(),
                        });
                    }
                } else {
                    for target in &rule.matches.targets {
                        let Some(catalog) = self.catalogs.get(target) else {
                            continue;
                        };
                        if !catalog.is_empty() && !catalog.knows(&named.id) {
                            return Err(MintError::UnknownAction {
                                target: target.clone(),
                                action: named.id.clone(),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Revoke a token immediately. Returns whether a live token was removed.
    pub fn revoke(&self, token: &str) -> bool {
        self.control.tokens.revoke(token)
    }

    /// Evict expired token-table entries, returning the count reclaimed. Driven by the
    /// server's background sweeper so the table doesn't grow without bound.
    pub fn sweep_expired(&self) -> usize {
        self.control.tokens.sweep((self.clock)())
    }

    /// Project a [`ProvisionDoc`] for the consumer holding `token`: the token's bound
    /// policy ⋈ the service registry. Returns `None` for an unknown/expired token. The
    /// doc carries no real upstream secrets — only the token, endpoints, and (later) the
    /// CA.
    pub fn provision(&self, token: &str) -> Option<hackamore_models::provision::ProvisionDoc> {
        let now = (self.clock)();
        let (policy, expires_at_ms) = self.control.tokens.resolve_full(token, now)?;
        Some(hackamore_models::provision::ProvisionDoc {
            hackamore_token: token.to_string(),
            hackamore_ca: self.hackamore_ca.clone(),
            expires_at_ms,
            services: self.provisionable_services(token, &policy, now, expires_at_ms),
        })
    }

    /// The services a policy grants the consumer access to: every service whose name a
    /// rule's `targets` names, or — if any allow rule has empty `targets` (= any
    /// service) — all of them. Each entry carries the credential material the consumer
    /// presents: the hackamore token for bearer/passthrough services, or a freshly minted
    /// dummy SigV4 credential (bound to the same policy) for SigV4 services.
    fn provisionable_services(
        &self,
        token: &str,
        policy: &hackamore_models::policy::Policy,
        now: u64,
        expires_at_ms: u64,
    ) -> Vec<hackamore_models::provision::ProvisionService> {
        use hackamore_models::policy::Effect;
        let mut any_target = false;
        let mut named: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for rule in &policy.rules {
            if rule.effect != Effect::Allow {
                continue;
            }
            if rule.matches.targets.is_empty() {
                any_target = true;
            }
            for t in &rule.matches.targets {
                named.insert(t.as_str());
            }
        }
        let ttl_remaining = (expires_at_ms.saturating_sub(now) / 1000).max(1);
        // Explicit loop, not a `.map()`: producing each entry *mints a dummy credential*
        // for SigV4 services — a side effect that must not hide inside what reads as a pure
        // projection.
        let mut out = Vec::new();
        let router = self.router_read();
        for s in router.services() {
            if !(any_target || named.contains(s.name.as_str())) {
                continue;
            }
            let (mode, auth) = self.mint_service_auth(s, token, policy, now, ttl_remaining);
            out.push(hackamore_models::provision::ProvisionService {
                target: s.name.clone(),
                // A tool-config hint for the agent (which native config to write). Carried by
                // the service's `tool_hint` (set by the CLI presets), NOT its name — so a
                // service named `github-api`/`aws:ec2` still hints `github`/`aws`.
                tool_hint: s.tool_hint.clone(),
                address: s.address.clone(),
                mode,
                auth,
            });
        }
        out
    }

    /// Produce the consumer mode + auth material for one service. **This mints**: a SigV4
    /// service gets a freshly minted dummy credential bound to the same policy (hence the
    /// `mint_` name and the explicit caller loop); everything else reuses the bearer hackamore
    /// token and has no effect.
    fn mint_service_auth(
        &self,
        service: &Service,
        token: &str,
        policy: &hackamore_models::policy::Policy,
        now: u64,
        ttl_remaining: u64,
    ) -> (
        hackamore_models::provision::ProvisionMode,
        hackamore_models::provision::ProvisionAuth,
    ) {
        use hackamore_models::provision::{BearerAuth, ProvisionAuth, ProvisionMode, SigV4Auth};
        match &service.outbound {
            Outbound::SigV4 { region, .. } => {
                let dummy = self
                    .control
                    .tokens
                    .mint_sigv4(policy.clone(), ttl_remaining, now);
                let auth = ProvisionAuth::SigV4(SigV4Auth {
                    access_key_id: dummy.access_key_id,
                    secret_access_key: dummy.secret_access_key,
                    region: region.clone(),
                });
                (ProvisionMode::Inject, auth)
            }
            Outbound::Passthrough => (
                ProvisionMode::Passthrough,
                ProvisionAuth::Bearer(BearerAuth {
                    token: token.to_string(),
                }),
            ),
            Outbound::Bearer { .. } | Outbound::Header { .. } | Outbound::Basic { .. } => (
                ProvisionMode::Inject,
                ProvisionAuth::Bearer(BearerAuth {
                    token: token.to_string(),
                }),
            ),
        }
    }

    /// Authenticate the request to its bound policy. Two inbound schemes: AWS SigV4 (the
    /// `Authorization` header is `AWS4-HMAC-SHA256 …`, verified against a minted dummy
    /// credential) or a hackamore bearer token (`X-Hackamore-Token` or `Authorization: Bearer`).
    fn authenticate(
        &self,
        req: &ProxyRequest,
        now: u64,
    ) -> Result<(hackamore_models::policy::Policy, AuthSource), Box<Outcome>> {
        if let Some(auth) = req
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if auth.starts_with("AWS4-HMAC-SHA256") {
                return self.authenticate_sigv4(req, auth, now);
            }
            // git-over-HTTPS presents the launch token in the Basic *password* slot. A
            // present-but-malformed `Basic` header fails closed (it is never treated as a
            // bearer fallback) so a broken credential can't slip through.
            if let Some(prefix) = basic_scheme_value(auth) {
                let Some(token) = basic_password(prefix) else {
                    return Err(Box::new(reject(
                        http::StatusCode::UNAUTHORIZED,
                        DenyReason::Unauthenticated,
                        "malformed Basic credential",
                    )));
                };
                return match self.control.tokens.resolve(&token, now) {
                    Some(policy) => Ok((policy, AuthSource::BasicPassword)),
                    None => Err(Box::new(reject(
                        http::StatusCode::UNAUTHORIZED,
                        DenyReason::Unauthenticated,
                        "unknown or expired hackamore token",
                    ))),
                };
            }
        }
        let Some((token, source)) = extract_auth(&req.headers) else {
            return Err(Box::new(reject(
                http::StatusCode::UNAUTHORIZED,
                DenyReason::Unauthenticated,
                "missing hackamore token",
            )));
        };
        match self.control.tokens.resolve(&token, now) {
            Some(policy) => Ok((policy, source)),
            None => Err(Box::new(reject(
                http::StatusCode::UNAUTHORIZED,
                DenyReason::Unauthenticated,
                "unknown or expired hackamore token",
            ))),
        }
    }

    /// Verify an inbound AWS SigV4 signature against the dummy credential it names, and
    /// resolve the bound policy. The dummy AKID is the lookup key; the signature is
    /// recomputed with the stored dummy secret over the request as signed.
    fn authenticate_sigv4(
        &self,
        req: &ProxyRequest,
        auth: &str,
        now: u64,
    ) -> Result<(hackamore_models::policy::Policy, AuthSource), Box<Outcome>> {
        let unauth = || {
            Box::new(reject(
                http::StatusCode::UNAUTHORIZED,
                DenyReason::Unauthenticated,
                "invalid or unknown SigV4 credential",
            ))
        };
        let parsed = crate::sigv4::parse_authorization(auth).ok_or_else(unauth)?;
        let (policy, secret) = self
            .control
            .tokens
            .resolve_sigv4(&parsed.access_key_id, now)
            .ok_or_else(unauth)?;
        // Recompute over exactly the headers the client signed (read live from the
        // request) and bound replay via the `x-amz-date` freshness window.
        match crate::sigv4::verify(
            &secret,
            &parsed,
            req.method.as_str(),
            &req.path,
            &req.query,
            &req.headers,
            &req.body,
            now,
        ) {
            Ok(()) => Ok((policy, AuthSource::SigV4)),
            Err(_) => Err(unauth()),
        }
    }

    /// Authenticate, authorize, and (on allow) plan the upstream forward.
    pub fn handle(&self, mut req: ProxyRequest) -> Outcome {
        let now = (self.clock)();

        let (policy, source) = match self.authenticate(&req, now) {
            Ok(v) => v,
            Err(outcome) => return *outcome,
        };

        // Route to a configured service by the request Host. An unmatched host is denied
        // (fail closed) — hackamore only forwards to its allowlist.
        let host = extract_host(&req.headers).unwrap_or_default();
        let Some(service) = self.router_read().route(&host).cloned() else {
            self.audit_raw(&host, Decision::Deny, "no service for host", now);
            return reject(
                http::StatusCode::NOT_FOUND,
                DenyReason::UnknownTarget,
                "no service configured for this host",
            );
        };

        // Fold the path into its canonical form *before* deciding or forwarding, so a
        // disguised path (dot traversal, double/trailing slashes, encoded separators) can't
        // slip past the resource globs. A root escape fails closed. The decision uses the
        // decoded view; the forward/sign uses the re-encoded view.
        let canonical = match canonicalize::path(&req.path) {
            Ok(c) => c,
            Err(_) => {
                self.audit_raw(&host, Decision::Deny, "non-canonical path", now);
                return reject(
                    http::StatusCode::BAD_REQUEST,
                    DenyReason::NotAllowed,
                    "non-canonical request path",
                );
            }
        };
        let action = normalize::normalize(&service, &req, &canonical.decoded);
        req.path = canonical.encoded;

        let trace = hackamore_policy::decide_traced(&action, &policy);
        match trace.verdict {
            Verdict::Deny(d) => {
                // Carry which rule denied (if any) so a denial is debuggable from the
                // audit log alone; `None` = default-deny fallthrough.
                let detail = match trace.matched_rule {
                    Some(rule) => format!("{:?} (rule {rule})", d.reason),
                    None => format!("{:?} (no rule matched)", d.reason),
                };
                self.audit(&action, Decision::Deny, &detail, now);
                reject(http::StatusCode::FORBIDDEN, d.reason, "denied by policy")
            }
            // On allow the outbound credential is the matched service's property, not the
            // policy's — the engine's allow is bare.
            Verdict::Allow(_) => {
                self.plan_forward(&service, &action, req, source, trace.matched_rule, now)
            }
        }
    }

    /// Build the upstream forward plan according to the matched service's outbound
    /// stance. `Passthrough` forwards the consumer's own credential (preserved by
    /// `sanitize_headers` when the hackamore token arrived via `X-Hackamore-Token`); `Bearer`
    /// and `Header` swap in the target's real credential from the vault. A missing
    /// credential fails closed.
    fn plan_forward(
        &self,
        service: &Service,
        action: &Action,
        req: ProxyRequest,
        source: AuthSource,
        matched_rule: Option<usize>,
        now: u64,
    ) -> Outcome {
        let mut headers = sanitize_headers(&req.headers, source);

        let detail = match &service.outbound {
            Outbound::Passthrough => "allowed (passthrough)".to_string(),
            Outbound::Bearer { credential } => {
                let value = match self.resolve_header_value(action, credential, "Bearer ", now) {
                    Ok(v) => v,
                    Err(outcome) => return *outcome,
                };
                headers.insert(http::header::AUTHORIZATION, value);
                format!("allowed; injected bearer [{credential}]")
            }
            Outbound::Header { name, credential } => {
                let Ok(header_name) = http::HeaderName::from_bytes(name.as_bytes()) else {
                    self.audit(action, Decision::Deny, "invalid header name", now);
                    return reject(
                        http::StatusCode::BAD_GATEWAY,
                        DenyReason::NotAllowed,
                        "configured header name is invalid",
                    );
                };
                let value = match self.resolve_header_value(action, credential, "", now) {
                    Ok(v) => v,
                    Err(outcome) => return *outcome,
                };
                headers.insert(header_name, value);
                format!("allowed; injected header {name} [{credential}]")
            }
            Outbound::Basic {
                username,
                credential,
            } => {
                let Some(secret) = self.control.credentials.resolve(credential) else {
                    self.audit(
                        action,
                        Decision::Deny,
                        &format!("credential '{credential}' not configured"),
                        now,
                    );
                    return reject(
                        http::StatusCode::BAD_GATEWAY,
                        DenyReason::NotAllowed,
                        "required credential is not configured",
                    );
                };
                // Basic auth is `base64(username:password)`; the password is the resolved
                // secret. `.expose()` is the audited injection boundary — the encoded value
                // never appears in the audit/outcome string.
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{}", secret.expose()));
                let Ok(value) = http::HeaderValue::from_str(&format!("Basic {encoded}")) else {
                    self.audit(action, Decision::Deny, "credential not header-safe", now);
                    return reject(
                        http::StatusCode::BAD_GATEWAY,
                        DenyReason::NotAllowed,
                        "credential is not header-safe",
                    );
                };
                headers.insert(http::header::AUTHORIZATION, value);
                format!("allowed; injected basic [{credential}]")
            }
            Outbound::SigV4 {
                credential,
                region,
                service: aws_service,
            } => {
                // SigV4 resolves an AWS *bundle* (akid + secret + optional session token), not
                // a token-shaped secret. A missing bundle (unknown id, or the id holds a
                // token) fails closed.
                let Some(bundle) = self.control.credentials.resolve_aws(credential) else {
                    self.audit(
                        action,
                        Decision::Deny,
                        &format!("credential '{credential}' not configured"),
                        now,
                    );
                    return reject(
                        http::StatusCode::BAD_GATEWAY,
                        DenyReason::NotAllowed,
                        "required credential is not configured",
                    );
                };
                let host = host_of(&service.upstream_base);
                // `.expose()` is the audited injection boundary — the secret and session
                // token never appear in the audit/outcome string.
                let signed = crate::sigv4::sign(
                    &crate::sigv4::Creds {
                        access_key_id: &bundle.access_key_id,
                        secret_access_key: bundle.secret_access_key.expose(),
                        session_token: bundle.session_token.as_ref().map(|t| t.expose()),
                    },
                    region,
                    aws_service,
                    req.method.as_str(),
                    host,
                    &req.path,
                    &req.query,
                    &req.body,
                    now,
                );
                // The forward URL's host equals `host`, so reqwest sends the same Host we
                // signed. Set the SigV4 headers (these values are always header-safe).
                set_header(
                    &mut headers,
                    http::header::AUTHORIZATION,
                    &signed.authorization,
                );
                set_header(
                    &mut headers,
                    http::HeaderName::from_static("x-amz-date"),
                    &signed.amz_date,
                );
                set_header(
                    &mut headers,
                    http::HeaderName::from_static("x-amz-content-sha256"),
                    &signed.content_sha256,
                );
                // Temporary credentials ride out their session token in the signed
                // `X-Amz-Security-Token` header.
                if let Some(token) = &signed.security_token {
                    set_header(
                        &mut headers,
                        http::HeaderName::from_static("x-amz-security-token"),
                        token,
                    );
                }
                format!("allowed; sigv4 re-signed [{credential}]")
            }
        };
        let detail = match matched_rule {
            Some(rule) => format!("{detail}; rule {rule}"),
            None => detail,
        };
        self.audit(action, Decision::Allow, &detail, now);

        Outcome::Forward(ForwardPlan {
            url: upstream_url(&service.upstream_base, &req.path, &req.query),
            method: req.method,
            headers,
            body: req.body,
        })
    }

    /// Resolve a vault credential into a header value `<prefix><secret>`, or a boxed
    /// `Err(Outcome)` that fails closed (audited) when the credential is missing or not
    /// header-safe. (Boxed because `Outcome` is large.)
    fn resolve_header_value(
        &self,
        action: &Action,
        credential: &str,
        prefix: &str,
        now: u64,
    ) -> Result<http::HeaderValue, Box<Outcome>> {
        let Some(secret) = self.control.credentials.resolve(credential) else {
            self.audit(
                action,
                Decision::Deny,
                &format!("credential '{credential}' not configured"),
                now,
            );
            return Err(Box::new(reject(
                http::StatusCode::BAD_GATEWAY,
                DenyReason::NotAllowed,
                "required credential is not configured",
            )));
        };
        http::HeaderValue::from_str(&format!("{prefix}{}", secret.expose())).map_err(|_| {
            self.audit(action, Decision::Deny, "credential not header-safe", now);
            Box::new(reject(
                http::StatusCode::BAD_GATEWAY,
                DenyReason::NotAllowed,
                "credential is not header-safe",
            ))
        })
    }

    fn audit(&self, action: &Action, decision: Decision, detail: &str, now: u64) {
        self.control.audit.record(AuditEvent {
            at_ms: now,
            action: action.clone(),
            decision,
            detail: detail.to_string(),
        });
    }

    /// Audit a decision made before a routed `Action` exists (e.g. an unroutable host).
    /// The recorded action carries the raw host as its target so the event is still
    /// attributable.
    fn audit_raw(&self, host: &str, decision: Decision, detail: &str, now: u64) {
        let action = Action::of(
            "<unrouted>",
            hackamore_models::action::Verb::method("GET"),
            hackamore_models::action::Resource::of(host),
        );
        self.audit(&action, decision, detail, now);
    }
}

/// The host portion of an upstream base URL (`https://ec2.us-east-1.amazonaws.com/...` →
/// `ec2.us-east-1.amazonaws.com`).
fn host_of(base: &str) -> &str {
    let no_scheme = base.split_once("://").map(|(_, r)| r).unwrap_or(base);
    no_scheme.split('/').next().unwrap_or(no_scheme)
}

/// Insert a header, ignoring values that aren't header-safe (SigV4 values always are).
fn set_header(headers: &mut http::HeaderMap, name: http::HeaderName, value: &str) {
    if let Ok(v) = http::HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// Join an upstream base with the request path and optional query.
fn upstream_url(base: &str, path: &str, query: &str) -> String {
    let base = base.trim_end_matches('/');
    if query.is_empty() {
        format!("{base}{path}")
    } else {
        format!("{base}{path}?{query}")
    }
}

/// Extract the `Host` header value.
fn extract_host(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn reject(status: http::StatusCode, reason: DenyReason, message: &str) -> Outcome {
    Outcome::Reject(Rejection {
        status,
        reason,
        message: message.to_string(),
    })
}

/// Validate a tenant-submitted policy: every `Allow` rule must name explicit targets, all
/// owned by the tenant. An empty-targets allow rule would grant *any* service — unsafe
/// across trust domains — so it is rejected for tenants.
fn validate_tenant_policy(
    policy: &hackamore_models::policy::Policy,
    owned: &std::collections::BTreeSet<String>,
) -> Result<(), MintError> {
    use hackamore_models::policy::Effect;
    for rule in &policy.rules {
        if rule.effect != Effect::Allow {
            continue;
        }
        if rule.matches.targets.is_empty() {
            return Err(MintError::TenantWildcardTarget);
        }
        for t in &rule.matches.targets {
            if !owned.contains(t.as_str()) {
                return Err(MintError::TargetNotOwned(t.clone()));
            }
        }
    }
    Ok(())
}

/// Why a mint request was refused. A typed error so the data plane maps each cause to a
/// precise response instead of threading an opaque `String`. All variants are
/// Why a dry-run request could not even be normalized (the authoring-tool analogue of
/// the proxy's 4xx rejections). Rendered as a 400 by the admin API.
#[derive(Debug, PartialEq, Eq)]
pub enum DryRunError {
    /// `target` names no configured service.
    UnknownTarget(String),
    /// The method string is not a valid HTTP method.
    InvalidMethod(String),
    /// The path failed canonicalization (escapes the root, bad encoding, …).
    NonCanonicalPath(String),
}

impl std::fmt::Display for DryRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DryRunError::UnknownTarget(t) => write!(f, "unknown target '{t}'"),
            DryRunError::InvalidMethod(m) => write!(f, "invalid method '{m}'"),
            DryRunError::NonCanonicalPath(p) => write!(f, "non-canonical path '{p}'"),
        }
    }
}

impl std::error::Error for DryRunError {}

/// authorization/validation failures the operator surface renders as `403`.
/// (`PartialEq` only: lint findings are fluorite wire types without `Eq`.)
#[derive(Debug, PartialEq)]
pub enum MintError {
    /// Tenants are configured but the request presented no tenant credential.
    MissingTenant,
    /// The presented tenant credential is not registered.
    UnknownTenant,
    /// A tenant allow rule named a target the tenant does not own.
    TargetNotOwned(String),
    /// A tenant allow rule left `targets` empty — that would grant *any* service, unsafe
    /// across trust domains.
    TenantWildcardTarget,
    /// A named-action verb is absent from the target's action catalog.
    UnknownAction { target: String, action: String },
    /// The policy failed lint with at least one `Error` finding. Carries *all* findings
    /// (warnings included) so the rejection response can show the full picture.
    PolicyLint(Vec<hackamore_models::lint::Finding>),
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintError::MissingTenant => f.write_str("missing tenant credential"),
            MintError::UnknownTenant => f.write_str("unknown tenant credential"),
            MintError::TargetNotOwned(t) => write!(f, "target '{t}' is not owned by this tenant"),
            MintError::TenantWildcardTarget => {
                f.write_str("tenant allow rules must name explicit targets")
            }
            MintError::UnknownAction { target, action } => {
                write!(
                    f,
                    "action '{action}' is not in the catalog for target '{target}'"
                )
            }
            MintError::PolicyLint(findings) => {
                let errors: Vec<&hackamore_models::lint::Finding> =
                    findings.iter().filter(|f| f.is_error()).collect();
                let first = errors
                    .first()
                    .map(|e| format!("rule {}: {}", e.rule_index, e.message))
                    .unwrap_or_default();
                match errors.len() {
                    0 | 1 => write!(f, "policy failed lint: {first}"),
                    n => write!(f, "policy failed lint: {first} (+{} more)", n - 1),
                }
            }
        }
    }
}

impl std::error::Error for MintError {}

/// The dedicated header a consumer uses to present its hackamore token *without* consuming
/// the `Authorization` slot — so a filter-only (passthrough) consumer can carry its own
/// upstream credential in `Authorization` at the same time.
const HACKAMORE_TOKEN_HEADER: &str = "x-hackamore-token";

/// Where the hackamore token was found. This decides whether `Authorization` belongs to
/// hackamore (and must be stripped) or to the consumer (and must be preserved for
/// passthrough).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AuthSource {
    /// The token came from the dedicated `X-Hackamore-Token` header; `Authorization` (if
    /// any) is the consumer's own upstream credential.
    HackamoreHeader,
    /// The token came from `Authorization` itself (e.g. `gh`/`kubectl`, which have only
    /// one auth slot); `Authorization` is the hackamore token and must not be forwarded.
    Authorization,
    /// The token came from the password half of an inbound HTTP Basic `Authorization`
    /// (git-over-HTTPS: `Basic base64(x-access-token:<launch token>)`). The inbound
    /// `Authorization` is hackamore's and must be stripped/replaced before forwarding.
    BasicPassword,
    /// The request was authenticated by an inbound AWS SigV4 signature; the inbound
    /// `Authorization` and `X-Amz-*` signing headers are hackamore's to replace on re-sign.
    SigV4,
}

/// The hackamore token from a request's headers, ignoring its source. Used by the
/// `/provision` endpoint, which never forwards, so the channel does not matter.
pub fn token_from_headers(headers: &http::HeaderMap) -> Option<String> {
    extract_auth(headers).map(|(token, _)| token)
}

/// Extract the hackamore token and where it came from. `X-Hackamore-Token` is preferred (it
/// frees `Authorization` for passthrough); otherwise fall back to `Authorization`,
/// accepting both `Bearer <t>` and GitHub's `token <t>` schemes.
fn extract_auth(headers: &http::HeaderMap) -> Option<(String, AuthSource)> {
    if let Some(v) = headers
        .get(HACKAMORE_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        let v = v.trim();
        if !v.is_empty() {
            return Some((v.to_string(), AuthSource::HackamoreHeader));
        }
    }
    let raw = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = raw.split_once(' ')?;
    let scheme = scheme.to_ascii_lowercase();
    if (scheme == "bearer" || scheme == "token") && !value.trim().is_empty() {
        Some((value.trim().to_string(), AuthSource::Authorization))
    } else {
        None
    }
}

/// The base64 payload of a `Basic <payload>` `Authorization` value (case-insensitive
/// scheme), or `None` if it isn't a Basic header.
fn basic_scheme_value(auth: &str) -> Option<&str> {
    let (scheme, value) = auth.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("basic") {
        Some(value.trim())
    } else {
        None
    }
}

/// Decode the password half of an inbound HTTP Basic credential: base64-decode `payload`,
/// then take everything after the first `:` (the username is non-secret config — for git it
/// is `x-access-token`). Fail closed (`None`) on bad base64, non-UTF-8, a missing `:`, or an
/// empty password.
fn basic_password(payload: &str) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (_user, pass) = text.split_once(':')?;
    if pass.is_empty() {
        None
    } else {
        Some(pass.to_string())
    }
}

/// Copy request headers for the upstream, always dropping the `X-Hackamore-Token` header,
/// the inbound `Host` and `Content-Length` (recomputed by the client), and hop-by-hop
/// headers. `Authorization` is dropped only when it carried the hackamore token
/// (`source == Authorization`); under `HackamoreHeader` it is the consumer's own credential
/// and is preserved for passthrough.
fn sanitize_headers(headers: &http::HeaderMap, source: AuthSource) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in headers {
        if is_dropped_header(name, source) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn is_dropped_header(name: &http::HeaderName, source: AuthSource) -> bool {
    const HOP_BY_HOP: [&str; 8] = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];
    let n = name.as_str().to_ascii_lowercase();
    if n == HACKAMORE_TOKEN_HEADER || n == "host" || n == "content-length" {
        return true;
    }
    if n == "authorization" {
        // The hackamore token (Authorization source), the inbound SigV4 signature (SigV4
        // source), and the inbound Basic launch token (BasicPassword source) are all
        // hackamore's to strip/replace; only a HackamoreHeader token leaves Authorization as
        // the consumer's own credential.
        return source != AuthSource::HackamoreHeader;
    }
    // Inbound SigV4 signing headers are replaced by the outbound re-sign.
    if source == AuthSource::SigV4 && (n == "x-amz-date" || n == "x-amz-content-sha256") {
        return true;
    }
    HOP_BY_HOP.contains(&n.as_str())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::service::{Extract, Service, ServiceRouter};
    use hackamore_control::{InMemoryAudit, Secret};
    use hackamore_models::policy::{Effect, Match, Policy, Rule};

    /// A control plane wired with an in-memory audit sink we can inspect, plus a seeded
    /// credential. Returns the plane, the audit handle, and the credential handle.
    fn test_control() -> (
        Arc<ControlPlane>,
        Arc<InMemoryAudit>,
        Arc<hackamore_control::InMemoryCredentials>,
    ) {
        let creds = Arc::new(hackamore_control::InMemoryCredentials::new());
        creds.insert("github-app", Secret::new("real-secret-token"));
        let audit = Arc::new(InMemoryAudit::new());
        let plane = ControlPlane::new(creds.clone(), audit.clone());
        (Arc::new(plane), audit, creds)
    }

    /// A catch-all service that injects the `github-app` credential.
    fn router() -> ServiceRouter {
        ServiceRouter::new(vec![
            Service::new("github", "*", "https://api.github.com").with_outbound(Outbound::Bearer {
                credential: "github-app".into(),
            }),
        ])
    }

    /// A catch-all generic service that forwards the consumer's own credential.
    fn router_passthrough() -> ServiceRouter {
        ServiceRouter::new(vec![Service::new("svc", "*", "https://up.example")])
    }

    /// A catch-all generic service that injects a credential as `X-API-Key`.
    fn router_header() -> ServiceRouter {
        ServiceRouter::new(vec![
            Service::new("keyed", "*", "https://api.keyed.com").with_outbound(Outbound::Header {
                name: "X-API-Key".into(),
                credential: "keyed-key".into(),
            }),
        ])
    }

    /// A catch-all generic service that injects a credential as HTTP Basic auth with the
    /// git-over-HTTPS username.
    fn router_basic() -> ServiceRouter {
        ServiceRouter::new(vec![
            Service::new("git", "*", "https://github.com").with_outbound(Outbound::Basic {
                username: "x-access-token".into(),
                credential: "gh-login".into(),
            }),
        ])
    }

    fn allow_all() -> Policy {
        Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![],
                    verbs: vec![],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        }
    }

    fn read_only() -> Policy {
        Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![],
                    verbs: vec![hackamore_models::action::Verb::method("GET")],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        }
    }

    fn bearer(token: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    /// Headers with the hackamore token in `X-Hackamore-Token` and the consumer's own
    /// credential in `Authorization` (the passthrough shape).
    fn hackamore_header_with_own_cred(token: &str, own_cred: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            HACKAMORE_TOKEN_HEADER,
            http::HeaderValue::from_str(token).unwrap(),
        );
        h.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(own_cred).unwrap(),
        );
        h
    }

    fn get(headers: http::HeaderMap, path: &str) -> ProxyRequest {
        ProxyRequest {
            method: http::Method::GET,
            path: path.into(),
            query: String::new(),
            headers,
            body: bytes::Bytes::new(),
        }
    }

    fn fixed_clock(t: u64) -> Clock {
        Arc::new(move || t)
    }

    #[test]
    fn missing_token_is_unauthorized() {
        let (control, _audit, _) = test_control();
        let gw = Gateway::new(control, router());
        match gw.handle(get(http::HeaderMap::new(), "/repos/o/r")) {
            Outcome::Reject(r) => {
                assert_eq!(r.status, http::StatusCode::UNAUTHORIZED);
                assert_eq!(r.reason, DenyReason::Unauthenticated);
            }
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn unknown_token_is_unauthorized() {
        let (control, _a, _) = test_control();
        let gw = Gateway::new(control, router());
        match gw.handle(get(bearer("not-a-real-token"), "/repos/o/r")) {
            Outcome::Reject(r) => assert_eq!(r.reason, DenyReason::Unauthenticated),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn allowed_request_injects_targets_credential() {
        let (control, audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);

        match gw.handle(get(bearer(&minted.token), "/repos/octocat/hello")) {
            Outcome::Forward(plan) => {
                assert_eq!(plan.url, "https://api.github.com/repos/octocat/hello");
                let auth = plan
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                // The consumer's token is gone; the target's real secret is in its place.
                assert_eq!(auth, "Bearer real-secret-token");
                assert!(!auth.contains(&minted.token));
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
        let events = audit.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, Decision::Allow);
    }

    #[test]
    fn passthrough_with_token_in_authorization_forwards_no_credential() {
        let (control, _audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router_passthrough(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        // The consumer put the hackamore token in Authorization and carries no separate
        // upstream credential → it is stripped, nothing replaces it.
        match gw.handle(get(bearer(&minted.token), "/x")) {
            Outcome::Forward(plan) => {
                assert!(plan.headers.get(http::header::AUTHORIZATION).is_none());
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn passthrough_preserves_consumers_own_credential() {
        let (control, _audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router_passthrough(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        // The hackamore token rides X-Hackamore-Token; the consumer's own credential in
        // Authorization is forwarded untouched (the real filter-only behaviour).
        let headers = hackamore_header_with_own_cred(&minted.token, "Bearer consumer-own-key");
        let req = ProxyRequest {
            method: http::Method::GET,
            path: "/x".into(),
            query: String::new(),
            headers,
            body: bytes::Bytes::new(),
        };
        match gw.handle(req) {
            Outcome::Forward(plan) => {
                assert_eq!(
                    plan.headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok()),
                    Some("Bearer consumer-own-key")
                );
                // The hackamore token header is not forwarded.
                assert!(plan.headers.get(HACKAMORE_TOKEN_HEADER).is_none());
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn inject_overrides_consumers_own_credential() {
        let (control, _audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        // Even if the consumer presents its own credential, inject replaces it with the
        // target's real secret.
        let headers = hackamore_header_with_own_cred(&minted.token, "Bearer consumer-own-key");
        let req = ProxyRequest {
            method: http::Method::GET,
            path: "/repos/o/r".into(),
            query: String::new(),
            headers,
            body: bytes::Bytes::new(),
        };
        match gw.handle(req) {
            Outcome::Forward(plan) => {
                assert_eq!(
                    plan.headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok()),
                    Some("Bearer real-secret-token")
                );
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn header_mechanism_injects_custom_header() {
        let (control, _a, creds) = test_control();
        creds.insert("keyed-key", Secret::new("sk-keyed"));
        let gw = Gateway::with_clock(control, router_header(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        match gw.handle(get(bearer(&minted.token), "/v1/x")) {
            Outcome::Forward(plan) => {
                assert_eq!(
                    plan.headers.get("x-api-key").and_then(|v| v.to_str().ok()),
                    Some("sk-keyed")
                );
                // No Bearer Authorization for a header-keyed service.
                assert!(plan.headers.get(http::header::AUTHORIZATION).is_none());
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn basic_mechanism_injects_base64_authorization() {
        let (control, audit, creds) = test_control();
        creds.insert("gh-login", Secret::new("ghp_realtoken"));
        let gw = Gateway::with_clock(control, router_basic(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        match gw.handle(get(bearer(&minted.token), "/octocat/hello.git/info/refs")) {
            Outcome::Forward(plan) => {
                let auth = plan
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                // Authorization: Basic base64("x-access-token:ghp_realtoken").
                let expected = base64::engine::general_purpose::STANDARD
                    .encode("x-access-token:ghp_realtoken");
                assert_eq!(auth, format!("Basic {expected}"));
                // The real secret never appears verbatim in the header.
                assert!(!auth.contains("ghp_realtoken"));
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
        // The audit detail names the credential id, never the secret.
        let events = audit.events();
        assert_eq!(events[0].decision, Decision::Allow);
        assert!(events[0].detail.contains("injected basic [gh-login]"));
        assert!(!events[0].detail.contains("ghp_realtoken"));
    }

    #[test]
    fn basic_mechanism_missing_credential_fails_closed() {
        let (control, _a, _) = test_control();
        // No `gh-login` credential seeded → fail closed with a bad gateway.
        let gw = Gateway::with_clock(control, router_basic(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        match gw.handle(get(bearer(&minted.token), "/x")) {
            Outcome::Reject(r) => assert_eq!(r.status, http::StatusCode::BAD_GATEWAY),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    fn sigv4_ec2_router() -> ServiceRouter {
        ServiceRouter::new(vec![
            Service::new("ec2", "*", "https://ec2.us-east-1.amazonaws.com").with_outbound(
                Outbound::SigV4 {
                    credential: "aws-secret".into(),
                    region: "us-east-1".into(),
                    service: "ec2".into(),
                },
            ),
        ])
    }

    #[test]
    fn sigv4_mechanism_signs_outbound_request() {
        let (control, _a, creds) = test_control();
        // The akid now comes from the resolved AWS bundle, not from the service config.
        creds.insert_aws(
            "aws-secret",
            hackamore_control::AwsCredential {
                access_key_id: "AKID".into(),
                secret_access_key: Secret::new("secret-key"),
                session_token: None,
                expires_at_ms: None,
            },
        );
        let gw = Gateway::with_clock(control, sigv4_ec2_router(), fixed_clock(1_700_000_000_000));
        let minted = gw.mint(allow_all(), 60);
        match gw.handle(get(bearer(&minted.token), "/")) {
            Outcome::Forward(plan) => {
                let auth = plan
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/"));
                assert!(auth.contains("/us-east-1/ec2/aws4_request"));
                assert!(auth.contains("Signature="));
                // The real secret is not present anywhere in the outbound headers.
                assert!(!auth.contains("secret-key"));
                assert!(plan.headers.get("x-amz-date").is_some());
                assert!(plan.headers.get("x-amz-content-sha256").is_some());
                // A long-lived key pair (no session token) sets no security-token header.
                assert!(plan.headers.get("x-amz-security-token").is_none());
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn sigv4_mechanism_with_session_token_sets_security_token_header() {
        let (control, _a, creds) = test_control();
        creds.insert_aws(
            "aws-secret",
            hackamore_control::AwsCredential {
                access_key_id: "AKID".into(),
                secret_access_key: Secret::new("secret-key"),
                session_token: Some(Secret::new("the-session-token")),
                expires_at_ms: None,
            },
        );
        let gw = Gateway::with_clock(control, sigv4_ec2_router(), fixed_clock(1_700_000_000_000));
        let minted = gw.mint(allow_all(), 60);
        match gw.handle(get(bearer(&minted.token), "/")) {
            Outcome::Forward(plan) => {
                let token = plan
                    .headers
                    .get("x-amz-security-token")
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(token, "the-session-token");
                // The session token is part of the signed header set.
                let auth = plan
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(auth.contains("x-amz-security-token"));
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn sigv4_mechanism_missing_bundle_fails_closed() {
        let (control, _a, creds) = test_control();
        // Seed a *token* under the id the service expects an AWS bundle for → resolve_aws
        // returns None → fail closed.
        creds.insert("aws-secret", Secret::new("not-a-bundle"));
        let gw = Gateway::with_clock(control, sigv4_ec2_router(), fixed_clock(1_700_000_000_000));
        let minted = gw.mint(allow_all(), 60);
        match gw.handle(get(bearer(&minted.token), "/")) {
            Outcome::Reject(r) => assert_eq!(r.status, http::StatusCode::BAD_GATEWAY),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    /// Build a SigV4-signed request the way the AWS CLI would, using `dummy` creds.
    fn signed_aws_request(
        akid: &str,
        secret: &str,
        host: &str,
        body: &'static [u8],
        now: u64,
    ) -> ProxyRequest {
        let signed = crate::sigv4::sign(
            &crate::sigv4::Creds {
                access_key_id: akid,
                secret_access_key: secret,
                session_token: None,
            },
            "us-east-1",
            "ec2",
            "POST",
            host,
            "/",
            "",
            body,
            now,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, host.parse().unwrap());
        headers.insert(
            http::header::AUTHORIZATION,
            signed.authorization.parse().unwrap(),
        );
        headers.insert("x-amz-date", signed.amz_date.parse().unwrap());
        headers.insert(
            "x-amz-content-sha256",
            signed.content_sha256.parse().unwrap(),
        );
        ProxyRequest {
            method: http::Method::POST,
            path: "/".into(),
            query: String::new(),
            headers,
            body: bytes::Bytes::from_static(body),
        }
    }

    fn aws_router() -> ServiceRouter {
        ServiceRouter::new(vec![
            Service::new(
                "ec2",
                "ec2.amazonaws.com",
                "https://ec2.us-east-1.amazonaws.com",
            )
            .with_outbound(Outbound::SigV4 {
                credential: "aws-secret".into(),
                region: "us-east-1".into(),
                service: "ec2".into(),
            })
            .with_extract(Extract {
                protocol: crate::service::Protocol::parse(Some("aws-query")),
                path_template: None,
            }),
        ])
    }

    #[test]
    fn sigv4_inbound_authenticates_then_resigns_with_real_credential() {
        let (control, _a, creds) = test_control();
        // The real akid + secret live in the AWS bundle; the inbound dummy AKID is unrelated.
        creds.insert_aws(
            "aws-secret",
            hackamore_control::AwsCredential {
                access_key_id: "REALAKID".into(),
                secret_access_key: Secret::new("real-secret"),
                session_token: None,
                expires_at_ms: None,
            },
        );
        let now = 1_700_000_000_000;
        let gw = Gateway::with_clock(control.clone(), aws_router(), fixed_clock(now));
        let dummy = control.tokens.mint_sigv4(allow_all(), 60, now);
        let body = b"Action=DescribeInstances&Version=2016-11-15";
        let req = signed_aws_request(
            &dummy.access_key_id,
            &dummy.secret_access_key,
            "ec2.amazonaws.com",
            body,
            now,
        );
        match gw.handle(req) {
            Outcome::Forward(plan) => {
                let auth = plan
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                // Re-signed with the REAL access key id; the dummy AKID and real secret
                // are nowhere in the outbound request.
                assert!(auth.contains("Credential=REALAKID/"));
                assert!(!auth.contains(&dummy.access_key_id));
                assert!(!auth.contains("real-secret"));
            }
            Outcome::Reject(r) => panic!("expected forward, got {:?}", r.reason),
        }
    }

    #[test]
    fn sigv4_inbound_bad_signature_is_unauthorized() {
        let (control, _a, creds) = test_control();
        creds.insert_aws(
            "aws-secret",
            hackamore_control::AwsCredential {
                access_key_id: "REALAKID".into(),
                secret_access_key: Secret::new("real-secret"),
                session_token: None,
                expires_at_ms: None,
            },
        );
        let now = 1_700_000_000_000;
        let gw = Gateway::with_clock(control.clone(), aws_router(), fixed_clock(now));
        let dummy = control.tokens.mint_sigv4(allow_all(), 60, now);
        let body = b"Action=DescribeInstances&Version=2016-11-15";
        // Sign with the wrong secret → signature won't verify against the stored dummy.
        let req = signed_aws_request(
            &dummy.access_key_id,
            "WRONG-SECRET",
            "ec2.amazonaws.com",
            body,
            now,
        );
        match gw.handle(req) {
            Outcome::Reject(r) => assert_eq!(r.reason, DenyReason::Unauthenticated),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn expired_token_is_unauthorized() {
        let (control, _a, _) = test_control();
        // Mint at t=1000 with 60s TTL → expires at 61_000.
        let gw_mint = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw_mint.mint(allow_all(), 60);
        // Handle at t=61_000 (expired).
        let gw = Gateway::with_clock(control, router(), fixed_clock(61_000));
        match gw.handle(get(bearer(&minted.token), "/repos/o/r")) {
            Outcome::Reject(r) => assert_eq!(r.reason, DenyReason::Unauthenticated),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn denied_request_is_forbidden_and_audited() {
        let (control, audit, _) = test_control();
        // Policy allows only reads; a DELETE falls through to default-deny.
        let gw = Gateway::with_clock(control, router(), fixed_clock(1_000));
        let minted = gw.mint(read_only(), 60);
        let del = ProxyRequest {
            method: http::Method::DELETE,
            path: "/repos/o/r".into(),
            query: String::new(),
            headers: bearer(&minted.token),
            body: bytes::Bytes::new(),
        };
        match gw.handle(del) {
            Outcome::Reject(r) => {
                assert_eq!(r.status, http::StatusCode::FORBIDDEN);
                assert_eq!(r.reason, DenyReason::NotAllowed);
            }
            Outcome::Forward(_) => panic!("expected reject"),
        }
        assert_eq!(audit.events()[0].decision, Decision::Deny);
        // Default-deny fallthrough is explicit in the audit detail.
        assert_eq!(audit.events()[0].detail, "NotAllowed (no rule matched)");
    }

    #[test]
    fn audit_detail_carries_the_matched_rule_index() {
        let (control, audit, _) = test_control();
        let gw = Gateway::with_clock(control, router(), fixed_clock(1_000));
        let minted = gw.mint(read_only(), 60);
        let get = ProxyRequest {
            method: http::Method::GET,
            path: "/repos/o/r".into(),
            query: String::new(),
            headers: bearer(&minted.token),
            body: bytes::Bytes::new(),
        };
        assert!(matches!(gw.handle(get), Outcome::Forward(_)));
        assert_eq!(audit.events()[0].decision, Decision::Allow);
        assert!(
            audit.events()[0].detail.ends_with("; rule 0"),
            "{}",
            audit.events()[0].detail
        );
    }

    #[test]
    fn mint_rejects_policies_that_fail_lint() {
        let (control, _, _) = test_control();
        let gw = Gateway::with_clock(control, router(), fixed_clock(1_000));

        // An unmatchable glob (leading slash) is an Error finding.
        let bad_glob = Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![],
                    verbs: vec![],
                    resources: vec!["/repos/o/**".into()],
                    conditions: vec![],
                },
            }],
        };
        match gw.mint_checked(bad_glob, 60, None) {
            Err(MintError::PolicyLint(findings)) => {
                assert!(findings.iter().any(|f| f.is_error()));
            }
            other => panic!("expected lint rejection, got {other:?}"),
        }

        // A deny rule shadowed by an earlier allow-all never fires: also rejected.
        let shadowed_deny = Policy {
            rules: vec![
                allow_all().rules[0].clone(),
                Rule {
                    effect: Effect::Deny,
                    matches: Match {
                        targets: vec![],
                        verbs: vec![hackamore_models::action::Verb::method("DELETE")],
                        resources: vec![],
                        conditions: vec![],
                    },
                },
            ],
        };
        assert!(matches!(
            gw.mint_checked(shadowed_deny, 60, None),
            Err(MintError::PolicyLint(_))
        ));

        // Warnings alone do not reject: a glob outside the curated github catalog mints.
        let uncatalogued = Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec!["github".into()],
                    verbs: vec![],
                    resources: vec!["orgs/octocat/teams".into()],
                    conditions: vec![],
                },
            }],
        };
        assert!(gw.mint_checked(uncatalogued, 60, None).is_ok());
    }

    fn two_service_router() -> ServiceRouter {
        ServiceRouter::new(vec![
            Service::new("github-api", "api.github.com", "https://api.github.com")
                .with_outbound(Outbound::Bearer {
                    credential: "github-app".into(),
                })
                .with_tool_hint("github")
                .with_address("https://gh.hackamore.local"),
            Service::new("openai", "api.openai.com", "https://api.openai.com"),
        ])
    }

    fn target_policy(target: &str) -> Policy {
        Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![target.into()],
                    verbs: vec![],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        }
    }

    #[test]
    fn provision_lists_only_granted_services() {
        let (control, _a, _) = test_control();
        let gw = Gateway::with_clock(control, two_service_router(), fixed_clock(1_000));
        let minted = gw.mint(target_policy("github-api"), 60);
        let doc = gw.provision(&minted.token).unwrap();
        assert_eq!(doc.hackamore_token, minted.token);
        assert_eq!(doc.services.len(), 1);
        assert_eq!(doc.services[0].target, "github-api");
        // The agent tool-config hint is the service's `tool_hint` (set via the preset), not
        // its name — a `github-api` service hints `github`.
        assert_eq!(doc.services[0].tool_hint, "github");
        assert_eq!(doc.services[0].address, "https://gh.hackamore.local");
        assert_eq!(
            doc.services[0].mode,
            hackamore_models::provision::ProvisionMode::Inject
        );
        // An unknown token yields no doc.
        assert!(gw.provision("bogus").is_none());
    }

    #[test]
    fn catalog_validates_named_actions_at_mint() {
        use crate::service::ActionCatalog;
        let (control, _a, _) = test_control();
        let mut catalogs = std::collections::HashMap::new();
        catalogs.insert(
            "github".to_string(),
            ActionCatalog::of(["repo:read".to_string(), "repo:write".to_string()]),
        );
        let gw = Gateway::with_clock(control, two_service_router(), fixed_clock(1_000))
            .with_catalogs(catalogs);

        // A named action in the catalog mints.
        let ok = Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec!["github".into()],
                    verbs: vec![hackamore_models::action::Verb::action("repo:read")],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        };
        assert!(gw.mint_checked(ok, 60, None).is_ok());

        // An unknown named action is rejected (fail closed).
        let bad = Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec!["github".into()],
                    verbs: vec![hackamore_models::action::Verb::action(
                        "repo:delete-universe",
                    )],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        };
        assert!(gw.mint_checked(bad, 60, None).is_err());

        // A target with no catalog (openai) is unvalidated — any named action passes.
        let raw = Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec!["openai".into()],
                    verbs: vec![hackamore_models::action::Verb::action("anything:goes")],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        };
        assert!(gw.mint_checked(raw, 60, None).is_ok());
    }

    #[test]
    fn catalog_validates_empty_target_named_actions() {
        use crate::service::ActionCatalog;
        let (control, _a, _) = test_control();
        let mut catalogs = std::collections::HashMap::new();
        catalogs.insert(
            "github".to_string(),
            ActionCatalog::of(["repo:read".to_string()]),
        );
        let gw = Gateway::with_clock(control, two_service_router(), fixed_clock(1_000))
            .with_catalogs(catalogs);

        let any_target = |action: &str| Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![], // any service — the old check skipped these entirely
                    verbs: vec![hackamore_models::action::Verb::action(action)],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        };
        // Known by some catalog → ok.
        assert!(gw.mint_checked(any_target("repo:read"), 60, None).is_ok());
        // Known by no catalog → rejected even though no target is named (fail closed).
        assert!(gw.mint_checked(any_target("repo:typo"), 60, None).is_err());
    }

    #[test]
    fn mint_is_open_when_no_tenants_configured() {
        let (control, _a, _) = test_control();
        let gw = Gateway::with_clock(control, router(), fixed_clock(1_000));
        assert!(gw.mint_checked(allow_all(), 60, None).is_ok());
    }

    #[test]
    fn tenant_may_only_mint_owned_targets() {
        let (control, _a, _) = test_control();
        control.tenants.insert("t-a", ["github".to_string()]);
        let gw = Gateway::with_clock(control, two_service_router(), fixed_clock(1_000));
        // With tenants configured, a missing tenant credential is rejected.
        assert!(gw.mint_checked(target_policy("github"), 60, None).is_err());
        // Owned target → ok.
        assert!(
            gw.mint_checked(target_policy("github"), 60, Some("t-a"))
                .is_ok()
        );
        // Unowned target → err.
        assert!(
            gw.mint_checked(target_policy("openai"), 60, Some("t-a"))
                .is_err()
        );
        // An empty-targets (any-service) allow rule is rejected for tenants.
        assert!(gw.mint_checked(allow_all(), 60, Some("t-a")).is_err());
        // Unknown tenant → err.
        assert!(
            gw.mint_checked(target_policy("github"), 60, Some("ghost"))
                .is_err()
        );
    }

    #[test]
    fn provision_empty_targets_lists_all_services() {
        let (control, _a, _) = test_control();
        let gw = Gateway::with_clock(control, two_service_router(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        let doc = gw.provision(&minted.token).unwrap();
        assert_eq!(doc.services.len(), 2);
        // The passthrough service is surfaced as a passthrough mode.
        let openai = doc.services.iter().find(|s| s.target == "openai").unwrap();
        assert_eq!(
            openai.mode,
            hackamore_models::provision::ProvisionMode::Passthrough
        );
    }

    /// Headers carrying the launch token in the HTTP Basic *password* slot, with the git
    /// `x-access-token` username (the Basic-inbound shape `git push` uses).
    fn basic_password(token: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
        h.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        h
    }

    #[test]
    fn basic_inbound_password_resolves_bound_policy_and_injects() {
        let (control, audit, _) = test_control();
        let gw = Gateway::with_clock(control.clone(), router(), fixed_clock(1_000));
        let minted = gw.mint(allow_all(), 60);
        // The launch token rides in the Basic password slot; hackamore resolves it to the
        // bound policy exactly like the bearer path and injects the target's real secret.
        match gw.handle(get(basic_password(&minted.token), "/repos/octocat/hello")) {
            Outcome::Forward(plan) => {
                let auth = plan
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .unwrap()
                    .to_str()
                    .unwrap();
                // The inbound Basic credential is gone; the target's real secret replaces it.
                assert_eq!(auth, "Bearer real-secret-token");
                assert!(!auth.contains(&minted.token));
            }
            Outcome::Reject(_) => panic!("expected forward"),
        }
        assert_eq!(audit.events()[0].decision, Decision::Allow);
    }

    #[test]
    fn basic_inbound_unknown_token_is_unauthorized() {
        let (control, _a, _) = test_control();
        let gw = Gateway::new(control, router());
        match gw.handle(get(basic_password("not-a-real-token"), "/repos/o/r")) {
            Outcome::Reject(r) => assert_eq!(r.reason, DenyReason::Unauthenticated),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn malformed_basic_is_unauthorized() {
        let (control, _a, _) = test_control();
        let gw = Gateway::new(control, router());
        let mut h = http::HeaderMap::new();
        // Not valid base64, and no colon even if it were → fail closed.
        h.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Basic !!!notbase64!!!"),
        );
        match gw.handle(get(h, "/repos/o/r")) {
            Outcome::Reject(r) => assert_eq!(r.reason, DenyReason::Unauthenticated),
            Outcome::Forward(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn extract_auth_prefers_hackamore_header_then_authorization() {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::AUTHORIZATION, "token abc".parse().unwrap());
        assert_eq!(
            extract_auth(&h),
            Some(("abc".to_string(), AuthSource::Authorization))
        );
        h.insert(http::header::AUTHORIZATION, "Bearer xyz".parse().unwrap());
        assert_eq!(
            extract_auth(&h),
            Some(("xyz".to_string(), AuthSource::Authorization))
        );
        // X-Hackamore-Token wins over Authorization.
        h.insert(HACKAMORE_TOKEN_HEADER, "tok-123".parse().unwrap());
        assert_eq!(
            extract_auth(&h),
            Some(("tok-123".to_string(), AuthSource::HackamoreHeader))
        );
    }
}
