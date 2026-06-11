//! The gateway core: the transport-agnostic decision + enforcement path.
//!
//! [`Gateway::handle`] takes a normalized [`ProxyRequest`], authenticates the halter
//! token and resolves its bound policy, normalizes the request into an `Action`, calls
//! the pure [`policy::decide`], records an audit event, and returns an [`Outcome`] —
//! either a [`ForwardPlan`] (with the matched service's outbound stance applied) or a
//! [`Rejection`]. It performs no network I/O itself; the server module executes the
//! forward. Keeping this layer free of HTTP plumbing makes the whole decision path
//! deterministically testable.

use crate::service::{Catalog, Outbound, Service, ServiceRouter};
use crate::{canonicalize, normalize};
use control::{ControlPlane, now_ms};
use models::action::Action;
use models::audit::{AuditEvent, Decision};
use models::verdict::{DenyReason, Verdict};
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

/// A source of wall-clock time, injectable for tests.
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The data-plane decision engine. Holds the control plane and the service routing
/// table (any number of configured upstream HTTPS services).
pub struct Gateway {
    control: Arc<ControlPlane>,
    router: ServiceRouter,
    clock: Clock,
    /// Per-target action catalogs used to validate policies at mint time. A target with
    /// no entry (or an empty catalog) is unvalidated (raw).
    catalogs: HashMap<String, Catalog>,
    /// The CA bundle a consumer must trust to validate halter's TLS, surfaced in the
    /// provision doc. Empty when halter terminates plaintext (the sandbox-confined model).
    halter_ca: String,
}

impl Gateway {
    /// Build a gateway over `control` routing to `router`'s services, using the wall
    /// clock.
    pub fn new(control: Arc<ControlPlane>, router: ServiceRouter) -> Self {
        Self {
            control,
            router,
            clock: Arc::new(now_ms),
            catalogs: HashMap::new(),
            halter_ca: String::new(),
        }
    }

    /// Build a gateway with an injected clock (tests).
    pub fn with_clock(control: Arc<ControlPlane>, router: ServiceRouter, clock: Clock) -> Self {
        Self {
            control,
            router,
            clock,
            catalogs: HashMap::new(),
            halter_ca: String::new(),
        }
    }

    /// Attach per-target action catalogs (for mint-time policy validation). Builder.
    #[must_use]
    pub fn with_catalogs(mut self, catalogs: HashMap<String, Catalog>) -> Self {
        self.catalogs = catalogs;
        self
    }

    /// Set the CA bundle consumers must trust to validate halter's TLS (surfaced as
    /// `halter_ca` in the provision doc). Builder; empty means plaintext.
    #[must_use]
    pub fn with_ca(mut self, ca_pem: impl Into<String>) -> Self {
        self.halter_ca = ca_pem.into();
        self
    }

    /// Mint a launch token bound to `policy`. This is the control-plane verb the
    /// orchestrator calls at launch. Any valid policy mints a token — there is no agent
    /// identity (multi-tenant caller-authorization, when added, gates this earlier).
    pub fn mint(
        &self,
        policy: models::policy::Policy,
        ttl_seconds: u64,
    ) -> models::control::MintResponse {
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
        policy: models::policy::Policy,
        ttl_seconds: u64,
        tenant: Option<&str>,
    ) -> Result<models::control::MintResponse, MintError> {
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
        Ok(self.mint(policy, ttl_seconds))
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
    fn validate_catalog(&self, policy: &models::policy::Policy) -> Result<(), MintError> {
        use models::action::Verb;
        use models::policy::Effect;
        let nonempty: Vec<&Catalog> = self.catalogs.values().filter(|c| !c.is_empty()).collect();
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
    pub fn provision(&self, token: &str) -> Option<models::provision::ProvisionDoc> {
        let now = (self.clock)();
        let (policy, expires_at_ms) = self.control.tokens.resolve_full(token, now)?;
        Some(models::provision::ProvisionDoc {
            halter_token: token.to_string(),
            halter_ca: self.halter_ca.clone(),
            expires_at_ms,
            services: self.provisionable_services(token, &policy, now, expires_at_ms),
        })
    }

    /// The services a policy grants the consumer access to: every service whose name a
    /// rule's `targets` names, or — if any allow rule has empty `targets` (= any
    /// service) — all of them. Each entry carries the credential material the consumer
    /// presents: the halter token for bearer/passthrough services, or a freshly minted
    /// dummy SigV4 credential (bound to the same policy) for SigV4 services.
    fn provisionable_services(
        &self,
        token: &str,
        policy: &models::policy::Policy,
        now: u64,
        expires_at_ms: u64,
    ) -> Vec<models::provision::ProvisionService> {
        use models::policy::Effect;
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
        for s in self.router.services() {
            if !(any_target || named.contains(s.name.as_str())) {
                continue;
            }
            let (mode, auth) = self.mint_service_auth(s, token, policy, now, ttl_remaining);
            out.push(models::provision::ProvisionService {
                target: s.name.clone(),
                flavor: s.flavor.name().to_string(),
                address: s.address.clone(),
                mode,
                auth,
            });
        }
        out
    }

    /// Produce the consumer mode + auth material for one service. **This mints**: a SigV4
    /// service gets a freshly minted dummy credential bound to the same policy (hence the
    /// `mint_` name and the explicit caller loop); everything else reuses the bearer halter
    /// token and has no effect.
    fn mint_service_auth(
        &self,
        service: &Service,
        token: &str,
        policy: &models::policy::Policy,
        now: u64,
        ttl_remaining: u64,
    ) -> (
        models::provision::ProvisionMode,
        models::provision::ProvisionAuth,
    ) {
        use models::provision::{BearerAuth, ProvisionAuth, ProvisionMode, SigV4Auth};
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
            Outbound::Bearer { .. } | Outbound::Header { .. } => (
                ProvisionMode::Inject,
                ProvisionAuth::Bearer(BearerAuth {
                    token: token.to_string(),
                }),
            ),
        }
    }

    /// Authenticate the request to its bound policy. Two inbound schemes: AWS SigV4 (the
    /// `Authorization` header is `AWS4-HMAC-SHA256 …`, verified against a minted dummy
    /// credential) or a halter bearer token (`X-Halter-Token` or `Authorization: Bearer`).
    fn authenticate(
        &self,
        req: &ProxyRequest,
        now: u64,
    ) -> Result<(models::policy::Policy, AuthSource), Box<Outcome>> {
        if let Some(auth) = req
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            && auth.starts_with("AWS4-HMAC-SHA256")
        {
            return self.authenticate_sigv4(req, auth, now);
        }
        let Some((token, source)) = extract_auth(&req.headers) else {
            return Err(Box::new(reject(
                http::StatusCode::UNAUTHORIZED,
                DenyReason::Unauthenticated,
                "missing halter token",
            )));
        };
        match self.control.tokens.resolve(&token, now) {
            Some(policy) => Ok((policy, source)),
            None => Err(Box::new(reject(
                http::StatusCode::UNAUTHORIZED,
                DenyReason::Unauthenticated,
                "unknown or expired halter token",
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
    ) -> Result<(models::policy::Policy, AuthSource), Box<Outcome>> {
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
        // (fail closed) — halter only forwards to its allowlist.
        let host = extract_host(&req.headers).unwrap_or_default();
        let Some(service) = self.router.route(&host).cloned() else {
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

        match policy::decide(&action, &policy) {
            Verdict::Deny(d) => {
                self.audit(&action, Decision::Deny, &format!("{:?}", d.reason), now);
                reject(http::StatusCode::FORBIDDEN, d.reason, "denied by policy")
            }
            // On allow the outbound credential is the matched service's property, not the
            // policy's — the engine's allow is bare.
            Verdict::Allow(_) => self.plan_forward(&service, &action, req, source, now),
        }
    }

    /// Build the upstream forward plan according to the matched service's outbound
    /// stance. `Passthrough` forwards the consumer's own credential (preserved by
    /// `sanitize_headers` when the halter token arrived via `X-Halter-Token`); `Bearer`
    /// and `Header` swap in the target's real credential from the vault. A missing
    /// credential fails closed.
    fn plan_forward(
        &self,
        service: &Service,
        action: &Action,
        req: ProxyRequest,
        source: AuthSource,
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
            Outbound::SigV4 {
                credential,
                access_key_id,
                region,
                service: aws_service,
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
                let host = host_of(&service.upstream_base);
                let signed = crate::sigv4::sign(
                    &crate::sigv4::Creds {
                        access_key_id,
                        secret_access_key: secret.expose(),
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
                format!("allowed; sigv4 re-signed [{credential}]")
            }
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
            models::action::Verb::crud(models::action::CrudKind::Read),
            models::action::Resource::of(host, "host"),
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
    policy: &models::policy::Policy,
    owned: &std::collections::BTreeSet<String>,
) -> Result<(), MintError> {
    use models::policy::Effect;
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
/// authorization/validation failures the operator surface renders as `403`.
#[derive(Debug, PartialEq, Eq)]
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
        }
    }
}

impl std::error::Error for MintError {}

/// The dedicated header a consumer uses to present its halter token *without* consuming
/// the `Authorization` slot — so a filter-only (passthrough) consumer can carry its own
/// upstream credential in `Authorization` at the same time.
const HALTER_TOKEN_HEADER: &str = "x-halter-token";

/// Where the halter token was found. This decides whether `Authorization` belongs to
/// halter (and must be stripped) or to the consumer (and must be preserved for
/// passthrough).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AuthSource {
    /// The token came from the dedicated `X-Halter-Token` header; `Authorization` (if
    /// any) is the consumer's own upstream credential.
    HalterHeader,
    /// The token came from `Authorization` itself (e.g. `gh`/`kubectl`, which have only
    /// one auth slot); `Authorization` is the halter token and must not be forwarded.
    Authorization,
    /// The request was authenticated by an inbound AWS SigV4 signature; the inbound
    /// `Authorization` and `X-Amz-*` signing headers are halter's to replace on re-sign.
    SigV4,
}

/// The halter token from a request's headers, ignoring its source. Used by the
/// `/provision` endpoint, which never forwards, so the channel does not matter.
pub fn token_from_headers(headers: &http::HeaderMap) -> Option<String> {
    extract_auth(headers).map(|(token, _)| token)
}

/// Extract the halter token and where it came from. `X-Halter-Token` is preferred (it
/// frees `Authorization` for passthrough); otherwise fall back to `Authorization`,
/// accepting both `Bearer <t>` and GitHub's `token <t>` schemes.
fn extract_auth(headers: &http::HeaderMap) -> Option<(String, AuthSource)> {
    if let Some(v) = headers
        .get(HALTER_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        let v = v.trim();
        if !v.is_empty() {
            return Some((v.to_string(), AuthSource::HalterHeader));
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

/// Copy request headers for the upstream, always dropping the `X-Halter-Token` header,
/// the inbound `Host` and `Content-Length` (recomputed by the client), and hop-by-hop
/// headers. `Authorization` is dropped only when it carried the halter token
/// (`source == Authorization`); under `HalterHeader` it is the consumer's own credential
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
    if n == HALTER_TOKEN_HEADER || n == "host" || n == "content-length" {
        return true;
    }
    if n == "authorization" {
        // The halter token (Authorization source) and the inbound SigV4 signature (SigV4
        // source) are both halter's to strip/replace; a HalterHeader token leaves
        // Authorization as the consumer's own credential.
        return source != AuthSource::HalterHeader;
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
    use crate::service::{Extract, Flavor, Service, ServiceRouter};
    use control::{InMemoryAudit, Secret};
    use models::policy::{Effect, Match, Policy, Rule};

    /// A control plane wired with an in-memory audit sink we can inspect, plus a seeded
    /// credential. Returns the plane, the audit handle, and the credential handle.
    fn test_control() -> (
        Arc<ControlPlane>,
        Arc<InMemoryAudit>,
        Arc<control::InMemoryCredentials>,
    ) {
        let creds = Arc::new(control::InMemoryCredentials::new());
        creds.insert("github-app", Secret::new("real-secret-token"));
        let audit = Arc::new(InMemoryAudit::new());
        let plane = ControlPlane::new(creds.clone(), audit.clone());
        (Arc::new(plane), audit, creds)
    }

    /// A catch-all GitHub-flavored service that injects the `github-app` credential.
    fn router() -> ServiceRouter {
        ServiceRouter::new(vec![
            Service::new("github", "*", "https://api.github.com")
                .with_flavor(Flavor::Github)
                .with_outbound(Outbound::Bearer {
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
                    verbs: vec![models::action::Verb::crud(models::action::CrudKind::Read)],
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

    /// Headers with the halter token in `X-Halter-Token` and the consumer's own
    /// credential in `Authorization` (the passthrough shape).
    fn halter_header_with_own_cred(token: &str, own_cred: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            HALTER_TOKEN_HEADER,
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
        // The consumer put the halter token in Authorization and carries no separate
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
        // The halter token rides X-Halter-Token; the consumer's own credential in
        // Authorization is forwarded untouched (the real filter-only behaviour).
        let headers = halter_header_with_own_cred(&minted.token, "Bearer consumer-own-key");
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
                // The halter token header is not forwarded.
                assert!(plan.headers.get(HALTER_TOKEN_HEADER).is_none());
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
        let headers = halter_header_with_own_cred(&minted.token, "Bearer consumer-own-key");
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
    fn sigv4_mechanism_signs_outbound_request() {
        let (control, _a, creds) = test_control();
        creds.insert("aws-secret", Secret::new("secret-key"));
        let router = ServiceRouter::new(vec![
            Service::new("ec2", "*", "https://ec2.us-east-1.amazonaws.com").with_outbound(
                Outbound::SigV4 {
                    credential: "aws-secret".into(),
                    access_key_id: "AKID".into(),
                    region: "us-east-1".into(),
                    service: "ec2".into(),
                },
            ),
        ]);
        let gw = Gateway::with_clock(control, router, fixed_clock(1_700_000_000_000));
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
            }
            Outcome::Reject(_) => panic!("expected forward"),
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
                access_key_id: "REALAKID".into(),
                region: "us-east-1".into(),
                service: "ec2".into(),
            })
            .with_extract(Extract {
                protocol: crate::service::Protocol::AwsQuery,
                path_template: None,
            }),
        ])
    }

    #[test]
    fn sigv4_inbound_authenticates_then_resigns_with_real_credential() {
        let (control, _a, creds) = test_control();
        creds.insert("aws-secret", Secret::new("real-secret"));
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
        creds.insert("aws-secret", Secret::new("real-secret"));
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
    }

    fn two_service_router() -> ServiceRouter {
        ServiceRouter::new(vec![
            Service::new("github", "api.github.com", "https://api.github.com")
                .with_flavor(Flavor::Github)
                .with_outbound(Outbound::Bearer {
                    credential: "github-app".into(),
                })
                .with_address("https://gh.halter.local"),
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
        let minted = gw.mint(target_policy("github"), 60);
        let doc = gw.provision(&minted.token).unwrap();
        assert_eq!(doc.halter_token, minted.token);
        assert_eq!(doc.services.len(), 1);
        assert_eq!(doc.services[0].target, "github");
        assert_eq!(doc.services[0].flavor, "github");
        assert_eq!(doc.services[0].address, "https://gh.halter.local");
        assert_eq!(
            doc.services[0].mode,
            models::provision::ProvisionMode::Inject
        );
        // An unknown token yields no doc.
        assert!(gw.provision("bogus").is_none());
    }

    #[test]
    fn catalog_validates_named_actions_at_mint() {
        use crate::service::Catalog;
        let (control, _a, _) = test_control();
        let mut catalogs = std::collections::HashMap::new();
        catalogs.insert(
            "github".to_string(),
            Catalog::of(["repo:read".to_string(), "repo:write".to_string()]),
        );
        let gw = Gateway::with_clock(control, two_service_router(), fixed_clock(1_000))
            .with_catalogs(catalogs);

        // A named action in the catalog mints.
        let ok = Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec!["github".into()],
                    verbs: vec![models::action::Verb::action("repo:read")],
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
                    verbs: vec![models::action::Verb::action("repo:delete-universe")],
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
                    verbs: vec![models::action::Verb::action("anything:goes")],
                    resources: vec![],
                    conditions: vec![],
                },
            }],
        };
        assert!(gw.mint_checked(raw, 60, None).is_ok());
    }

    #[test]
    fn catalog_validates_empty_target_named_actions() {
        use crate::service::Catalog;
        let (control, _a, _) = test_control();
        let mut catalogs = std::collections::HashMap::new();
        catalogs.insert("github".to_string(), Catalog::of(["repo:read".to_string()]));
        let gw = Gateway::with_clock(control, two_service_router(), fixed_clock(1_000))
            .with_catalogs(catalogs);

        let any_target = |action: &str| Policy {
            rules: vec![Rule {
                effect: Effect::Allow,
                matches: Match {
                    targets: vec![], // any service — the old check skipped these entirely
                    verbs: vec![models::action::Verb::action(action)],
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
        assert_eq!(openai.mode, models::provision::ProvisionMode::Passthrough);
    }

    #[test]
    fn extract_auth_prefers_halter_header_then_authorization() {
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
        // X-Halter-Token wins over Authorization.
        h.insert(HALTER_TOKEN_HEADER, "tok-123".parse().unwrap());
        assert_eq!(
            extract_auth(&h),
            Some(("tok-123".to_string(), AuthSource::HalterHeader))
        );
    }
}
