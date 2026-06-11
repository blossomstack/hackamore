# halter Redesign — Phase 1: Model Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the halter model from agent-bound, GitHub-centric, credential-in-policy
to the redesign's spine: **policy-bound tokens (no agent identity)**, an **open `verb` tagged
union** (Option A), and **credentials bound to the target with a hybrid passthrough/inject**
outbound stance.

**Architecture:** The pure engine (`policy::decide`) and the `Action`/`Verdict` contract stay
the portability boundary; we change the contract types (fluorite schemas) and the control/data
planes that fill and consume them. No new external dependencies in Phase 1 — SigV4, catalogs,
k8s discovery, the `halter-agent` CLI, and transparent MITM are later phases (see *Deferred
subsystems*).

**Tech Stack:** Rust workspace (`models` via fluorite codegen, `policy`, `control`, `gateway`,
`cli`, `tests`); axum data plane; `make check` = `cargo fmt --check` + `cargo clippy
--all-targets -- -D warnings` + `cargo test --workspace`.

---

## Scope

This plan covers **Phase 1 only** — the model spine — which is self-contained, compiles, and
passes `make check` on its own. It maps to spec sections: *Roles* (no-agent), *Service model:
type vs instance*, *Auth mechanisms* (Bearer + hybrid passthrough/inject), *The Action/Verdict
contract* (Option-A verb), and *Mint and token (no agent)*.

**Deferred subsystems** (each needs its own spec+plan; flagged in the design's *Out of scope*):
SigV4 verify/re-sign + credential providers (EKS/GitHub-App minting); catalog ingestion
(botocore/OpenAPI/k8s discovery) + mint-time validation; the `halter-agent` CLI + `/provision`
endpoint + `ProvisionDoc`; RPC protocol parsers (aws-query/aws-json); transport (Upgrade,
streaming uploads) and transparent-MITM mode.

## File structure (Phase 1)

- `fluorite/action.fl` — drop `agent`; `verb` becomes a tagged union `Verb { Crud | Action }`.
- `fluorite/policy.fl` — drop `grant_credentials` from `Rule` (credential is the target's).
- `fluorite/audit.fl` — drop `agent`.
- `fluorite/control.fl` — `MintRequest { policy, ttl_seconds }`, `MintResponse { token,
  expires_at_ms }` (drop `agent`).
- `fluorite/verdict.fl` — `Obligation` gains a `Passthrough` arm; `InjectCredential` keeps
  carrying a `CredentialRef` but the id now comes from the matched service/target, not policy.
- `models/src/lib.rs` — update `Action::of`, `Verb` helpers, `Verdict` helpers, tests.
- `policy/src/lib.rs` — `verb_matches` over the union; `verdict_for` no longer reads
  `grant_credentials` (allow now yields a bare allow; the data plane attaches the target's
  credential obligation).
- `control/src/tokens.rs` — token → `Policy` (not agent).
- `control/src/registry.rs` — **deleted** (agent→policy registry is gone).
- `control/src/lib.rs` — `ControlPlane` drops `registry`.
- `gateway/src/service.rs` — `Service` gains `outbound: Outbound` (Passthrough | Inject{id}).
- `gateway/src/normalize.rs` — drop `agent` arg; keep generic + github resource parsing.
- `gateway/src/core.rs` — `mint(policy)`, `handle` resolves token→Policy and builds the
  outbound obligation from the routed service, not the policy.
- `cli/` — `mint` reads a policy JSON file instead of `--agent`.
- `examples/config.json`, `examples/README.md` — drop `agents`; move credential to the service.
- `tests/` — update e2e to mint-with-policy and target-bound credentials.

---

## Task 1: `Verb` becomes an open tagged union (Option A)

**Files:**
- Modify: `fluorite/action.fl`
- Modify: `models/src/lib.rs`
- Test: `models/src/lib.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing test** — add to `models/src/lib.rs` tests:

```rust
#[test]
fn verb_union_supports_crud_and_named_action() {
    use super::action::{CrudVerb, NamedVerb, Verb};
    let read = Verb::Crud(CrudVerb { kind: super::action::CrudKind::Read });
    let terminate = Verb::Action(NamedVerb { id: "ec2:TerminateInstances".into() });
    assert_ne!(read, terminate);
    // Round-trips through JSON (tagged by "type").
    let json = serde_json::to_string(&terminate).unwrap();
    let back: Verb = serde_json::from_str(&json).unwrap();
    assert_eq!(terminate, back);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p models verb_union_supports_crud_and_named_action`
Expected: FAIL — `CrudVerb`/`NamedVerb`/`Verb::Crud` do not exist yet.

- [ ] **Step 3: Change the schema.** Replace the `enum Verb {…}` block in `fluorite/action.fl`
with:

```
/// The CRUD operation kinds RESTful services map onto from the HTTP method.
enum CrudKind {
    Read,
    Create,
    Update,
    Delete,
}

/// A coarse CRUD verb (RESTful method mapping).
struct CrudVerb { kind: CrudKind }

/// A service-defined action id, e.g. "ec2:TerminateInstances" (RPC-style services).
struct NamedVerb { id: String }

/// The operation. A closed tagged union: the `Crud` arm is the closed RESTful set; the
/// `Action` arm carries one open, service-defined vocabulary (kept to this one field).
#[type_tag = "type"]
union Verb {
    Crud(CrudVerb),
    Action(NamedVerb),
}
```

- [ ] **Step 4: Update `models/src/lib.rs` helpers.** Add ergonomic constructors under the
existing `impl` area:

```rust
impl action::Verb {
    /// A CRUD verb.
    pub fn crud(kind: action::CrudKind) -> Self {
        action::Verb::Crud(action::CrudVerb { kind })
    }
    /// A named, service-defined action (e.g. "s3:PutObject").
    pub fn action(id: impl Into<String>) -> Self {
        action::Verb::Action(action::NamedVerb { id: id.into() })
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p models verb_union_supports_crud_and_named_action`
Expected: PASS. (Other crates will not compile yet — fixed in Tasks 2–6.)

- [ ] **Step 6: Commit**

```bash
git add fluorite/action.fl models/src/lib.rs
git commit -m "models: verb becomes open tagged union (Crud | Action)"
```

---

## Task 2: Engine matches over the verb union; drop `agent` from `Action`

**Files:**
- Modify: `fluorite/action.fl` (remove `agent`)
- Modify: `models/src/lib.rs` (`Action::of` loses `agent`)
- Modify: `policy/src/lib.rs` (`verb_matches`)
- Test: `policy/src/lib.rs`

- [ ] **Step 1: Write the failing test** — add to `policy/src/lib.rs` tests:

```rust
#[test]
fn named_verb_matches_named_rule() {
    use models::action::{Resource, Verb};
    let action = Action::of(
        "aws-acct-a",
        Verb::action("ec2:DescribeInstances"),
        Resource::of("", "root"),
    );
    let policy = Policy {
        rules: vec![allow(
            Match { verbs: vec![Verb::action("ec2:DescribeInstances")], ..empty_match() },
            &[],
        )],
    };
    assert!(decide(&action, &policy).is_allow());
    // A different named action falls through to default-deny.
    let other = Action::of("aws-acct-a", Verb::action("ec2:TerminateInstances"),
        Resource::of("", "root"));
    assert!(!decide(&other, &policy).is_allow());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p policy named_verb_matches_named_rule`
Expected: FAIL to compile — `Action::of` still takes `agent` first positionally and the
target arg shifts. (We are mid-refactor; the next steps make it build.)

- [ ] **Step 3: Drop `agent` from the schema.** In `fluorite/action.fl`, remove the `agent`
field from `struct Action`, so it reads:

```
struct Action {
    /// The configured service instance this targets — the routing key policy scopes to.
    target: String,
    verb: Verb,
    resource: Resource,
    fields: Any,
}
```

- [ ] **Step 4: Update `Action::of`** in `models/src/lib.rs` to drop the `agent` param:

```rust
impl action::Action {
    /// Ergonomic constructor with an empty `fields` object. `target` is the service
    /// instance name.
    pub fn of(
        target: impl Into<String>,
        verb: action::Verb,
        resource: action::Resource,
    ) -> Self {
        Self {
            target: target.into(),
            verb,
            resource,
            fields: empty_fields(),
        }
    }
    // with_fields unchanged
}
```

Update the `action_round_trips_through_json` test in `models/src/lib.rs` to the new signature:
`Action::of("github", Verb::crud(action::CrudKind::Create), Resource::of(...))`.

- [ ] **Step 5: `verb_matches` over the union.** In `policy/src/lib.rs` replace `verb_matches`:

```rust
fn verb_matches(verbs: &[Verb], verb: &Verb) -> bool {
    verbs.is_empty() || verbs.iter().any(|v| v == verb)
}
```

(`Verb` derives `PartialEq`, so equality covers both arms.) Update the test helpers
(`pr_create`, `read_only_agent_denied_create`, etc.) to the new `Action::of` signature and to
build verbs via `Verb::crud(CrudKind::Create)`.

- [ ] **Step 6: Run tests**

Run: `cargo test -p models -p policy`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add fluorite/action.fl models/src/lib.rs policy/src/lib.rs
git commit -m "models+policy: drop agent from Action; match verb union"
```

---

## Task 3: Credentials leave the policy; `Rule` drops `grant_credentials`

**Files:**
- Modify: `fluorite/policy.fl` (remove `grant_credentials`)
- Modify: `fluorite/verdict.fl` (add `Passthrough` obligation arm)
- Modify: `policy/src/lib.rs` (`verdict_for`)
- Modify: `models/src/lib.rs` (`Verdict::allow` no longer takes credentials)
- Test: `policy/src/lib.rs`, `models/src/lib.rs`

- [ ] **Step 1: Write the failing test** — in `policy/src/lib.rs` tests, replace the
credential-bearing allow assertions with a bare allow (the engine no longer attaches
credentials; the data plane does):

```rust
#[test]
fn allow_rule_yields_bare_allow_no_credentials() {
    let policy = Policy { rules: vec![allow(empty_match())] };
    match decide(&pr_create(), &policy) {
        Verdict::Allow(a) => assert!(a.obligations.is_empty()),
        Verdict::Deny(_) => panic!("expected allow"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p policy allow_rule_yields_bare_allow_no_credentials`
Expected: FAIL to compile — `allow` helper still takes `creds`.

- [ ] **Step 3: Schema — drop `grant_credentials`.** In `fluorite/policy.fl`, change `struct
Rule` to:

```
struct Rule {
    effect: Effect,
    matches: Match,
}
```

- [ ] **Step 4: Schema — add a `Passthrough` obligation.** In `fluorite/verdict.fl`:

```
/// Forward the consumer's own credential unchanged (filter-only mode).
struct PassthroughObligation {}

#[type_tag = "type"]
union Obligation {
    InjectCredential(InjectCredentialObligation),
    Passthrough(PassthroughObligation),
}
```

- [ ] **Step 5: Engine — bare allow.** In `policy/src/lib.rs`, replace `verdict_for`:

```rust
fn verdict_for(rule: &Rule) -> Verdict {
    match rule.effect {
        Effect::Allow => Verdict::allow(vec![]),
        Effect::Deny => Verdict::deny(DenyReason::ExplicitDeny),
    }
}
```

- [ ] **Step 6: Models — `Verdict::allow` takes obligations directly.** In `models/src/lib.rs`:

```rust
impl verdict::Verdict {
    pub fn is_allow(&self) -> bool { matches!(self, verdict::Verdict::Allow(_)) }

    /// Allow with explicit obligations (the data plane builds these from the target).
    pub fn allow(obligations: Vec<verdict::Obligation>) -> Self {
        verdict::Verdict::Allow(verdict::AllowVerdict { obligations })
    }

    pub fn inject(id: impl Into<String>) -> verdict::Obligation {
        verdict::Obligation::InjectCredential(verdict::InjectCredentialObligation {
            credential: verdict::CredentialRef { id: id.into() },
        })
    }
    pub fn passthrough() -> verdict::Obligation {
        verdict::Obligation::Passthrough(verdict::PassthroughObligation {})
    }

    pub fn deny(reason: verdict::DenyReason) -> Self {
        verdict::Verdict::Deny(verdict::DenyVerdict { reason })
    }
}
```

Update `policy/src/lib.rs` `allow`/`deny` test helpers to drop the `creds` arg:

```rust
fn allow(matches: Match) -> Rule { Rule { effect: Effect::Allow, matches } }
fn deny(matches: Match) -> Rule { Rule { effect: Effect::Deny, matches } }
```

Update `models/src/lib.rs` `verdict_helpers_build_expected_variants` test to
`Verdict::allow(vec![Verdict::inject("gh")])`.

- [ ] **Step 7: Run tests**

Run: `cargo test -p models -p policy`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add fluorite/policy.fl fluorite/verdict.fl policy/src/lib.rs models/src/lib.rs
git commit -m "policy: credentials leave the policy; allow is bare; add Passthrough obligation"
```

---

## Task 4: Tokens bind to a `Policy`; delete the agent registry

**Files:**
- Modify: `fluorite/control.fl`
- Modify: `control/src/tokens.rs`
- Delete: `control/src/registry.rs`
- Modify: `control/src/lib.rs`
- Test: `control/src/tokens.rs`

- [ ] **Step 1: Write the failing test** — replace `control/src/tokens.rs` tests body's first
test:

```rust
#[test]
fn mint_then_resolve_returns_policy() {
    use models::policy::Policy;
    let tokens = Tokens::new();
    let minted = tokens.mint(Policy { rules: vec![] }, 60, 1_000);
    assert!(tokens.resolve(&minted.token, 1_000).is_some());
    assert!(tokens.resolve(&minted.token, 61_000).is_none()); // expired
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p control mint_then_resolve_returns_policy`
Expected: FAIL to compile — `mint` still takes an agent string.

- [ ] **Step 3: Schema.** In `fluorite/control.fl`:

```
use policy.Policy;

/// Mint a launch token bound to a submitted policy. No agent identity: any valid policy
/// yields a token (caller-authorization, when multi-tenant, gates this separately).
struct MintRequest {
    policy: Policy,
    ttl_seconds: u64,
}

/// A minted token, honored only by halter.
struct MintResponse {
    token: String,
    expires_at_ms: u64,
}
```

- [ ] **Step 4: Tokens table → Policy.** Rewrite `control/src/tokens.rs` `Entry`/`mint`/
`resolve`:

```rust
use models::control::MintResponse;
use models::policy::Policy;
use parking_lot::RwLock;
use std::collections::HashMap;
use uuid::Uuid;

struct Entry {
    policy: Policy,
    expires_at_ms: u64,
}

#[derive(Default)]
pub struct Tokens {
    entries: RwLock<HashMap<String, Entry>>,
}

impl Tokens {
    pub fn new() -> Self { Self::default() }

    pub fn mint(&self, policy: Policy, ttl_seconds: u64, now_ms: u64) -> MintResponse {
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let expires_at_ms = now_ms.saturating_add(ttl_seconds.saturating_mul(1000));
        self.entries.write().insert(
            token.clone(),
            Entry { policy, expires_at_ms },
        );
        MintResponse { token, expires_at_ms }
    }

    /// Resolve a token to its bound policy, or `None` if unknown or expired.
    pub fn resolve(&self, token: &str, now_ms: u64) -> Option<Policy> {
        let entries = self.entries.read();
        let entry = entries.get(token)?;
        if entry.expires_at_ms <= now_ms { return None; }
        Some(entry.policy.clone())
    }

    pub fn revoke(&self, token: &str) -> bool {
        self.entries.write().remove(token).is_some()
    }
}
```

Update the remaining `tokens.rs` tests (`token_expires`, `unknown_token_resolves_none`,
`revoke_invalidates`) to mint with `Policy { rules: vec![] }` and assert on `is_some/is_none`.

- [ ] **Step 5: Delete the registry.** `git rm control/src/registry.rs`. Remove `mod registry;`
and any `pub use registry::*;` from `control/src/lib.rs`, and remove the `registry` field from
`ControlPlane` (and its constructor argument). Keep `tokens`, `credentials`, `audit`.

- [ ] **Step 6: Run tests**

Run: `cargo test -p control`
Expected: PASS (gateway will not build yet — Task 5).

- [ ] **Step 7: Commit**

```bash
git add fluorite/control.fl control/src/tokens.rs control/src/lib.rs
git rm control/src/registry.rs
git commit -m "control: tokens bind to a policy; remove agent registry"
```

---

## Task 5: Service carries its outbound stance; gateway builds the obligation

**Files:**
- Modify: `gateway/src/service.rs` (`Outbound` on `Service`)
- Modify: `gateway/src/normalize.rs` (drop `agent`)
- Modify: `gateway/src/core.rs` (`mint(policy)`, `handle`, `plan_forward`)
- Test: `gateway/src/core.rs`

- [ ] **Step 1: Write the failing test** — in `gateway/src/core.rs` tests, replace
`allowed_request_injects_credential_and_strips_agent_token` with:

```rust
#[test]
fn allowed_request_injects_targets_credential() {
    let (control, audit, _) = test_control();
    let gw = Gateway::with_clock(control.clone(), router_injecting("github-app"), fixed_clock(1_000));
    let minted = gw.mint(allow_all(), 60); // policy-bound mint

    match gw.handle(get(bearer(&minted.token), "/repos/octocat/hello")) {
        Outcome::Forward(plan) => {
            let auth = plan.headers.get(http::header::AUTHORIZATION).unwrap().to_str().unwrap();
            assert_eq!(auth, "Bearer real-secret-token"); // target's credential, not the token
            assert!(!auth.contains(&minted.token));
        }
        Outcome::Reject(_) => panic!("expected forward"),
    }
    assert_eq!(audit.events()[0].decision, Decision::Allow);
}

#[test]
fn passthrough_service_forwards_consumers_own_credential() {
    let (control, _a, _) = test_control();
    let gw = Gateway::with_clock(control.clone(), router_passthrough(), fixed_clock(1_000));
    let minted = gw.mint(allow_all(), 60);
    // The consumer presents the halter token; passthrough leaves whatever auth it sent —
    // here halter strips the halter token and injects nothing, so no Authorization upstream.
    match gw.handle(get(bearer(&minted.token), "/x")) {
        Outcome::Forward(plan) => assert!(plan.headers.get(http::header::AUTHORIZATION).is_none()),
        Outcome::Reject(_) => panic!("expected forward"),
    }
}
```

Add test helpers near `router()`:

```rust
fn allow_all() -> models::policy::Policy {
    models::policy::Policy { rules: vec![models::policy::Rule {
        effect: models::policy::Effect::Allow,
        matches: models::policy::Match {
            targets: vec![], verbs: vec![], resources: vec![], conditions: vec![],
        },
    }] }
}
fn router_injecting(cred: &str) -> ServiceRouter {
    ServiceRouter::new(vec![Service {
        name: "github".into(), host: "*".into(),
        upstream_base: "https://api.github.com".into(), flavor: Flavor::Github,
        outbound: Outbound::Inject { credential: cred.into() },
    }])
}
fn router_passthrough() -> ServiceRouter {
    ServiceRouter::new(vec![Service {
        name: "svc".into(), host: "*".into(),
        upstream_base: "https://up.example".into(), flavor: Flavor::Generic,
        outbound: Outbound::Passthrough,
    }])
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p gateway allowed_request_injects_targets_credential`
Expected: FAIL to compile — `Outbound`, `gw.mint(policy)` not present.

- [ ] **Step 3: Add `Outbound` to `Service`.** In `gateway/src/service.rs`, add:

```rust
/// What halter does with upstream auth on allow.
#[derive(Clone, Debug)]
pub enum Outbound {
    /// Forward the consumer's own credential unchanged (filter-only).
    Passthrough,
    /// Swap in the target's real credential, resolved from the vault by id.
    Inject { credential: String },
}
```

Add `pub outbound: Outbound,` to `struct Service`, and `outbound: Outbound::Passthrough` (or
`Inject`) to the `svc` test helper there.

- [ ] **Step 4: Drop `agent` from `normalize`.** In `gateway/src/normalize.rs`, change the
signature and body head:

```rust
pub fn normalize(service: &Service, req: &ProxyRequest) -> Action {
    let verb = verb_for(&req.method);
    let path = req.path.trim_start_matches('/');
    let resource = match service.flavor {
        Flavor::Github => github_resource(path),
        Flavor::Generic => generic_resource(path),
    };
    let fields = merge_fields(&req.query, &req.body);
    Action::of(service.name.clone(), verb, resource).with_fields(fields)
}
```

Change `verb_for` to return the union: `Verb::crud(CrudKind::Read)` etc. (import `CrudKind`).
Update `normalize.rs` tests to drop the `agent` arg and assert verbs via `Verb::crud(...)`.

- [ ] **Step 5: Rework `core.rs`.** Key changes:
  - `mint` takes a `Policy` and returns a `MintResponse`:

```rust
pub fn mint(&self, policy: models::policy::Policy, ttl_seconds: u64) -> models::control::MintResponse {
    self.control.tokens.mint(policy, ttl_seconds, (self.clock)())
}
```

  - `handle` resolves token→policy, routes, normalizes (no agent), decides, and on allow builds
    the obligation **from the routed service**, not from the verdict:

```rust
let Some(policy) = self.control.tokens.resolve(&token, now) else {
    return reject(http::StatusCode::UNAUTHORIZED, DenyReason::Unauthenticated,
        "unknown or expired halter token");
};
let host = extract_host(&req.headers).unwrap_or_default();
let Some(service) = self.router.route(&host).cloned() else {
    self.audit_raw(&host, Decision::Deny, "no service for host", now);
    return reject(http::StatusCode::NOT_FOUND, DenyReason::UnknownTarget,
        "no service configured for this host");
};
let action = normalize::normalize(&service, &req);
match policy::decide(&action, &policy) {
    Verdict::Deny(d) => {
        self.audit(&action, Decision::Deny, &format!("{:?}", d.reason), now);
        reject(http::StatusCode::FORBIDDEN, d.reason, "denied by policy")
    }
    Verdict::Allow(_) => self.plan_forward(&service, &action, req, now),
}
```

  - `plan_forward` consults `service.outbound`:

```rust
fn plan_forward(&self, service: &Service, action: &Action, req: ProxyRequest, now: u64) -> Outcome {
    let mut headers = sanitize_headers(&req.headers);
    let detail = match &service.outbound {
        Outbound::Passthrough => "allowed (passthrough)".to_string(),
        Outbound::Inject { credential } => {
            let Some(secret) = self.control.credentials.resolve(credential) else {
                self.audit(action, Decision::Deny,
                    &format!("credential '{credential}' not configured"), now);
                return reject(http::StatusCode::BAD_GATEWAY, DenyReason::NotAllowed,
                    "required credential is not configured");
            };
            match http::HeaderValue::from_str(&format!("Bearer {}", secret.expose())) {
                Ok(value) => { headers.insert(http::header::AUTHORIZATION, value); }
                Err(_) => {
                    self.audit(action, Decision::Deny, "credential not header-safe", now);
                    return reject(http::StatusCode::BAD_GATEWAY, DenyReason::NotAllowed,
                        "credential is not header-safe");
                }
            }
            format!("allowed; injected [{credential}]")
        }
    };
    self.audit(action, Decision::Allow, &detail, now);
    Outcome::Forward(ForwardPlan {
        url: upstream_url(&service.upstream_base, &req.path, &req.query),
        method: req.method, headers, body: req.body,
    })
}
```

  - `audit`/`audit_raw` drop the `agent` argument (see Task 6 for the `AuditEvent` change). For
    now, build the `AuditEvent` without an `agent` field.
  - Delete the now-unused `obligations`/`Obligation` import and the `NoPolicy` path (a token
    always carries a policy now). Remove the `authenticated_agent_without_policy_is_forbidden`
    and `mint_unknown_agent_returns_none` tests; adjust the remaining tests to `gw.mint(policy,
    ttl)`.

- [ ] **Step 6: Run tests**

Run: `cargo test -p gateway`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add gateway/src/service.rs gateway/src/normalize.rs gateway/src/core.rs
git commit -m "gateway: outbound stance on the service; mint takes a policy; no agent"
```

---

## Task 6: Drop `agent` from audit; update the server and admin mint

**Files:**
- Modify: `fluorite/audit.fl`
- Modify: `gateway/src/core.rs` (`audit` builders)
- Modify: `gateway/src/server.rs` (admin `/mint` handler reads a policy)
- Test: `gateway/src/core.rs` (audit assertions already updated in Task 5)

- [ ] **Step 1: Schema — drop `agent` from `AuditEvent`.** In `fluorite/audit.fl`:

```
struct AuditEvent {
    at_ms: u64,
    action: Action,
    decision: Decision,
    detail: String,
}
```

- [ ] **Step 2: Update audit builders** in `gateway/src/core.rs`:

```rust
fn audit(&self, action: &Action, decision: Decision, detail: &str, now: u64) {
    self.control.audit.record(AuditEvent {
        at_ms: now, action: action.clone(), decision, detail: detail.to_string(),
    });
}
fn audit_raw(&self, host: &str, decision: Decision, detail: &str, now: u64) {
    let action = Action::of("<unrouted>", Verb::crud(models::action::CrudKind::Read),
        Resource::of(host, "host"));
    self.audit(&action, decision, detail, now);
}
```

- [ ] **Step 3: Update the admin `/mint` handler** in `gateway/src/server.rs` to deserialize a
`MintRequest { policy, ttl_seconds }` and call `gateway.mint(req.policy, req.ttl_seconds)`.
(Read the existing handler to match its axum extractor style; replace the agent lookup with the
policy passthrough. If the handler returned 404 for unknown agents, drop that branch — any
valid policy mints.)

- [ ] **Step 4: Run the whole workspace**

Run: `cargo test --workspace`
Expected: PASS (the `tests/` e2e crate is updated in Task 7).

- [ ] **Step 5: Commit**

```bash
git add fluorite/audit.fl gateway/src/core.rs gateway/src/server.rs
git commit -m "audit+server: drop agent; admin mint accepts a policy"
```

---

## Task 7: CLI mint-from-file, config, and e2e

**Files:**
- Modify: `cli/` (the `mint` subcommand)
- Modify: `examples/config.json`, `examples/README.md`
- Modify: `tests/` e2e
- Test: `tests/`

- [ ] **Step 1: CLI — `mint --policy <file>`.** Read the `cli` mint subcommand; replace
`--agent <id>` with `--policy <path>` that reads the file, `serde_json::from_str::<Policy>`, and
POSTs a `MintRequest { policy, ttl_seconds }` to the admin `/mint`. Print the returned token.

- [ ] **Step 2: Config — move the credential onto the service, drop `agents`.** Rewrite
`examples/config.json` so each service entry carries its outbound stance, e.g.:

```jsonc
{
  "proxy_addr": "127.0.0.1:9090",
  "admin_addr": "127.0.0.1:9091",
  "services": [
    { "name": "github", "host": "api.github.com", "upstream_base": "https://api.github.com",
      "flavor": "github", "outbound": { "inject": "github-app" } },
    { "name": "openai", "host": "api.openai.com", "upstream_base": "https://api.openai.com",
      "flavor": "generic", "outbound": "passthrough" }
  ],
  "credentials": { "github-app": "ghs_REPLACE_WITH_REAL_INSTALLATION_TOKEN" }
}
```

Update the server's config deserialization (`gateway/src/server.rs` or wherever `services` are
parsed) to read the `outbound` field into `Outbound`. Update `examples/README.md` to describe
mint-by-policy-file and the per-service `outbound`.

- [ ] **Step 3: Update e2e.** In `tests/`, change every mint call to post a policy document and
assert: an allowed read injects the target credential (consumer token absent upstream); a denied
write never reaches upstream; an unknown host is 404; an invalid token is 401. Mirror the
existing e2e structure; replace agent registration with the inline policy.

- [ ] **Step 4: Run the gate**

Run: `make check`
Expected: PASS — `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --workspace`.

- [ ] **Step 5: Commit**

```bash
git add cli examples tests
git commit -m "cli+e2e: mint from a policy file; per-service outbound config"
```

---

## Self-review notes

- **Spec coverage (Phase 1):** no-agent tokens (Tasks 4–7), Option-A verb (Tasks 1–2),
  credential-bound-to-target + hybrid passthrough/inject (Tasks 3, 5, 7), `target` = instance
  name (Task 2). Catalog, SigV4, CLI-provision, discovery, MITM are explicitly deferred.
- **Type consistency:** `Verb::crud(CrudKind)` / `Verb::action(id)`; `Outbound::{Passthrough,
  Inject{credential}}`; `Tokens::mint(Policy, ttl, now) -> MintResponse`; `tokens.resolve ->
  Option<Policy>`; `Verdict::{allow(Vec<Obligation>), inject(id), passthrough(), deny(reason)}`;
  `Action::of(target, verb, resource)`; `normalize(service, req)`.
- **Fail-closed preserved:** default-deny in `decide`; unknown host → 404 deny; missing
  credential → 502 deny; unknown/expired token → 401.
- **Deferred follow-ups** each get their own spec+plan before implementation.
