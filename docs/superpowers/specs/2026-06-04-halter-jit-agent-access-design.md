# halter — JIT, policy-scoped access for untrusted agents (v1 design)

**Status:** v1 implemented. **Date:** 2026-06-04.

## Problem

AI agents need access to external services (GitHub first; Kubernetes, cloud, DBs later)
to do real work, but handing an agent a long-lived credential is unsafe: an agent can be
prompt-injected or otherwise go rogue. We want **just-in-time, policy-scoped** access
where the agent gets exactly what its task needs, for a bounded time, and **never holds
a real credential**.

## Decisions (from brainstorming)

1. **Trust model: untrusted agent.** Assume the agent may be compromised. Therefore it
   must never possess a real upstream credential, and every action is authorized inline.
2. **Enforcement point: an inline proxy holding the real credentials**, with the
   sandbox guaranteeing the proxy is the only egress (so the agent cannot bypass it).
   Chosen over (a) credential vending — can't enforce finer-than-native control, can't
   revoke mid-task — and (b) a CLI shim — bypassable via raw API calls.
3. **Token model.** halter mints a short-lived **capability token** bound to the agent's
   policy. It is injected into the sandbox so CLIs (`gh`/`git`) use it transparently, but
   it is honored **only by halter** — never the real upstream. halter swaps it for the
   real credential when forwarding.
4. **Policy model: Option 3 — standing policy attached to the agent identity.** Policy is
   a property of the agent, reused every launch; the token is derived from it at launch.
5. **v1 scope: GitHub REST API only.** Highest value, smallest protocol surface. `git
   push` (git Smart-HTTP) and Kubernetes are deferred — the `Action` abstraction makes
   them additive.
6. **Data plane: a reverse proxy, not Envoy or TLS-MITM.** The sandbox
   (nono = Landlock/Seatbelt, plus a netns/nftables redirect on Linux) does
   *confinement*; that is a different job from *policy*. Because confinement is handled
   below, halter can be a plain reverse proxy and avoid TLS interception and CA
   distribution. Envoy + `ext_authz` was considered and rejected for v1: heavyweight, and
   its only real win (out-of-process authz) is the very thing we get for free by keeping
   the engine a library.
7. **Engine decoupled from the proxy.** The policy engine is a pure library whose entire
   surface is `decide(&Action, &Policy) -> Verdict`. Any future data plane (Envoy
   `ext_authz`, a hudsucker MITM) reuses it by producing an `Action` and enforcing the
   `Verdict`. The engine internals (a custom matcher today; Cedar/CEL later) are hidden
   behind that boundary.
8. **Conventions from horsie:** semantic types, illegal states unrepresentable, deep
   modules, fail-closed, protocol-types-via-fluorite, and the deny-`unwrap`/`expect`/
   `panic` lint gate.

## Architecture

Three planes:

- **`policy` (engine)** — pure `decide(Action, Policy) -> Verdict`. First-match-wins,
  default-deny. `Allow` rules carry `grant_credentials` that become credential-injection
  obligations.
- **`control` (control plane)** — agent→policy registry, short-lived token mint/resolve,
  the credential vault (`CredentialRef` → `Secret`), and the audit sink. Secrets are a
  redacted semantic type; time is injected for testability.
- **`gateway` (data plane)** — a GitHub→`Action` normalizer, a transport-agnostic
  decision/enforcement core (`Gateway::handle` → `Forward`/`Reject`), and an axum reverse
  proxy + admin (`/mint`) API. On allow it injects the real credential and strips the
  agent token; it audits every decision.

`models` holds the fluorite-generated contract types (`Action`, `Verdict`, `Policy`,
audit, mint). `cli` is the `halter` binary. `tests` is full-stack e2e.

### Request lifecycle

1. **Launch:** orchestrator calls admin `/mint` → halter mints a token bound to the
   agent's standing policy; the sandbox injects it and locks egress to halter.
2. Agent calls GitHub via the proxy with `Authorization: Bearer <halter token>`.
3. halter resolves token → agent → policy, normalizes the request to an `Action`,
   `policy::decide`s, and on allow injects the real credential and forwards; on deny
   returns 403. Either way it records an `AuditEvent`.

## The `Action` / `Verdict` contract (portability boundary)

```
Action  { agent, target, verb, resource{path,kind}, fields }
Verdict = Allow { obligations: [InjectCredential(CredentialRef)] } | Deny { reason }
```

The engine sees only `Action`, never HTTP — so a K8s or Envoy adapter reuses it
unchanged.

## Out of scope (v1) / future

- `git push` gating (git Smart-HTTP `receive-pack` ref inspection) → v2.
- Kubernetes adapter (reuses `Action` + engine) → v2.
- Dynamic mid-task access requests / human approval → later.
- Response redaction obligations → later.
- Swapping the custom matcher for Cedar/CEL behind `decide` → optional.
- Real GitHub App installation-token minting/rotation in the vault (v1 takes a
  provisioned token).

## Addendum (2026-06-05): any HTTPS service, any HTTP transport

Generalized beyond the GitHub-only v1, without changing the core model:

- **Any HTTPS service.** `Action.target` is now a generic **service name** (the `Github`
  enum is gone). halter holds a **configured service allowlist**, each entry
  `{ name, host, upstream_base, flavor }`, and routes a request to a service by its
  `Host` header. An unmatched host is **denied (fail closed)** — halter only forwards to
  its allowlist. Policy rules scope by service via `targets`.
- **Flavors.** Normalization is **generic** by default (path-based; works for any
  HTTP/JSON/SSE API); a service may opt into a richer flavor (`github`) for nicer
  resource kinds. Adding a flavor never changes the engine — only the adapter.
- **Any HTTP transport.** The forwarder **streams** the response body instead of
  buffering it, so Server-Sent Events, chunked responses, and long-polls pass through
  transparently. The request body is still buffered (policy conditions may inspect it).
  WebSocket/`Upgrade` is the remaining transport not yet handled.

This kept the `Action`/`Verdict` contract and the pure engine unchanged — only the
`gateway` (new `service` router, flavored `normalize`, streaming `forward`) and config
(a `services` list replacing the single `route`) moved.

## Verification

- Unit tests: engine (matching, globs, conditions, first-match/default-deny), control
  (token mint/expiry/revoke, secret redaction, registry, audit), gateway core
  (auth/deny/allow/cred-injection/expiry), GitHub normalization.
- e2e: live server + mock GitHub upstream proving the user stories — allowed read
  injects the real credential (agent token absent upstream), denied write never reaches
  upstream, PR creation gated by base branch, unauthenticated/invalid token rejected,
  admin mint behavior, and that every decision is audited.
- Gate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --workspace`, enforced in CI.
