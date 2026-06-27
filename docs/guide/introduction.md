# Introduction

**hackamore** gives an untrusted AI agent just-in-time, policy-scoped access to real
services — GitHub, AWS, Kubernetes, or any HTTPS API — without ever handing the agent a
real credential.

You run hackamore as a reverse proxy in front of those services. The agent runs in a
sandbox whose only network egress is hackamore. It is issued a short-lived **launch
token**, never an upstream secret. Every request the agent makes is normalized, checked
against a policy you wrote (default-deny), and — only when allowed — forwarded with the
**real** credential injected by the proxy. The agent never sees the secret, can't exceed
its policy, and every decision is audited.

## The problem

An AI agent that can run shell commands and call APIs is useful precisely because it
acts on your behalf. But an agent is also untrusted: it can be prompt-injected, it can
misread an instruction, or it can simply go off the rails. The moment you hand such an
agent a GitHub personal access token, an AWS access key, or a kubeconfig, two bad things
become possible:

- **Credential leak.** The secret now lives in the agent's environment, its logs, its
  prompt history, and any file it writes. A jailbroken agent can exfiltrate it, and from
  then on the blast radius is *everything that credential can do*, forever — not just
  what you wanted the agent to do this session.
- **Unbounded blast radius.** Even without leaking the secret, the agent can use its
  full power: a token scoped to "repo" can force-push to `main`, delete branches, or
  open the floodgates on every repository it can reach. Native permission systems are
  usually far coarser than the task at hand.

You want the agent to open a pull request against one branch of one repo — not to hold a
credential that can rewrite history across your whole org.

## hackamore's answer

hackamore moves the credential out of the agent entirely and puts a policy checkpoint in
front of every call:

- The agent holds a **launch token**, not a real secret. The token is bound to a policy
  and expires.
- Every request is **normalized** into a uniform `Action` (target, verb, resource,
  fields) regardless of which tool or protocol produced it.
- A **policy engine** decides allow or deny. The default is deny: if no rule explicitly
  allows the action, it is rejected.
- On allow, the proxy **strips the launch token, injects the real short-lived
  credential, forwards** the request to the real upstream, and **audits** the decision.
  The agent never observes the injected secret.

The credential is a property of the *service*, resolved from the vault at the moment of
forwarding — not something the policy names and not something the agent can reach.

## The request lifecycle

```
  ┌─────────────────────────┐
  │   sandboxed AI agent     │   holds only a launch token
  │  gh / git / aws / curl   │
  └───────────┬─────────────┘
              │  (sandbox confines all egress to hackamore)
              │  request + X-Hackamore-Token / Authorization: Bearer <token>
              ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                  hackamore gateway (proxy)                    │
  │                                                              │
  │   1. authenticate the launch token → resolve bound policy    │
  │   2. route by Host to a configured service (allowlist)       │
  │   3. normalize the request → Action{target, verb,            │
  │                                      resource, fields}        │
  │   4. decide(Action, Policy) → Allow | Deny                   │
  │        Deny  ─────────────────────────────▶ 403              │
  │        Allow ─▶ strip token, inject real credential,         │
  │                 forward to the real upstream                  │
  │   5. emit an audit event (with the matched rule)             │
  └───────────────────────────────┬─────────────────────────────┘
                                  │  request + real credential
                                  ▼
                       ┌──────────────────────┐
                       │   real upstream       │  GitHub / AWS / k8s / …
                       └──────────────────────┘
```

Step by step:

1. **Authenticate.** The gateway reads the launch token. It can arrive in the
   `X-Hackamore-Token` header, as `Authorization: Bearer <token>` (or GitHub's
   `Authorization: token <token>`), in the password slot of an HTTP Basic header (how
   `git` over HTTPS presents it), or as a dummy AWS SigV4 signature (how the `aws` CLI
   presents it). An unknown, missing, or expired token is rejected. The token resolves to
   the policy it was minted with.
2. **Route.** The request's `Host` header selects a configured service. Services are an
   allowlist — a request whose host matches no service is denied.
3. **Normalize.** The gateway turns the raw request into an `Action`: the `target` is the
   service name, the `verb` is the HTTP method or a named action (depending on the
   service's protocol), the `resource` is the canonical request path, and `fields` is a
   flattened view of the query and JSON body for conditional rules.
4. **Decide.** The pure policy engine evaluates the `Action` against the bound policy.
   Rules run top-to-bottom, first match wins. A deny (explicit, or default-deny because
   nothing matched) returns `403`. An allow proceeds.
5. **Inject and forward.** On allow the gateway strips the inbound token, resolves the
   matched service's credential from the vault, injects it (as a bearer header, a basic
   header, a custom header, or an AWS SigV4 re-signature), and forwards to the real
   upstream. The response streams back to the agent.
6. **Audit.** Every decision — allow or deny — is recorded, including which rule decided,
   so any action is traceable.

For how the agent gets configured and what tokens look like in practice, see
[Running agents](running-agents.md).

## The three planes

hackamore is built as three planes, with the policy engine deliberately decoupled from
everything that does I/O:

- **Policy engine** — a pure function: `decide(Action, Policy) -> Verdict`. No I/O, no
  HTTP, no async, no awareness that a proxy exists. Its entire public surface is one
  function. This is what makes the engine portable: any data plane can reuse it by
  translating its native request into an `Action` and enforcing the returned `Verdict`.
- **Control plane** — the credential vault (resolves a credential id to a real secret),
  launch-token minting, and the audit sink. Secrets live here and never leave as plain
  strings; the agent and the policy author never touch them.
- **Data plane (gateway)** — the reverse proxy. It normalizes each request into an
  `Action`, calls the policy engine, enforces the verdict (deny → 403; allow → inject
  credential and forward), and emits an audit event.

The engine is decoupled because authorization logic should outlive any single proxy.
The `Action`/`Verdict` contract is the boundary; the same engine could sit behind a
different proxy or an external authorization adapter without changing a line of policy
code.

## Default-deny / fail-closed

The guiding principle is **fail closed**. The default decision is deny, and *any*
ambiguity denies:

- A missing, unknown, or expired token denies.
- A request to a host hackamore does not proxy denies.
- A request whose path can't be canonicalized denies.
- A required credential that isn't configured in the vault denies (the request is never
  forwarded without it).
- If no rule matches, the action denies.

There is no bypass and no implicit allow. You grant capability by writing explicit allow
rules; everything else is refused. See [Policies](policies.md) for how to write those
rules.

## Trust and threat model

hackamore assumes the agent is **hostile**. Within that assumption, here is what holds
and what does not.

**A compromised agent still cannot:**

- **Read the real upstream credential.** The secret is resolved from the vault and
  injected by the proxy only on the outbound leg. It is never placed in a response, an
  audit line, or anything the agent receives. The launch token the agent holds is useless
  against the real upstream.
- **Perform an action its policy does not allow.** Every request is normalized and
  checked. The policy is default-deny, so the agent's capability is exactly the union of
  its allow rules — no more.
- **Reach anything but the gateway** — *provided the sandbox actually confines egress*
  (see below). hackamore only forwards to its configured allowlist of services.

**Out of scope (your responsibility, not hackamore's):**

- **Confinement.** hackamore's guarantees depend on the gateway being the agent's *only*
  network egress. Forcing that — so the agent can't open a socket straight to GitHub and
  skip the proxy — is the **sandbox runtime's** job (for example, network capabilities
  that redirect or block all other egress). If the agent can reach the internet directly,
  hackamore is not in the path and none of the above applies. Run the agent in a sandbox
  that pins egress to hackamore.
- **The upstream's own behavior.** hackamore controls *what the agent can ask for*, not
  what the upstream does with an allowed request. Scope your policies and your injected
  credentials accordingly.

---

Next: [Core concepts](concepts.md) · [Getting started](getting-started.md)
