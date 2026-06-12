# hackamore — generic policy-enforcing egress proxy (redesign)

**Status:** design approved, pre-implementation. **Date:** 2026-06-06.
**Supersedes:** the GitHub-centric model in `2026-06-04-hackamore-jit-agent-access-design.md`
(and its "any HTTPS service" addendum). The pure policy engine and the `Action`/`Verdict`
portability boundary survive unchanged; everything else generalizes.

## What changes, and why

Three drivers, surfaced by stress-testing the v1 model against GitHub, EKS/k8s, and the
AWS CLI:

1. **Any HTTPS service, registered by an admin — no built-in service flavors.** v1 had a
   hardcoded GitHub normalizer and a single `Bearer` injection path. We replace per-service
   *code* with a per-service **descriptor** (data) interpreted by one generic pipeline.
2. **No agent identity.** v1 bound a token to a pre-registered `agent` whose policy lived in
   a registry. Now a caller submits a **policy document** and, if it validates, receives a
   token bound to that policy. A separate entity uses the token to proxy requests.
3. **Credential handling is optional and per-rule (hybrid).** hackamore becomes an **L7 egress
   policy enforcer** first. By default the consumer brings its own credential and hackamore only
   allows/denies + audits. A rule *may* additionally inject/hide a credential where
   zero-exposure matters — paying per-scheme complexity only for the services that need it.

## Roles and what each party sees

Three roles (v1 conflated the first two):

- **Operator** — runs hackamore; registers services with their address, type, auth mechanism,
  and (for injection) the real credential. **The only party that holds real credentials.**
- **Minter** — submits a **policy document + TTL** to the admin API; receives an **opaque
  token** (or, for SigV4 upstreams, a minted **dummy credential**). Sees service/target
  *names* and the action vocabulary — **never a real secret**.
- **Consumer** — holds only the token + the hackamore endpoint; runs stock `gh`/`kubectl`/
  `aws`/an SDK after a one-shot `hackamore-agent setup --token` (see *Agent setup*). **Never sees
  a real credential.** In injection mode it never sees the upstream secret; in filter-only mode
  it carries its *own* credential, which hackamore passes through.

**TLS / what hackamore sees.** Content-aware policy (verb, path, body conditions) requires
plaintext, which requires hackamore to **terminate TLS** on the consumer→hackamore leg. The default
is **endpoint-override**: each tool is pointed at hackamore (`GH_HOST`, kubeconfig `server`,
`AWS_ENDPOINT_URL`) and trusts **hackamore's own serving cert** (one host to trust) — written by
the `hackamore-agent` CLI, not by hand. This is **not** MITM and **not** system-CA distribution —
hackamore presents its own identity; the client is knowingly pointed at it. (A **transparent-MITM**
mode — a sandbox-scoped forging CA + L4 redirect, agent unconfigured — is the fallback for
cert-pinning clients that can't override their endpoint.) Consequence: hackamore sees the
consumer's `Authorization` header in plaintext even in filter-only mode. "Filter on the body"
and "see the credential" are the same property; what a rule controls is only whether hackamore
*swaps* the credential or passes it through.

The only alternative — filtering without decrypting — degrades to a host/SNI allowlist (no
verb/path/body policy), which the sandbox layer already does. So termination is required for
the policy hackamore exists to enforce.

## Architecture: one generic pipeline

The policy engine stays pure and decoupled (`decide(&Action, &Policy) -> Verdict`). All
protocol-specific knowledge lives in **data** (the service descriptor) interpreted by a
single data-plane pipeline. Per request:

```
leg-1 TLS terminate
  └─▶ [1] authenticate inbound        (auth mechanism: bearer | sigv4 | apikey | mtls …)
      └─▶ [2] route → target instance (by address for REST; by inbound identity for SigV4)
          └─▶ [3] normalize → Action  (RESTful method+path default; or declared RPC parser)
              └─▶ decide(Action, Policy)
                  └─▶ on allow: [4] apply outbound credential
                                   (passthrough | inject bearer | re-sign sigv4 | mTLS)
                      └─▶ forward → stream response → audit
```

Steps 1–4 are the descriptor's surface. The proxy, engine, audit, and token model are
service-agnostic and never learn which service they are handling.

## Service model: type vs instance

The v1 `Service` conflated *type* (protocol/auth) with *instance* (a concrete cluster/
account). We split them:

- **Service type** — declares the **auth mechanism**, the **wire protocol** (for extraction),
  and **how its catalog is resolved**. Shared across instances.
- **Service instance** — binds a type to a concrete **endpoint** + **credential** (+ for
  injection, the real identity). This is the `target` the policy and audit name.

`Action.target` is the **instance name** (`eks-prod`, `aws-acct-A`), not the type. Policy
scopes by target; the **credential is a property of the target**, resolved by hackamore and
**never named in the policy** (this closes the v1 credential-laundering hole and lets policy
authors reference targets, not secrets).

### Model resolution — four strategies (admin chooses at registration)

Registration provides `{type, address, credential, auth}` together, so the catalog can be
resolved immediately, before any mint (no chicken-and-egg). The model is **one ingested
artifact with two projections**: a **catalog** (authoring + validation) and a **recognizer**
(runtime extraction).

| Strategy | Example | Catalog source | Refresh scope |
|---|---|---|---|
| **a. live-discovery** | k8s | the cluster's discovery API + OpenAPI (uses the instance credential) | per-instance, periodic (CRDs are per-cluster) |
| **b. embedded** | aws | vendored botocore models + Service Authorization Reference | per-type, regen on upgrade |
| **c. openapi** | any documented HTTPS API | an OpenAPI doc the admin supplies (URL/path) | per-type, on change |
| **d. raw / none** | anything | none — author writes raw `method + path` matches | n/a |

Lifecycle, strictly ordered:

```
register instance → resolve model (cache catalog + recognizer) → mint (validate) → enforce
```

A stale-cache miss at mint triggers an on-demand refresh.

## Auth mechanisms (a closed, shared library)

Auth is **not** per-service code. The world's HTTP auth schemes are a closed sum type,
selected per service for both inbound (authenticate the caller) and outbound (apply the real
credential on allow):

```
AuthMechanism = Bearer | SigV4 | ApiKeyHeader{name} | Basic | MutualTls | …
```

| Service | inbound (verify caller) | outbound (on allow) |
|---|---|---|
| github | Bearer (hackamore token) | inject Bearer (GitHub-App token; mint + rotate) |
| k8s | Bearer | inject Bearer (EKS `get-token`; mint + rotate) |
| aws | **SigV4-verify** vs a minted **dummy** credential | **re-sign SigV4** with the real account identity |
| filter-only (any) | the scheme above | **passthrough** (agent's own credential forwarded unchanged) |

**Token channel (defect fix).** Passthrough needs *two* credentials on one request — the
hackamore token (to resolve the policy) **and** the consumer's own upstream credential (to
forward). They cannot share the `Authorization` slot. So the hackamore token has a dedicated
header, **`X-Hackamore-Token`**: when present, `Authorization` is the consumer's own credential
and is preserved (passthrough) or overwritten (inject). For single-slot tools (`gh`/`kubectl`,
which can only set `Authorization`) the token may instead ride `Authorization: Bearer`; hackamore
then treats `Authorization` as the hackamore token and strips it. Rule: *token in `X-Hackamore-Token`
⇒ keep `Authorization`; token in `Authorization` ⇒ strip it.*

The **hybrid** stance is exactly the outbound column: `passthrough` = filter-only;
`inject`/`re-sign` = zero-exposure. Choosable **per rule / per target**. Adding a scheme adds
one shared variant, never per-service code. SigV4 and EKS/GitHub-App minting are shared
**credential providers** that mint/rotate/sign — referenced by config, implemented once.

## Normalization / extraction

Extraction generalizes to a single declared dimension — the **wire protocol** — which the
service model declares (so extraction is *inherited* from the catalog strategy, not separately
configured):

| Protocol | Operation lives in | Extractor | Covers |
|---|---|---|---|
| **RESTful** (default) | HTTP method + URL path | one generic `method + path` engine | strategies a, c, d **and** S3 — the majority |
| **aws-query / aws-json** | `Action=` form body / `X-Amz-Target` header | one closed parser each, driven by the embedded model | strategy b (AWS non-S3) |
| *(future: graphql, json-rpc)* | query body / `method` field | add a parser when needed | — |

Three of four strategies use the one RESTful extractor with **zero per-service code**; only
AWS pulls a protocol parser, itself generic over all of AWS.

**Tiers of expressiveness (pay only for what you need):**
- **Tier 0 — method + path glob (zero config).** Covers every RESTful service for coarse
  "which verb on which path" rules. E.g. `allow PUT my-data/**`. `fields` unused.
- **Tier 1 — + field extraction (opt-in).** Required when (a) the operation isn't in the path
  (AWS query/JSON, GraphQL, JSON-RPC — path is constant), or (b) policy needs **value-level**
  conditions (e.g. PRs only against `base=develop`). Sources fields from path-template
  captures, query, headers, or body (JSONPath / XPath / form).

**Strict + fail-closed.** Generic extraction must canonicalize and **deny on ambiguity** —
unparseable body for the declared content type, duplicate query/JSON keys, non-canonical
paths. A lenient extractor is a policy bypass.

## The `Action` / `Verdict` contract

`Action { target, verb, resource{path, kind}, fields }`,
`Verdict = Allow{obligations} | Deny{reason}` remains the portability boundary. The
descriptor's `extract` block is **not** a new per-service schema — it is the recipe that
*fills in this one fixed model* from a raw request.

**Verb granularity (decided: open the verb — Option A).** CRUD verbs fit RESTful services but
not IAM-action-shaped policy (`ec2:TerminateInstances` ≠ one of four verbs). So `verb` is a
**tagged union**, not a bare CRUD enum:

```
Verb = Crud(Read | Create | Update | Delete)   // RESTful method mapping
     | Action(String)                           // service-defined action id, e.g. "ec2:TerminateInstances"
```

The named action is **first-class and top-level** (it *is* the verb), so a rule reads the way
authors think about IAM/RBAC — `verbs: ["ec2:DescribeInstances"]` — and the catalog vocabulary
is the verb vocabulary. The engine's verb-matching handles both arms; it stays exhaustive
because the union is closed (two arms), preserving the make-illegal-states-unrepresentable
property — the `Action(String)` arm is the one open vocabulary, scoped to a single field. The
`extract` recipe decides which arm a service produces (method-map → `Crud`; RPC action parse →
`Action`).

## Catalog: the policy-authoring + validation frontend

The catalog (from strategy a/b/c) gives policy authors a **named vocabulary** instead of path
globs — exactly how they already think (IAM actions, k8s RBAC verbs×resources, GitHub
permissions). It is sugar **above** the generic `Action`: a catalog action **compiles down** to
the low-level matcher.

```
allow s3:PutObject on my-data/*   ──(catalog: how is PutObject recognized?)──▶
  match { verb: Update, resource: "my-data/*" }   ← what decide() sees
```

Both forms coexist: the **raw** form (`allow PUT my-data/**`) is the simple default and the
escape hatch; the **catalog** form is the ergonomic, validated form.

**Validation at mint, two tiers (see Mint below):** catalog-backed references are checked
semantically (unknown → reject, fail closed); raw matches are checked only structurally.
Where the catalog knows them, **condition keys** are validated too (AWS SAR enumerates them;
OpenAPI params supply them).

## Multiplicity (N clusters, N accounts)

`target` is an instance name, so N instances are just N descriptors of the same type. The
**routing key differs by how a service is addressed**, an asymmetry worth designing for:

- **k8s (N clusters): disambiguate by address.** Each cluster is a distinct endpoint; the
  consumer uses distinct kubeconfig contexts. Give each cluster a distinct hackamore
  hostname (`prod.k8s.hackamore.local`, one wildcard cert) or path-prefix; route by it.
- **aws (N accounts): disambiguate by identity.** AWS endpoints are region-scoped, not
  account-scoped — accounts differ only by credential. Mint a **distinct dummy AKID per
  account**; the consumer selects via `AWS_PROFILE`; hackamore maps dummy AKID → real account.
  Endpoint comes from the SigV4 scope (region+service); account from the credential.

So routing generalizes from "the Host header" to a **mechanism-aware** `route(request) → target`:
address for REST, inbound identity for SigV4.

## Mint and token (no agent)

The control plane mints a token from a **policy document + TTL**. There is no agent registry.

- For bearer upstreams the token is an opaque capability bound to the policy.
- For SigV4 upstreams the minted artifact is a **dummy credential pair** (the consumer's
  tooling signs with it; hackamore verifies then re-signs). The token envelope therefore varies by
  the consumer's auth scheme; the policy→token binding is identical.

**Validation against the service model** (per confirmed design):
- catalog-backed actions/resources/targets → **semantic** check, reject on unknown (fail closed);
- raw matches → **structural** check only (opting out of semantic validation, by design);
- validated against the **cached** model from registration (on-demand refresh on miss).

In the single-trust-domain local setup, the mint endpoint is localhost-bound and admin =
minter, so "valid policy → token" is safe. Caller-authorization becomes necessary only with
multiple trust domains (see Deferred).

## Agent setup / provisioning (consumer side)

Per-tool wiring is **automated by a consumer CLI**, not hand-configured — that is what keeps
the endpoint-override model from being intrusive. The agent runs one command and then uses
stock tools unaware of hackamore.

**Provision doc — the artifact the CLI acts on.** The policy alone can't configure the tools
(it says *what's allowed*, not *how to reach each target or with what credential material*).
The control plane projects the policy into a **provision doc** =
`policy targets ⋈ service-registry connection info ⋈ minted credential material`, served from a
token-authenticated `GET /provision`:

```jsonc
ProvisionDoc {                          // fluorite protocol type
  hackamore_ca: "<pem>",                   // hackamore's own serving cert — one host to trust
  expires_at_ms: …,
  services: [
    { target: "github",     type: "github", address: "https://hackamore.local:9090",
      auth: { scheme: "bearer", token: "<hackamore-token>" } },
    { target: "eks-prod",   type: "k8s",    address: "https://prod.k8s.hackamore.local",
      auth: { scheme: "bearer", token: "<hackamore-token>" } },
    { target: "aws-acct-A", type: "aws",    address: "https://hackamore.local:9090",
      auth: { scheme: "sigv4", access_key_id: "AKIA_DUMMY…",
              secret_access_key: "…", region: "us-east-1" } }
  ]
}
```

It contains **no real secrets** — only the bearer token the holder already has, *dummy* AWS
creds (worthless against real AWS), and hackamore's endpoints/CA. So returning it to the token
holder is safe and recommended for transparency. The **consumer-facing `address`** per target
comes from a registry field distinct from `upstream_base` (how the *consumer* reaches the
target through hackamore vs. how hackamore reaches the real upstream).

**The `hackamore-agent` CLI** (new consumer binary):

```
hackamore-agent setup    --token <t> [--ca hackamore-ca.pem]   # fetch doc, configure every service
hackamore-agent env      --token <t>                        # export lines for `eval` (SDK/base-url tools)
hackamore-agent status   --token <t>                        # configured state + reachability + expiry
hackamore-agent policy   --token <t>                        # human-readable allowed actions (transparency)
hackamore-agent teardown                                    # remove what setup added
```

`setup` walks `services[]` and writes each tool's **native** config, **idempotent and
merge-not-clobber**:
- **github** → git `http.sslCAInfo`, `url.…insteadOf https://github.com/`, a credential helper
  returning the bearer token; `GH_HOST`/`GH_TOKEN` for `gh`.
- **k8s** → merge a namespaced context per cluster into kubeconfig (`server`, CA, `user.token`).
- **aws** → a `~/.aws/credentials` profile per account (dummy cred) + `~/.aws/config`
  (`endpoint_url`, `region`, `ca_bundle`).
- **generic** → `hackamore-agent env` emits base-url + CA-bundle vars.

**Trust bootstrap (one chicken-and-egg).** `setup` fetches the doc over TLS but must trust
hackamore's cert *before* the doc delivers the CA. Resolve by delivering `(token, CA)` together at
launch (`--ca`, image pre-placement, or first-contact pinning over localhost). The orchestrator
handing both is the clean path.

**Lifecycle.** Namespacing what `setup` writes (a dedicated kubeconfig context, a named aws
profile, scoped git config) makes re-running on token rotation update in place and `teardown`
remove exactly what was added.

## Out of scope / deferred

- **Multi-tenant mint authorization.** When one hackamore serves multiple trust domains, add:
  (1) an authenticated mint caller (tenant), (2) a tenant→owned-targets table, (3) a
  subset check `referenced_targets(policy) ⊆ tenant.owned_targets` (fail closed). Purely
  additive to the control-plane mint path; engine, contract, and data plane unchanged. Kept
  out now: single domain, localhost mint.
- **Transport gaps.** `Upgrade`/streaming subresources — `kubectl exec`/`port-forward`/
  `logs -f`/`watch` (SPDY/WebSocket) and large streaming S3 uploads
  (`STREAMING-…-PAYLOAD`/multipart). Plain request/response (incl. SSE) is in scope; `aws s3
  presign` is client-side and bypasses hackamore → unsupported (fails closed).
- **Additional RPC parsers** (GraphQL, JSON-RPC) — add when a registered service needs one.
- **Cedar/CEL** behind `decide` — optional, still hidden by the engine boundary.

## Worked examples

- **github — PRs only against `develop`.** `POST /repos/o/r/pulls` body `{"base":"main"}`.
  Bearer-in (hackamore token) → route by Host → REST normalize: `verb=Create`,
  `resource="repos/o/r/pulls"`, `fields={base:"main"}` → rule `allow Create on repos/*/*/pulls
  if base==develop` → `main≠develop` → **deny**. Allowed PRs inject the GitHub-App token.
- **k8s — read pods in `dev`.** `hackamore-agent setup` merged the cluster context (`server`→
  hackamore, static `token`, CA). `kubectl get pods -n dev` → Bearer-in → route by per-cluster
  host → REST normalize `verb=Read, resource=api/v1/namespaces/dev/pods` → allow → inject EKS
  `get-token` → forward. Consumer never saw AWS creds or the EKS token.
- **aws s3 — write to one bucket (Tier 0).** `hackamore-agent setup` wrote the aws profile (dummy
  cred, `endpoint_url`, `ca_bundle`). `aws s3 cp f s3://my-data/…` → SigV4-verify dummy → route
  by AKID → REST normalize `verb=Update, resource=my-data/…` → rule `allow PUT my-data/**` →
  re-sign with real account A → forward. No field extraction needed.
- **aws ec2 — read but not destroy (Tier 1).** Both ops are `POST /`; the action is in the
  form body. The `aws-query` parser sets `verb = Action("ec2:DescribeInstances")` vs
  `Action("ec2:TerminateInstances")` → rule `allow verbs:["ec2:DescribeInstances"]`, nothing
  for terminate → terminate falls to default-deny. Path-glob alone could not distinguish these.

## Verification

- **Unit:** engine (unchanged); auth-mechanism library (bearer extract, SigV4 verify/sign);
  the RESTful extractor and each RPC parser (canonicalization + fail-closed on ambiguity);
  catalog resolution per strategy; mint-time validation (semantic reject vs structural pass);
  routing (address vs inbound-identity); provision-doc projection (no real secrets leak) and
  `hackamore-agent setup` config writing (idempotent merge + teardown).
- **e2e:** live server + mock upstreams proving — REST allow/deny with credential
  passthrough *and* injection; SigV4 re-sign (dummy verified, real signature upstream,
  consumer secret absent); k8s discovery-backed catalog validation; AWS Tier-1 action
  extraction gating destroy; unknown-target/unknown-action mint rejection; `/provision` returns
  a usable doc that configures a stock tool end-to-end; every decision audited with the
  concrete target.
- **Gate:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --workspace`.

## Implementation status (2026-06-06)

Built and green (`make check`), beyond the Phase-1 spine:

- **Token channel** — `X-Hackamore-Token` dual-channel so passthrough forwards the consumer's
  own credential (defect fixed).
- **Auth mechanism library** — `Outbound = Passthrough | Bearer | Header{name} | SigV4{…}`.
  SigV4 is a from-scratch `ring`-based signer (SHA-256 + HMAC), unit-tested against the AWS
  documented signing-key vector and a sign↔verify round-trip; the `Outbound::SigV4` arm
  re-signs allowed requests with the real account credential (the consumer never holds it).
- **Provisioning** — `ProvisionDoc` + token-authenticated `GET /provision` (policy ⋈ service
  registry, no real secrets), and a `hackamore-agent` consumer CLI (`show`/`env`/`status`/`setup`).
- **Extraction** — `Protocol = Rest | AwsQuery | AwsJson` (operation from body/header,
  fail-closed sentinel verb), form-body field extraction, and `{bucket}/{key+}` path templates.
- **Catalog + validation** — per-target action catalog with fail-closed mint-time validation
  (unknown named action → reject); static config source today.
- **Multi-tenant mint authorization** — `X-Hackamore-Tenant` credential + owned-targets table +
  subset check (empty-target allow rules rejected for tenants).

Residuals (each a contained extension, not a redesign):

- **SigV4 *inbound*** — verifying a minted dummy AKID *as the policy-identifying token* (so the
  `aws` CLI signs and hackamore routes by the signed AKID). Today an AWS-target consumer presents a
  hackamore token via `X-Hackamore-Token` to identify the policy, and hackamore re-signs outbound; the
  signer's `verify` is implemented and tested, ready to drive this path.
- **Catalog ingesters** — live k8s discovery / OpenAPI / botocore-SAR sources produce the same
  `Catalog` set; only the static source is wired.
- **`hackamore-agent` native writers** — `setup` writes an env file + summary; per-tool
  kubeconfig/`~/.aws`/git writers build on the same provision doc.
- **Transport** — `Upgrade`/streaming subresources and transparent-MITM mode (per *Out of
  scope*).
