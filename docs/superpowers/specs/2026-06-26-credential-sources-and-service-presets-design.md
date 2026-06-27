# Credential Sources & Service Presets — Design

**Status:** approved design, pending implementation phasing
**Date:** 2026-06-26
**Supersedes the auth portion of:** [2026-06-25-idl-driven-services-design.md](2026-06-25-idl-driven-services-design.md)

## Problem

Registering a service today conflates two unrelated concerns into one "outbound"
knob (`Passthrough | Bearer | Header | SigV4`, with the secret pasted inline and
vaulted under the service name). That knob only answers *how the credential goes on the
wire*. It cannot answer *where the real upstream credential comes from* — a static paste,
an environment variable, a rotating file, `gh auth token`, a minted GitHub-App
installation token, an STS AssumeRole, or a kubeconfig exec-plugin.

Separately, registering a real service is tedious: the operator must locate and supply an
OpenAPI/Smithy description and hand-configure host/upstream/protocol for services hackamore
could simply *know* (GitHub, AWS, k8s).

## Core principle

**Auth is two orthogonal axes — Source × Injection.**

- **Source** — where/how hackamore obtains the real upstream credential material. Resolves
  to credential material, either static or minted-and-rotated. Lives on a named
  **credential**, not on the service.
- **Injection** — how resolved material is placed on the proxied request. Lives on the
  service. Today's `Outbound`, minus the embedded secret.

A service's injection **references a credential by id**; one credential can back many
services with different injections (this is how `github-api` and `github-git` share one
`gh` token). The policy engine never names a credential; injection is a property of the
service instance, as before.

**Presets are CLI sugar over a generic engine.** The CLI knows a handful of well-known
services and pins everything *intrinsic* to each — its model, wire protocol, host, and
injection. The operator supplies only the *extrinsic* thing: the source. Every preset
compiles to the same generic `POST /admin/services`; **the gateway and policy engine never
learn the word "github" or "aws."** The engine knows generic *protocols* (wire framings),
never *services*.

```
preset  = (model, protocol, host, injection)        // CLI-side, opinionated
operator = source                                    // the one thing you supply
engine  = decide(Action, Policy) + generic protocols // never names a service
```

---

## Axis 1 — Source (on a credential)

A **credential** is `(id, source)`. The source resolves the id to material in the vault,
static or minted+rotated. Register once; services reference the id.

```bash
hackamore credentials add <id> --source <kind> [params…]
```

| Source kind | Resolves from | Shape | Lifetime |
|---|---|---|---|
| `static` | pasted secret (vaulted) | token | long-lived |
| `env` | env var on the hackamore host | token | static |
| `file` | a file path, re-read on change (e.g. projected SA token) | token | rotating |
| `gh-token` | `gh auth token` on the host | token | re-read |
| `github-app` | app id + installation id + private key → installation token | token | minted ~1h |
| `assume-role` | STS AssumeRole with a base credential | **AWS bundle** | minted ~1h |
| `instance` | host AWS credential chain (env/profile/IMDS/container) | **AWS bundle** | rotating |
| `kubeconfig` | a kubeconfig context: bearer token **or** exec-plugin (incl. `aws eks get-token`) | token | static or minted |

**The AWS bundle.** Token-shaped sources resolve to a single `Secret`. AWS temporary
credentials are a triple `{access_key_id, secret_access_key, session_token, expires_at}`;
the session token must ride out in `X-Amz-Security-Token` and rotate with the rest. This is
the one place the source boundary must widen beyond `Secret`. Static IAM-user keys
(AKID+SAK, no session token) still fit the narrow shape; assume-role / instance / EKS
require the bundle. The minting scaffolding already exists
(`CredentialProvider`, `CachingCredentials`, `EksGetTokenProvider`, `GitHubAppProvider`);
a generic `AssumeRoleProvider` and the bundle-typed resolve are new.

---

## Axis 2 — Injection (on a service)

Today's `Outbound`, with the secret replaced by a **credential id reference** and a new
`basic` arm.

| Injection | Wire effect | Non-secret params | Status |
|---|---|---|---|
| `passthrough` | forward the consumer's own credential unchanged | — | today |
| `bearer` | `Authorization: Bearer <secret>` | — | today |
| `header` | `<name>: <secret>` | header name | today |
| `basic` | `Authorization: Basic base64(<username>:<secret>)` | username | **new** |
| `sigv4` | **re-sign** the canonical request | service, region, `X-Amz-Security-Token` for temp creds | partial (today: no session token; region pinned) |
| `mtls` | client cert on the upstream TLS handshake | — | **deferred** |

`basic` exists for git-over-HTTPS (`x-access-token:<token>`). `sigv4` must re-sign rather
than swap a header because the signature covers headers and body; gains a session-token
header and (optionally) region-from-host. `mtls` is deferred (k8s uses bearer/exec tokens
in v1).

---

## Generic protocols (engine-side, no service names)

The engine maps a request to an `Action` via a fixed set of generic normalizers, selected
per service by a `protocol` field. Adding a service never adds engine code beyond, at most,
a new generic protocol.

| Protocol | Verb derived from | Resource | Status |
|---|---|---|---|
| `rest` | HTTP method | canonical path | today |
| `query` (AWS) | `Action=` parameter | — | today |
| `json` (AWS) | `X-Amz-Target` header | — | today |
| `git-http` | `?service=` / path suffix → literal `git-upload-pack` / `git-receive-pack` | `{owner}/{repo}` | **new** |

`git-http` recognizes the four Smart-HTTP shapes (`…/{repo}.git/info/refs?service=…` and
`…/{repo}.git/{git-upload-pack,git-receive-pack}`) and emits a `Verb::Action` with the
literal protocol service name — no invented translation, consistent with the established
"verb = the literal thing the request states" rule. Branch-level enforcement (deny push to
`main`) requires parsing the packfile's ref updates and is deferred.

---

## Inbound auth (agent → hackamore)

The agent holds no real credential; it carries a handle that hackamore maps to the bound
policy.

| Transport | Inbound handle | Status |
|---|---|---|
| HTTPS (REST / git-http) | hackamore bearer launch token (`X-Hackamore-Token` / `Authorization: Bearer`) | today |
| HTTPS git-http | launch token in the **HTTP Basic password slot** | **new** (Basic inbound) |
| AWS (SigV4) | **dummy** AWS creds issued per launch; the signature *is* the auth (`authenticate_sigv4` recomputes it, dummy AKID → policy) | today |

---

## CLI presets

```bash
hackamore services add github-api  --auth-source gh-token
hackamore services add github-git  --auth-source gh-token             # same token, Basic-injected
hackamore services add aws:ec2     --auth-source assume-role --role-arn arn:aws:iam::123:role/agent
hackamore services add aws:s3      --auth-source assume-role --role-arn arn:aws:iam::123:role/agent
hackamore services add k8s --cluster https://my-cluster:6443 --kubeconfig ~/.kube/config
# generic, unchanged:
hackamore services add my-api --openapi <url|file> --upstream … --host … --inject bearer --auth-source env:MY_API_TOKEN
```

| Preset | Model source | Protocol | Default injection |
|---|---|---|---|
| `github-api` | **bundled** GitHub OpenAPI (gzip in binary) | `rest` | `bearer` |
| `github-git` | **hardcoded** `ApiModel` (2 ops) | `git-http` | `basic` (`x-access-token`) |
| `aws:<svc>` | **bundled** Smithy model for that service (gzip) | `query`/`json`/`rest` per model | `sigv4` (service+region) |
| `k8s` | **fetched live** from the cluster `…/openapi/v2` at registration | `rest` | `bearer` (kube/exec token) |
| generic | operator supplies (`--openapi`/`--smithy`, file/url) | inferred | operator picks |

Decisions:
- **`github-git`: hardcode the IR, not a fake OpenAPI.** Git's verb depends on the
  `?service=` query value under the same method+path, which OpenAPI selectors cannot
  express, so the request→Action mapping is the custom `git-http` normalizer regardless. The
  model only advertises vocabulary (2 ops + a `repo` resource) for lint/discovery/UI, so the
  preset constructs a tiny `ApiModel` in code. `git-http` is generic (works for GitLab/Gitea);
  the preset adds GitHub's host.
- **`aws` is a family**, one preset per service, each bundling that service's compressed
  Smithy model. Curated starter set: **`ec2, s3, sts, iam, lambda, dynamodb`**. Services not
  bundled fall back to generic `--smithy <file>`. `sigv4` is fixed by the preset; static-keys
  vs assume-role is purely the operator's `--auth-source` choice (this dissolves the AWS
  source fork into the source axis).
- **`k8s` fetches the model at registration**: the CLI reads the kubeconfig, GETs
  `…/openapi/v2` (authenticated, cluster CA), and registers with the model **inline**, so the
  gateway never needs cluster creds just to read a spec. **Bearer-token / exec-plugin auth
  only in v1**; mTLS client-cert (a transport-level injection) deferred.
- **Bundling:** ship bundled specs gzip-compressed via `include_bytes!`, inflate on use —
  self-contained (no network for bundled presets), binary stays reasonable. k8s adds nothing
  to the binary.

A preset expands CLI-side to the generic admin call, e.g. `github-api`:

```jsonc
POST /admin/services
{ "name": "github-api", "host": "api.github.com", "upstreamBase": "https://api.github.com",
  "protocol": "rest", "idl": "openapi", "specInline": "<bundled GitHub OpenAPI bytes>",
  "outbound": { "kind": "bearer", "credential": "gh-login" } }
```

The server imports `specInline` with the existing `OpenApiImporter`/`SmithyImporter`
(import stays server-side). For `github-git` the CLI sends a prebuilt `ApiModel` inline
(`modelInline`) instead of a spec to import.

---

## Sandbox bootstrap (`hackamore launch` + `hackamore-agent`)

`hackamore launch --policy <p> --image <img> -- <cmd>` mints the inbound handles and stamps
the sandbox so `git`, `gh`, `aws`, and `kubectl` route through hackamore transparently. The
`hackamore-agent` crate is currently empty — this is mostly new.

`launch` does: (1) mint a bearer launch token bound to the policy; (2) issue dummy AWS creds
bound to the policy; (3) confine egress so only hackamore's proxy port is reachable
(fail-closed; env vars are convenience, the netns is enforcement); (4) install hackamore's
CA; (5) write tool config.

Sandbox config written by `hackamore-agent`:

```sh
# egress + trust
HTTPS_PROXY=http://<hackamore>:<port>   HTTP_PROXY=…   NO_PROXY=localhost,127.0.0.1
SSL_CERT_FILE / GIT_SSL_CAINFO / NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / AWS_CA_BUNDLE = /etc/hackamore/ca.pem
# gh
GH_TOKEN=<launch-token>                 ~/.config/gh/hosts.yml: { github.com: { oauth_token: <launch-token> } }
# git (option B: HTTPS + Basic)
git config --global url."https://github.com/".insteadOf "git@github.com:"   # keep git on HTTPS
git credential helper → emits password=<launch-token>, username=x-access-token
# aws (dummy creds; signature is the inbound auth)
AWS_ACCESS_KEY_ID=<dummy>  AWS_SECRET_ACCESS_KEY=<dummy>  AWS_REGION=…
# k8s
kubeconfig server → hackamore; token = launch token
```

---

## Worked flows (end to end)

**`gh api` create PR.** `POST api.github.com/repos/{o}/{r}/pulls` `Authorization: token
<launch>` → proxy → MITM → authenticate(launch)→policy → normalize (GitHub OpenAPI:
`pulls/create`, fields `{title,head,base}`) → decide (field-level, e.g. deny `base==main`) →
inject `Bearer <real gh token>` → forward → audit.

**`git push` (option B).** `git` over HTTPS, `Authorization: Basic
base64(x-access-token:<launch>)` → MITM → authenticate(Basic password = launch)→policy →
`git-http` normalize (`git-receive-pack 'o/r'` → verb `git-receive-pack`, resource `o/r`) →
decide (allow push only to specific repos) → inject `Basic base64(x-access-token:<real
token>)` → forward → audit.

**`aws ec2 run-instances`.** `aws` signs with dummy creds → MITM → `authenticate_sigv4`
(dummy AKID → recompute → policy) → Smithy normalize (`query`: `Action=RunInstances`) →
decide → inject `sigv4` (resolve `aws-prod` bundle, **re-sign** with real AKID/SAK, set
`Authorization` + `X-Amz-Date` + `X-Amz-Security-Token`) → forward → audit.

**`kubectl get pods`.** `GET <cluster>/api/v1/namespaces/default/pods` `Authorization:
Bearer <launch>` → MITM → authenticate(launch)→policy → `rest` normalize against the fetched
k8s OpenAPI → decide → inject `bearer <real kube/exec token>` → forward → audit.

---

## Exists vs. new

**Exists:** HTTPS gateway; launch-token + dummy-SigV4 inbound auth; `bearer`/`header`/`sigv4`
injection; `sigv4::sign`; OpenAPI + Smithy importers; live `/admin/services` registration;
`Verb::Action` model; vault; minting scaffolding (`CredentialProvider`, `CachingCredentials`,
`GitHubAppProvider`, `EksGetTokenProvider`).

**New:**
1. **Auth model restructure** — split injection (service) from source (credential);
   `credential`-by-reference; `hackamore credentials add`.
2. **AWS credential bundle** — widen the source/resolve boundary beyond `Secret`;
   `AssumeRoleProvider`; `instance` chain; `X-Amz-Security-Token` injection.
3. **`basic` injection** + **Basic inbound** scheme.
4. **`git-http` protocol** normalizer + hardcoded git `ApiModel`.
5. **CLI preset system** — `github-api`, `github-git`, `aws:<svc>` (curated bundle), `k8s`
   (live fetch), generic; gzip-bundled specs; `specInline`/`modelInline` on the admin API.
6. **Sandbox bootstrap** — `hackamore launch` + the `hackamore-agent` crate (env, CA, gh/git/aws/k8s config, dummy AWS creds).
7. Sources: `gh-token`, `file`, `env`, `kubeconfig` (token/exec); wire `github-app` into runtime registration.

## Deferred / out of scope

- SSH-key git via an SSH broker (option A) — option B (HTTPS + gh token) chosen instead.
- mTLS client-cert injection (k8s and elsewhere).
- Branch-level git policy (packfile ref-update parsing).
- Region-from-host for one-service-many-regions (start with pinned region).
- Evicting a service's vaulted/derived secret on `DELETE` (current behavior leaves it).

## Implementation phasing (independent plans)

This design spans several subsystems; build in dependency order, each independently testable:

- **P1 — Auth model split.** Source × Injection types; `credential`-by-reference;
  `credentials add`; `basic` injection. Unblocks everything. (No new protocols.)
- **P2 — git-http.** The normalizer + git `ApiModel`; Basic inbound scheme. Depends on P1.
- **P3 — AWS bundle.** Widen resolve to the bundle; `AssumeRoleProvider` / `instance`;
  `X-Amz-Security-Token`. Depends on P1.
- **P4 — CLI presets.** `github-api`/`github-git`/`aws:<svc>`/`k8s`/generic; gzip bundling;
  `specInline`/`modelInline`. Depends on P1–P3 for the injections/protocols they select.
- **P5 — Sandbox bootstrap.** `hackamore launch` + `hackamore-agent`. Depends on the
  services existing; ties the user story together end to end.

Each phase gets its own implementation plan (`writing-plans`).
