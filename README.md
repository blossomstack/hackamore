# hackamore

**JIT, policy-scoped access for untrusted AI agents.**

An agent runs in a sandbox whose only network egress is the hackamore proxy. It is given a
short-lived **hackamore token** — never a real credential. When it calls a configured
service — GitHub, AWS, Kubernetes, any HTTPS API (via `gh`, `git`, an SDK, or raw HTTP) —
hackamore routes by Host, normalizes the request, evaluates the agent's standing policy,
and — only if allowed — swaps the hackamore token for the **real** upstream credential and
forwards it. The agent never sees a secret, can't exceed its policy, and every decision
is audited.

**Any HTTPS service, any HTTP transport.** Upstreams are a configured allowlist routed
by `Host` (unknown host → denied, fail closed). Responses are **streamed**, so plain
request/response, Server-Sent Events, and long-polls all flow through transparently.

This is the companion to [horsie](../horsie): horsie sandboxes the agent runtime (via
[nono](https://github.com/always-further/nono): Landlock/Seatbelt) and points its egress
at hackamore; hackamore decides what that egress is allowed to do.

## Documentation

📖 **[Operator guide →](docs/guide/README.md)** — start here. Introduction, core concepts,
a hands-on [getting-started walkthrough](docs/guide/getting-started.md), per-service
how-tos ([GitHub](docs/guide/services/github.md) · [AWS](docs/guide/services/aws.md) ·
[Kubernetes](docs/guide/services/kubernetes.md) · [generic OpenAPI/Smithy](docs/guide/services/generic.md)),
[credentials](docs/guide/credentials.md), [writing policies](docs/guide/policies.md),
[running an agent](docs/guide/running-agents.md), and a full [reference](docs/guide/reference.md).

## Why a reverse proxy + sandbox, not MITM

The agent is **untrusted** (it may be prompt-injected or go rogue). Two invariants hold:

1. The agent never holds a real upstream credential.
2. The sandbox guarantees hackamore is the *only* reachable destination, so the agent
   cannot bypass policy — whether it uses `gh`, `git`, or `curl`.

Because confinement is the sandbox's job (nono/Seatbelt/Landlock + a netns/nftables
redirect on Linux), hackamore can be a plain **reverse proxy** and skip TLS interception
and CA distribution entirely.

## Architecture

Three planes, with the policy engine deliberately decoupled from the data plane so it
can be reused by any proxy (an Envoy `ext_authz` adapter, a hudsucker MITM, …) later.

```
 sandboxed agent ──(only egress)──▶ hackamore reverse proxy ──▶ any configured HTTPS service
   gh / git / sdk / curl            │  route by Host → service        (GitHub, AWS, …)
   <hackamore token>                │  normalize → Action
                                    │  hackamore_policy::decide(Action) → Verdict
                                    │  inject real credential, strip hackamore token
                                    │  stream response (HTTP / SSE)
                                    ▼
                          audit every decision
```

| Crate | Role |
|-------|------|
| `hackamore-models` | fluorite-generated contract types: `Action`, `Verdict`, `Policy`, the API model, audit + mint wire types |
| `hackamore-policy` | the **reusable engine** — pure `decide(&Action, &Policy) -> Verdict`, no I/O |
| `hackamore-control` | control plane: token minting, the credential vault (static + minting providers), audit sink |
| `hackamore-gateway` | data plane: Host router + live service registry, request→`Action` normalizer (REST, AWS query/json, git), decision/enforcement core, streaming reverse proxy |
| `hackamore` | the `hackamore` binary: `serve`, `mint`, manage `services`/`credentials`, `policy` lint/test |
| `hackamore-agent` | consumer side: fetch the provision doc and configure stock tools (`gh`, `git`, kubeconfig, AWS) in the sandbox |
| `hackamore-tests` | full-stack e2e tests (mock upstream + live server) |

The `Action`/`Verdict` contract is the portability boundary: the engine never sees HTTP,
only a normalized `Action`, so a future Envoy or other adapter reuses it unchanged.

## How a service is described

A service points at its own **API description** — an OpenAPI document or an AWS
Smithy/botocore model — which hackamore imports into one internal model that gives the
service its policy vocabulary (operations, resource paths, and the fields conditions can
reference). You can register a service three ways:

- **A preset** (`github-api`, `github-git`, `aws:<svc>`, `k8s`) that bundles or fetches the
  description for you — see [Registering services](docs/guide/services/overview.md).
- **A generic registration** pointing at your own OpenAPI/Smithy file or URL.
- **The config file**, imported at startup.

Auth is two independent choices: a **source** (where the real credential comes from) and an
**injection** (how it goes on the wire) — see [Credentials](docs/guide/credentials.md).

## Policy model

A **token is minted from a policy document**. Rules are evaluated **first-match-wins**,
**default-deny**. `verb` is a tagged union — the HTTP **method** for REST services, a named
**action** (`{"type":"Action","value":{"id":"…"}}`) for RPC/AWS/git:

```json
{ "effect": "Allow",
  "matches": {
    "verbs": [ { "type": "Method", "value": { "method": "POST" } } ],
    "resources": ["repos/octocat/*/pulls"],
    "conditions": [ { "type": "Equals", "value": { "field": "base", "value": "develop" } } ]
  } }
```

That rule means: *may open pull requests in any `octocat` repo, but only against the
`develop` base branch* — finer-grained than GitHub's native permissions. **Credentials are
not named in the policy**: each service instance owns its credential and outbound stance.

`hackamore policy lint` validates a document against the imported model (rules that can
never match or never fire are errors, and the mint API rejects them too); `hackamore policy
test` dry-runs one request through the real normalize + decide path and reports which rule
matched. For interactive authoring, the **policy studio** web UI (served at `/ui` on the
admin listener) pairs model exploration with a composer: add a rule, edit
verbs/resources/conditions, watch lint run live, dry-run a request, and mint. See
[Writing policies](docs/guide/policies.md).

## Quickstart

```bash
make build
# validate a policy and dry-run a request — offline, no server
cargo run -p cli --bin hackamore -- policy lint examples/policy.reviewer-bot.json
cargo run -p cli --bin hackamore -- policy test examples/policy.reviewer-bot.json \
  --target github --request "POST /repos/octocat/hello/pulls" --field base=develop

# edit examples/config.json (set real credentials and your agents' policies), then serve
make run                      # proxy on :9090, admin API on :9091
# open the policy studio:  http://127.0.0.1:9091/ui   (set "web_ui": false to disable)

# register a service at runtime — a preset bundles the API description for you
cargo run -p cli --bin hackamore -- services add --admin-url http://127.0.0.1:9091 \
  github-api --auth-source gh-token

# mint a launch token from a policy document (the orchestrator does this at launch)
cargo run -p cli --bin hackamore -- mint --admin-url http://127.0.0.1:9091 \
  --policy examples/policy.reviewer-bot.json --ttl 3600
```

In the sandbox, the agent self-configures from the proxy with
`hackamore-agent setup --hackamore-url http://127.0.0.1:9090 --token <minted-token>`, which
points `gh`/`git`/etc. at hackamore using the token — never a real secret. See
[Running an agent](docs/guide/running-agents.md).

## Development

```bash
make check     # cargo fmt --check + clippy -D warnings + test  (the CI gate)
```

Production code denies `unwrap`/`expect`/`panic`/wildcard match arms; see `CLAUDE.md`
for the full design philosophy and fluorite conventions.

## License

MIT.
