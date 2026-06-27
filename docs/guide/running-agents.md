# Running agents

This guide walks the full lifecycle: from a policy you author to a live agent whose
every request is enforced by hackamore. It picks up where
[Getting started](getting-started.md) leaves off — you already have a `hackamore serve`
running with at least one service registered — and shows how to put an agent in front of
it.

Running an agent is four steps:

1. **Author a policy** — the rules that decide what the agent may do.
2. **Mint a launch token** bound to that policy.
3. **Provision the sandbox** — the agent configures its stock tools to reach hackamore.
4. **Run** — the agent's tools route through hackamore; the real upstream credential is
   injected by the proxy and never seen by the agent.

You also need to **confine** the sandbox so the proxy is the agent's only egress. That is
the sandbox runtime's job, not hackamore's — see [Confinement](#confinement-is-the-sandbox-runtimes-job)
below.

Throughout, the admin API is at `http://127.0.0.1:9091` and the agent-facing proxy is at
`127.0.0.1:9090`.

## 1. Author a policy

A policy is a JSON document: an ordered list of rules, evaluated top-to-bottom,
first-match-wins, default-deny. Each rule grants (`Allow`) or denies (`Deny`) the actions
its `matches` block selects. See [Policies](policies.md) for the full authoring guide; for
this walkthrough, here is a policy that lets an agent read and open pull requests against
one repo, and nothing else:

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [{ "type": "Method", "value": { "method": "GET" } }],
        "resources": ["repos/acme/widgets/**"]
      }
    },
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [{ "type": "Method", "value": { "method": "POST" } }],
        "resources": ["repos/acme/widgets/pulls"],
        "conditions": [
          { "type": "Equals", "value": { "field": "base", "value": "main" } }
        ]
      }
    }
  ]
}
```

Save this as `policy.json`. Before minting, check it offline:

```bash
hackamore policy lint policy.json
```

`lint` reports structural problems — rules that can never match, or that are shadowed by
an earlier rule. To see exactly how one request would be decided, dry-run it:

```bash
hackamore policy test policy.json \
  --target github-api \
  --request "POST /repos/acme/widgets/pulls" \
  --field base=main
```

The output shows the normalized action, which rule matched, and the verdict. Use
`--field key=value` (repeatable) to set body fields a condition inspects; values parse as
JSON where possible, so `--field draft=true` is the boolean `true`. Neither command needs
a running server — they validate against the policy alone.

## 2. Mint a launch token

A launch token is a short-lived secret, bound to your policy, that the agent presents to
hackamore. Mint one against a running server:

```bash
hackamore mint --admin-url http://127.0.0.1:9091 --policy policy.json --ttl 3600
```

This prints the token and its expiry:

```json
{
  "token": "hk_…",
  "expires_at_ms": 1750000000000
}
```

`--ttl` is the token's lifetime in seconds (default `3600` — one hour). Keep tokens short:
a token is the agent's entire authority, and the only way to cut it off early is to
[revoke](#revocation-and-ttl) it. The token is honored **only** by the hackamore proxy and
is useless against the real upstream.

> The admin API is operator surface. Bind it to localhost (the default
> `127.0.0.1:9091`) and never expose it to the sandbox — it also serves the unauthenticated
> mint endpoint. The sandbox reaches hackamore only through the proxy listener.

## 3. Provision the sandbox

Inside the sandbox, the agent runs the **`hackamore-agent`** binary. It fetches a
**provision doc** from the proxy and writes native tool config so the agent's stock tools
(`gh`, `git`, `kubectl`, `aws`, SDKs) transparently route through hackamore.

```bash
hackamore-agent setup \
  --hackamore-url http://127.0.0.1:9090 \
  --token "hk_…" \
  --home /home/agent
```

`setup` writes config under `--home` (defaults to `$HOME`) and prints each file it wrote.
Related subcommands:

- `hackamore-agent show` — fetch and pretty-print the raw provision doc.
- `hackamore-agent status` — a human-readable summary of what the token can reach.
- `hackamore-agent env` — print shell `export` lines, for `eval "$(hackamore-agent env …)"`.
- `hackamore-agent teardown --home /home/agent` — remove exactly the files `setup` wrote.

`show`, `status`, and `env` take the same `--hackamore-url` / `--token` flags as `setup`;
`teardown` takes only `--home`.

### The provision doc

The provision doc is the bundle the sandbox can self-serve from the one path it can reach —
`GET /.hackamore/provision` on the proxy listener, authenticated by the launch token in the
`X-Hackamore-Token` header (or `Authorization`). It carries:

- the **launch token** the agent already holds (echoed back for convenience);
- the **CA bundle** — present only when hackamore terminates TLS, so the agent's tools can
  trust the proxy's certificate;
- the token's **expiry** (`expires_at_ms`);
- one entry **per service** the token's policy can reach, each with its consumer-facing
  **address**, its **mode** (`inject` — hackamore supplies the credential — or
  `passthrough` — bring your own), and a **tool hint**.

It contains **no real upstream secrets**. The only credential material in the doc is the
launch token itself (which the agent already has) and, for AWS services, a *dummy* SigV4
credential (see [The AWS dummy credential](#the-aws-dummy-credential)). The real GitHub
token, AWS account key, or kube token never appears.

### What `hackamore-agent setup` writes

The doc lists a **tool hint** per service. The agent writes the native config that hint
implies, keyed entirely off the hint:

| Tool hint    | What gets written                                                                 |
| ------------ | --------------------------------------------------------------------------------- |
| `github`     | `~/.config/gh/hosts.yml` — the launch token as `gh`'s oauth token for the host    |
| `git`        | `~/.git-credentials` (`https://x-access-token:<token>@<host>`) + `~/.gitconfig`    |
| `kubernetes` | `~/.kube/config` — a kubeconfig with the launch token as a static bearer token    |
| `aws`        | `~/.aws/credentials` + `~/.aws/config` — the dummy SigV4 credential + the endpoint |
| `generic`    | nothing beyond the shared env file                                                |

Every run also writes `hackamore.env` (the token and, when present, CA-bundle exports). An
AWS profile is written whenever a service's auth is SigV4, even if its hint is missing, so
SigV4 services stay robust. When hackamore terminates TLS, the CA bundle is written once
under `<home>/.hackamore/hackamore-ca.pem` and referenced by path from every tool's config.

Each file written is recorded in a **manifest** (`<home>/.hackamore/manifest`). Line-based
files (git credentials) are merged idempotently, never clobbered — provisioning a second
service does not drop the first. `hackamore-agent teardown` reads the manifest and removes
exactly those files and nothing else; it is idempotent and touches nothing outside the
manifest.

## 4. Run

With the sandbox provisioned, the agent just uses its tools normally. `gh pr create`,
`git push`, `kubectl get pods`, `aws s3 ls` — each is configured to address hackamore, and
each carries the launch token (in a header, a Basic password slot, or — for AWS — a dummy
SigV4 signature). hackamore authenticates the token, checks the request against the bound
policy, and on allow **strips the token, injects the real upstream credential, and
forwards**. The agent never observes the injected secret and cannot exceed its policy.

### The AWS dummy credential

AWS tools sign every request with SigV4, so there is no header slot to carry the launch
token. hackamore solves this by handing the agent a **dummy** AWS credential in the
provision doc. The agent's `aws` CLI / SDK signs requests with that dummy key; hackamore
verifies the dummy signature (that is how it authenticates the token), then **re-signs the
outbound request with the real account credential** from the vault. The dummy credential is
useless against real AWS — it only ever proves identity to hackamore. The real access key
and secret never reach the sandbox.

## Confinement is the sandbox runtime's job

hackamore's guarantees hold **only if the proxy is the agent's sole network egress.** If
the agent can open a socket straight to `api.github.com`, it bypasses hackamore entirely
and none of the policy enforcement applies.

Forcing that confinement is **out of scope for hackamore** — it is the **sandbox
runtime's** responsibility. Run the agent in a sandbox whose network capabilities redirect
or block all egress except the hackamore proxy address. hackamore itself only forwards to
its configured service allowlist; it cannot stop an agent that never went through it. See
[Introduction](introduction.md) for the trust and threat model.

## Revocation and TTL

Every token expires at its TTL — that is the baseline bound on the agent's authority. To
cut a token off **before** its TTL, revoke it on the admin API:

```bash
curl -X POST http://127.0.0.1:9091/revoke \
  -H 'content-type: application/json' \
  -d '{"token":"hk_…"}'
```

The response is `{"revoked":true}` if a live token was removed, or `{"revoked":false}` if
it was already unknown, expired, or revoked. Presenting the token is sufficient to revoke
it — there is no separate operator credential. After revocation (or expiry) every request
the agent makes is rejected, and re-provisioning fails.

---

## A worked example: launch a GitHub agent

This sequence assumes a `hackamore serve` is already running with a `github-api` service
registered (see [Getting started](getting-started.md) and
[GitHub](services/github.md)). It takes you from policy to a live, enforced agent.

**1. Author and check the policy.** Save the read-and-open-PRs policy from
[step 1](#1-author-a-policy) as `policy.json`, then:

```bash
hackamore policy lint policy.json
hackamore policy test policy.json \
  --target github-api \
  --request "GET /repos/acme/widgets/contents/README.md"
```

The dry-run should report the first rule matched and an **Allow** verdict.

**2. Mint a launch token.**

```bash
hackamore mint \
  --admin-url http://127.0.0.1:9091 \
  --policy policy.json \
  --ttl 1800
```

Copy the `token` from the output.

**3. Provision the sandbox.** Inside the sandbox (with egress confined to the proxy):

```bash
hackamore-agent setup \
  --hackamore-url http://127.0.0.1:9090 \
  --token "hk_…" \
  --home "$HOME"
```

This writes `~/.config/gh/hosts.yml` for the `github-api` service's `github` tool hint.

**4. Run the agent's tools.** `gh` now authenticates through hackamore:

```bash
gh api repos/acme/widgets/contents/README.md   # allowed → 200
gh api repos/other/secret                       # denied  → 403
```

The first call matches the read rule and is forwarded with the real GitHub credential
injected by hackamore; the second matches no allow rule and is rejected default-deny. The
agent only ever held the launch token.

**5. Tear down (optional).** When the session ends:

```bash
hackamore-agent teardown --home "$HOME"
```

and revoke the token if it has not expired:

```bash
curl -X POST http://127.0.0.1:9091/revoke \
  -H 'content-type: application/json' -d '{"token":"hk_…"}'
```

---

See also: [Core concepts](concepts.md) · [Credentials](credentials.md) ·
[Services overview](services/overview.md) · [Reference](reference.md)
