# Getting started

This tutorial walks you, the operator, through giving an untrusted AI agent
**just-in-time, policy-scoped GitHub access**. By the end you'll have a running hackamore
server, a policy that lets an agent read repositories and open one kind of pull request
while pushing to a single repo, and a short-lived launch token you can hand to a sandboxed
agent — which never sees your real GitHub token.

If you want the bigger picture first, read the [introduction](./introduction.md) and the
[core concepts](./concepts.md). Otherwise, follow along: every command below is
copy-pasteable.

## What you'll build

A single hackamore server that proxies the agent's GitHub traffic, with a policy that
allows read-only REST calls, opening pull requests, and pushing to one repository — and
denies everything else by default. The agent authenticates to hackamore with a launch
token; hackamore swaps that token for your real GitHub credential only when the policy
allows the request.

Throughout, the **admin API** (operator-only) lives at `http://127.0.0.1:9091` and the
**proxy** the agent talks to lives at `127.0.0.1:9090`.

## Prerequisites

- The `hackamore` binary on your `PATH` (`hackamore --help` should print usage).
- A GitHub credential on this host. The simplest source is the GitHub CLI: run
  `gh auth login` once, then confirm a token is available:

  ```bash
  gh auth token
  ```

  ```
  gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ```

  You'll register this command as hackamore's credential **source** in a moment, so the
  real token is read on demand and vaulted — never pasted into a file.

## 1. Start the server

Create a minimal `config.json`. You can start with an empty service list and an empty
credential vault; you'll fill both in at runtime through the admin API.

```json
{
  "proxy_addr": "127.0.0.1:9090",
  "admin_addr": "127.0.0.1:9091",
  "services": [],
  "web_ui": true
}
```

Start the server:

```bash
hackamore serve --config config.json
```

```
INFO loaded config credentials=0 services=0
INFO policy studio web UI enabled url=http://127.0.0.1:9091/ui
INFO hackamore listening proxy_addr=127.0.0.1:9090 admin_addr=127.0.0.1:9091 proxy_scheme=http
```

Two listeners are now up:

- **`127.0.0.1:9090`** — the agent-facing proxy. The only thing it exposes to the agent
  besides forwarded traffic is `GET /.hackamore/provision`.
- **`127.0.0.1:9091`** — the operator admin API (minting, services, credentials) and the
  policy studio web UI at `http://127.0.0.1:9091/ui`.

> **Keep the admin API away from the agent.** The admin listener can mint tokens and read
> your registry, so it must never be reachable from the sandbox. Only the proxy listener
> should be exposed to the agent. Leave the server running and open a second terminal for
> the rest of this guide.

## 2. Register a shared GitHub credential

Register your GitHub token under the id `gh-login`, sourced from the `gh auth token`
command. hackamore runs the command on this host, vaults the result, and returns only the
id — the secret is never echoed.

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 gh-login --command "gh auth token"
```

```json
{
  "id": "gh-login"
}
```

The available credential sources are `--secret` (a pasted value), `--env VAR`,
`--file path`, `--command "..."`, and `--source aws-static|assume-role|instance` for AWS.
See [credentials](./credentials.md) for the full set.

You can list the ids hackamore knows — but never the secrets behind them:

```bash
curl -s http://127.0.0.1:9091/admin/credentials
```

```json
{"ids":["gh-login"]}
```

## 3. Register the two GitHub services

GitHub speaks over two hosts: the REST API at `api.github.com` and git-over-HTTPS at
`github.com`. hackamore ships a **preset** for each, so you supply only the credential and
the preset pins everything else.

Register the REST API service. The `github-api` preset pins host `api.github.com`, the
REST protocol, and **bearer** credential injection, and tells a sandboxed agent to
configure `gh`:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 github-api --credential gh-login
```

```json
{
  "name": "github-api"
}
```

Register the git service. The `github-git` preset pins host `github.com`, the git-HTTP
protocol, and **basic** injection (username `x-access-token`), and tells the agent to
configure `git`:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 github-git --credential gh-login
```

```json
{
  "name": "github-git"
}
```

Both services reference the **same** `gh-login` credential — hackamore injects it as a
bearer token for REST and as basic auth for git, exactly as each upstream expects. See
[the GitHub service guide](./services/github.md) for more on the presets.

## 4. Write a policy

A policy is an ordered list of rules, evaluated top-to-bottom, **first match wins**, with
**default-deny** for anything no rule allows. Each rule's `matches` block scopes by target
(service name), verb, resource glob, and optional field conditions; an empty list means
"any".

Save this as `policy.json`. Replace `youruser/yourrepo` with the repository you want the
agent to be able to push to.

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [ { "type": "Method", "value": { "method": "GET" } } ],
        "resources": ["repos/**"],
        "conditions": []
      }
    },
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [ { "type": "Method", "value": { "method": "POST" } } ],
        "resources": ["repos/*/*/pulls"],
        "conditions": [
          { "type": "Equals", "value": { "field": "base", "value": "main" } }
        ]
      }
    },
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-git"],
        "verbs": [ { "type": "Action", "value": { "id": "git-receive-pack" } } ],
        "resources": ["youruser/yourrepo"],
        "conditions": []
      }
    }
  ]
}
```

What each rule allows:

1. **Read-only REST.** Any `GET` against the REST API under `repos/` — so the agent can
   list, read, and inspect repositories. The `**` glob matches the whole remainder of the
   path.
2. **Open a pull request, but only into `main`.** A `POST` to `repos/<owner>/<repo>/pulls`
   (`*` matches one path segment), but only when the request body's `base` field equals
   `main`. A PR targeting any other base branch falls through to default-deny.
3. **Push to exactly one repo.** The literal git action `git-receive-pack` (a push) against
   the resource `youruser/yourrepo`. Fetches (`git-upload-pack`) and pushes to any other
   repo are not listed, so they're denied.

Everything else — deleting repos, pushing elsewhere, writing to other services — is denied
because no rule matches. For more on rule shapes, globs, and conditions, see
[policies](./policies.md).

## 5. Dry-run the policy

Before minting anything, test the policy offline with `hackamore policy test`. It runs a
synthetic request through the same normalize-and-decide path the live proxy uses, then
prints the normalized **action** and the **verdict**. No server is needed.

A read it should **allow** (rule 0):

```bash
hackamore policy test policy.json --target github-api --request "GET /repos/octocat/hello-world"
```

```
action: {
  "target": "github-api",
  "verb": {
    "type": "Method",
    "value": {
      "method": "GET"
    }
  },
  "resource": {
    "path": "repos/octocat/hello-world"
  },
  "fields": {}
}
decision: Allow (rule 0)
```

A write it should **deny** — nothing in the policy permits `DELETE`, so it falls through to
default-deny:

```bash
hackamore policy test policy.json --target github-api --request "DELETE /repos/octocat/hello-world"
```

```
action: {
  "target": "github-api",
  "verb": {
    "type": "Method",
    "value": {
      "method": "DELETE"
    }
  },
  "resource": {
    "path": "repos/octocat/hello-world"
  },
  "fields": {}
}
decision: Deny NotAllowed (no rule matched)
```

Test the pull-request condition too. Use `--field` to set body fields (values parse as
JSON when possible). A PR into `main` is allowed (rule 1); the same call into `develop`
falls through to deny:

```bash
hackamore policy test policy.json --target github-api \
  --request "POST /repos/octocat/hello-world/pulls" --field base=main
```

```
...
decision: Allow (rule 1)
```

```bash
hackamore policy test policy.json --target github-api \
  --request "POST /repos/octocat/hello-world/pulls" --field base=develop
```

```
...
decision: Deny NotAllowed (no rule matched)
```

> **Testing the git push rule.** The git verbs (`git-receive-pack` for a push,
> `git-upload-pack` for a fetch) are derived from the *shape* of a real git-over-HTTPS
> request against the registered `github-git` service. The offline `policy test` command
> normalizes against a generic REST target, so it won't reproduce that verb on its own. To
> exercise the push rule against the actual git service, use the **policy studio** at
> `http://127.0.0.1:9091/ui` on your running server — it normalizes requests through your
> live service registry, so a git request resolves to the `git-receive-pack` action and you
> can see rule 2 fire.

## 6. Mint a launch token

When the policy looks right, mint a token bound to it. The token is honored only by the
hackamore proxy and is useless against GitHub directly. Here it lives for one hour.

```bash
hackamore mint --admin-url http://127.0.0.1:9091 --policy policy.json --ttl 3600
```

```json
{
  "token": "hkm_3f9c0a7b2e1d4856b0a1c2d3e4f5a6b7",
  "expires_at_ms": 1718268000000
}
```

That `token` is the launch token — the only secret the agent receives. The minting step
also lints the policy against your registered services' models, so a policy that can never
match is rejected here rather than silently failing later.

## 7. Hand it to the agent

In the sandbox — where the proxy at `127.0.0.1:9090` is the agent's only network egress —
the agent runs the `hackamore-agent` helper to self-configure. It fetches the provision
document from `GET /.hackamore/provision` using the launch token, then writes native
config for the tools each service hinted: a `gh` config for `github-api` and a `git`
config for `github-git`.

```bash
hackamore-agent setup --hackamore-url http://127.0.0.1:9090 --token "$HACKAMORE_TOKEN"
```

From then on the agent's ordinary commands flow through hackamore transparently:

```bash
gh api repos/octocat/hello-world      # allowed: read-only REST
git push origin main                  # allowed only for youruser/yourrepo
```

Each request is normalized, evaluated against your policy, and — only on allow — has your
real GitHub credential injected before it's forwarded. The agent never holds that
credential, and anything outside the policy is rejected with a 403.

> **Confinement is the sandbox's job.** hackamore enforces *what* the agent may do; making
> the proxy the agent's *only* reachable destination is the sandbox runtime's
> responsibility, not hackamore's. See [running agents](./running-agents.md) for how the
> pieces fit together.

## What you just built

- A hackamore server with an operator admin API and an agent-facing proxy.
- A vaulted GitHub credential (`gh-login`), sourced on demand and never exposed.
- Two GitHub services (REST + git) that reuse that one credential, injected the way each
  upstream expects.
- A policy that allows reading repos, opening PRs into `main`, and pushing to one repo —
  and denies everything else by default.
- A short-lived launch token an agent can use without ever seeing your real token.

## Next steps

- [The GitHub service](./services/github.md) — the `github-api` and `github-git` presets in
  depth, and what each one pins.
- [Policies](./policies.md) — rule ordering, resource globs, verbs, and field conditions.
- [Credentials](./credentials.md) — every credential source and how the vault keeps secrets
  out of reach.
- [Running agents](./running-agents.md) — provisioning, confinement, and operating the
  proxy in a real sandbox.
- [Reference](./reference.md) — the complete CLI, config, and admin API.
