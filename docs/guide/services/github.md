# GitHub

hackamore reaches GitHub two ways, each a separate service:

- **`github-api`** — the GitHub REST API (`api.github.com`): issues, pull requests, repo
  contents, anything the REST API exposes.
- **`github-git`** — git over HTTPS (`github.com`): `git clone`, `git fetch`, `git push`.

They are registered independently because they use different hosts, different wire protocols,
and different injection mechanisms — but they can share one credential.

All commands assume the admin API at `http://127.0.0.1:9091`.

## Register the REST API

```bash
hackamore services add --admin-url http://127.0.0.1:9091 github-api \
  --auth-source gh-token
```

`--auth-source gh-token` runs `gh auth token` on the hackamore host, vaults the result under
the id `github-api`, and points the service at it. The `github-api` preset pins:

- host `api.github.com`, upstream `https://api.github.com`
- the bundled GitHub OpenAPI description as the service's model
- injection **bearer**: hackamore sends `Authorization: Bearer <token>` upstream
- the `github` tool hint, so a provisioned agent configures the `gh` CLI

## Register git-over-HTTPS

```bash
hackamore services add --admin-url http://127.0.0.1:9091 github-git \
  --auth-source gh-token
```

The `github-git` preset pins:

- host `github.com`, upstream `https://github.com`
- the git Smart-HTTP protocol (no imported description — hackamore attaches a built-in git
  model)
- injection **basic** with username `x-access-token`: hackamore sends
  `Authorization: Basic base64(x-access-token:<token>)`, which is how GitHub expects a token
  on a git HTTPS request
- the `git` tool hint, so the agent configures `git`'s credential store

## Sharing one credential

Running `--auth-source gh-token` twice registers the token twice (once per service name). To
vault the token once and have both services reference it, register the credential first, then
reference it by id:

```bash
# Register the token once, under an id you choose.
hackamore credentials add --admin-url http://127.0.0.1:9091 gh-login \
  --command "gh auth token"

# Both services reference the same credential id.
hackamore services add --admin-url http://127.0.0.1:9091 github-api --credential gh-login
hackamore services add --admin-url http://127.0.0.1:9091 github-git --credential gh-login
```

The `--command "gh auth token"` source re-runs `gh auth token` on the hackamore host whenever
the credential is resolved, so a rotated token is picked up. See
[Credentials](../credentials.md) for the full set of credential sources.

## How each is injected

| Service | Injection | On the wire |
| --- | --- | --- |
| `github-api` | bearer | `Authorization: Bearer <token>` |
| `github-git` | basic | `Authorization: Basic base64(x-access-token:<token>)` |

In both cases the agent authenticates to hackamore with its launch token; hackamore swaps in
the real GitHub token only after the policy allows the request.

## The git verb model

A REST request's verb is its HTTP method. A git request is different: every clone, fetch, and
push is an HTTP request to the same path, distinguished only by the git smart-HTTP service.
hackamore normalizes git requests into two named verbs:

| Verb | Operation |
| --- | --- |
| `git-upload-pack` | fetch / clone (read) |
| `git-receive-pack` | push (write) |

The resource is the repository as `{owner}/{repo}` — for example `octocat/hello-world`. Your
policy rules name these git verbs and repository resources, not HTTP methods.

## Example policies

Policies are evaluated top to bottom, first match wins, default deny. Each rule's `matches`
names the verbs, resource globs, and field conditions an action must satisfy. See
[Policies](../policies.md) for the full rule language.

### Read pull requests (REST)

A GET to any pull-requests path under the `octocat` org:

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [ { "type": "Method", "value": { "method": "GET" } } ],
        "resources": ["repos/octocat/*/pulls", "repos/octocat/*/pulls/**"],
        "conditions": []
      }
    }
  ]
}
```

### Create a pull request only against `main` (REST)

A condition pins the request body's `base` field, so the agent may open PRs that target
`main` and nothing else:

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [ { "type": "Method", "value": { "method": "POST" } } ],
        "resources": ["repos/octocat/hello-world/pulls"],
        "conditions": [
          { "type": "Equals", "value": { "field": "base", "value": "main" } }
        ]
      }
    }
  ]
}
```

### Push to one repository (git)

Allow `git push` only to `octocat/hello-world`:

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-git"],
        "verbs": [ { "type": "Action", "value": { "id": "git-receive-pack" } } ],
        "resources": ["octocat/hello-world"],
        "conditions": []
      }
    }
  ]
}
```

### Fetch any repository (git)

Allow read-only git access (`git clone` / `git fetch`) to any repository, while leaving push
denied by default:

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-git"],
        "verbs": [ { "type": "Action", "value": { "id": "git-upload-pack" } } ],
        "resources": [],
        "conditions": []
      }
    }
  ]
}
```

An empty `resources` list means "any resource", so this rule covers every repository; because
no rule allows `git-receive-pack`, push is denied.

## Limitation: repository granularity for git

Git policy is enforced at **repository + push/fetch** granularity. A rule can allow or deny a
fetch or a push to a given `{owner}/{repo}`, but it cannot inspect refs, branches, or the
contents of the packfile. There is no branch-level or per-object control for git operations.
(For the REST API you can constrain finer with field conditions, as the "base = main" example
above shows.)

See [Services overview](./overview.md) for listing and removing services, and the sibling
pages: [AWS](./aws.md), [Kubernetes](./kubernetes.md), [Generic](./generic.md).
