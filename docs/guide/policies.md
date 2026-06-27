# Policies

A **policy** is the set of rules that decide what an agent may do. Every request the agent
makes is normalized into an action — a target, a verb, a resource, and a bag of fields — and
checked against the policy. The default is **deny**: if no rule allows the action, it is
refused. This page covers the policy language, how it is evaluated, how to verify a policy
before you ship it, and three complete examples.

All admin commands here assume the admin API at `http://127.0.0.1:9091`.

## Where a policy lives

A policy is a JSON document. You author it as a file, then bind it to a launch token when you
mint that token:

```bash
hackamore mint --admin-url http://127.0.0.1:9091 --policy ./reviewer.json --ttl 3600
```

The minted token carries the policy: the policy is attached to the agent's identity for the
life of the token, and every request the agent makes with that token is checked against it.
You don't choose a policy per task — the token *is* the capability. See
[Running agents](running-agents.md) for handing the token to a sandboxed agent.

Minting **lints** the policy first (see [Verify offline](#verify-a-policy-offline)); a policy
with lint errors is rejected with `403` and the findings, so a broken policy never reaches
production.

## The shape of a policy

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": [],
        "verbs": [],
        "resources": [],
        "conditions": []
      }
    }
  ]
}
```

A policy is an ordered list of `rules`. Each rule has:

- an **`effect`** — `"Allow"` or `"Deny"`, and
- a **`matches`** block describing which actions the rule applies to.

`matches` has four lists: `targets`, `verbs`, `resources`, and `conditions`. A rule applies
to an action only when **every** facet matches. An **empty list means "any"** — an all-empty
`matches` matches every action. The rule above (`Allow`, everything empty) allows everything.

## `matches` — the four facets

### `targets` — which services

`targets` is a list of service names the rule applies to. The service is whatever hackamore
routed the request to (`github-api`, `aws`, `github-git`, …). Empty matches any service.

```json
"targets": ["github-api"]
```

### `verbs` — which operations

`verbs` is a list of operations the rule applies to, matched by exact equality. Empty matches
any verb. A verb is a tagged union with two arms — see [The verb union](#the-verb-union) below.

### `resources` — which paths

`resources` is a list of path globs. The rule matches if **any** glob matches the action's
resource. Empty matches any resource. See [Resource globs](#resource-globs).

```json
"resources": ["repos/octocat/*/pulls"]
```

### `conditions` — field predicates

`conditions` is a list of predicates over the action's request fields. **All** conditions must
hold (logical AND). Empty means no field constraints. See [Conditions over fields](#conditions-over-fields).

## The verb union

The `verb` of an action is *literally* what the request states — never a derived category.
It's a tagged union with two arms, so REST methods and named RPC/AWS actions can't be
confused for each other.

### `Method` — a REST HTTP method

For a REST service, the verb is the HTTP method, verbatim:

```json
{ "type": "Method", "value": { "method": "GET" } }
```

```json
{ "type": "Method", "value": { "method": "POST" } }
```

### `Action` — a named operation

For an RPC-style service, the verb is the named operation. This covers AWS operations:

```json
{ "type": "Action", "value": { "id": "RunInstances" } }
```

…and git over HTTPS, whose two operations are named verbs — `git-upload-pack` (fetch/clone)
and `git-receive-pack` (push):

```json
{ "type": "Action", "value": { "id": "git-receive-pack" } }
```

Verb matching is exact equality, so a rule listing `GET` does not cover `HEAD`, and a rule
listing `git-upload-pack` does not cover `git-receive-pack`.

## Resource globs

A `resources` glob matches against the action's **resource path** — for a REST service the
normalized request path, for a git service the repository as `{owner}/{repo}`. The path has no
leading slash and no empty segments.

Glob syntax is segment-wise over the `/`-separated path:

- A literal segment matches itself.
- `*` matches exactly **one** path segment.
- A trailing `**` matches **any number** of remaining segments (including zero).

| Glob | Matches | Does not match |
| --- | --- | --- |
| `repos/octocat/hello/pulls` | exactly that path | `repos/octocat/hello/pulls/1` |
| `repos/octocat/*/pulls` | `repos/octocat/hello/pulls` | `repos/octocat/hello/issues`, `repos/a/b/c/pulls` |
| `repos/octocat/**` | `repos/octocat`, `repos/octocat/hello/pulls/1` | `repos/other/x` |
| `octocat/hello-world` (git) | the `octocat/hello-world` repo | any other repo |

A single `*` is one segment only — `repos/*/pulls` does **not** match `repos/a/b/pulls`. Use
`**` when you mean "and everything below".

## Conditions over fields

Conditions test the action's **fields** — a flattened view of the request's query string and
JSON body. This is how you constrain *what* an allowed request asks for, not just which
endpoint it hits. `field` is a dotted path into the fields object (e.g. `base`, `head.ref`).
There are three predicates:

- **`Equals`** — the field equals a JSON value.

  ```json
  { "type": "Equals", "value": { "field": "base", "value": "main" } }
  ```

- **`OneOf`** — the field is one of a list of JSON values.

  ```json
  { "type": "OneOf", "value": { "field": "base", "values": ["develop", "staging"] } }
  ```

- **`Exists`** — the field is present and non-null.

  ```json
  { "type": "Exists", "value": { "field": "title" } }
  ```

All conditions in a rule must hold for the rule to apply. For example, to **deny** opening a
pull request that targets `main`, write a `Deny` rule on the create-PR endpoint conditioned on
`base = main`, and place it before your allow rule:

```json
{
  "effect": "Deny",
  "matches": {
    "targets": ["github-api"],
    "verbs": [ { "type": "Method", "value": { "method": "POST" } } ],
    "resources": ["repos/octocat/*/pulls"],
    "conditions": [
      { "type": "Equals", "value": { "field": "base", "value": "main" } }
    ]
  }
}
```

Field names come from the service's imported API model. For GitHub's create-PR, `base`, `head`,
and `title` are real body fields; for an AWS operation, the parameter names of that operation.
The linter knows these names and warns when a condition references a field no matched operation
documents (a likely typo — see [Verify offline](#verify-a-policy-offline)).

## How a policy is evaluated

Three rules, and they are the whole model:

- **First match wins.** Rules are tried top to bottom; the first rule whose `matches` matches
  the action decides the outcome, and evaluation stops.
- **Default deny.** If no rule matches, the action is denied. There is no implicit allow and no
  bypass.
- **A `Deny` placed before an `Allow` wins.** Because the first match wins, a narrow `Deny`
  ahead of a broad `Allow` carves an exception out of it.

### A tiny ordering example

```json
{
  "rules": [
    {
      "effect": "Deny",
      "matches": {
        "targets": [], "resources": [],
        "verbs": [ { "type": "Method", "value": { "method": "DELETE" } } ],
        "conditions": []
      }
    },
    {
      "effect": "Allow",
      "matches": { "targets": [], "verbs": [], "resources": [], "conditions": [] }
    }
  ]
}
```

A `DELETE` matches rule 0 first and is denied. Every other method falls through to rule 1 and
is allowed. Swap the order and the deny becomes unreachable — which the linter flags as an
error (see below).

## Verify a policy offline

You can validate and dry-run a policy without a running server. (A *running* server lints
against its configured services' real API models too, catching path- and field-shape
mistakes; offline lint runs the structural checks.)

### `policy lint` — structural and model checks

```bash
hackamore policy lint ./reviewer.json
```

Lint reports two severities. **Errors** mean a rule can't do what its author meant — an
unmatchable resource glob, or a rule made unreachable by an earlier opposite-effect rule.
**Warnings** are model-derived advice (a glob that reaches no catalogued operation, a
condition field no matched operation documents). Lint **exits non-zero** if any error is
present — wire it into CI.

A clean policy:

```
ok: no findings
```

A policy with problems:

```
error rule 1: unreachable: rule 0 matches everything this rule does but with effect Allow — this rule never fires
error rule 2: resource glob '/repos/octocat/**' has a leading '/' — action paths never do, so it can never match
warning rule 2: redundant: rule 0 already matches everything this rule does
2 error(s), 1 warning(s)
```

Add `--json` for machine-readable findings (the same data the server returns when a mint is
rejected):

```bash
hackamore policy lint ./reviewer.json --json
```

```json
[
  {
    "severity": "Error",
    "ruleIndex": 1,
    "message": "unreachable: rule 0 matches everything this rule does but with effect Allow — this rule never fires"
  }
]
```

An empty `[]` means no findings.

### `policy test` — dry-run one request

`policy test` runs one synthetic request through the **real** normalize-and-decide path and
prints what the request normalized to, which rule matched, and the verdict:

```bash
hackamore policy test ./reviewer.json \
  --target github-api \
  --request "GET /repos/octocat/hello/contents/README.md"
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
    "path": "repos/octocat/hello/contents/README.md"
  },
  "fields": {}
}
decision: Allow (rule 0)
```

- `--request` is `"METHOD /path[?query]"`.
- `--target` sets the service name the action carries (default `target`); use the real service
  name so target-scoped rules apply.
- `--field key=value` (repeatable) supplies request fields for conditions. Values parse as JSON
  when they can — `--field draft=true` is the boolean `true`, `--field base=main` is the string
  `"main"`.

Supply fields to exercise a condition. Here the policy allows opening a PR only against
`develop`:

```bash
hackamore policy test ./reviewer.json \
  --target github-api \
  --request "POST /repos/octocat/hello/pulls" \
  --field base=develop
```

```
action: {
  "target": "github-api",
  "verb": {
    "type": "Method",
    "value": {
      "method": "POST"
    }
  },
  "resource": {
    "path": "repos/octocat/hello/pulls"
  },
  "fields": {
    "base": "develop"
  }
}
decision: Allow (rule 1)
```

The decision line reads `Allow (rule N)` for an allow, `Deny ExplicitDeny (rule N)` when an
explicit `Deny` rule matched, and `Deny NotAllowed (no rule matched)` for the default-deny
fallthrough:

```
decision: Deny NotAllowed (no rule matched)
```

`policy test` always exits 0 — the decision is the output, not a pass/fail. Inspect the
decision line.

## The policy studio

When the web UI is enabled, hackamore serves an authoring studio at `GET /ui` on the admin
listener (`http://127.0.0.1:9091/ui`). It lets you build rules with controls, lint as you
type, dry-run a request, and mint a token — the same lint and dry-run paths the CLI uses,
wrapped in a UI. It's an authoring aid; the policy you produce is the same JSON you'd write by
hand.

## Complete examples

### Read-only GitHub

Allow read-only REST access — `GET` to anything — and deny everything else by default.

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [ { "type": "Method", "value": { "method": "GET" } } ],
        "resources": [],
        "conditions": []
      }
    }
  ]
}
```

Because only `GET` is allowed and nothing else matches, every write (`POST`, `PATCH`,
`DELETE`, …) falls through to default-deny.

### Create pull requests, but never against `main`

Allow opening pull requests under the `octocat` org, but deny any PR whose `base` is `main`.
The `Deny` rule is listed first, so it wins over the broad allow that follows.

```json
{
  "rules": [
    {
      "effect": "Deny",
      "matches": {
        "targets": ["github-api"],
        "verbs": [ { "type": "Method", "value": { "method": "POST" } } ],
        "resources": ["repos/octocat/*/pulls"],
        "conditions": [
          { "type": "Equals", "value": { "field": "base", "value": "main" } }
        ]
      }
    },
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [ { "type": "Method", "value": { "method": "POST" } } ],
        "resources": ["repos/octocat/*/pulls"],
        "conditions": []
      }
    }
  ]
}
```

Verify the carve-out both ways:

```bash
hackamore policy test ./create-prs.json --target github-api \
  --request "POST /repos/octocat/hello/pulls" --field base=develop
# decision: Allow (rule 1)

hackamore policy test ./create-prs.json --target github-api \
  --request "POST /repos/octocat/hello/pulls" --field base=main
# decision: Deny ExplicitDeny (rule 0)
```

### Read-only AWS

Allow a small set of read-only AWS operations and nothing else. AWS verbs are named actions,
so each is a `Action` arm.

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["aws"],
        "verbs": [
          { "type": "Action", "value": { "id": "DescribeInstances" } },
          { "type": "Action", "value": { "id": "DescribeRegions" } },
          { "type": "Action", "value": { "id": "ListBuckets" } }
        ],
        "resources": [],
        "conditions": []
      }
    }
  ]
}
```

Any operation not in the list — `RunInstances`, `TerminateInstances`, `PutObject` — falls
through to default-deny. (Use the service name you registered for `targets`; see
[AWS](services/aws.md).)

---

Related: [Concepts](concepts.md) · [Getting started](getting-started.md) ·
[Credentials](credentials.md) · [Services overview](services/overview.md) ·
[GitHub](services/github.md) · [AWS](services/aws.md) · [Running agents](running-agents.md) ·
[Reference](reference.md)
