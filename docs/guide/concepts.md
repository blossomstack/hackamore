# Core concepts

This page is the vocabulary the rest of the guide leans on. Read it once and the
command-line flags, the policy JSON, and the service presets will all line up.

The single idea to anchor on is **Source × Injection**:

- A **credential** is registered once, with a **source** that tells hackamore how to
  resolve the real secret into the vault. The secret is never echoed back.
- A **service** chooses an **injection** that references a credential by id and decides
  *how* that secret is placed on the outbound request.

The two axes are independent. One credential can back many services with different
injections; one service uses exactly one injection referencing one credential. The
**Source** axis answers "where does the real secret come from?"; the **Injection** axis
answers "how does it get onto the wire?". Keep them apart and everything else follows.

See [Credentials](credentials.md) for the Source axis in depth and
[Services overview](services/overview.md) for the Injection axis.

## Service (and target)

A **service** is one configured upstream that hackamore will proxy to — for example a
GitHub instance, an AWS service in a region, or a Kubernetes API server. A service pins:

- a **name** (its logical identity),
- a **host** pattern matched against the inbound request's `Host` header (an exact host,
  a `*.suffix` wildcard, or `*` catch-all),
- an **upstream base** URL to forward to,
- its **wire protocol** (how a request is read), and
- its **injection** (how the real credential is placed outbound).

Configured services form an **allowlist**: a request whose host matches no service is
denied (fail closed). When more than one pattern could match, the first configured
service wins, so list specific hosts before catch-alls.

The service's name is what a policy rule scopes to — and in policy vocabulary that name
is called the **target**. When a request is normalized, `Action.target` is set to the
matched service's name, and a rule's `targets` list is checked against it. "Service" and
"target" are the same string seen from two sides: the operator configures a *service*; the
policy author references it as a *target*.

Set up services with the `hackamore services add` command and its presets — see
[Services overview](services/overview.md), [GitHub](services/github.md),
[AWS](services/aws.md), [Kubernetes](services/kubernetes.md), and
[Generic](services/generic.md).

## API model / IDL

An **API model** is a service's imported vocabulary — its operations, resource shapes,
and (for RPC services) its wire protocol — derived from an **IDL**: an OpenAPI document
or a Smithy model (`service-2.json`). hackamore supports two IDL kinds, selected with
`--idl openapi` (the default) or `--idl smithy`.

The model is optional. A service with a model gets richer policy authoring help: the
policy **lint** can check a rule against the real operations, and dry-run knows the
operation set. A service without a model is normalized generically (the structural checks
still run). Presets bundle the right model automatically — `github-api` carries the
GitHub OpenAPI, each `aws:<svc>` carries that service's Smithy model, and the `k8s` preset
fetches the cluster's OpenAPI live at registration time.

## Wire protocol

The **wire protocol** decides *where the operation lives in a request* — how the gateway
reads a request into a verb and a resource. hackamore supports four, named by mechanism,
never by a brand:

- **rest** — the operation is the HTTP method plus the URL path. The verb is the literal
  method (`GET`, `POST`, `PATCH`, …) and the resource is the path. This is the default and
  covers GitHub's REST API, Kubernetes, S3, and most APIs.
- **aws-query** — the operation name is the value of a body/query field named `Action`
  (form-style RPC, e.g. EC2). The verb is a named action.
- **aws-json** — the operation name is read from the `x-amz-target` header, keeping the
  part after the last `.` (e.g. DynamoDB). The verb is a named action.
- **git-http** — git Smart-HTTP. The verb (`git-upload-pack` for fetch/clone,
  `git-receive-pack` for push) and the resource (`{owner}/{repo}`) are derived from the
  request shape by a dedicated normalizer.

A service that imports a model takes its protocol from the model. For a generic service
you set it explicitly. Extraction is strict and fail-closed: an RPC request whose
operation can't be parsed is given an unmatchable verb, so no allow rule fires.

## Credential and source (the Source axis)

A **credential** is a named handle (an id) for a real upstream secret held in the vault.
You register it once; thereafter services and audit surfaces refer to it by id only — the
secret value is never returned.

A **source** tells hackamore how to resolve the real secret when you register the
credential. The token-shaped sources are:

| Source     | CLI flag                  | What it resolves                                  |
|------------|---------------------------|---------------------------------------------------|
| static     | `--secret <value>`        | the pasted value, vaulted as-is                   |
| env        | `--env <VAR>`             | an environment variable on the hackamore host     |
| file        | `--file <path>`          | the trimmed contents of a file on the host        |
| command    | `--command "<argv>"`      | the trimmed stdout of a command (e.g. `gh auth token`) |

The AWS sources resolve a credential *bundle* (access key id + secret + optional session
token) and are selected with `--source`:

| Source       | `--source` value | Notes                                                          |
|--------------|------------------|----------------------------------------------------------------|
| aws-static   | `aws-static`     | an IAM key pair (`--access-key-id`, `--secret-access-key`, optional `--session-token`) |
| assume-role  | `assume-role`    | STS `AssumeRole` (`--role-arn`, `--region`), short-lived and auto-rotated |
| instance     | `instance`       | the host's instance/role credential chain                      |

Register a credential with:

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 my-gh \
  --command "gh auth token"
```

The response carries the id only, never the secret. Full details, including how
assume-role and minted credentials rotate, are in [Credentials](credentials.md).

## Injection (the Injection axis)

An **injection** is how a service places the real credential on the outbound request once
an action is allowed. It is chosen per service with `--inject`, and references a credential
by id (or carries an inline secret for a generic registration). The mechanisms:

| Injection    | `--inject` value | What goes on the wire                                              |
|--------------|------------------|-------------------------------------------------------------------|
| passthrough  | `passthrough`    | nothing injected — the agent's own credential is forwarded unchanged (filter-only) |
| bearer       | `bearer`         | `Authorization: Bearer <secret>`                                  |
| basic        | `basic`          | `Authorization: Basic base64(<username>:<secret>)` (default username `x-access-token`) |
| header       | `header`         | a custom header `<name>: <secret>` (default name `X-API-Key`)     |
| sigv4        | `sigv4`          | re-signs the request with AWS SigV4 for a `--service` + `--region`; sets `X-Amz-Security-Token` for temporary credentials |

Because the credential is the service's property, it is **never named in policy**. The
policy author writes rules about targets, verbs, and resources; which secret a target
injects is your configuration, decided here. See [Services overview](services/overview.md).

## Policy, rule, effect

A **policy** is a JSON document — the standing authorization for a launch token. It is a
single ordered list of rules:

```json
{ "rules": [ { "effect": "Allow", "matches": { … } } ] }
```

A **rule** has an **effect** (`Allow` or `Deny`) and a `matches` block describing which
actions it applies to. Rules are evaluated **top-to-bottom, first match wins**. If no rule
matches, the action is **denied** (default-deny). Because the first match wins, a `Deny`
rule placed before a later `Allow` beats it — useful for carving an exception out of a
broad allow. Inside a `matches` block, every list is "any" when empty: empty `targets`
means any service, empty `verbs` means any verb, and so on.

See [Policies](policies.md) for patterns and the full `matches` grammar.

## Verb (Method vs Action)

A **verb** is the operation a request states, as a tagged union with two arms tied to the
wire protocol:

- **Method** — the literal HTTP method, for REST services:
  `{"type":"Method","value":{"method":"GET"}}`.
- **Action** — a named action id, for RPC and git services:
  `{"type":"Action","value":{"id":"RunInstances"}}`.

The engine matches verbs by exact equality. A REST service produces `Method` verbs; an
`aws-query`/`aws-json` service produces `Action` verbs named after the operation; a
git-http service produces the `Action` verbs `git-upload-pack` and `git-receive-pack`.

## Resource and glob

A **resource** is the path an action addresses — the canonical, slash-joined request path,
e.g. `repos/octocat/hello-world/pulls`. It is matched by **globs** in a rule's `resources`
list, segment by segment:

- `*` matches exactly one path segment.
- `**` matches any number of trailing segments (including zero).

So `repos/*/*/pulls` matches `repos/octocat/hello/pulls`, and `repos/octocat/**` matches
everything under that org's repos. The path is canonicalized (percent-decoding and
dot-segments resolved) before it is matched, so a disguised path can't slip past a glob.

## Condition and field

A **condition** narrows a rule by inspecting the request's **fields** — a flattened JSON
view of the merged query string and JSON (or form) body, e.g. `{"base":"main","draft":true}`
for a pull-request creation. A condition's `field` is a dotted path into that object (e.g.
`base`, or `head.ref`). Three condition kinds exist:

- `Equals` — the field equals a given JSON value.
- `OneOf` — the field is one of a given list of values.
- `Exists` — the field is present and non-null.

All conditions in a rule must hold (they AND together). This is how you express rules like
"open a pull request, but only against the `develop` base":

```json
{ "type": "Equals", "value": { "field": "base", "value": "develop" } }
```

See [Policies](policies.md) for the condition grammar and more examples.

## Launch token

A **launch token** is the short-lived bearer credential the agent holds. You mint one from
a policy document; it is bound to that policy and to a time-to-live. The agent presents it
on every request (the gateway accepts it via `X-Hackamore-Token`, `Authorization: Bearer`,
the Basic password slot, or a dummy AWS SigV4 signature). The token is useless against the
real upstream — it only authenticates the agent to hackamore and resolves the policy to
enforce. Mint one with:

```bash
hackamore mint --admin-url http://127.0.0.1:9091 \
  --policy ./policy.json --ttl 3600
```

The `--ttl` is in seconds (default `3600`). See [Running agents](running-agents.md).

## Provision doc

A **provision doc** is the setup bundle the agent's host fetches to configure its tools. It
is projected from the token's bound policy joined with the service registry, and it carries
**no real upstream secrets** — only the launch token the holder already has, the consumer-
facing endpoints, the gateway's CA (when TLS is terminated), and, per service, a tool hint
and how the agent should authenticate to hackamore (bearer token, or a dummy SigV4
credential for AWS). The agent's host fetches it from the reserved
`/.hackamore/provision` path on the proxy listener — the one address a sandboxed agent can
reach. See [Running agents](running-agents.md).

## Tool hint

A **tool hint** is a per-service tag in the provision doc — one of `github`, `git`, `aws`,
`kubernetes`, or `generic` — telling the agent which native tool config to write for that
service (configure `gh`, write `.git-credentials`, write `~/.aws`, write a kubeconfig, or
nothing beyond the token and endpoint). Presets set it automatically; it is decoupled from
the service name, so a service named `aws-ec2` can still hint `aws`. See
[Running agents](running-agents.md).

## How they fit together

Here is one request, end to end, naming each concept as it appears.

You, the operator, did two things up front. You registered a **credential** named
`gh-app` with a **source** (`--command "gh auth token"`), which resolved the real token
into the **vault**. Then you added a **service** named `github` whose **wire protocol** is
rest, that routes the host `api.github.com`, and whose **injection** is `bearer`
referencing `gh-app`. You wrote a **policy** with one allow **rule** whose `matches`
targets `github`, allows the `POST` **verb**, scopes to the **resource** glob
`repos/*/*/pulls`, and adds a **condition** `Equals base=develop`. You minted a **launch
token** from that policy with a one-hour ttl and handed it to the agent (the agent's host
configured `gh` from the **provision doc**, guided by the `github` **tool hint**).

Now the agent runs `gh pr create`:

1. The request reaches the gateway carrying the **launch token**. The gateway
   authenticates it and resolves the bound **policy**.
2. The `Host` header `api.github.com` **routes** to the `github` **service**.
3. The gateway **normalizes** the request into an `Action`: `target` = `github`, `verb` =
   `Method POST`, `resource` = `repos/octocat/site/pulls`, `fields` = `{"base":"develop",…}`.
4. The policy engine **decides**: the rule's target, verb, resource glob, and `base`
   **condition** all hold, so the verdict is allow.
5. The gateway strips the launch token, resolves `gh-app` from the **vault**, applies the
   `bearer` **injection** (`Authorization: Bearer <real token>`), and **forwards** to
   `https://api.github.com`.
6. The decision is **audited**, with the matched rule recorded.

Had the agent tried `gh pr create --base main`, the `base` condition would have failed, no
rule would have matched, and the gateway would have returned `403` — default-deny — without
ever contacting GitHub.

---

Next: [Getting started](getting-started.md) · [Policies](policies.md) ·
[Running agents](running-agents.md) · [Reference](reference.md)
