# Services overview

A **service** is one upstream that your agent is allowed to reach through hackamore. You
register each service once; from then on, every request the agent makes to that upstream is
normalized, checked against the agent's policy, and — when allowed — forwarded with a real,
short-lived credential injected by hackamore. The agent never holds that credential.

This page explains the two ways to register a service, the model behind every registration,
and how to list and remove services. The per-service pages cover the details:

- [GitHub](./github.md) — the GitHub REST API and git-over-HTTPS
- [AWS](./aws.md) — EC2, S3, STS, IAM, Lambda, DynamoDB
- [Kubernetes](./kubernetes.md) — a cluster's API server
- [Generic](./generic.md) — any service described by OpenAPI or Smithy

All commands below assume the admin API is reachable at `http://127.0.0.1:9091`. See
[Getting started](../getting-started.md) for how to run the server.

## Two ways to register: presets and generic

Every registration is the same command:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 <name> ...
```

What you pass for `<name>` decides which of two paths you take.

**A preset** is a well-known name (`github-api`, `github-git`, `aws:<svc>`, `k8s`). A preset
pins everything intrinsic to that service for you: its host, its upstream URL, its wire
protocol, its API model, the way the real credential is placed on the wire, and which native
tool the agent configures. You supply only the one thing the preset can't know — the
credential.

```bash
hackamore services add --admin-url http://127.0.0.1:9091 github-api --auth-source gh-token
```

**A generic registration** is any other name. Here you describe the service yourself: its
upstream URL, the format of its API description, where to read that description, and how to
inject the credential.

```bash
hackamore services add --admin-url http://127.0.0.1:9091 my-api \
  --upstream-base https://api.example.com \
  --idl openapi --source-file ./openapi.json \
  --inject header --header-name X-API-Key --credential my-api-key
```

## The registration model: a source and an injection

Whichever path you take, a registration is two independent decisions.

**The source — where the API description comes from.** hackamore imports an API description
into a model. That model is what gives the service its policy vocabulary: the verbs and
resources your policy rules can name. A description is sourced one of four ways:

| How the model is sourced | Which services |
| --- | --- |
| **Bundled** in the binary, sent at registration | `github-api`, `aws:<svc>` |
| **Built in** (no description; hackamore attaches a fixed model) | `github-git` |
| **Fetched live** from the cluster at registration | `k8s` |
| **Imported from your file or URL** | generic (`--source-file` / `--source-url`) |

Presets handle the source for you. For a generic service you provide it with `--idl`
(`openapi` or `smithy`, default `openapi`) plus exactly one of `--source-file <path>` or
`--source-url <url>`.

**The injection — how the real credential is placed on the outbound request.** This is the
mechanism hackamore uses to authenticate to the upstream on the agent's behalf:

| Injection | What hackamore puts on the wire |
| --- | --- |
| `passthrough` | nothing — forwards the agent's own header unchanged |
| `bearer` | `Authorization: Bearer <secret>` |
| `basic` | `Authorization: Basic base64(<username>:<secret>)` |
| `header` | a named header, e.g. `X-API-Key: <secret>` |
| `sigv4` | re-signs the request with AWS SigV4 using the real account key |

Every injection except `passthrough` references a credential **by id**. Presets pin the
injection; a generic service selects it with `--inject` (default `passthrough`). See
[Credentials](../credentials.md) for how credentials are registered and resolved, and
[Policies](../policies.md) for how the imported model becomes your policy vocabulary.

## The preset catalog

| Preset | Host | Protocol | Injection | Configures tool | Credential you supply |
| --- | --- | --- | --- | --- | --- |
| `github-api` | `api.github.com` | REST | `bearer` | `gh` | a GitHub token |
| `github-git` | `github.com` | git-over-HTTPS | `basic` (`x-access-token`) | `git` | a GitHub token |
| `aws:ec2` | `ec2.<region>.amazonaws.com` | AWS | `sigv4` | `aws` | an AWS credential bundle |
| `aws:s3` | `s3.<region>.amazonaws.com` | AWS | `sigv4` | `aws` | an AWS credential bundle |
| `aws:sts` | `sts.<region>.amazonaws.com` | AWS | `sigv4` | `aws` | an AWS credential bundle |
| `aws:iam` | `iam.<region>.amazonaws.com` | AWS | `sigv4` | `aws` | an AWS credential bundle |
| `aws:lambda` | `lambda.<region>.amazonaws.com` | AWS | `sigv4` | `aws` | an AWS credential bundle |
| `aws:dynamodb` | `dynamodb.<region>.amazonaws.com` | AWS | `sigv4` | `aws` | an AWS credential bundle |
| `k8s` | the cluster API host | REST | `bearer` | `kubernetes` | a cluster token or exec plugin |

The AWS region defaults to `us-east-1`; override it with `--region`. An AWS service outside
the six listed above is not a preset — register it generically with a Smithy description.

## Supplying a preset's credential

A preset needs exactly one of these (not both, not neither):

- **`--credential <id>`** — reference a credential you already registered (see
  [Credentials](../credentials.md)).
- **`--auth-source <kind>`** — register a credential from a source first, then reference it.
  The id defaults to the service name; override it with `--auth-id <id>`.

The GitHub presets accept the shorthand `--auth-source gh-token`, which runs `gh auth token`
on the hackamore host and vaults the result. The AWS presets need an AWS credential bundle,
supplied either with `--credential` (pointing at an `aws-static` / `assume-role` credential)
or with `--auth-source aws-static …`. See the per-service pages for worked examples.

## Listing and removing services

List the live registry:

```bash
curl http://127.0.0.1:9091/admin/services
```

Each entry shows the service name, host, and its outbound injection mechanism — never a
secret.

Remove a service (takes effect immediately, no restart):

```bash
curl -X DELETE http://127.0.0.1:9091/admin/services/github-api
```

Re-registering a service with the same name replaces the existing one in place.

## Which page do I need?

- Reaching GitHub (issues, PRs, clone, push)? → [GitHub](./github.md)
- Calling an AWS service? → [AWS](./aws.md)
- Talking to a Kubernetes cluster? → [Kubernetes](./kubernetes.md)
- Anything else with an OpenAPI or Smithy description? → [Generic](./generic.md)

See also [Concepts](../concepts.md) for the policy model and
[Running agents](../running-agents.md) for how a provisioned agent picks the service up.
