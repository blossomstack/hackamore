# Reference

A scannable lookup for every command, flag, endpoint, config field, and schema. For the
narrative, start at [Getting started](getting-started.md) and [Running agents](running-agents.md).

Conventions used throughout: the admin API listens on `http://127.0.0.1:9091`, the
agent-facing proxy on `127.0.0.1:9090`.

## CLI: `hackamore`

The server + operator binary. One subcommand per task.

### `hackamore serve`

Start the reverse proxy and admin API from a config file.

| Flag        | Meaning                          | Default    |
| ----------- | -------------------------------- | ---------- |
| `--config`  | Path to the JSON config file     | _required_ |

See [Serve config file](#serve-config-file) for the file's fields.

### `hackamore mint`

Mint a launch token bound to a policy, via a running server's admin API. Prints
`{ "token", "expires_at_ms" }`.

| Flag          | Meaning                                  | Default    |
| ------------- | ---------------------------------------- | ---------- |
| `--admin-url` | Base URL of the admin API                | _required_ |
| `--policy`    | Path to a JSON policy document           | _required_ |
| `--ttl`       | Token lifetime, in seconds               | `3600`     |

### `hackamore policy lint`

Validate a policy offline: structural errors (rules that can never match or fire). Exits
nonzero on any error.

| Flag       | Meaning                                  | Default    |
| ---------- | ---------------------------------------- | ---------- |
| `<policy>` | Path to the JSON policy document (positional) | _required_ |
| `--json`   | Emit findings as JSON instead of text    | off        |

### `hackamore policy test`

Dry-run one request through normalize + decide. Prints the normalized action, the matched
rule, and the verdict. Always exits 0 (the verdict is the output, not a failure).

| Flag        | Meaning                                                        | Default    |
| ----------- | ------------------------------------------------------------- | ---------- |
| `<policy>`  | Path to the JSON policy document (positional)                 | _required_ |
| `--request` | The request, as `"METHOD /path[?query]"`                      | _required_ |
| `--target`  | Service-instance name the synthetic action carries           | `target`   |
| `--field`   | Body field `key=value` (repeatable); JSON-parsed when possible | none       |

### `hackamore credentials add`

Register a credential under `<id>`, resolved from a source, via `POST /admin/credentials`.
Exactly one source is required.

| Flag          | Meaning                                              | Default    |
| ------------- | --------------------------------------------------- | ---------- |
| `--admin-url` | Base URL of the admin API                           | _required_ |
| `<id>`        | Credential id to register under (positional)        | _required_ |

Source flags (exactly one of the token flags **or** `--source`):

| Flag                    | Meaning                                                                       |
| ----------------------- | ----------------------------------------------------------------------------- |
| `--secret`              | A pasted secret, vaulted as-is (`static`)                                      |
| `--env`                 | An env var on the hackamore host (`env`)                                       |
| `--file`                | A file on the host; trimmed contents are the secret (`file`)                   |
| `--command`             | A command (whitespace-split) on the host; trimmed stdout is the secret (`command`) |
| `--source`              | An AWS source kind: `aws-static`, `assume-role`, or `instance`                |
| `--access-key-id`       | AWS access key id (for `--source aws-static`)                                  |
| `--secret-access-key`   | AWS secret access key (for `--source aws-static`)                              |
| `--session-token`       | AWS session token, optional (for `--source aws-static`)                        |
| `--role-arn`            | Role ARN to assume (for `--source assume-role`)                               |
| `--region`              | AWS region (for `--source assume-role`)                                        |
| `--base`                | Base credential for `assume-role`: `env` or `instance` (alias of `env`)        | `env` |

### `hackamore services add`

Register a service via `POST /admin/services`. Dispatches by `<name>`: a known **preset**
expands to the generic call with everything but the credential pinned; any other name is a
fully generic registration.

| Flag          | Meaning                                                | Default    |
| ------------- | ------------------------------------------------------ | ---------- |
| `--admin-url` | Base URL of the admin API                              | _required_ |
| `<name>`      | Preset name (`github-api`, `github-git`, `aws:<svc>`, `k8s`) or a generic service name (positional) | _required_ |

**Generic registration** (when `<name>` is not a preset):

| Flag             | Meaning                                                      | Default       |
| ---------------- | ----------------------------------------------------------- | ------------- |
| `--upstream-base`| Upstream base URL, e.g. `https://api.example.com`           | _required_    |
| `--host`         | Inbound `Host` routing pattern                              | upstream host |
| `--idl`          | API description format: `openapi` or `smithy`               | `openapi`     |
| `--source-file`  | Path to the API description (one of file/url required)      | none          |
| `--source-url`   | URL to fetch the API description from                       | none          |
| `--address`      | Consumer-facing address surfaced in the provision doc      | none          |
| `--inject`       | Outbound injection: `passthrough`/`bearer`/`header`/`basic`/`sigv4` | `passthrough` |
| `--credential`   | Reference an existing vault credential id                  | none          |
| `--secret`       | Inline secret vaulted under the service name               | none          |
| `--header-name`  | Header name for `--inject header`                          | `X-API-Key`   |
| `--username`     | Username for `--inject basic`                             | `x-access-token` |
| `--region`       | Region for `--inject sigv4`                               | none          |
| `--service`      | AWS service for `--inject sigv4`                          | none          |

An injecting `--inject` needs exactly one of `--credential` / `--secret`; `passthrough`
takes neither.

**Preset registration** (`github-api`, `github-git`, `aws:<svc>`): host/upstream/protocol/
model/injection are pinned; you supply only the credential, with exactly one of:

| Flag             | Meaning                                                                |
| ---------------- | --------------------------------------------------------------------- |
| `--credential`   | Reference an existing vault credential id                             |
| `--auth-source`  | Register a credential from a source first, then reference it          |
| `--auth-id`      | Override the id `--auth-source` registers under (defaults to preset name) |

`--auth-source` kinds: `gh-token` (github → `gh auth token`), `static`, `env`, `file`,
`command`, `aws-static`, `assume-role`, `instance`. Each reads its matching params:
`--auth-secret`, `--auth-env`, `--auth-file`, `--auth-command`, plus the AWS flags
`--access-key-id`, `--secret-access-key`, `--session-token`, `--role-arn`, `--region`, and
`--role-base` (`env`|`instance`, default `env`). `--region` also pins an `aws:<svc>`
preset's host + signature region (default `us-east-1`).

**`k8s` preset** (fetches the cluster's OpenAPI live, registers a `bearer` service):

| Flag                          | Meaning                                                         | Default                   |
| ----------------------------- | -------------------------------------------------------------- | ------------------------- |
| `--cluster`                   | Cluster API server URL (overrides kubeconfig `cluster.server`) | from kubeconfig           |
| `--kubeconfig`                | Path to the kubeconfig                                          | `$KUBECONFIG`, else `~/.kube/config` |
| `--context`                   | kubeconfig context name                                         | file's `current-context`  |
| `--token`                     | Bearer token for the OpenAPI fetch (overrides kubeconfig user) | from kubeconfig user      |
| `--ca`                        | Path to the cluster CA PEM                                      | from kubeconfig           |
| `--insecure-skip-tls-verify`  | Skip TLS verification when fetching the OpenAPI                 | off                       |

The kube credential is registered automatically: a `token` → `static` source, an `exec`
plugin → `command` source. Override the registered id with `--auth-id`, or reference an
existing one with `--credential`.

## CLI: `hackamore-agent`

The consumer-side setup binary, run inside the sandbox. It fetches the provision doc from
`GET /.hackamore/provision` and renders native tool config.

| Subcommand | Purpose                                                                  |
| ---------- | ------------------------------------------------------------------------ |
| `show`     | Fetch and pretty-print the raw provision doc                             |
| `status`   | Print a human-readable summary of what the token can reach               |
| `env`      | Print shell `export` lines (for `eval "$(hackamore-agent env …)"`)       |
| `setup`    | Write native tool config (gh / git / kubeconfig / AWS) into a home dir   |
| `teardown` | Remove the config a prior `setup` wrote, per its manifest                |

| Flag              | Meaning                                              | Used by                  |
| ----------------- | --------------------------------------------------- | ------------------------ |
| `--hackamore-url` | Base URL of the proxy listener, e.g. `http://127.0.0.1:9090` | `show`/`env`/`status`/`setup` |
| `--token`         | The hackamore launch token                          | `show`/`env`/`status`/`setup` |
| `--home`          | Home directory to write/remove config in            | `setup`/`teardown` (default `$HOME`) |

## Admin API

Operator-only listener (`http://127.0.0.1:9091`). Bind to localhost; never expose to the
sandbox.

| Method | Path                       | Purpose                                                      |
| ------ | -------------------------- | ----------------------------------------------------------- |
| POST   | `/mint`                    | Mint a launch token for a submitted policy                  |
| POST   | `/revoke`                  | Invalidate a token immediately, before its TTL              |
| POST   | `/policy/lint`             | Lint a policy against the configured services' models       |
| POST   | `/policy/test`             | Dry-run one synthetic request through normalize + decide    |
| GET    | `/admin/services`          | List the live service registry                              |
| POST   | `/admin/services`          | Register a service from an API description + outbound auth   |
| DELETE | `/admin/services/{name}`   | Remove a registered service                                 |
| GET    | `/admin/credentials`       | List known credential ids (never secrets)                   |
| POST   | `/admin/credentials`       | Register a credential under an id, resolved from a source   |
| GET    | `/ui`                      | The policy-studio web UI (also `/ui/app.js`, `/ui/style.css`) |

`/policy/lint`, `/policy/test`, and the `/ui` routes return `404` when `web_ui` is `false`.
`/mint` returns `{ "token", "expires_at_ms" }`; `/revoke` returns `{ "revoked": bool }`;
credential registration returns `201` with `{ "id" }` (never the secret); service
registration returns `{ "name", "replaced", "model" }`.

### Proxy listener: provision

The proxy listener (`127.0.0.1:9090`) serves exactly one sandbox-reachable hackamore path;
every other path is run through the gateway.

| Method | Path                      | Auth                        | Purpose                                  |
| ------ | ------------------------- | --------------------------- | ---------------------------------------- |
| GET    | `/.hackamore/provision`   | `X-Hackamore-Token` (or `Authorization`) | The consumer-setup bundle for the token |

Returns the [provision doc](#schemas): the launch token, the CA (when TLS-terminated),
per-service endpoints + tool hints — and **no real upstream secrets**.

## Serve config file

JSON, loaded by `hackamore serve --config`.

| Field           | Type                          | Meaning                                                            |
| --------------- | ----------------------------- | ----------------------------------------------------------------- |
| `proxy_addr`    | string                        | Address the agent-facing proxy listens on                         |
| `admin_addr`    | string                        | Address the operator/admin API listens on                         |
| `services`      | array of [service](#service-object) | The proxied service allowlist, routed by `Host`             |
| `credentials`   | object `{id: secret}`         | Static credential seed (logical id → real secret). Optional       |
| `providers`     | object `{id: provider}`       | Minting providers for short-lived, rotated secrets. Optional      |
| `tenants`       | object `{token: [name…]}`     | Multi-tenant mint authorization; empty = open. Optional           |
| `tls`           | [tls object](#tls-object)     | TLS termination for the proxy listener. Optional                  |
| `audit_log`     | string (path)                 | Durable JSONL audit log path; absent = `tracing`-only. Optional   |
| `web_ui`        | bool                          | Serve the policy-studio UI + authoring endpoints                  | default `true` |

### service object

| Field             | Type            | Meaning                                                                |
| ----------------- | --------------- | --------------------------------------------------------------------- |
| `name`            | string          | Logical instance name; becomes `Action.target`                        |
| `host`            | string          | `Host` match: exact, `*.suffix`, or `*`                               |
| `upstream_base`   | string          | Upstream base URL, e.g. `https://api.github.com`                      |
| `consumer_address`| string          | Address the agent points its tool at (in the provision doc). Optional |
| `tool_hint`       | string          | `github`/`git`/`aws`/`kubernetes`/`generic`. Optional, default `generic` |
| `protocol`        | string          | Wire protocol: `rest` (default), `aws-query`, `aws-json`. Optional    |
| `path_template`   | string          | Path template capturing named segments, e.g. `/{bucket}/{key+}`. Optional |
| `description`     | [description](#description-object) | API description imported at startup. Optional          |
| `catalog`         | array of string | Known named-action ids for mint-time validation. Optional             |
| `catalog_openapi` | string (path)   | OpenAPI v3 spec whose operations seed the catalog. Optional           |
| `outbound`        | [outbound](#outbound-stance) | What hackamore does with upstream auth on allow. Default passthrough |

### description object

| Field  | Type          | Meaning                                  |
| ------ | ------------- | ---------------------------------------- |
| `idl`  | string        | `openapi` or `smithy`                    |
| `file` | string (path) | Path to the description (one of file/url) |
| `url`  | string        | URL to fetch the description from         |

### tls object

| Field  | Type          | Meaning                                                |
| ------ | ------------- | ------------------------------------------------------ |
| `cert` | string (path) | Serving certificate chain (PEM)                        |
| `key`  | string (path) | Serving private key (PEM: PKCS#8, PKCS#1, or SEC1)     |
| `ca`   | string (path) | CA bundle consumers must trust; defaults to `cert`. Optional |

### outbound stance

`"passthrough"` (a bare string), or one of the tagged objects:

| Stance        | JSON                                                                  |
| ------------- | --------------------------------------------------------------------- |
| passthrough   | `"passthrough"`                                                       |
| bearer        | `{ "bearer": "<cred-id>" }`                                            |
| header        | `{ "header": { "name": "X-API-Key", "credential": "<cred-id>" } }`    |
| sigv4         | `{ "sigv4": { "credential": "<cred-id>", "region": "...", "service": "..." } }` |

### provider object

Tagged by `kind`:

| Kind         | Fields                                                                      |
| ------------ | -------------------------------------------------------------------------- |
| `eks`        | `access_key_id`, `secret_access_key`, `region`, `cluster_name`             |
| `github-app` | `app_id`, `installation_id`, `private_key_path`; `api_base` optional       |

### Complete example

```json
{
  "proxy_addr": "127.0.0.1:9090",
  "admin_addr": "127.0.0.1:9091",
  "web_ui": true,
  "audit_log": "/var/log/hackamore/audit.jsonl",
  "services": [
    {
      "name": "github-api",
      "host": "api.github.com",
      "upstream_base": "https://api.github.com",
      "consumer_address": "https://api.github.com",
      "tool_hint": "github",
      "description": { "idl": "openapi", "file": "/etc/hackamore/github.openapi.json" },
      "outbound": { "bearer": "gh-app" }
    },
    {
      "name": "s3",
      "host": "s3.us-east-1.amazonaws.com",
      "upstream_base": "https://s3.us-east-1.amazonaws.com",
      "tool_hint": "aws",
      "protocol": "rest",
      "path_template": "/{bucket}/{key+}",
      "outbound": { "sigv4": { "credential": "aws-prod", "region": "us-east-1", "service": "s3" } }
    },
    {
      "name": "internal-api",
      "host": "api.internal.example",
      "upstream_base": "https://api.internal.example",
      "outbound": { "header": { "name": "X-API-Key", "credential": "internal-key" } }
    }
  ],
  "credentials": {
    "internal-key": "raw-api-key-value"
  },
  "providers": {
    "gh-app": {
      "kind": "github-app",
      "app_id": "123456",
      "installation_id": "789012",
      "private_key_path": "/etc/hackamore/app.pem"
    }
  },
  "tenants": {
    "tenant-token-a": ["github-api"]
  },
  "tls": {
    "cert": "/etc/hackamore/tls/cert.pem",
    "key": "/etc/hackamore/tls/key.pem"
  }
}
```

> Field names differ between the config file and the admin API. The config file uses
> snake_case (`upstream_base`, `consumer_address`); the `POST /admin/services` body uses
> camelCase (`upstreamBase`, `address`). The CLI handles the admin-API casing for you.

## Injections

How hackamore places the real credential on the outbound request, on allow. Configured per
service. See [Credentials](credentials.md).

| Name          | Wire effect                                             | Params              | References a credential? |
| ------------- | ------------------------------------------------------- | ------------------- | ------------------------ |
| `passthrough` | Forwards the consumer's own credential unchanged        | —                   | No                       |
| `bearer`      | `Authorization: Bearer <secret>`                        | —                   | Yes                      |
| `basic`       | `Authorization: Basic base64(<username>:<secret>)`      | `username`          | Yes                      |
| `header`      | Injects the secret as a custom header                   | `name`              | Yes                      |
| `sigv4`       | Re-signs the request with AWS SigV4                     | `service`, `region` | Yes (an AWS bundle)      |

## Sources

Where hackamore obtains a credential's real material, when registering via
`POST /admin/credentials`. See [Credentials](credentials.md).

| Name          | Resolves from                                              | CLI flag(s)                                         | Kind         |
| ------------- | --------------------------------------------------------- | --------------------------------------------------- | ------------ |
| `static`      | A pasted secret, vaulted as-is                            | `--secret`                                          | static       |
| `env`         | An env var on the hackamore host                          | `--env`                                             | static       |
| `file`        | A file on the host (trimmed contents)                     | `--file`                                            | static       |
| `command`     | A command's trimmed stdout on the host                    | `--command`                                         | static       |
| `aws-static`  | An explicit AWS key pair (+ optional session token)       | `--source aws-static --access-key-id --secret-access-key [--session-token]` | static AWS bundle |
| `assume-role` | STS `AssumeRole`, signed with a base credential           | `--source assume-role --role-arn --region [--base]` | minted       |
| `instance`    | The host AWS env chain (`AWS_*` vars), vaulted static     | `--source instance`                                 | static AWS bundle |

`assume-role` and `instance` are AWS-bundle sources; `assume-role` registers a minting
provider, so it needs a minting-capable credential store. `instance` reads the host
`AWS_*` environment chain only (no IMDS in v1).

## Wire protocols

How hackamore extracts the `Action`'s verb and resource from a request, per the service's
protocol (usually derived from its imported model). See [Services overview](services/overview.md).

| Name        | Verb from                                  | Resource                                     |
| ----------- | ------------------------------------------ | -------------------------------------------- |
| `rest`      | The HTTP method (`GET`, `POST`, …)         | The canonical request path                   |
| `aws-query` | The `Action` request parameter            | The request path                             |
| `aws-json`  | The `X-Amz-Target` header                  | The request path                             |
| `git-http`  | Literal `git-upload-pack` / `git-receive-pack` | `{owner}/{repo}`                        |

(`aws-query` is also called the *parameter* protocol; `aws-json` the *header* protocol.)

## Presets

Sugar over `hackamore services add`: each pins host, upstream, protocol, model, injection,
and tool hint. You supply only the credential. See [Services overview](services/overview.md).

| Name           | Host                              | Protocol   | Injection | Tool hint    |
| -------------- | --------------------------------- | ---------- | --------- | ------------ |
| `github-api`   | `api.github.com`                  | rest       | bearer    | `github`     |
| `github-git`   | `github.com`                      | git-http   | basic (`x-access-token`) | `git` |
| `aws:ec2`      | `ec2.<region>.amazonaws.com`      | aws-query  | sigv4     | `aws`        |
| `aws:s3`       | `s3.<region>.amazonaws.com`       | rest       | sigv4     | `aws`        |
| `aws:sts`      | `sts.<region>.amazonaws.com`      | aws-query  | sigv4     | `aws`        |
| `aws:iam`      | `iam.<region>.amazonaws.com`      | aws-query  | sigv4     | `aws`        |
| `aws:lambda`   | `lambda.<region>.amazonaws.com`   | rest       | sigv4     | `aws`        |
| `aws:dynamodb` | `dynamodb.<region>.amazonaws.com` | aws-json   | sigv4     | `aws`        |
| `k8s`          | the cluster API host              | rest       | bearer    | `kubernetes` |

`<region>` defaults to `us-east-1` (override with `--region`). The protocol of each AWS
preset is declared by its bundled model. Any other `<name>` falls through to a generic
registration. See [GitHub](services/github.md), [AWS](services/aws.md),
[Kubernetes](services/kubernetes.md), and [Generic](services/generic.md).

## Policy schema

A policy is a JSON document evaluated top-to-bottom, **first-match-wins, default-deny**. If
no rule matches, the action is denied. See [Policies](policies.md).

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["github-api"],
        "verbs": [{ "type": "Method", "value": { "method": "GET" } }],
        "resources": ["repos/acme/widgets/**"],
        "conditions": [
          { "type": "Equals", "value": { "field": "base", "value": "main" } }
        ]
      }
    }
  ]
}
```

### Rule

| Field     | Type   | Meaning                                          |
| --------- | ------ | ------------------------------------------------ |
| `effect`  | string | `Allow` or `Deny`                                |
| `matches` | object | What an action must look like for this rule to apply |

### Match

Each list means "any" when empty. All four must hold for the rule to apply.

| Field        | Type             | Meaning                                                  |
| ------------ | ---------------- | -------------------------------------------------------- |
| `targets`    | array of string  | Service names this rule applies to; empty = any          |
| `verbs`      | array of [verb](#verb-forms) | Verbs this rule applies to; empty = any      |
| `resources`  | array of string  | Resource-path globs; empty = any                         |
| `conditions` | array of [condition](#condition-forms) | All must hold (AND); empty = no field constraints |

Resource globs are segment-wise: `*` matches one path segment, trailing `**` matches any
remainder, e.g. `repos/acme/*/pulls`.

### Verb forms

A verb is a tagged object selecting the literal verb the request states.

| Form     | JSON                                              | Matches                       |
| -------- | ------------------------------------------------- | ----------------------------- |
| Method   | `{ "type": "Method", "value": { "method": "GET" } }` | A REST HTTP method         |
| Action   | `{ "type": "Action", "value": { "id": "RunInstances" } }` | A named RPC action  |

### Condition forms

A condition is a predicate over one entry in the action's `fields` (a flattened view of the
merged query + JSON body). `field` is a dotted path, e.g. `base`, `head.ref`.

| Form   | JSON                                                              | Holds when                       |
| ------ | ---------------------------------------------------------------- | -------------------------------- |
| Equals | `{ "type": "Equals", "value": { "field": "base", "value": "main" } }` | `field` equals the value    |
| OneOf  | `{ "type": "OneOf", "value": { "field": "base", "values": ["main", "dev"] } }` | `field` is one of the values |
| Exists | `{ "type": "Exists", "value": { "field": "draft" } }`            | `field` is present and non-null  |

### Evaluation rules

- Rules are evaluated **in order**; the **first** rule whose `matches` matches the action
  decides the outcome.
- The default is **deny**: if no rule matches, the action is denied.
- A rule applies only when **every** non-empty part of its `matches` matches (targets AND
  verbs AND resources AND all conditions).
- Conditions within a rule are **AND**ed. To express OR over values, use `OneOf` (or
  multiple rules).
- Policy never names credentials — the matched service owns its credential. Rules reference
  `targets`, not secrets.

---

See also: [Running agents](running-agents.md) · [Concepts](concepts.md) ·
[Policies](policies.md) · [Credentials](credentials.md) · [Services overview](services/overview.md)
