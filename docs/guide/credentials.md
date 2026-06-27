# Credentials

A **credential** is a real upstream secret hackamore holds on your behalf and injects into
allowed requests — a GitHub token, an AWS key pair, a Kubernetes bearer token. The agent
never sees it. This page covers the **source** of a credential: where hackamore obtains the
real material when you register it.

Every command here talks to the admin API at `http://127.0.0.1:9091`. The admin API is
operator surface — bind it to localhost and keep it off the agent's network.

## The model: register once, reference by id

A credential has two parts:

- an **id** you choose (e.g. `gh-login`, `aws-deploy`), and
- a **source** that tells hackamore how to obtain the real secret.

You register the pair once:

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 <id> <source>
```

hackamore resolves the source to a real secret, stores it in the vault under `<id>`, and
returns the id — never the secret:

```json
{
  "id": "gh-login"
}
```

A service then references the credential **by id** in its injection stance. One credential
can back many services: the same GitHub token can be injected as a bearer header for the REST
API and as a basic-auth password for git over HTTPS (see
[Sharing one credential across services](#sharing-one-credential-across-services)). Policies
never name credentials — the service a request routes to owns its credential, so policy
authors reason about *targets*, not secrets. (See [Concepts](concepts.md) for the two axes:
the **source** of a credential and its **injection** into a request.)

The rest of this page is one section per source kind, then sharing, rotation, and security.

## Token sources

A token source resolves to a single string secret — a token, a key, a password — vaulted as
one value. There are four, each a single flag on `credentials add`.

### `--secret` — a pasted secret

Vault a secret you paste directly. The value is stored as-is.

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 gh-login \
  --secret ghp_xxxxxxxxxxxxxxxxxxxx
```

Simple, but the secret lands in your shell history and process arguments. Prefer `--env`,
`--file`, or `--command` for anything long-lived.

### `--env` — an environment variable on the host

Read the secret from an environment variable in hackamore's own environment at registration
time.

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 gh-login \
  --env GITHUB_TOKEN
```

hackamore reads `GITHUB_TOKEN` from its host environment. Registration fails if the variable
is unset or empty (fail closed). The value is read once, when you register.

### `--file` — a file on the host

Read the secret from a file on the hackamore host. The file's contents are **trimmed** of
surrounding whitespace.

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 k8s-token \
  --file /var/run/secrets/kubernetes.io/serviceaccount/token
```

This suits a mounted or projected secret — a Kubernetes service-account token, a Docker
secret, a file dropped by your secret manager. Registration fails if the file is missing or
empty.

### `--command` — a command on the host

Run a command on the hackamore host and take its **trimmed stdout** as the secret. Pass the
whole command as one quoted string; it is split on whitespace into a program and arguments.

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 gh-login \
  --command "gh auth token"
```

This is the source for tools that print a fresh token on demand — `gh auth token`, a cloud
CLI's token printer, your own helper script. Registration fails if the command exits
non-zero or prints nothing.

Unlike the other token sources, a `--command` source is **re-run every time the credential is
resolved**, not just at registration — so a rotated token is picked up automatically. See
[Rotating and short-lived credentials](#rotating-and-short-lived-credentials).

## AWS sources

AWS credentials are a *bundle* — an access key id, a secret access key, and an optional
session token — not a single string, so they have their own source kinds selected with
`--source`. hackamore signs each allowed AWS request with the bundle (SigV4); the agent never
holds AWS keys.

### `--source aws-static` — a static key bundle

Vault an explicit access-key pair. For long-lived IAM-user keys, omit the session token; for
temporary credentials you already hold, include it.

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 aws-deploy \
  --source aws-static \
  --access-key-id AKIA................ \
  --secret-access-key wJalr................................ \
  --session-token IQoJb3JpZ2luX2VjE...   # optional
```

The bundle is stored as-is; nothing is minted or rotated.

### `--source assume-role` — STS AssumeRole (minted and rotated)

Register a role to assume. hackamore calls STS `AssumeRole` to **mint** a short-lived bundle,
and a background refresher **re-mints it before it expires**, so the injected credential is
always fresh.

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 aws-deploy \
  --source assume-role \
  --role-arn arn:aws:iam::123456789012:role/agent \
  --region us-east-1 \
  --base env
```

- `--role-arn` and `--region` are required.
- `--base` is the credential that *signs* the AssumeRole call: `env` reads the host's
  `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (and `AWS_SESSION_TOKEN` if set); `instance`
  is an alias for the same host environment chain. The default is `env`.

This source needs a minting-capable credential store — see
[Provider-backed sources require a minting store](#provider-backed-sources-require-a-minting-store).

### `--source instance` — the host AWS environment chain

Vault a bundle from the hackamore host's `AWS_*` environment variables.

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 aws-deploy \
  --source instance
```

In this version `instance` reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and an
optional `AWS_SESSION_TOKEN` from the host environment and vaults them as a static bundle.

> **Not yet supported.** `instance` does not resolve credentials from EC2 instance metadata
> (IMDS) or shared-profile files; it reads the host `AWS_*` environment only.

See [AWS](services/aws.md) for wiring an AWS service to one of these credentials and signing
its requests.

## Sharing one credential across services

A single credential can back several services. The classic case is GitHub: the REST API and
git-over-HTTPS are two services with different hosts and different injection mechanisms, but
the same token authenticates both.

Register the token once under an id of your choosing:

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 gh-login \
  --command "gh auth token"
```

Then point both services at it by id. `github-api` injects it as a bearer header; `github-git`
injects it as the password half of HTTP Basic auth — same secret, two injection stances:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 github-api --credential gh-login
hackamore services add --admin-url http://127.0.0.1:9091 github-git --credential gh-login
```

Now there is one secret in the vault and one place to rotate it, regardless of how many
services reference it. See [GitHub](services/github.md) for the full GitHub setup.

## Rotating and short-lived credentials

hackamore is built to inject *fresh* credentials, not credentials it captured weeks ago.
There are three ways a credential stays current.

- **`--command` re-runs on use.** A `--command` token source executes its command each time
  the credential is resolved, so whatever the command prints *now* is what gets injected. Point
  it at a token printer (`gh auth token`, your own rotation helper) and rotation is automatic —
  no re-registration.
- **`--source assume-role` mints and rotates.** An assume-role credential is minted from STS on
  first use and **re-minted by a background refresher before it expires**, with no gap. The
  injected bundle is always within its validity window. If a mint fails, hackamore keeps serving
  the last good bundle until it too expires, then fails closed (the request is denied rather
  than forwarded with a stale credential).
- **Static sources are snapshots.** `--secret`, `--env`, `--file`, and `--source aws-static`
  read their material once, at registration. To rotate one of these, register it again under
  the same id — the new value replaces the old.

### Provider-backed sources require a minting store

Minting sources — `--source assume-role`, and any other source backed by a credential
provider — need hackamore to be running a **provider-backed (minting) credential store**.

The default in-memory vault accepts every token source (`--secret`, `--env`, `--file`,
`--command`) and the static `--source aws-static` and `--source instance` bundles. It does
**not** accept a runtime minting provider. Register an `assume-role` source against a server
running only the default vault and you get a clear `409 Conflict`:

```
register credential failed: HTTP 409 Conflict: this server's credential store does not
accept this credential source at runtime; an assume-role/instance source requires a
minting-capable store
```

To use minting sources, run hackamore with providers configured. See
[Getting started](getting-started.md) for configuring the server and
[AWS](services/aws.md) for the AWS specifics.

## Listing credentials

List the credential ids the server knows about:

```bash
curl http://127.0.0.1:9091/admin/credentials
```

```json
{
  "ids": ["aws-deploy", "gh-login", "k8s-token"]
}
```

The listing is **ids only**. No secret value, and no hint of a secret's shape, ever appears
here.

## Security

Credentials are the whole point of hackamore's trust model, so the handling is deliberate.

- **Secrets are never echoed.** Registering a credential returns `{ "id": "..." }` and
  nothing else. There is no admin endpoint that reads a secret back out.
- **The vault is the only home.** A resolved secret lives in hackamore's credential vault and,
  momentarily, in the outbound request hackamore signs or injects. It is never written to a
  response the agent receives, and never to an audit line.
- **Listing exposes ids only.** `GET /admin/credentials` returns the set of ids — never
  values, never shapes.
- **A redacted secret type guards the boundary.** Internally a secret is a dedicated type
  whose debug form renders as `Secret(***)`, so it cannot leak into a log line. The raw value
  is reachable only at the explicit, narrow point where hackamore injects it into an outbound
  request.
- **The admin API is operator-only.** Registering a credential, with its `--secret` / `--env`
  / `--file` / `--command` source, happens on the admin listener. Bind it to localhost and
  keep it unreachable from the agent's sandbox. The agent's only endpoint is the proxy; it can
  never register, list, or read a credential.

The host-reading sources (`--env`, `--file`, `--command`, the AWS `env`/`instance` bases) read
hackamore's *own* host — so a secret never has to pass through your shell or the network to be
registered. Treat the hackamore host as the trust boundary for these.

---

Related: [Concepts](concepts.md) · [Services overview](services/overview.md) ·
[GitHub](services/github.md) · [AWS](services/aws.md) · [Policies](policies.md) ·
[Running agents](running-agents.md) · [Reference](reference.md)
