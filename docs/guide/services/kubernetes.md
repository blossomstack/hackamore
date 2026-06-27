# Kubernetes

The `k8s` preset registers a Kubernetes cluster's API server as a service. Unlike the other
presets, it ships no bundled model — a cluster's vocabulary is its own (versioned, extended by
CRDs), so hackamore **fetches the cluster's OpenAPI live at registration** and uses that as
the service's model.

All commands assume the admin API at `http://127.0.0.1:9091`.

## Register a cluster

The simplest form reads your kubeconfig and registers the current context:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 k8s
```

The `k8s` preset pins:

- the cluster API server URL as the upstream, and its host for routing
- the cluster's OpenAPI (fetched live from `<server>/openapi/v2`) as the model
- injection **bearer**: hackamore sends the real cluster token as
  `Authorization: Bearer <token>` upstream
- the `kubernetes` tool hint, so a provisioned agent writes a kubeconfig

## What registration needs

To fetch the cluster OpenAPI, hackamore needs three things: the **cluster URL**, a **bearer
token** to authenticate the fetch, and the **CA** to trust the cluster's TLS. Each is resolved
from your kubeconfig, and each can be overridden with an explicit flag:

| Flag | Overrides | Default |
| --- | --- | --- |
| `--cluster <url>` | the kubeconfig `cluster.server` | from kubeconfig |
| `--kubeconfig <path>` | which kubeconfig file is read | `$KUBECONFIG`, else `~/.kube/config` |
| `--context <name>` | which context is used | the file's `current-context` |
| `--token <t>` | the user's auth token | from kubeconfig |
| `--ca <path>` | the cluster CA PEM | the kubeconfig CA (inline or path) |
| `--insecure-skip-tls-verify` | enables skipping TLS verification | from the context |

For example, fetch against an explicit cluster and token, trusting a CA file:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 k8s \
  --cluster https://prod.example.com:6443 \
  --token "$KUBE_TOKEN" \
  --ca /etc/k8s/ca.pem
```

Registration fails closed: if the cluster can't be reached, the token is missing, or the
OpenAPI doesn't come back as JSON, nothing is registered.

## Authentication: bearer token or exec plugin

hackamore supports two kubeconfig auth shapes, and turns each into a credential it can replay:

- **A bearer `token`** in the kubeconfig user becomes a static credential carrying that token.
- **An `exec` plugin** (`user.exec`, e.g. `aws eks get-token` or `kubelogin`) becomes a
  command credential: hackamore re-runs the plugin to mint a fresh token, so the token rotates.

This means an EKS cluster whose kubeconfig uses `aws eks get-token` works directly — hackamore
re-runs `aws eks get-token` to keep the token current.

By default the credential is registered under the id `k8s`; override it with `--auth-id`. To
reference a credential you already registered instead, pass `--credential <id>` and hackamore
will use it verbatim rather than reading the kubeconfig user.

## Example policy

Kubernetes is RESTful, so its verbs are HTTP methods and its resources are API paths. The
following policy allows reading pods in the `dev` namespace (`get` and `list` are both `GET`)
while leaving deletes denied by default:

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["k8s"],
        "verbs": [ { "type": "Method", "value": { "method": "GET" } } ],
        "resources": ["api/v1/namespaces/dev/pods", "api/v1/namespaces/dev/pods/**"],
        "conditions": []
      }
    }
  ]
}
```

A `DELETE` to any pod matches no `Allow` rule and is denied. To scope to a whole namespace,
use a trailing `**`:

```json
{
  "effect": "Allow",
  "matches": {
    "targets": ["k8s"],
    "verbs": [ { "type": "Method", "value": { "method": "GET" } } ],
    "resources": ["api/v1/namespaces/dev/**"],
    "conditions": []
  }
}
```

See [Policies](../policies.md) for the full rule language.

## Limitation: bearer / exec auth only

hackamore authenticates to the cluster with a **bearer token or an exec-plugin token only**.
A kubeconfig user that authenticates with a client certificate (mTLS) is not yet supported —
registration fails closed if the selected user has no token and no exec plugin.

Note also that an exec plugin's declared `env` entries are not yet threaded into the replayed
command; the plugin runs with hackamore's inherited process environment. A plugin that depends
on extra environment variables beyond that is not yet supported.

See [Services overview](./overview.md) and the sibling pages: [GitHub](./github.md),
[AWS](./aws.md), [Generic](./generic.md).
