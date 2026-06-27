# Generic services

Any service with an OpenAPI or Smithy description can be registered without a preset. You give
it a logical name, point it at the upstream, tell hackamore where to read the description, and
choose how to inject the credential.

All commands assume the admin API at `http://127.0.0.1:9091`.

## The command

```bash
hackamore services add --admin-url http://127.0.0.1:9091 <name> \
  --upstream-base <url> \
  --idl <openapi|smithy> \
  --source-file <path> | --source-url <url> \
  --inject <kind> \
  --credential <id> | --secret <inline>
```

| Flag | Meaning | Default |
| --- | --- | --- |
| `<name>` | logical service name (also the `target` in policy) | — (required) |
| `--upstream-base` | the real upstream base URL | — (required) |
| `--host` | inbound `Host` routing pattern | the upstream host |
| `--idl` | description format: `openapi` or `smithy` | `openapi` |
| `--source-file` | path to the description file | — |
| `--source-url` | URL to fetch the description from | — |
| `--inject` | injection mechanism (see below) | `passthrough` |
| `--credential` | reference an existing vault credential id | — |
| `--secret` | inline secret, vaulted under the service name | — |
| `--header-name` | header name for `--inject header` | `X-API-Key` |
| `--username` | username for `--inject basic` | `x-access-token` |
| `--region` / `--service` | region and service for `--inject sigv4` | — |
| `--address` | consumer-facing address surfaced to the agent | — |

Supply exactly one of `--source-file` / `--source-url`, and — for any injecting stance —
exactly one of `--credential` / `--secret`. `passthrough` takes neither.

## Choosing an injection

| `--inject` | When to use it | Extra flags |
| --- | --- | --- |
| `bearer` | the API expects `Authorization: Bearer <token>` | `--credential` or `--secret` |
| `header` | the API expects a token in a named header (e.g. `X-API-Key`) | `--header-name`, `--credential` or `--secret` |
| `basic` | the API expects HTTP Basic auth | `--username`, `--credential` or `--secret` |
| `sigv4` | the API expects AWS SigV4 signing | `--region`, `--service`, `--credential` (an AWS bundle) |
| `passthrough` | hackamore filters but injects nothing; the agent's own header is forwarded | none |

For `sigv4`, the credential must be an AWS bundle registered via
[Credentials](../credentials.md) (an `aws-static` / `assume-role` / `instance` source); the
access key id rides in the bundle, so you pass only `--region` and `--service`.

## Worked example: an API behind an `X-API-Key` header

Suppose a REST API at `https://api.example.com` authenticates with an API key in the
`X-API-Key` header and ships an OpenAPI description.

First register the API key as a credential:

```bash
hackamore credentials add --admin-url http://127.0.0.1:9091 example-key \
  --secret "$EXAMPLE_API_KEY"
```

Then register the service, injecting that key into the `X-API-Key` header:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 example \
  --upstream-base https://api.example.com \
  --idl openapi --source-file ./example-openapi.json \
  --inject header --header-name X-API-Key \
  --credential example-key
```

Now an agent allowed to reach `example` sends plain requests through hackamore; on allow,
hackamore adds `X-API-Key: <the real key>` before forwarding. The agent never sees the key.

You can also vault the secret inline in one step with `--secret` instead of `--credential`:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 example \
  --upstream-base https://api.example.com \
  --idl openapi --source-file ./example-openapi.json \
  --inject header --header-name X-API-Key \
  --secret "$EXAMPLE_API_KEY"
```

## Where the policy vocabulary comes from

The description you import becomes the service's model, and that model is the vocabulary your
policy rules name. For an OpenAPI service the verbs are HTTP methods and the resources are API
paths; for a Smithy service the verbs are operation names. A rule for the `example` service
above might allow only reads:

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["example"],
        "verbs": [ { "type": "Method", "value": { "method": "GET" } } ],
        "resources": ["v1/widgets", "v1/widgets/**"],
        "conditions": []
      }
    }
  ]
}
```

Because the model is imported at registration, you can lint a policy against it on the running
server and confirm the verbs and resources you named actually exist. See
[Policies](../policies.md) for the rule language and linting, and [Concepts](../concepts.md)
for how a request becomes an action.

## Note: SigV4 for non-preset AWS services

A generic registration with `--inject sigv4` is exactly how you reach an AWS service that
isn't one of the bundled presets — import its Smithy description with
`--idl smithy --source-file <service-2.json>` and sign with `--region` / `--service`. See
[AWS](./aws.md) for the SigV4 model and credential sources.

See [Services overview](./overview.md) and the sibling pages: [GitHub](./github.md),
[AWS](./aws.md), [Kubernetes](./kubernetes.md).
