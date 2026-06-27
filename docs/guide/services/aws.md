# AWS

hackamore reaches AWS through per-service presets named `aws:<svc>` for the six bundled
services:

`aws:ec2` · `aws:s3` · `aws:sts` · `aws:iam` · `aws:lambda` · `aws:dynamodb`

Each pins its host, its bundled Smithy model, and SigV4 signing. The agent signs its requests
with a **dummy** AWS credential and never holds your real account keys.

All commands assume the admin API at `http://127.0.0.1:9091`.

## Register an AWS service

First register the real AWS credential bundle, then register the service that references it:

```bash
# Register a static AWS key pair as a credential bundle.
hackamore credentials add --admin-url http://127.0.0.1:9091 aws-prod \
  --source aws-static \
  --access-key-id AKIAEXAMPLE \
  --secret-access-key "$AWS_SECRET_ACCESS_KEY"

# Register the EC2 service, referencing the bundle by id.
hackamore services add --admin-url http://127.0.0.1:9091 aws:ec2 \
  --credential aws-prod
```

Or register the credential inline with `--auth-source` in one step:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 aws:ec2 \
  --auth-source aws-static \
  --access-key-id AKIAEXAMPLE \
  --secret-access-key "$AWS_SECRET_ACCESS_KEY" \
  --auth-id aws-prod
```

The `aws:ec2` preset pins:

- host `ec2.us-east-1.amazonaws.com`, upstream `https://ec2.us-east-1.amazonaws.com`
- the bundled EC2 Smithy model (its operations become your policy vocabulary, e.g.
  `RunInstances`, `DescribeInstances`)
- injection **sigv4** with `service = ec2` and `region = us-east-1`
- the `aws` tool hint, so a provisioned agent configures the `aws` CLI / SDK

### Choosing a region

The region defaults to `us-east-1`. Override it with `--region`; it threads into both the
host and the signature:

```bash
hackamore services add --admin-url http://127.0.0.1:9091 aws:s3 \
  --region eu-west-1 --credential aws-prod
# host becomes s3.eu-west-1.amazonaws.com, signature region eu-west-1
```

## The SigV4 model: the agent never holds real keys

AWS requests are authenticated by signing them with an access key. hackamore keeps the real
key out of the sandbox entirely:

1. When the agent is provisioned, it receives a **dummy** AWS access key pair (in its
   `~/.aws` config). The dummy key is not your account credential.
2. The agent's `aws` CLI / SDK signs each request with that dummy key, exactly as it normally
   would, and sends it to hackamore.
3. hackamore **verifies** the dummy signature (proving the request came from this agent),
   runs the request through the policy, and on allow **re-signs** the request with your real
   account credential before forwarding it to AWS.

The real access key id and secret never enter the sandbox; the agent only ever sees the
dummy. Because hackamore re-signs from scratch, the upstream request carries your real access
key id, not the dummy one.

## Credential sources for AWS

The SigV4 injection references a credential **bundle** — an access key id, a secret access
key, and (for temporary credentials) a session token. Register the bundle with one of these
sources:

| Source | What it is | Session token |
| --- | --- | --- |
| `aws-static` | a static key pair you supply | optional (pass `--session-token`) |
| `assume-role` | STS `AssumeRole` against a role ARN; minted and rotated | yes (minted) |
| `instance` | the hackamore host's `AWS_*` environment variables | if present in the environment |

```bash
# A long-lived IAM-user key pair (no session token).
hackamore credentials add --admin-url http://127.0.0.1:9091 aws-prod \
  --source aws-static --access-key-id AKIA... --secret-access-key ...

# Assume a role; the resulting temporary credentials carry a session token and rotate.
hackamore credentials add --admin-url http://127.0.0.1:9091 aws-role \
  --source assume-role \
  --role-arn arn:aws:iam::123456789012:role/reader \
  --region us-east-1
```

Temporary credentials (from `assume-role`) carry a session token, which hackamore includes in
the signature it sends upstream. See [Credentials](../credentials.md) for the full source
reference.

## Example policy

AWS verbs are the **operation name** the request states, carried as a named-action verb. EC2,
for example, reads the operation from the request as `RunInstances`, `DescribeInstances`, and
so on. The following policy allows two read operations and leaves a destructive one denied by
default:

```json
{
  "rules": [
    {
      "effect": "Allow",
      "matches": {
        "targets": ["aws-ec2"],
        "verbs": [
          { "type": "Action", "value": { "id": "DescribeInstances" } },
          { "type": "Action", "value": { "id": "DescribeImages" } }
        ],
        "resources": [],
        "conditions": []
      }
    }
  ]
}
```

`TerminateInstances` matches no `Allow` rule, so it is denied — the default. The target name
is `aws-ec2` (the `:` in the preset name becomes `-` in the registered service name; check
with `GET /admin/services`).

## Limitations

- **One region per service.** An `aws:<svc>` service is pinned to a single region. To reach
  the same AWS service in a second region, register it again under a different name with
  `--region`.
- **Six bundled services.** Only `ec2`, `s3`, `sts`, `iam`, `lambda`, and `dynamodb` are
  presets. For any other AWS service, register it generically with a Smithy description (see
  [Generic](./generic.md)) and `--inject sigv4`.
- **Assume-role / instance need a minting-capable store.** The default in-memory vault
  accepts an `aws-static` bundle directly. An `assume-role` or `instance` source mints and
  rotates credentials, which requires a credential store configured for that — see
  [Credentials](../credentials.md). A static-only store rejects those sources at registration.

See [Services overview](./overview.md) and the sibling pages: [GitHub](./github.md),
[Kubernetes](./kubernetes.md), [Generic](./generic.md).
