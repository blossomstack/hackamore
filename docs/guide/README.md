# hackamore — operator guide

**hackamore** gives an untrusted AI agent just-in-time, policy-scoped access to real
services — GitHub, AWS, Kubernetes, or any OpenAPI/Smithy API — **without ever handing the
agent a real credential.** The agent runs in a sandbox whose only network egress is the
hackamore proxy. Every request is normalized, checked against a default-deny policy, and —
only if allowed — forwarded with a real, short-lived credential the agent never sees.

This guide is for the **operator**: the person who runs hackamore and decides what an agent
is allowed to do.

## Start here

New to hackamore? Read these in order:

1. **[Introduction](introduction.md)** — the problem, how hackamore works, and its trust model.
2. **[Core concepts](concepts.md)** — the vocabulary: services, credentials, sources, injections, policies.
3. **[Getting started](getting-started.md)** — a hands-on walkthrough: build a policy-scoped GitHub agent end to end.

## How-to guides

Task-focused recipes once you know the basics:

- **[Registering services](services/overview.md)** — presets vs. generic registration, and the preset catalog.
  - [GitHub](services/github.md) — the REST API (`gh`) and git push/pull, sharing one token.
  - [AWS](services/aws.md) — SigV4-signed access with static keys or assumed roles.
  - [Kubernetes](services/kubernetes.md) — a cluster's own API, discovered at registration.
  - [Generic OpenAPI / Smithy](services/generic.md) — bring your own API description.
- **[Credentials](credentials.md)** — where the real secret comes from (the Source axis), and sharing one credential across services.
- **[Writing policies](policies.md)** — rules, verbs, resources, and field conditions; how to lint and dry-run them.
- **[Running an agent](running-agents.md)** — mint a token, provision the sandbox, and put the agent to work.

## Reference

- **[Reference](reference.md)** — every CLI command, the admin API, the config file, and the policy schema, in tables.

## The one idea to take away

Two questions, answered independently, describe every service:

- **Source** — *where does the real upstream credential come from?* (a pasted secret, an env var, `gh auth token`, an assumed AWS role, …) → see [Credentials](credentials.md).
- **Injection** — *how does hackamore put it on the wire?* (a bearer header, HTTP Basic, AWS SigV4, …) → see [Registering services](services/overview.md).

One credential can back many services with different injections. The agent supplies neither —
it only ever holds a launch token bound to a [policy](policies.md).
