# hackamore

JIT, policy-scoped access for **untrusted** AI agents to external services (GitHub
first). The agent runs in a sandbox whose only network egress is the hackamore proxy; it
never holds a real credential. The proxy normalizes each request into an `Action`, a
reusable policy engine decides allow/deny, and on allow the proxy injects a real
short-lived credential the agent never sees.

## Architecture

Three planes, with the policy engine deliberately decoupled from the data plane so it
can be reused by any proxy (hudsucker, Envoy `ext_authz`, …) in future:

- **`hackamore-policy`** — the reusable engine. Pure: `decide(&Action, &Policy) -> Verdict`. No
  I/O, no HTTP, no async. The `Action`/`Verdict` contract (in `hackamore-models`) is the
  portability boundary.
- **`hackamore-control`** — the control plane: agent→policy registry, short-lived token minting,
  the credential vault (resolves a `CredentialRef` to a real secret), and the audit
  sink. Secrets never leave this crate as plain `String`.
- **`hackamore-gateway`** — the data plane. A reverse proxy that translates an HTTP request into
  an `Action`, calls `hackamore_policy::decide`, enforces the `Verdict` (deny → 403; allow →
  inject credential + forward), and emits an audit event. Confinement (forcing the
  agent's egress through the gateway) is the sandbox's job — see horsie's nono caps.
- **`hackamore-cli`** — the `hackamore` binary: serve the gateway + admin API, mint tokens.
- **`hackamore-models`** — fluorite-generated protocol/contract types.
- **`hackamore-tests`** — full-stack e2e tests.

## Design philosophy

**Semantic types over convenient types.** Types should encode domain intent, not just
data shape. If reusing an existing type would let a caller pass something semantically
wrong, define a new type. A credential `Secret` is not a `String`; an `AgentId` is not
a `String`. The name of a type is part of its contract.

**Make illegal states unrepresentable.** Use sum types (enums / tagged unions) to
eliminate invalid combinations at the type level. Prefer exhaustive `match` over
runtime guards — the compiler should enforce completeness, not tests.

**Deep modules.** Narrow public interface, deep implementation. The policy engine's
entire public surface is one function; whatever it uses inside (custom matcher today,
Cedar tomorrow) is hidden. Every abstraction boundary should ask: what mistakes does
this prevent, and what complexity does this hide?

**Compile-time over runtime enforcement.** Validate invariants at construction, not at
call sites. Lints, type constraints, and the type system catch mistakes before
production.

**Functional / immutable by default.** Prefer pure functions and combinator chains
over mutation and shared state. Mutation should be local and obvious. The policy
engine is pure; all side effects (credential injection, audit, forwarding) live in the
data plane.

**Fail closed.** The default decision is deny. A missing token, unknown agent, unknown
target, or any ambiguity denies the action. There is no bypass.

**Protocol types are not storage types.** Wire formats evolve at the speed of the
interface contract; persisted structures at the speed of data migrations. Never
conflate them.

## Protocol models (fluorite)

Use [fluorite](https://github.com/blossomstack/fluorite) to generate all protocol message
types — any data transported between modules or between server and clients (the
`Action`/`Verdict` contract, audit events, the control-plane mint API).

- Define schemas as `.fl` files under `fluorite/` at the workspace root.
- The `hackamore-models` crate runs `fluorite_codegen` in `build.rs` and exposes generated types
  via `models::<package>::*`.
- Generated types automatically derive `Debug`, `Clone`, `PartialEq`, `Serialize`,
  `Deserialize`, `JsonSchema`.
- Add hand-written convenience methods in `models/src/lib.rs` (not in the schema).
- **Never use fluorite for persisted data structures** (credential vault entries, the
  in-memory token table). Those are owned by `hackamore-control` and evolve independently.

## Tests

Unit tests live alongside source files under `#[cfg(test)] mod tests` in the same
`.rs` file. Full-stack e2e tests that spin up the gateway + a mock upstream go in the
`tests/` crate.

## Lint / fmt

Workspace lints are in `Cargo.toml`; each crate inherits via `[lints] workspace =
true`. Production code denies `unwrap_used`, `expect_used`, `panic`, and
`wildcard_enum_match_arm`. Test code opts out per-file with
`#![cfg_attr(test, allow(...))]`.

Pre-PR gate (also `make check`):

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```
