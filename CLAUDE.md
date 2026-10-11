# CLAUDE.md

Guide for agents that work in this repository.

## What this is

`autumn-plugin-cloudflare`: an Autumn (`autumn-web` 0.8) plugin for apps
behind Cloudflare. Design: one Tower layer
(`docs/adr/0001-identity-layer.md`). Planning and acceptance criteria:
`docs/planning.md` and issue #1.

## Layout

| Path | Content |
|---|---|
| `src/lib.rs` | Public API and `__private` (items for tests only). |
| `src/plugin.rs` | `CloudflarePlugin`, `PeerSource`: options and wiring. |
| `src/layer.rs` | `CloudflareLayer`: edge check, identity, headers, lock, secret. |
| `src/core.rs` | Pure core. Each function has a Verus twin. |
| `src/ranges.rs` | `IpRange`, `CloudflareRanges`, built-in list, safety rules. |
| `src/refresh.rs` | Range refresh from the Cloudflare API. |
| `src/headers.rs` | Cloudflare header parsing and removal. |
| `src/request.rs` | `CloudflareRequest` extractor. |
| `src/cache_tags.rs` | `CacheTags` response part. |
| `src/purge.rs` | `CloudflareCache` purge client, `ApiToken`, `PurgeError`. |
| `verification/core.rs` | Verus model and proofs of the pure core. |
| `verification/verify.sh` | Runs the proofs. |
| `tests/` | Unit, property, layer, purge, refresh, plugin, and end-to-end tests. |
| `examples/hello.rs` | Full app. The end-to-end tests run it. |

## Rules

- Process: SPEC, PROOF, RED, GREEN, REFACTOR. Write a test for each behavior.
- To change a function in `src/core.rs`:
  1. Change the twin in `verification/core.rs`.
  2. Run `verification/verify.sh`.
  3. Update `tests/spec_conformance.rs`.
- Before a commit, run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`, and `cargo test`.
- Keep line coverage at 85% or more.
- Do not use `unwrap()` in `src/`. Do not use `unsafe`.
- Write comments and docs in ASD-STE100 style: simple words, active voice,
  one idea in each sentence. Keep them short.

## Important facts

- Plugin layers run inside Autumn's `TrustedProxiesLayer` and outside rate
  limits, CSRF, maintenance mode, and handlers.
- The Autumn rate limiter does not read `ResolvedClientIdentity`. It
  resolves the IP again from `ConnectInfo` and `X-Forwarded-For`. So a
  verified request must have all three set to the visitor IP.
- The access log, metrics, tenancy, method override, and the `/mcp`
  endpoint run outside plugin layers. They show the edge IP.
- `CF-Connecting-IPv6` wins only over a Pseudo IPv4 (Class E)
  `CF-Connecting-IP`. A Worker can set `CF-Connecting-IPv6`.
- Range lists from the API must be public and small. Outbound URLs must
  use `https` (loopback `http` is for tests).
- Each `no_redirect()` request builds a new client, so it uses a new
  connection.
- The README examples compile as doctests (`src/lib.rs`).
- Outbound calls use `autumn_web::http::Client` with `no_retry()` and
  `no_redirect()`. A purge is not sent twice, and the token never follows
  a redirect.
- Autumn checks the `Host` header. End-to-end tests set
  `AUTUMN_SECURITY__TRUSTED_HOSTS__HOSTS`.
