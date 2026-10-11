# Planning: Autumn plugin for Cloudflare

This document records the planning phase. It uses three methods:
brainstorming, reverse brainstorming, and six thinking hats.

## Goal

Run an Autumn (`autumn-web` 0.8) application safely behind Cloudflare.
Add one line to the app: `.plugin(CloudflarePlugin::new())`.

## Facts from research

- Autumn core already has Turnstile (bot protection), R2 (S3 storage),
  and Cloudflare DNS-01 (ACME). The plugin does not repeat them.
- `App::run` wraps the router in `TrustedProxiesLayer`. This layer puts
  `ResolvedClientIdentity` (client IP, host, scheme) in the request
  extensions. `ClientAddr`, `ClientScheme`, and `ClientHost` read it.
- Layers from `AppBuilder::layer` run inside `TrustedProxiesLayer`. They
  run outside rate limiting, maintenance mode, bot protection, CSRF,
  trusted hosts, and the handlers. A plugin layer can correct the
  identity before these features run.
- The rate limiter does not read `ResolvedClientIdentity`. It resolves
  the client IP again from the peer (`ConnectInfo`) and
  `X-Forwarded-For`. (Found during the RED phase.)
- The access log, metrics, and tenancy layers run outside plugin layers.
  They use the identity from `[security.trusted_proxies]`.
- Cloudflare sends `CF-Connecting-IP` (one IP), `CF-Connecting-IPv6`
  (Pseudo IPv4 "Overwrite Headers" mode), `CF-Visitor`
  (`{"scheme":"https"}`), `X-Forwarded-Proto`, `CF-Ray`, `CF-IPCountry`,
  and `CF-Worker` (zone of a Worker subrequest).
- Cloudflare publishes its edge ranges at `https://www.cloudflare.com/ips`
  and `GET https://api.cloudflare.com/client/v4/ips`. On 2026-10-11 the
  list had 15 IPv4 and 7 IPv6 ranges. The broadest are `/13` and `/29`.
- Purge API: `POST /zones/{zone_id}/purge_cache`, Bearer token. Bodies:
  `files`, `tags`, `prefixes`, `hosts`, or `purge_everything`. The limit
  is 100 items in one request. The API returns `429` when the rate limit
  is reached.
- `Cache-Tag` rules: a tag has 1 byte or more, printable ASCII, no
  spaces. Commas separate tags. Purge accepts tags of 1,024 characters
  or less. The full header value is 16 KB or less.

## 1. Brainstorming

Possible designs:

1. **Origin plugin (Rust layer).** Check that the TCP peer is a
   Cloudflare edge. Then set the client identity from Cloudflare headers.
2. **Configuration only.** Tell users to put Cloudflare ranges in
   `[security.trusted_proxies]`. No code.
3. **Workers shim.** Run `autumn-edge` capsules in a Cloudflare Worker.
4. **Tunnel manager.** Start `cloudflared` from the plugin.

Feature ideas:

- Real client IP from `CF-Connecting-IP`, only from a Cloudflare peer.
- Support Pseudo IPv4: prefer `CF-Connecting-IPv6`.
- Remove spoofed `cf-*` headers when the peer is not Cloudflare.
- Origin lock: reject peers that are not Cloudflare.
- Shared-secret header from a Cloudflare Transform Rule.
- Typed `CloudflareRequest` extractor: ray ID, country, scheme, worker.
- Load balancer between Cloudflare and Autumn: check the IP that
  Autumn resolved, not the socket peer.
- Refresh the ranges from the Cloudflare API.
- Cache purge client: URLs, tags, prefixes, hosts, everything.
- `CacheTags` response part that checks the Cloudflare rules.

## 2. Reverse brainstorming

Question: "How can we make this plugin fail?" Each answer gives a guard.

| How to cause failure | Guard |
|---|---|
| Correct only `ResolvedClientIdentity`. The rate limiter resolves the IP again from the peer and `X-Forwarded-For`. All visitors share the limit of the edge. | For a verified request, also set `ConnectInfo` and `X-Forwarded-For` to the visitor IP. Remove `X-Real-IP`. The e2e test checks the real rate limiter. |
| A client sends `CF-Connecting-IP` directly to the origin. | Use the header only when the peer is in a Cloudflare range. Remove all `cf-*` headers and `true-client-ip` from other peers. |
| Only configure `[security.trusted_proxies]` with Cloudflare ranges. A Worker request comes from a Cloudflare IP. Autumn skips it and trusts the attacker's `X-Forwarded-For` entry. | Read `CF-Connecting-IP`, which Cloudflare always overwrites. Do not walk `X-Forwarded-For`. |
| Bind Autumn on `[::]`. IPv4 peers appear as `::ffff:a.b.c.d`. The range check fails. | Convert IPv4-mapped IPv6 addresses to IPv4 before the check. |
| Turn on Pseudo IPv4 "Overwrite Headers". `CF-Connecting-IP` is a fake `240.x` address. All IPv6 users share rate limits. | Prefer a valid `CF-Connecting-IPv6`. |
| Send a bad value in `CF-Connecting-IP`. | Ignore it. Use the peer IP. |
| Put a load balancer in front. The peer is never Cloudflare. | `PeerSource::Resolved` checks the IP that Autumn resolved. |
| Point an attacker's own Cloudflare zone at the origin IP. The peer is a real Cloudflare IP. | Optional shared-secret header. Compare in constant time. Remove it before the handler. |
| Leak the shared secret into handlers or logs. | Remove the header in all cases. `Debug` output hides the secret. |
| Turn on the origin lock. Load balancer health checks fail. | `allow(cidr)` lets listed peers pass. Their `cf-*` headers are still removed. |
| A changed or bad API answer for the range refresh opens `0.0.0.0/0`. | Reject a list that is empty, that has a bad entry, or that has a range broader than `/8` (IPv4) or `/16` (IPv6). Keep the last good list. |
| Send 256 `/8` ranges. Each range passes the width check. | Reject a list with more than 1,024 ranges, or a list that covers more than one `/8` (IPv4) or one `/16` (IPv6). |
| Send `10.0.0.0/8` from a changed API answer. Internal hosts become edges. | Reject API ranges that touch private, loopback, link-local, or shared (CGNAT) addresses. Require `https` for the range URL. |
| A Worker in another zone sets `CF-Connecting-IPv6`. | Use `CF-Connecting-IPv6` only when `CF-Connecting-IP` is a Pseudo IPv4 (Class E) address. |
| A client sends `X-Forwarded-Host` through Cloudflare. `ClientHost` and absolute URLs use it. | For a verified request, take the host from `Host`. Remove `X-Forwarded-Host` and `Forwarded`. |
| A timing difference shows the length of the shared secret. | The compare loop reads the secret length. It does not stop early. |
| An `http` API base sends the token in clear text. | Reject an API base that is not `https`. Only a loopback host can use `http`. |
| A purge error shows a URL that holds a signed token. | The error gives the position of the item, not the item. |
| The range refresh fails at startup. The app stops. | Log a warning. Keep the built-in list. |
| Purge 250 URLs in one call. The API rejects it. | Send batches of 100 or less. |
| Batch 2 of 3 fails. The caller does not know what was purged. | The error has the number of items that were purged. |
| The API returns `429`. | `PurgeError::RateLimited` with the `Retry-After` value. |
| The token appears in a log or a panic message. | `ApiToken` has no `Display`. Its `Debug` shows `***`. |
| A tag has a comma or a space. Cloudflare splits it. Purge misses. | `CacheTags::new` rejects it. |
| A response has too many tags. Cloudflare ignores the header. | Reject a header value longer than 16 KB. |
| Register the plugin twice. Two layers run. | The default `Plugin::name` makes the second call a no-op. |

## 3. Six thinking hats

**White hat (facts).** User layers run before every Autumn feature that
uses the client IP, except the access log, metrics, and tenancy.
Cloudflare publishes its ranges and API. Purge has a limit of 100 items.

**Red hat (feelings).** Users want "add one line, get the real IP".
They fear that a wrong proxy setting opens a spoofing hole. A plugin
that is safe by default feels better than a page of config.

**Black hat (risks).** The built-in range list becomes old. The access
log shows the edge IP. A too-strict origin lock blocks health checks.
Another Cloudflare zone can reach the origin. Purge rate limits.

**Yellow hat (benefits).** No fork of `autumn-web`. Rate limits, CSRF,
bot protection, and maintenance allow lists use the real IP. The pure
core (range check, decision, IP choice, tag rules, batches) is easy to
test and to prove.

**Green hat (ideas).** Range refresh. Shared-secret header. Pseudo IPv4.
Later: a Workers shim for `autumn-edge` capsules, Authenticated Origin
Pulls guide, Tunnel guide.

**Blue hat (process).** Decision: design (1), origin plugin. Order of
work: Verus spec and proof for the pure core, then failing tests (RED),
then code (GREEN), then refactor. Then agents review the code for
different concerns, and we fix the findings.

## Decision

Use an origin plugin with a Tower layer. See
[ADR 0001](adr/0001-identity-layer.md).

## Acceptance criteria

- **AC1. Install.** `.plugin(CloudflarePlugin::new())` is the full
  setup. The plugin declares a `PluginContract` for `autumn-web` 0.8. A
  second registration is a no-op.
- **AC2. Edge check.** The plugin checks the peer IP against the
  Cloudflare IPv4 and IPv6 ranges. The default list is a snapshot of the
  published list. IPv4-mapped IPv6 peers work. `PeerSource::Resolved`
  checks the IP that Autumn resolved.
- **AC3. Real identity.** For a request from Cloudflare, `ClientAddr` is
  the visitor IP. The plugin prefers a valid `CF-Connecting-IPv6`, then
  `CF-Connecting-IP`, then the peer IP. `ClientScheme` comes from
  `CF-Visitor`, then `X-Forwarded-Proto`. Autumn rate limits use the
  visitor IP.
- **AC4. Anti-spoofing.** For a request that is not from Cloudflare, the
  plugin removes all `cf-*` headers and `true-client-ip`. It does not
  change the identity.
- **AC5. Extractor.** `CloudflareRequest` gives the visitor IP, ray ID,
  country, scheme, and worker zone. It is present only for requests from
  Cloudflare.
- **AC6. Origin lock.** With `lock_origin(true)`, the plugin returns
  `403` to peers that are not Cloudflare and not in `allow(...)`.
- **AC7. Shared secret.** With `require_header(name, value)`, a request
  is from Cloudflare only if the header matches. The compare takes
  constant time. The plugin removes the header before the handler.
- **AC8. Range refresh.** With `refresh_ranges(interval)`, the plugin
  gets the list from the Cloudflare API at startup and then at each
  interval. It rejects unsafe lists and keeps the last good list.
- **AC9. Cache tags.** `CacheTags` adds a `Cache-Tag` header. It rejects
  tags that break the Cloudflare rules.
- **AC10. Cache purge.** `CloudflareCache` purges URLs, tags, prefixes,
  hosts, or everything. It sends batches of 100 or less. Errors give the
  API messages, the `Retry-After` time, and the number of purged items.
  The token never appears in `Debug` output.
- **AC11. Quality.** Verus proofs for the pure core. Spec conformance
  property tests. Unit, integration, and end-to-end tests. Line coverage
  85% or more. `clippy` pedantic and nursery clean. No `unwrap()` and no
  `unsafe` in `src/`. Docs in ASD-STE100 style. README, CLAUDE.md, ADR,
  CI (format, lint, docs, test, coverage, MSRV, Verus), pre-commit hook.

## Scope

Out of scope:

- Workers, Tunnel, and Authenticated Origin Pulls (mTLS is in Autumn
  core). These are possible later work.
- Turnstile, R2, and DNS-01. Autumn core has them.

## Review

After REFACTOR, five agents reviewed the code: security, framework
integration, tests and proofs, API and docs (ASD-STE100), and
robustness. The fixes are in the "Reverse brainstorming" table above.
The review also changed two Verus twins (`choose_client_ip` and
`constant_time_eq`) and added limits to the README.

Known limits (documented in the README):

- The access log, metrics, tenancy, and method override run outside the
  plugin. They see the edge IP.
- With the Autumn `mcp` feature, the `/mcp` endpoint runs outside plugin
  layers.
- Unix sockets and Cloudflare Tunnel show every peer as loopback. The
  plugin cannot verify them.
