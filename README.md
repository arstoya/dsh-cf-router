# dsh-cf-router

A DSH plugin that pins Cloudflare-fronted API upstreams to the **fastest IPv4 edge** and keeps the TLS connection alive.

It is not a standalone proxy — it runs inside the DeepSeek Harness host process.

English · [简体中文](README.zh-CN.md)

## The problem

On hosts that prefer IPv6, a dual-stack domain resolves to both A and AAAA records and the OS picks AAAA first. If the IPv6 route leaves through a far-away edge, every request pays a long TLS handshake. Measured against a Cloudflare-fronted API endpoint on one home connection (2026-11-06):

| Path | Edge hit | TLS handshake | First byte |
| --- | --- | --- | --- |
| IPv6 (OS default) | LAX, Los Angeles | 0.92 – 2.68 s | 1.20 – 4.44 s |
| IPv4 | HKG, Hong Kong | 0.60 – 0.63 s | 0.81 – 0.85 s |
| IPv4 + connection reuse | HKG | 0 (reused) | **0.30 s** |

On Windows the IPv6 prefix policy (`::/0` = 40 > `::ffff:0:0/96` = 35) makes AAAA win whenever both exist, so this is not something a single `curl` flag fixes globally.

The plugin automates two things: **pick the right IP**, and **remember the connection**.

## How it works

1. Every `probeIntervalMs` (default 5 min) it sends `probeSamples` real requests to each IPv4 of the target domain and keeps the median of TCP + TLS + first-byte time.
2. The local HTTP proxy (default `127.0.0.1:8787`) pins outbound connections to the best IP through `https.Agent`'s `lookup`, while `servername` stays the domain — so SNI and certificate validation are unaffected.
3. Agents run with `keepAlive`, so follow-up requests to the same IP skip the handshake entirely.
4. After `failThreshold` consecutive failures an IP is dropped with a cooldown, and the pool is re-probed immediately.

Probing is two-stage: with many candidates it first does cheap TCP connects (`l1Concurrency` / `l1TimeoutMs`), then full HTTP measurement only on the fastest `l2TopN`. The candidate pool starts from DNS and can be widened by sampling Cloudflare's published IPv4 ranges (`discoverEnabled`) — DNS often returns only three addresses, which is not enough to find the genuinely fastest edge.

## Install

This is a DSH plugin, so it installs into a DSH profile.

**Option A — link a local checkout (recommended for development)**

```bash
git clone https://github.com/arstoya/dsh-cf-router.git
```

Add it to the profile's `package.json`:

```json
{
  "dependencies": {
    "dsh-cf-router": "link:/path/to/dsh-cf-router"
  },
  "dsh": {
    "profile": {
      "bundles": ["...", "dsh-cf-router"]
    }
  }
}
```

Restart DSH (or reload the profile) to apply.

**Option B — copy into the profile**

Copy this directory to `$DSH_HOME/profiles/<profile>/node_modules/dsh-cf-router`, then register `dsh-cf-router` in `dsh.profile.bundles` as above.

No `npm install` is needed. The plugin depends on `@deepseek-ai/dsh-tools` and `@deepseek-ai/schemastery`, which ship inside the DSH installation and are resolved by the host.

Verify the package before installing:

```bash
node scripts/doctor.mjs
```

## Configuration

Copy the block from [`cordis.patch.yml`](cordis.patch.yml) into your profile's patch layer. **You must change `targets` and `probePath`** — the shipped values are placeholders.

| Field | Default | Meaning |
| --- | --- | --- |
| `targets` | `[]` | Domains to optimize. Empty means the proxy answers `400 no_target` instead of forwarding anywhere. |
| `listenHost` / `listenPort` | `127.0.0.1` / `8787` | Local proxy binding |
| `probePath` | `/provider/v1/models` | Path used for probing. Any response counts as reachable (200 / 401 / 404 all fine). |
| `probeSamples` | `3` | Samples per IP; the median is used |
| `probeIntervalMs` | `300000` | Re-probe interval |
| `discoverEnabled` / `discoverPerRange` | `true` / `2` | Sample extra candidates from public CF ranges |
| `l1Concurrency` / `l1TimeoutMs` / `l2TopN` | `20` / `1200` / `10` | Two-stage probing |
| `coloAllow` | `[]` | Keep only IPs whose edge matches (e.g. `["HKG"]`); empty = no restriction |
| `idleSkipMs` | `1800000` | Skip probe rounds when idle this long (`0` = never skip) |
| `maxSockets` / `keepAlive` | `16` / `true` | Connection reuse |
| `failThreshold` / `cooldownMs` | `2` / `60000` | Failures before an IP is dropped, and how long it stays out |
| `ewmaAlpha` / `ewmaMaxMs` | `0.3` / `3000` | EWMA weight. `ewmaMaxMs` is a **classification threshold, not a filter**: samples above it are still recorded and still feed the EWMA, they are only counted separately (`*OverCap`) so the scoring layer can judge data quality |
| `firstByteTimeoutMs` | `60000` | Give up on an upstream that sends no first byte |
| `upstreamTimeoutMs` | `600000` | Overall upstream timeout (raise for long reasoning) |
| `allowDirectFallback` | `true` | Fall back to plain DNS when every candidate is cooling down |
| `routingMode` | `"auto"` | `auto` = optimize; `direct` = no pinning (still through the proxy, for isolating whether the optimizer itself is the problem) |
| `stateFile` | `""` | Where the runtime mode is persisted; empty = `$DSH_HOME/cf-router-state.json` |
| `verbose` | `false` | Log every forward and switch |

## Usage

Point the provider's base URL at the proxy, keeping the path:

```
before: https://api.example.com/v1/chat/completions
after:  http://127.0.0.1:8787/v1/chat/completions
```

The target is chosen from the `Host` header. When the `Host` is the local proxy address itself, the first entry of `targets` is used. You can also override per request with `x-cf-target: <domain>`.

**`x-cf-target` does not grant permission by itself.** Both `Host` and `x-cf-target` go through the same four-layer guard, and the resolved domain must be an exact match for an entry in `targets` — no suffix or wildcard matching:

| Layer | What it does |
| --- | --- |
| Authority parsing | Structured parse instead of `split(':')`. Rejects schemes, paths, queries, userinfo, IPv6 literals, IP literals, decimal/hex IP disguises, bad ports, multi-value Host, control characters. Normalizes case and trailing dots. |
| Allowlist | Exact match against normalized `targets`. Unconfigured domains are refused; there is no "forward any public host" behaviour. |
| Address class | Every resolved address must be globally routable. Loopback, RFC1918, link-local, CGNAT, multicast, reserved and documentation ranges are rejected — and a **mixed** result is rejected outright rather than picking a safe entry. |
| DNS rebinding | The validated resolution is the one used for connecting. A domain that resolves public first and private later is re-validated and refused on the second pass. |

`direct` mode is **not** an exemption — it changes IP pinning, not authorization. Both modes go through the same guard.

Refused targets return `403 target_not_allowed` (not in the allowlist) or `400 invalid_target` (malformed), and no upstream socket is opened.

If you genuinely need a private/local target (local development, trusted LAN), set `allowPrivateTargets: true`. The allowlist and format checks still apply.

Upstream connections are always made with `https.request` on port 443 with `servername` set, and there is no redirect-following code, so a request can never be silently downgraded or lose its `Authorization` header.

### Tools registered

| Tool | Purpose |
| --- | --- |
| `cf_router_status` | Proxy address, selected IP per domain, per-candidate metric breakdown (see below), success/failure counts, cooldown, recent switches, forwarding stats |
| `cf_router_probe` | Re-probe now (optionally one domain, optionally with a sample count) |
| `cf_router_reset` | Clear failure counters, cooldowns and connection pools |
| `cf_router_mode` | Switch `auto` / `direct` and persist it; without an argument it reports the current value |

### Configuration floors

Some values have hard floors. They are **not** silently applied — `GET /__router/status` reports both what you configured and what actually runs, under `configEffective`:

```json
"configEffective": {
  "firstByteTimeoutMs": { "configured": 300, "effective": 5000, "floorMs": 5000 }
}
```

| Field | Floor | Why |
| --- | --- | --- |
| `firstByteTimeoutMs` | 5000 ms | `setTimeout(0)` would abort every request immediately |
| `cooldownMs` | 1000 ms | shorter cooldowns cause flapping between candidates |
| `probeIntervalMs` | 30000 ms | probing every second would look like a scan to the edge |
| `healthCheckMs` | 5000 ms | same reason as above |
| `ewmaMaxMs` | 200 ms | classification threshold for `*OverCap`; below this every sample would be "over cap" |

**There are no upper bounds.** Long-running inference legitimately needs `firstByteTimeoutMs` in the hundreds of seconds; capping it would create a new silent rewrite of the very kind these floors are trying to expose.

All values are in milliseconds.

### routingMode resolution

`routingMode` has three sources, and `GET /__router/status` reports all of them under `routingModeSources`:

```json
"routingModeSources": {
  "configMode": "direct",
  "stateFileMode": "auto",
  "effectiveMode": "auto",
  "stateFileWins": true
}
```

Resolution at startup:

| stateFile | config | effective |
| --- | --- | --- |
| absent / no valid value | `direct` | `direct` |
| `auto` | `direct` | `auto` (stateFile wins) |
| `direct` | `auto` | `direct` (stateFile wins) |

When `stateFileWins` is true, the runtime value comes from a previous `setRoutingMode()` call. To make the configuration take effect again, call `resetRoutingMode` (it removes only the `routingMode` key and keeps any other state in the file) rather than deleting `stateFile` wholesale.

`direct` mode keeps background probing and health checks running, so switching back to `auto` can immediately use fresh measurements. This is deliberate, not a leak.

### Per-candidate metrics

Since v0.2.1 each candidate reports six independent EWMA values. Every one of them is measured from a single well-defined event pair — nothing is mixed, and a value that cannot be measured is `null` rather than guessed.

| Field | Start | End | Source |
| --- | --- | --- | --- |
| `tcpEwmaMs` | socket created | `connect` | probe |
| `tlsEwmaMs` | TCP connected | `secureConnect` | probe / fresh request |
| `probeTtfbEwmaMs` | request sent | response headers | probe |
| `probeTotalEwmaMs` | request sent | body end | probe |
| `freshTtfbEwmaMs` | request sent | response headers | real request, new connection |
| `reusedTtfbEwmaMs` | request sent | response headers | real request, reused connection |

`samples` counts how many samples fed each EWMA, plus `<metric>OverCap` counters for samples exceeding `ewmaMaxMs`.

**No raw observation is ever discarded.** Every TTFB value goes into its EWMA and into a 20-entry `recentTtfbMs` ring (with `source: probe | fresh | reused`), so you can tell "consistently slow" from "one big prompt". Large TTFB is a signal, not garbage — a model that genuinely takes 10s to start producing tokens is a real property of that route.

Routing score uses **`probeTtfbMs` only** — TCP/TLS are connection-establishment cost, and real-request TTFB is skewed by model prefill. When no probe median exists, the score is computed from the **median of clean samples in the raw ring**, not from the EWMA: a single 5000 ms outlier would otherwise drag a 120 ms line to ~2500 ms. If every sample is over-cap, the route is marked unscoreable (`null` score) rather than ranked on polluted data.

Two compatibility notes:

- `probeMs` / `probeBestMs` are retained but now mean **probe TTFB** (previously they included body download time).
- `ewmaMs` is **gone** — it was the mixed TLS-or-TTFB value this split removed.

### HTTP control endpoints

Useful for scripting without the tools:

| Endpoint | Effect |
| --- | --- |
Method semantics follow HTTP conventions: reads are `GET`, anything with a side effect is `POST`.

| Method | Path | Body | Effect |
| --- | --- | --- | --- |
| `GET` | `/__router/status` | — | Same payload as `cf_router_status` |
| `GET` | `/__router/mode` | — | Report current mode and its sources |
| `POST` | `/__router/mode` | `{"mode":"direct"}` | Switch mode and persist it |
| `POST` | `/__router/probe` | empty | Re-probe, then return status |
| `POST` | `/__router/reset` | empty | Clear runtime counters, cooldowns and pools |
| `POST` | `/__router/reset-mode` | empty | Clear only the persisted `routingMode` |

The legacy `GET /__router/mode?value=direct` form is rejected with `405` and `Allow: GET, POST` — the path genuinely supports both methods, only that *form* of mutating via GET is refused.

```bash
curl -X POST -H 'content-type: application/json'      -d '{"mode":"direct"}' http://127.0.0.1:8787/__router/mode
```

Error responses share one shape:

```json
{ "ok": false, "error": "invalid_value", "message": "mode must be auto or direct", "field": "mode" }
```

| Status | `error` | When |
| --- | --- | --- |
| 400 | `invalid_json` | body is not valid JSON / not an object |
| 400 | `missing_field` | required field absent (or `undefined`) |
| 400 | `unknown_field` | field not accepted by that endpoint |
| 400 | `invalid_value` | value present but out of range (e.g. `mode: null`) |
| 405 | `method_not_allowed` | wrong method; `Allow` header lists the accepted ones |
| 413 | `payload_too_large` | control body over 64 KiB |
| 415 | `unsupported_media_type` | body sent with a non-JSON `Content-Type` |
| 401 / 403 | `unauthorized` / `forbidden` | reserved for the auth layer (Issue #8) |

### Admin authentication

Mutating endpoints require a Bearer token:

```bash
node scripts/generate-admin-token.mjs --write /path/outside/repo/admin.token
# then in your profile patch:
#   adminTokenFile: /path/outside/repo/admin.token

curl -X POST -H 'content-type: application/json'      -H "Authorization: Bearer $(cat /path/outside/repo/admin.token)"      -d '{"mode":"direct"}' http://127.0.0.1:8787/__router/mode
```

**Do not put the token in `cordis.patch.yml`.** Use `adminTokenFile` pointing outside the repo. Only use `adminToken` directly if the file is untracked and you understand the risk. Tokens are compared with `crypto.timingSafeEqual` and are never echoed in logs, errors, or `/__router/status`.

**Safe default: no token configured means mutating endpoints are disabled** (`403 admin_token_not_configured`). They are not silently open. `allowUnauthenticatedLocalAdmin: true` is an explicit escape hatch for a trusted dev machine.

Read-only endpoints (`/status`, `/mode`) stay open by default because DSH tools and monitoring need them; set `adminProtectStatus: true` to require the token there too.

Three layers guard the endpoints:

| Layer | Behaviour | Why |
| --- | --- | --- |
| `Host` | When listening on loopback, only loopback/localhost hosts are accepted | Blocks DNS rebinding: an attacker domain resolving to 127.0.0.1 still sends its own name as `Host` |
| `Origin` | Any browser origin is refused unless listed in `adminAllowedOrigins` | Blocks cross-site calls from a page you happen to have open. Requests **without** an `Origin` header (curl, DSH, server scripts) are unaffected — their credential is the token |
| Rate limit | `adminRateLimit` per `adminRateWindowMs`, bucketed per source **and** read/write | Stops a runaway script without locking out valid operations: hammering writes never blocks reads |

In-process DSH tool calls (`cf_router_*`) do not go through HTTP and are not affected by any of this.

## Header handling

The proxy sits between the client and the upstream, so it has to respect the **end-to-end vs hop-by-hop** boundary (RFC 7230 §6.1) rather than deleting whatever looks unusual.

| Class | Examples | Behaviour |
| --- | --- | --- |
| End-to-end | `content-encoding`, `content-type`, `authorization`, `accept-encoding`, `x-request-id` | Forwarded untouched — dropping `content-encoding` would make gzip responses undecodable |
| Hop-by-hop | `connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `upgrade` | Stripped in both directions |
| Dynamically declared | anything named in `Connection: X-Internal` | Stripped too — that header is a per-hop declaration, so `X-Internal` must not leak |

`transfer-encoding` never reaches either side: framing is re-decided by Node from the actual stream. When the upstream declares chunked, a `content-length` alongside it is discarded rather than trusted.

`Expect: 100-continue` is **not forwarded**. The request body starts streaming immediately, so there is no window to negotiate a `100` with the upstream; passing the header through would leave the client waiting on a hop that no longer exists. `x-cf-target` is stripped before forwarding.

SSE additionally gets `x-accel-buffering: no`, `cache-control: no-cache` when absent, and `setNoDelay` — otherwise events arrive in batches instead of as they are produced.

## Limits

- IPv4 edge selection only. It does not touch the system network stack, `hosts`, or prefix policy.
- Only domains in `targets` are forwarded at all. `x-cf-target` selects among those; it cannot name a new one.
- Request bodies are not compressed (that would need upstream support).
- The proxy lives inside the host process and is rebuilt by `apply()` after a DSH restart.
- Requires the host-provided `@deepseek-ai/*` packages; it cannot run outside DSH.

## License

MIT
