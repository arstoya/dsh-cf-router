# dsh-cf-router

A DSH plugin that pins Cloudflare-fronted API upstreams to the **fastest IPv4 edge** and keeps the TLS connection alive.

It is not a standalone proxy — it runs inside the DeepSeek Harness host process.

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
| `ewmaAlpha` / `ewmaMaxMs` | `0.3` / `3000` | EWMA of real TTFB; samples above the cap are ignored so prompt prefill is not mistaken for network latency |
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

Upstream connections are always made with `https.request` on port 443 with `servername` set, and there is no redirect-following code, so a request can never be silently downgraded or lose its `Authorization` header.

### Tools registered

| Tool | Purpose |
| --- | --- |
| `cf_router_status` | Proxy address, selected IP per domain, per-candidate probe medians / TTFB EWMA / success and failure counts / cooldown, recent switches, forwarding stats |
| `cf_router_probe` | Re-probe now (optionally one domain, optionally with a sample count) |
| `cf_router_reset` | Clear failure counters, cooldowns and connection pools |
| `cf_router_mode` | Switch `auto` / `direct` and persist it; without an argument it reports the current value |

### HTTP control endpoints

Useful for scripting without the tools:

| Endpoint | Effect |
| --- | --- |
| `GET /__router/status` | Same payload as `cf_router_status` |
| `GET /__router/probe` | Re-probe, then return status |
| `GET /__router/reset` | Reset counters and pools |
| `GET /__router/mode` | Report current mode |
| `GET /__router/mode?value=direct` | Switch mode |

## Limits

- IPv4 edge selection only. It does not touch the system network stack, `hosts`, or prefix policy.
- Only domains in `targets` (or named by `x-cf-target`) are optimized; everything else is forwarded as-is.
- Request bodies are not compressed (that would need upstream support).
- The proxy lives inside the host process and is rebuilt by `apply()` after a DSH restart.
- Requires the host-provided `@deepseek-ai/*` packages; it cannot run outside DSH.

## License

MIT
