# Changelog

All notable changes to this project. Versions follow the milestone plan tracked in the issue tracker.

---

## [0.2.2] — 2026-11-21

**Milestone: 健康管理与智能选路** — issues #9, #10, #11, #12.

Test count 237 → **458**, all passing. Four modules with separated responsibilities:

```
#9   what happened / is this IP currently usable
#11 which IPs are worth keeping, probing, evicting
#12 the connection resources behind each IP and their lifetime
#10 among usable candidates, which one to prefer
```

### ⚠️ Behaviour changes

| Change | Detail |
| --- | --- |
| Switch criterion | Was "30% faster this round → switch". Now four gates: sample count (3) → improvement (15%) → consecutive rounds (2) → dwell time (120s). Old behaviour is still expressible: `minImprovementRatio: 0.3` + `consecutiveBetterRounds: 1` + `minDwellTimeMs: 0` |
| Route switching no longer destroys the old connection pool | It drains; in-flight requests finish. `drainTimeoutMs` (120s) is the backstop |
| Candidates persist across refreshes | Previously re-randomised every round, so a good IP could vanish after one refresh |
| 12 new config fields | 8 candidate-pool, 1 drain timeout, 4 hysteresis |

### Added

- **Unified error classifier (#9)** — `classifyError()` answers only three things: what happened, is it retryable, should it penalise the IP and by how much. It does not touch statistics, state, or routing. Classification uses stable error codes, never fuzzy message matching. Three timeout phases are distinguished (`connect` / `first_byte` / `transfer`); first-byte timeout is weighted 0.5 because it may be model prefill rather than a broken route.
- **Health state machine (#9)** — `healthy` / `cooling` / `half_open`. Transitions are deliberately restricted: no jumping straight from healthy to half-open, no returning from cooling without verification. `penaltyUntil` is preserved for compatibility and only ever changes through `transitionHealth()`.
- **Half-open recovery probe (#9)** — cooldown expiry no longer restores full eligibility. A real probe runs first; success refreshes the routing metrics from that round rather than smoothing on top of stale EWMA.
- **Candidate pool (#11)** — four sources (current / historical / dns / exploration) with quota-based selection, bounded exploration, capacity and TTL pruning.
- **Connection pool lifecycle (#12)** — `active` / `draining` / `destroyed`, per-`host|ip` with multiple generations allowed so a switch back does not queue behind a draining pool.
- **Switch hysteresis (#10)** — sample count, improvement ratio, consecutive rounds, dwell time. Hard failures bypass all four.

### Fixed

- **Upstream response errors were unhandled** — `upRes` had no `error` listener, so a response that died mid-body produced an uncaught exception and hung the process (reproduced: a test ran 400 s without returning).
- **DNS candidates bypassed health filtering** — a cooling IP was re-probed on every refresh, wasting requests and contradicting "cooling does not participate in routing".
- **First refresh skipped exploration** — `makePool(now)` made the pool look freshly refreshed, so `discoverEnabled: true` produced zero discovered candidates.
- **`resetAll` did not clear the candidate pool** — only `__resetForTest` did.

### Notes

- `pruneCandidatePool` reports `overCapacity` instead of deleting protected entries. If DNS returns more addresses than `candidatePoolMaxSize`, the pool exceeds the cap on purpose — a number is not worth losing the fallback.
- Evicting a candidate does not delete its `ipStats`. Performance history has its own lifecycle; a returning IP resumes with its previous EWMA rather than being treated as new.
- The 24-hour real-network soak the plan asks for cannot run locally. All verification is fixture-level; parameters are the plan's initial experimental values, not calibrated against live Cloudflare.

---

## [0.2.1] — 2026-11-21

**Milestone: 正确性与安全基础** — issues #1–#8, plus follow-ups #17/#18.

Test count went from 0 (where `npm test` merely ran `doctor`) to **237**, all passing, zero third-party dependencies.

### ⚠️ Breaking changes — read before upgrading

| # | Change | What to do |
| --- | --- | --- |
| 1 | `x-cf-target` can no longer name an arbitrary domain — it selects **among** `targets` | Add every upstream you forward to into `targets`; everything else gets `403` |
| 2 | Mutating admin endpoints now require a Bearer token | Run `scripts/generate-admin-token.mjs --write <path outside repo>` and set `adminTokenFile`. Without a token they return `403 admin_token_not_configured` |
| 3 | `ewmaMs` is gone, replaced by six independent metrics under `metrics` | Update dashboards to read `metrics.*EwmaMs` |
| 4 | `GET /__router/{probe,reset}` and `GET /__router/mode?value=` return `405` | Use `POST`; `Allow` header lists what each path accepts |
| 5 | No unconditional `Access-Control-Allow-Origin` | Set `corsAllowOrigin` if you genuinely need cross-origin browser access |

### Added

- **Test infrastructure (#1)** — `node:test` harness with a local HTTPS fixture, injected clock, DNS, upstream port and TLS options. No real Cloudflare node, no API key, no network.
- **Six independent latency metrics (#3)** — `tcpEwmaMs`, `tlsEwmaMs`, `probeTtfbEwmaMs`, `probeTotalEwmaMs`, `freshTtfbEwmaMs`, `reusedTtfbEwmaMs`. Each is measured from one well-defined event pair; a value that cannot be measured is `null`, never guessed. Raw TTFB observations are kept in a 20-entry ring so "consistently slow" can be told apart from "one big prompt".
- **SSRF guard (#6)** — four layers: structured authority parsing, exact-match allowlist, address-class filtering on every resolved IP, and rebinding protection. Rejected targets open **no upstream socket at all**, verified by connection counters rather than status codes.
- **Admin authentication (#8)** — Bearer token (`crypto.randomBytes` + `timingSafeEqual`), Host check against DNS rebinding, Origin check that leaves non-browser clients alone, and per-source/per-method rate limiting.
- **Unified control API (#7)** — `GET /__router/{status,mode}`, `POST /__router/{mode,probe,reset,reset-mode}`, one error shape (`invalid_json` / `missing_field` / `unknown_field` / `invalid_value` / `method_not_allowed` / `payload_too_large` / `unsupported_media_type`).
- **Config observability (#17)** — `configEffective` reports both the configured value and the value actually in effect, so a floor silently rewriting 300 → 5000 is now visible instead of invisible.
- **`routingMode` sources (#18)** — `routingModeSources` shows `configMode`, `stateFileMode`, `effectiveMode` and `stateFileWins`, plus `resetRoutingMode` to clear only the persisted value without deleting the whole state file.

### Fixed

- **Stale route overwrite (#2)** — request callbacks no longer write `currentIp` at all; `switchRoute()` is the single entry point, and a request whose generation has gone stale may update statistics but not drive a switch. Covers the A→B→A case where a plain IP comparison would have looked correct.
- **Conflated latency samples (#3)** — probe timing used to end at `res.end`, so "probe latency" included body download; TLS handshake time was averaged together with HTTP TTFB; fresh and reused connections shared one EWMA. All three separated.
- **Upstream not cancelled on client disconnect (#4)** — `res.on('close')` only cleared a timer. Measured: the upstream used to write all 8 MB after the client left; now it stops at ~81 KB.
- **Header boundary (#5)** — hop-by-hop fields are stripped in both directions, including any field named in `Connection:`. End-to-end fields such as `content-encoding` are preserved byte-for-byte.

### Notes

- `Expect: 100-continue` is **not forwarded** — the body starts streaming immediately, so there is no window to negotiate with the upstream. Documented rather than silently mishandled.
- `Trailer` is stripped; HTTP trailers are not forwarded.
- `allowPrivateTargets` (default `false`) exists for local development and trusted LANs. It relaxes the **address class** layer only; format checks and the allowlist still apply.
- Known remaining gap: `resetAll()` / `dropAgents()` still call `agent.destroy()` directly, which can affect other in-flight requests on the same Agent. Tracked as #12.

---

## [0.1.0] — 2026-11-20

First public release. IPv4 edge selection with two-stage probing, IP pinning via `https.Agent` lookup, keep-alive reuse, and automatic failover.
