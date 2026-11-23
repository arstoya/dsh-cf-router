# Reference: status, upgrading, troubleshooting

Three things people ask about, in one place. Field names, config keys, and error codes stay in their original form in both languages.

- [1. `statusSnapshot()` reference](#1-statussnapshot-reference)
- [2. Upgrading between versions](#2-upgrading-between-versions)
- [3. Troubleshooting](#3-troubleshooting)

---

## 1. `statusSnapshot()` reference

Returned by `cf_router_status` and `GET /__router/status`. 30 top-level fields.

### 1.1 Listener and mode

| Field | Type | Meaning |
| --- | --- | --- |
| `ok` | bool | Always `true` on a successful snapshot |
| `listen` | string | The address the proxy actually bound, e.g. `http://127.0.0.1:8787` |
| `baseUrlHint` | string | The same address, for pasting into an LLM `baseURL` |
| `statePath` | string | Absolute path of the state file in use (empty if none resolved) |
| `bootError` | string | Non-empty only when startup failed; usually an empty string |
| `routingMode` | `"auto"` \| `"direct"` | The mode currently in effect |
| `keepAlive` | bool | Whether agent connection reuse is on |

Echoed config and idle accounting, so you can confirm what is actually running without opening the patch file:

| Field | Meaning |
| --- | --- |
| `probeIntervalMs` | Background probe cadence |
| `healthCheckMs` | Health-tick cadence |
| `failThreshold` | Consecutive failures before an IP is cooled |
| `coloAllow` | Cloudflare colo allowlist (empty = accept all) |
| `idleSkipMs` | Idle window after which probing is skipped |
| `idleSkips` | How many probe rounds were skipped for idleness since startup |
| `lastRequestAt` | Timestamp of the last forwarded request, `null` if none |

`idleSkips` climbing while `requests` stays flat means the proxy is correctly staying quiet — not broken.

### 1.1b `allowedTargets` / `rejectedTargets` — the effective allowlist

| Field | Meaning |
| --- | --- |
| `allowedTargets` | Hostnames that survived normalisation and may be forwarded to |
| `rejectedTargets` | Entries dropped at load time, each with `{ value, reason }` |

**`allowedTargets: []` is the single most likely cause of "everything returns 403".** If your config lists targets but this is empty, the derived allowlist was never built — see §3.2.

`rejectedTargets` explains why an entry did not make it: `ip_literal`, `has_scheme`, `has_path_or_query`, `bad_port`, `control_or_space`, and so on. An entry landing here is silently unusable, so check it before wondering why a host is refused.

Matching is exact. `evil-example.com` does not match `example.com`; subdomains need their own entry.

### 1.2 `routingModeSources` — three sources, one effective value

Easily misread. `routingMode` is a *result*; this object explains where it came from.

| Field | Meaning |
| --- | --- |
| `configMode` | What the config file says |
| `stateFileMode` | What the persisted state says, or `null` if absent |
| `effectiveMode` | Which one actually won |
| `stateFileWins` | `true` when the state file overrode the config |

**Precedence**: a valid persisted `routingMode` beats the config. A missing or invalid one falls through to config. If neither exists, `auto`.

> `stateFileWins: false` with a non-null `stateFileMode` means the persisted value was present but invalid — it was rejected, not ignored.

### 1.3 `healthSummary` — how many IPs are in which state

| Field | Meaning |
| --- | --- |
| `counts.healthy` | Eligible for normal routing |
| `counts.cooling` | Serving a cooldown; not routable |
| `counts.half_open` | Cooldown expired, awaiting a recovery probe; not routable |
| `pendingRecovery` | Half-open entries with a probe currently in flight |
| `staleMetrics` | Entries whose metrics were flagged stale (excluded from scoring) |

`half_open` is **not** a softer kind of healthy. It means "was failing, has not yet proven itself". Only a successful recovery probe promotes it back to `healthy`.

### 1.4 `candidatePools` — one entry per host

| Field | Meaning |
| --- | --- |
| `host` | The upstream hostname |
| `size` | Current candidate count |
| `maxSize` | Configured `candidatePoolMaxSize` |
| `dnsCount` / `discoveredCount` | Split by source |
| `overCapacity` | `max(0, size - maxSize)` |
| `lastRefreshAt` | Last exploration timestamp, `null` if never |
| `ratios` | The normalised source ratios actually in effect |

**`overCapacity > 0` is not a bug.** DNS fallback entries and the current IP are protected from eviction, so the pool is allowed to exceed `maxSize`. The field reports the excess instead of hiding it.

`ratios.normalized: true` means your four ratios did not sum to 1 and were normalised. `ratios.degenerate: true` means all four were 0 and the pool fell back to DNS-only.

### 1.5 `connectionPools` — connection resource lifetime

| Field | Meaning |
| --- | --- |
| `activeCount` | Pools accepting new requests |
| `drainingCount` | Pools that refuse new requests but let in-flight ones finish |
| `totalInFlight` | Requests across all pools |
| `activePools[]` | `{ id, key, inFlight, peakInFlight }` per pool |
| `drainingPools[]` | `{ id, key, inFlight, drainingForMs, forcedReclaimInMs }` |
| `drainTimeoutMs` | Backstop for pools that never drain |

**`drainingPools[].forcedReclaimInMs`** is how long until that pool is destroyed regardless of in-flight requests. It reaching 0 means the request was cut — that is `drainTimeoutMs` working as designed, not a fault.

A key like `host|ip` can appear more than once with different `id`s: switching back to an IP creates a new generation rather than reusing a draining pool.

### 1.6 `switchHysteresis` — why a switch did or did not happen

| Field | Meaning |
| --- | --- |
| `host` | Upstream |
| `roundsBetter` | Consecutive rounds where another candidate was meaningfully faster |
| `lastSwitchAt` | Last switch timestamp, `null` if never |
| `minDwellTimeMs` | Configured dwell requirement |
| `dwellRemainingMs` | Time left before another *performance* switch is allowed |

An empty array means no performance switch has been considered yet. Hard-failure switches do not appear here — they are not subject to hysteresis.

### 1.7 `configEffective` — configured vs effective

Only fields with hard floors appear here.

```json
"firstByteTimeoutMs": { "configured": 300, "effective": 5000, "floorMs": 5000 }
```

`configured ≠ effective` means a floor was applied. It is reported rather than silent, so a value of 300 that becomes 5000 is visible instead of mysterious.

`ewmaMaxMs` carries an extra `note` explaining that it is a **grading threshold, not a filter** — samples above it are still recorded, just classified.

### 1.8 `statePersistence` — write throttling

| Field | Meaning |
| --- | --- |
| `dirty` | Changes pending, not yet written |
| `lastFlushAt` | Last successful write, `null` if never |
| `minIntervalMs` | `stateFlushMinIntervalMs` |

`dirty: true` is normal between flushes. It is only a problem if `lastFlushAt` stays unchanged for far longer than `minIntervalMs` — that suggests writes are failing (check `statePath` permissions).

### 1.9 `stateSchema` — file format version

| Field | Meaning |
| --- | --- |
| `version` | Schema version this build writes (currently 2) |
| `loadedFrom` | Schema version read from disk, `null` if no file |
| `path` | The file actually used |

`loadedFrom < version` means the file was migrated on read. Migration does **not** rewrite the file; it happens on the next intentional write.

### 1.10 `restore` — what startup recovered

| Field | Meaning |
| --- | --- |
| `hosts` | Hosts found in the state file |
| `candidates` | Candidate records restored |
| `stats` | Metric records restored |
| `demoted` | Cooling entries downgraded to `half_open` because their cooldown had expired |
| `dropped` | Malformed records discarded |

`demoted > 0` is expected after a long shutdown, not an error.

### 1.11 `stats` — this process only

| Field | Meaning |
| --- | --- |
| `requests` | Requests forwarded through the proxy |
| `errors` | Failures attributed to an IP |
| `timeouts` | First-byte or transfer timeouts |
| `switches` | Route switches |
| `directRequests` | Requests made while explicitly in `direct` mode |
| `directFallback` | Requests that fell back to `direct` while in `auto` |
| `byCategory` | Error counts split by classifier category |
| `bytesIn` / `bytesOut` | Payload volume |

These reset on restart. They are "since this process started", not lifetime totals.

### 1.12 `hosts` — per-candidate detail

`hosts[].candidates[]` carries `ip`, `colo`, `probeMs`, `probeOk`, `ok`, `fail`, `consecutiveFail`, `cooldownMsLeft`, `score`, and `health: { state, failureScore, halfOpenInFlight, recoveryProbeSuccesses, cooldownUntil, metricsStale, lastRecoveryAt }`.

`score: null` means not scorable (cooling, half-open, stale metrics, or no data).

---

## 2. Upgrading between versions

### 2.1 v0.2.0 → v0.2.1

Five breaking changes. Each one needs action.

**1. `x-cf-target` no longer names an arbitrary domain**

```yaml
# Before: any domain could be targeted per request
# After:  the domain must be listed in targets first
targets: ["api.example.com"]     # ← add every upstream you forward to
```

Anything not in `targets` returns `403 target_not_allowed`.

**2. Mutating admin endpoints require a Bearer token**

```bash
node scripts/generate-admin-token.mjs --write /path/outside/repo/admin.token
# then in the profile patch:
#   adminTokenFile: /path/outside/repo/admin.token
```

Without a token, `POST /__router/...` returns `403 admin_token_not_configured`. Read-only endpoints stay open unless you set `adminProtectStatus: true`.

**3. `ewmaMs` is gone**

Read `metrics.*EwmaMs` instead — six independent metrics replacing one conflated value.

**4. `GET` no longer mutates**

| Old | New |
| --- | --- |
| `GET /__router/probe` | `POST /__router/probe` |
| `GET /__router/reset` | `POST /__router/reset` |
| `GET /__router/mode?value=x` | `POST /__router/mode` with `{"mode":"x"}` |

Old forms return `405` with an `Allow` header.

**5. No unconditional `Access-Control-Allow-Origin`**

Set `corsAllowOrigin` if you genuinely need cross-origin browser access.

### 2.2 v0.2.1 → v0.2.2

No required action. Four behaviour changes to be aware of:

1. **Switch criterion** — was "30% faster this round". Now four gates: sample count (3) → improvement (15%) → consecutive rounds (2) → dwell time (120s). Old behaviour is still expressible: `minImprovementRatio: 0.3` + `consecutiveBetterRounds: 1` + `minDwellTimeMs: 0`.
2. **Switching no longer destroys the old pool** — it drains. `drainTimeoutMs` (120s) is the backstop. **Set it above your longest SSE.** A common mistake is leaving 120s while `firstByteTimeoutMs` is 180s.
3. **Candidates persist across refreshes** — previously re-randomised every round.
4. **13 new config fields** — all have defaults, no action needed.

### 2.3 v0.2.2 → v0.2.3

No required action. Four fixes:

1. Cooling IPs no longer bypass health filtering during L1 probing
2. Expired probe generations no longer write shared statistics
3. `retryable` is no longer always `true` (protocol errors are now correctly non-retryable)
4. Cooling retention uses the health-entry timestamp, not `lastProbeAt`

Plus one production-blocking fix: `apply()` now goes through `withDefaults`. Before this, the allowlist was never initialised on the production path and **every request returned 403**.

### 2.4 Rolling back

```powershell
# Plugin files
Copy-Item "<backup>\dsh-cf-router" "<profile>\node_modules\" -Recurse -Force
# Config
Copy-Item "<backup>\cordis.patch.yml" "<profile>\" -Force
```

Backups live under `.plugin-backups/<timestamp>/`. Rolling back the plugin does not require deleting the state file — an older build will refuse a newer schema rather than corrupt it (see §1.9).

---

## 3. Troubleshooting

### 3.1 Plugin does not load

**Symptom**: `plugin_manager list_plugins` has no `dsh-cf-router` entry at all — not `fiberPhase: failed`, simply absent. Port 8787 not listening. The DSH UI may report "invalid API key", which is a symptom: requests to 8787 fail, and the UI blames the key.

**Check**:

```bash
node --input-type=module -e "import('dsh-cf-router')"
```

If it reports `ERR_MODULE_NOT_FOUND: @deepseek-ai/dsh-tools`, the plugin is installed via `link:` and cannot reach the host's module tree.

**Fix**: ensure the plugin directory's own `node_modules/@deepseek-ai/` contains real directories for `dsh-tools` and its peers. A working sibling plugin is the reference:

```powershell
Copy-Item "<other-plugin>\node_modules\@deepseek-ai" "<plugin>\node_modules\" -Recurse
```

**Note**: HMR is not a file watcher. After copying new code you must toggle the plugin off and on; waiting will not reload it.

### 3.2 Every request returns `403 target_not_allowed`

**Check** `allowedTargets` in the snapshot. If it is `[]` while your config lists targets, the derived allowlist was never built.

**Cause**: the plugin was assembled through a path that skips `withDefaults`. Fixed in v0.2.3; on older builds the only workaround is to not use the proxy.

If `allowedTargets` is populated but your host is missing, the name is not an exact match. Matching is exact — `evil-example.com` does not match `example.com`, and subdomains need explicit entries.

### 3.3 Admin endpoint returns `403 admin_token_not_configured`

No `adminToken` or `adminTokenFile` is set, so mutating endpoints are disabled by design. Generate one:

```bash
node scripts/generate-admin-token.mjs --write /path/outside/repo/admin.token
```

Set `adminTokenFile` to that path. Do **not** put the token in `cordis.patch.yml` — it would enter version control.

### 3.4 Long SSE streams get cut

**Check**:

| Field | Where |
| --- | --- |
| `drainTimeoutMs` | `connectionPools.drainTimeoutMs` |
| `firstByteTimeoutMs` | `configEffective.firstByteTimeoutMs.effective` |

If `drainTimeoutMs` is lower than how long your stream actually runs, a route switch will reclaim the pool mid-stream. Raise it. It is a backstop, not a normal path — the pool is destroyed immediately once in-flight requests finish.

`drainingPools[].forcedReclaimInMs` counting down to 0 is the moment of the cut.

### 3.5 A request failed but nothing was penalised

Expected for several categories. `stats.byCategory` shows what the classifier decided:

| Category | Penalises IP? |
| --- | --- |
| `client_abort` | No — the client left, the route is fine |
| `auth` (401/403) | No — your credentials are the problem |
| `rate_limit` (429) | No — throttling is not a broken route |
| `upstream` (5xx) | No — the server answered, the path works |
| `network` / `timeout` | Yes |

If `errors` grows but `fail` on every candidate stays 0, check `byCategory` — the failures are probably not attributable to routes.

### 3.6 Switching too often, or never

**Too often**: check `switchHysteresis[].roundsBetter`. Non-zero and rising means candidates are genuinely alternating; consider raising `consecutiveBetterRounds` or `minDwellTimeMs`. If `roundsBetter` is 0 but switches happen, those are hard-failure switches — look at `switches[].reason`.

**Never**: `minSamples` may exceed what one probe round produces. With `probeSamples: 3`, `minSamples: 3` means one round is enough; `minSamples: 6` requires two. Also confirm `switches[].reason` shows `initial` having fired at least once.

### 3.7 State file keeps being rewritten / never written

| Symptom | Cause |
| --- | --- |
| `dirty: true` forever, `lastFlushAt` frozen | Write failing — check `statePath` permissions and disk space |
| File grows unexpectedly | `candidatePoolMaxSize` too high for the host count |
| File absent | No state change yet, or `stateFile` resolves to an unwritable path |

Writes are throttled to one per `stateFlushMinIntervalMs` (default 60s) and forced on shutdown.
