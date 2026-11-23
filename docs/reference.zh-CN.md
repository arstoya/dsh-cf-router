# 参考：状态字段、升级、故障排查

三件最常被问的事放一处。字段名、配置键、错误码在中英文里都保持原样。

- [一、`statusSnapshot()` 字段说明](#一statussnapshot-字段说明)
- [二、版本升级](#二版本升级)
- [三、故障排查](#三故障排查)

---

## 一、`statusSnapshot()` 字段说明

`cf_router_status` 与 `GET /__router/status` 返回同一份数据，30 个顶层字段。

### 1.1 监听与模式

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `ok` | bool | 快照成功时恒为 `true` |
| `listen` | string | 实际绑定的地址，如 `http://127.0.0.1:8787` |
| `baseUrlHint` | string | 同一地址，可直接粘进 LLM 的 `baseURL` |
| `statePath` | string | 正在使用的状态文件绝对路径（没解析到则为空） |
| `bootError` | string | 仅启动失败时非空，正常是空串 |
| `routingMode` | `"auto"` \| `"direct"` | 当前生效的模式 |
| `keepAlive` | bool | 是否启用连接复用 |

配置回显与空闲记账，用于不开 patch 文件也能确认实际在跑什么：

| 字段 | 含义 |
| --- | --- |
| `probeIntervalMs` | 后台探测周期 |
| `healthCheckMs` | 健康巡检周期 |
| `failThreshold` | 连续失败多少次进入冷却 |
| `coloAllow` | Cloudflare colo 白名单（空 = 全接受） |
| `idleSkipMs` | 空闲多久后跳过探测 |
| `idleSkips` | 启动以来因空闲跳过的探测轮数 |
| `lastRequestAt` | 最近一次转发请求的时刻，无则 `null` |

`idleSkips` 在涨而 `requests` 不动，说明代理在正确地保持安静——不是坏了。

### 1.1b `allowedTargets` / `rejectedTargets` — 生效的白名单

| 字段 | 含义 |
| --- | --- |
| `allowedTargets` | 通过规范化、允许转发的域名 |
| `rejectedTargets` | 装载期被剔除的条目，每条含 `{ value, reason }` |

**`allowedTargets: []` 是「所有请求都 403」最可能的原因。** 如果配置里写了 targets 而这里是空，说明派生白名单从未构建——见 §3.2。

`rejectedTargets` 解释某个条目为什么没通过：`ip_literal`、`has_scheme`、`has_path_or_query`、`bad_port`、`control_or_space` 等。落在这里的条目是静默不可用的，所以在疑惑某个 host 为什么被拒之前先看它。

匹配是**精确**的。`evil-example.com` 不会命中 `example.com`；子域需要单独列一条。

### 1.2 `routingModeSources` — 三个来源，一个生效值

**容易误读**。`routingMode` 是*结果*，这个对象解释它从哪来。

| 字段 | 含义 |
| --- | --- |
| `configMode` | 配置文件写的值 |
| `stateFileMode` | 持久化文件里的值，没有则 `null` |
| `effectiveMode` | 实际胜出的那个 |
| `stateFileWins` | 状态文件是否覆盖了配置 |

**优先级**：有效的持久化 `routingMode` 压过配置；缺失或非法则回落到配置；都无则 `auto`。

> `stateFileWins: false` 且 `stateFileMode` 非 null，说明持久化值**存在但非法、被拒绝**，不是被忽略。

### 1.3 `healthSummary` — 各状态的 IP 数量

| 字段 | 含义 |
| --- | --- |
| `counts.healthy` | 可参与正常选路 |
| `counts.cooling` | 冷却中，不可选路 |
| `counts.half_open` | 冷却已到期、等恢复探测，不可选路 |
| `pendingRecovery` | 正在探测中的 half_open 条目数 |
| `staleMetrics` | 指标被标脏的条目（不参与评分） |

`half_open` **不是**「轻微一点的 healthy」，它的意思是「出过问题、还没证明自己好了」。只有恢复探测成功才会升回 `healthy`。

### 1.4 `candidatePools` — 每个 host 一条

| 字段 | 含义 |
| --- | --- |
| `host` | 上游域名 |
| `size` | 当前候选数 |
| `maxSize` | 配置的 `candidatePoolMaxSize` |
| `dnsCount` / `discoveredCount` | 按来源拆分 |
| `overCapacity` | `max(0, size - maxSize)` |
| `lastRefreshAt` | 最近探索时刻，从未分析则为 `null` |
| `ratios` | 实际生效的归一化比例 |

**`overCapacity > 0` 不是 bug。** DNS 兜底条目与当前线路受保护、不会被淘汰，所以池子允许超过 `maxSize`。这个字段是如实报告超出量，不是隐藏问题。

`ratios.normalized: true` 说明四个比例之和不为 1、已归一化；`ratios.degenerate: true` 说明四个都是 0、退化成「只用 DNS 兜底」。

### 1.5 `connectionPools` — 连接资源生命周期

| 字段 | 含义 |
| --- | --- |
| `activeCount` | 接受新请求的池 |
| `drainingCount` | 拒绝新请求、让在飞请求跑完的池 |
| `totalInFlight` | 所有池的在飞请求总数 |
| `activePools[]` | 每池 `{ id, key, inFlight, peakInFlight }` |
| `drainingPools[]` | 每池 `{ id, key, inFlight, drainingForMs, forcedReclaimInMs }` |
| `drainTimeoutMs` | 永不排空的池的强制回收兜底 |

**`drainingPools[].forcedReclaimInMs`** 是「还有多久不管在飞请求直接销毁」。它归零的那一刻就是请求被切断——这是 `drainTimeoutMs` 按设计生效，不是故障。

同一个 `host|ip` 可能出现多条、`id` 不同：切回该 IP 时会新建一代，而不是复用在排空的旧池。

### 1.6 `switchHysteresis` — 为什么切了 / 为什么没切

| 字段 | 含义 |
| --- | --- |
| `host` | 上游 |
| `roundsBetter` | 连续多少轮有别的候选明显更快 |
| `lastSwitchAt` | 上次切换时刻，从未切则为 `null` |
| `minDwellTimeMs` | 配置的驻留要求 |
| `dwellRemainingMs` | 距离允许下一次**性能**切换还有多久 |

空数组表示还没评估过性能切换。硬故障切换不出现在这里——它不受迟滞约束。

### 1.7 `configEffective` — 配置值 vs 生效值

只列出有硬下限的字段。

```json
"firstByteTimeoutMs": { "configured": 300, "effective": 5000, "floorMs": 5000 }
```

`configured ≠ effective` 表示下限被应用了。它是**报告**而不是静默——你写的 300 变成 5000 这件事是可见的，不是神秘的。

`ewmaMaxMs` 多一个 `note`，说明它是**分级阈值而不是过滤阈值**：超过它的样本照样记录，只是被单独分类。

### 1.8 `statePersistence` — 写盘节流

| 字段 | 含义 |
| --- | --- |
| `dirty` | 有变化待写 |
| `lastFlushAt` | 上次成功写入，从未则为 `null` |
| `minIntervalMs` | `stateFlushMinIntervalMs` |

两次 flush 之间 `dirty: true` 是正常的。只有当 `lastFlushAt` 远超过 `minIntervalMs` 都不更新时才是问题——那说明写盘一直失败（查 `statePath` 权限）。

### 1.9 `stateSchema` — 文件格式版本

| 字段 | 含义 |
| --- | --- |
| `version` | 本程序写入的 schema 版本（当前 2） |
| `loadedFrom` | 从磁盘读到的版本，无文件则 `null` |
| `path` | 实际使用的文件 |

`loadedFrom < version` 表示读的时候做了迁移。迁移**不重写文件**，真正落盘要等下一次有意的写入。

### 1.10 `restore` — 启动恢复了什么

| 字段 | 含义 |
| --- | --- |
| `hosts` | 状态文件里的 host 数 |
| `candidates` | 恢复的候选记录数 |
| `stats` | 恢复的指标记录数 |
| `demoted` | 因冷却已过期而被降级为 `half_open` 的条目数 |
| `dropped` | 被丢弃的非法记录数 |

长时间关机后重启，`demoted > 0` 是预期行为，不是错误。

### 1.11 `stats` — 仅本进程

| 字段 | 含义 |
| --- | --- |
| `requests` | 经代理转发的请求数 |
| `errors` | 归因到 IP 的失败数 |
| `timeouts` | 首字节或传输超时 |
| `switches` | 路由切换次数 |
| `directRequests` | 明确处于 `direct` 模式时的请求 |
| `directFallback` | `auto` 下回落到 `direct` 的请求 |
| `byCategory` | 按分类器类别拆分的错误数 |
| `bytesIn` / `bytesOut` | 载荷字节量 |

重启即清零。这些是「本进程启动以来」，不是累计总量。

### 1.12 `hosts` — 逐候选明细

`hosts[].candidates[]` 含 `ip`、`colo`、`probeMs`、`probeOk`、`ok`、`fail`、`consecutiveFail`、`cooldownMsLeft`、`score`，以及 `health: { state, failureScore, halfOpenInFlight, recoveryProbeSuccesses, cooldownUntil, metricsStale, lastRecoveryAt }`。

`score: null` 表示不可评分（冷却、half_open、指标标脏，或没有数据）。

---

## 二、版本升级

### 2.1 v0.2.0 → v0.2.1

五条破坏性变更，每条都需要动作。

**1. `x-cf-target` 不再能指定任意域名**

```yaml
targets: ["api.example.com"]     # ← 要转发的上游都必须先进这里
```

不在 `targets` 里的一律 `403 target_not_allowed`。

**2. 修改型管理端点必须带 Bearer Token**

```bash
node scripts/generate-admin-token.mjs --write /仓库外路径/admin.token
# 然后在 profile patch 里配 adminTokenFile
```

没配 Token 时 `POST /__router/...` 返回 `403 admin_token_not_configured`。只读端点默认开放，除非设 `adminProtectStatus: true`。

**3. `ewmaMs` 已移除**

改读 `metrics.*EwmaMs` —— 六个独立指标取代了一个混合值。

**4. `GET` 不再产生副作用**

| 旧 | 新 |
| --- | --- |
| `GET /__router/probe` | `POST /__router/probe` |
| `GET /__router/reset` | `POST /__router/reset` |
| `GET /__router/mode?value=x` | `POST /__router/mode` + `{"mode":"x"}` |

旧写法返回 `405` 并带 `Allow` 头。

**5. 不再无条件发送 `Access-Control-Allow-Origin`**

确需跨源浏览器访问时配 `corsAllowOrigin`。

### 2.2 v0.2.1 → v0.2.2

无必做动作。四条行为变化需要知道：

1. **切换判据** —— 从「单轮快 30%」改为四道闸：样本量 3 → 改善 15% → 连续 2 轮 → 驻留 120s。旧行为可等价表达：`minImprovementRatio: 0.3` + `consecutiveBetterRounds: 1` + `minDwellTimeMs: 0`。
2. **切换不再销毁旧连接池** —— 改为排空，`drainTimeoutMs`（默认 120s）是兜底。**必须设成大于你最长 SSE 的时长。** 常见错误是留着 120s 而 `firstByteTimeoutMs` 是 180s。
3. **候选跨轮持久** —— 不再每轮重随机。
4. **新增 13 个配置项** —— 都有默认值，无需动作。

### 2.3 v0.2.2 → v0.2.3

无必做动作。四项修复：

1. Cooling 的 IP 不再在 L1 探测阶段绕过健康过滤
2. 过期的探测代次不再写入共享统计
3. `retryable` 不再恒为 `true`（协议错误现在正确标为不可重试）
4. Cooling 保留期改用健康状态进入时刻，不再用 `lastProbeAt`

外加一个生产阻断级修复：`apply()` 现在走 `withDefaults`。在此之前，生产路径的白名单从未初始化，**所有请求都 403**。

### 2.4 回滚

```powershell
Copy-Item "<备份>\dsh-cf-router" "<profile>\node_modules\" -Recurse -Force
Copy-Item "<备份>\cordis.patch.yml" "<profile>\" -Force
```

备份在 `.plugin-backups/<时间戳>/`。回滚插件**不需要**删状态文件——旧版本遇到新 schema 会拒绝使用而不是破坏它（见 §1.9）。

---

## 三、故障排查

### 3.1 插件不加载

**症状**：`plugin_manager list_plugins` 里完全没有 `dsh-cf-router` —— 不是 `fiberPhase: failed`，是整条不存在。8787 无监听。DSH 界面可能报「密钥无效」，那是**症状**：请求打 8787 失败，界面把原因归到了 key 上。

**检查**：

```bash
node --input-type=module -e "import('dsh-cf-router')"
```

若报 `ERR_MODULE_NOT_FOUND: @deepseek-ai/dsh-tools`，说明插件是用 `link:` 装的、够不到宿主的模块树。

**修复**：确保插件目录自己的 `node_modules/@deepseek-ai/` 里有 `dsh-tools` 及其 peer 的**实体目录**。可参照同机能工作的插件：

```powershell
Copy-Item "<能工作的插件>\node_modules\@deepseek-ai" "<插件目录>\node_modules\" -Recurse
```

**注意**：HMR 不是文件监视器。复制新代码后必须把插件关掉再打开，等是等不来的。

### 3.2 所有请求返回 `403 target_not_allowed`

**检查**快照里的 `allowedTargets`。如果配置里写了 targets 而这里是 `[]`，说明派生白名单从未构建。

**原因**：插件通过跳过 `withDefaults` 的路径装配。v0.2.3 已修；旧版无法绕过，只能不用代理。

如果 `allowedTargets` 有值但你访问的 host 不在里面，是名字没对上。匹配是**精确**的——`evil-example.com` 不会命中 `example.com`，子域也必须显式列出。

### 3.3 管理端点返回 `403 admin_token_not_configured`

没配 `adminToken` 或 `adminTokenFile`，修改型端点在设计上被禁用。生成：

```bash
node scripts/generate-admin-token.mjs --write /仓库外路径/admin.token
```

把 `adminTokenFile` 指向该路径。**不要**把 Token 写进 `cordis.patch.yml`——那会进版本库。

### 3.4 长 SSE 被切断

**检查**：

| 字段 | 位置 |
| --- | --- |
| `drainTimeoutMs` | `connectionPools.drainTimeoutMs` |
| `firstByteTimeoutMs` | `configEffective.firstByteTimeoutMs.effective` |

如果 `drainTimeoutMs` 小于你的流实际跑多久，一次切换就会在流中间回收连接池。把它调大。它是兜底不是正常路径——在飞请求一结束池子就立刻销毁。

`drainingPools[].forcedReclaimInMs` 数到 0 的那一刻就是切断点。

### 3.5 请求失败了但没有 IP 被惩罚

对若干类别是预期行为。`stats.byCategory` 显示分类器的判断：

| 类别 | 惩罚 IP？ |
| --- | --- |
| `client_abort` | 否 —— 客户端自己走的，线路没问题 |
| `auth`（401/403） | 否 —— 是你的凭据问题 |
| `rate_limit`（429） | 否 —— 限流不是线路坏了 |
| `upstream`（5xx） | 否 —— 服务器应答了，通路是好的 |
| `network` / `timeout` | 是 |

若 `errors` 在涨但每个候选的 `fail` 都是 0，查 `byCategory`——那些失败大概率不归因于线路。

### 3.6 切得太频繁，或者从不切换

**太频繁**：看 `switchHysteresis[].roundsBetter`。非零且持续上涨说明候选在真实地交替领先，考虑调高 `consecutiveBetterRounds` 或 `minDwellTimeMs`。若 `roundsBetter` 是 0 却有切换，那些是硬故障切换——看 `switches[].reason`。

**从不切换**：`minSamples` 可能超过一轮探测能提供的样本。`probeSamples: 3` 配 `minSamples: 3` 意味着一轮就够；配 `minSamples: 6` 需要两轮。同时确认 `switches[].reason` 里至少出现过一次 `initial`。

### 3.7 状态文件反复重写 / 从不写入

| 症状 | 原因 |
| --- | --- |
| `dirty: true` 一直不变、`lastFlushAt` 冻住 | 写盘失败——查 `statePath` 权限与磁盘空间 |
| 文件意外变大 | host 数量对应的 `candidatePoolMaxSize` 太高 |
| 文件不存在 | 还没有状态变化，或 `stateFile` 指到了不可写路径 |

写入节流到每 `stateFlushMinIntervalMs`（默认 60 秒）一次，退出时强制写。
