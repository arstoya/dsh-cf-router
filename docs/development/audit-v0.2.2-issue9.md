# v0.2.2 审计报告 — #9 统一错误分类器与健康状态机

> 审计日期：2026-11-21 · 依据《dsh-cf-router v0.2.2 技术审计方案与改进思路》§4
> 执行方式：按方案 §12 流程，**只审计不改代码**。每项标注「已实现 / 部分实现 / 未实现 / 存在缺陷」。

---

## 一、结论先行

| 审计项 | 现状 | 严重度 |
|---|---|---|
| HTTP 状态码与网络错误是否混淆 | **已实现（比预期更好）** | — |
| 401/403/429 是否误惩罚 IP | **已实现** | — |
| 客户端取消是否计入失败 | **已实现**（#4 时已修） | — |
| 一次失败是否重复计数 | **代码缺守卫，实测未复现** | 低 |
| 超时是否区分阶段 | **部分实现** | 中 |
| 错误分类是否结构化 | **未实现**（只有 `kind: timeout\|error` 两值） | 高 |
| 健康状态机（Healthy/Degraded/Cooling/Half-Open） | **未实现**（只有 `penaltyUntil` 一个二元量） | 高 |
| Half-Open 并发限制 | **未实现** | 高 |
| 恢复后是否重新积累样本 | **未实现** | 中 |

**核心判断**：当前实现是「二值熔断」（正常 / 冷却），不是状态机。它在「不要误惩罚」方面做得已经比方案预期好，但在「能不能表达中间状态」和「恢复过程怎么管」方面完全是空白。

---

## 二、逐项审计

### 2.1 错误分类审计（§4.2）

#### ✅ HTTP 状态码与网络错误没有混淆

方案担心「501/502/503 被当成 IP 故障」，实测**根本不会发生**：

```js
// lib/index.js:1912-1926 —— 唯一记录失败的地方
up.on('error', (err) => {
  if (ctx.clientAborted) return                 // 客户端取消，不计
  if (err?.code === 'ECONNRESET' && res.destroyed) return
  if (ip) recordRequestFailure(...)
})
```

失败只在 `up.on('error')` 里记录。HTTP 状态码走的是另一条路（`upRes` 回调），**从不计入 IP 失败**。

验证方式：`grep -n "upRes.statusCode" lib/index.js` 只有两处，都在 `filterResponseHeaders` 与 `writeHead`，与 `recordRequestFailure` 无交集。

**实测验证**（2026-11-21）：上游连续返回 5 次 401，该 IP 的 `fail` 计数保持 0。

**因此 401 / 403 / 429 / 500 / 502 / 503 全部天然不惩罚 IP。** 方案 §4.2 的第 1、3、4、5 条担心的问题，当前实现已经不存在。

#### ✅ 客户端取消不计入失败

```js
if (ctx.clientAborted) { log(...); return }
```

这是 #4 修复时一并处理的。有 4 条用例覆盖（SSE 取消、中途断开、重复 close、正常完成不误判）。

#### ⚠️ 代码缺少幂等守卫（实测未复现双触发）

`recordRequestFailure` 在文件里有 5 处出现，其中**真正的调用点只有 1 个**（`up.on('error')`），另 4 处是定义、薄封装、导出。所以「多个错误处理入口各记一次」的情况不存在。

真正的疑点是 `up.on('error')` 自身：

```js
up.on('error', (err) => {
  settled = true          // ← 只赋值，没有 if (settled) return
  release()
  ...
  if (ip) recordRequestFailure(...)
})
```

对比 `probeOnce` 的两处实现（L968、L1030）都规规矩矩写了 `if (settled) return`，唯独这里是裸的。

**但我实测未能复现双触发**：构造「timeout + 主动 destroy 竞争」的场景，`error` 事件只触发 1 次。

结论修正：这是一个**防御性缺口**（缺少守卫），不是已证实的缺陷。Node 当前版本行为正常，但依赖实现细节——将来 Node 改动或出现更奇特的竞争（如 socket 半关闭）时可能出问题。建议补守卫，优先级从中降为低。

#### ⚠️ 部分实现：超时不区分阶段

当前超时来源有三个，但都归到同一个 `kind: 'timeout'`：

| 来源 | 代码位置 | 语义 |
|---|---|---|
| `first_byte_timeout` | L1813 | 上游迟迟不给首字节（**可能是模型 prefill，不是网络问题**） |
| `upstream_timeout` | L1900 | 整体无响应 |
| TLS/TCP 层 | Node 内部 | 真正的建连超时 |

区分方式是 `msg.includes('timeout')` —— 三个都命中，无法分辨。

**最要紧的是第一个**：`first_byte_timeout` 很可能是「模型在想」而不是「线路坏了」。当前它和真正的连接超时受同样惩罚，这与方案 §3.2 区分硬故障/性能波动的精神冲突。

不过要注意：`firstByteTimeoutMs` 默认 60s，本机部署配了 180s，实际很难触发。

#### ❌ 未实现：错误分类不结构化

方案要求：

```js
{ category: 'network', retryable: true, penalizeIp: true, reason: 'connect_timeout' }
```

现状只有：

```js
{ message: string, kind: 'timeout' | 'error' }
```

`kind` 只有两个值，且 `'error'` 是个垃圾桶——TCP 连接失败、TLS 握手失败、上游重置全在里面。**无法据此做差异化惩罚**。

### 2.2 健康状态机审计（§4.3）

#### ❌ 未实现：只有二元熔断，没有状态机

现状全部状态就是一个字段：

```js
{ penaltyUntil: 0 }    // 时间戳；大于 now 表示冷却中
```

对应关系：

| 方案要求的状态 | 现状 |
|---|---|
| Healthy | `penaltyUntil <= now` |
| Degraded | **无对应**（不存在「降级但仍可用」） |
| Cooling | `penaltyUntil > now` |
| Half-Open | **无对应**（冷却到点直接回 Healthy） |

**缺失的实际后果**：

1. **没有 Degraded**：一个 IP 失败 1 次（阈值 2）时，状态与完全正常时一模一样，仍会被 `chooseBest` 以完全相同优先级选中。
2. **没有 Half-Open**：冷却到期瞬间，该 IP 立刻以完整权重回到候选池，可能与几十个其他请求同时涌入一条刚出问题的线路。方案 §4.4-D 明确要求限制这个。

#### ⚠️ 状态转换入口单一（这是好消息）

只有 `recordRequestFailure` 会写 `penaltyUntil`（L664），且 `switchRoute` 是唯一改路由的入口。不存在多个入口乱改状态的问题。

#### ⚠️ 冷却时间计算规则明确但简单

```js
s.penaltyUntil = deps.now() + Math.max(1000, cfg.cooldownMs)
```

固定时长，不随失败次数递增（无指数退避）。恢复也没有 Half-Open 探测环节——时间一到就完全恢复资格。

#### ❌ 未实现：恢复后不重新积累样本

冷却到期后，该 IP 的 `metrics.*EwmaMs` 与 `samples.*` 原封不动地保留。也就是说它带着**冷却前的旧数据**直接参与评分竞争。

一个刚恢复的 IP 用的是可能几十分钟前的 TTFB 数据——这正是方案 §9 表格里「探测数据是否可信」担心的场景。

### 2.3 跨模块检查（§9 相关行）

| 检查项 | 现状 |
|---|---|
| 错误是否重复计数（#4、#9） | ⚠️ 缺少 `settled` 守卫；单调用点，实测触发 1 次 |
| 健康状态是否被绕过（#9/#11/#10） | ✅ `scoreOf` 与 `chooseBest` 都检查 `penaltyUntil`；`healthTick` 也检查 |
| 探测数据是否混用（#9/#10/#11） | ✅ #3 已拆成六个独立指标，各有采样计数 |

---

## 三、问题清单（按严重度）

| # | 问题 | 位置 | 影响 |
|---|---|---|---|
| 1 | 无健康状态机，只有二元熔断 | `penaltyUntil` | 无法表达 Degraded/Half-Open；冷却到期即刻全速回归 |
| 2 | `settled` 未用作幂等守卫 | L1921 | 防御性缺口；实测未复现双触发 |
| 3 | 错误分类只有 `timeout\|error` | `kind` | 无法差异化惩罚 |
| 4 | `first_byte_timeout` 与真连接超时同罚 | L1813 附近 | 模型 prefill 可能被误判为线路故障 |
| 5 | 恢复后沿用旧样本 | `metrics` | 刚恢复的 IP 带过期数据参与竞争 |

**明确不存在的问题**（方案担心但实际已做好）：HTTP 状态码误惩罚、鉴权失败惩罚、429 惩罚、客户端取消计入失败。

---

## 四、建议的接口调整

方案要求「#9 先定接口，避免后续模块反复改」。建议如下，**待确认后再实现**：

```js
/** 结构化错误分类（纯函数，无状态） */
classifyError(err) → {
  category: 'network' | 'timeout' | 'upstream' | 'rate_limit' | 'auth' | 'client_abort' | 'protocol',
  phase:    'connect' | 'tls' | 'first_byte' | 'transfer' | 'unknown',   // 新增：解决 #4 条
  retryable: boolean,
  penalizeIp: boolean,      // 是否计入连续失败
  reason:    string,        // 原始 err.code / message 摘要
}

/** IP 健康状态（替代裸 penaltyUntil） */
health: {
  state: 'healthy' | 'degraded' | 'cooling' | 'half_open',
  consecutiveFail: number,
  cooldownUntil: number,
  halfOpenProbes: number,   // 当前在飞的恢复探测数
  lastRecoveryAt: number,
}
```

**关键取舍**：`penaltyUntil` 必须保留——已有代码与测试依赖它。改造方向是**在它之上叠加 `state`**，而不是替换。

---

## 五、建议的测试补充（§10.1 / §10.2）

现有测试已覆盖（可复用的）：

- `test/integration/proxy.test.js`：客户端中途断开、上游重置、首字节超时、SSE 取消
- `test/security/ssrf.test.js`：各种被拒目标

**缺口**：

| 方案要求 | 现状 |
|---|---|
| TCP 连接失败 / TLS 握手失败 的分类结果 | 无（只测了「探测判失败」，没测「归到哪一类」） |
| HTTP 401/403/429/500/502/503 不惩罚 IP | 无（**行为正确但没测试钉住**） |
| Healthy→Degraded→Cooling→Half-Open→Healthy 全流转 | 无 |
| Half-Open 并发限制 | 无 |
| 同一次错误不重复计数 | 无 |
| 冷却期间重复失败 | 部分（`router.test.js` 有「失败累加」） |

第 2 条尤其值得补：**当前「不惩罚」是架构副作用，不是显式保证**。将来若有人把 HTTP 状态码接进失败统计，测试不会报警。

---

## 六、待确认事项

在进入实现前需要你拍板：

1. **`Degraded` 是否需要？** 方案列了它，但当前没有「降级但仍可用」的需求。加进来会让 `chooseBest` 需要区分优先级权重——改动面比另三个状态大。
2. **`first_byte_timeout` 该不该惩罚 IP？** 它可能是模型 prefill。若不该，就需要在分类器里给它单列 `phase: 'first_byte'` 且 `penalizeIp: false`，但这会让真正的「上游卡死」也不惩罚。
3. **恢复后是否清空 EWMA？** 清空 = 更保守（用探测数据重新排队），不清 = 沿用历史（可能过期）。方案 §9 暗示该清，但会影响选路连续性。

我倾向：1 先不做 Degraded（就地加 `state` 四值，Degraded 留空位不实现）；2 单独 phase 但仍惩罚，只降权重；3 恢复时把 EWMA 标记为「待刷新」，用一轮探测覆盖。

你确认后我再动代码。
