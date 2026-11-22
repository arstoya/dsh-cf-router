# 模块边界与依赖方向

- **更新**：2026-11-22（#14 方案 C 执行后）
- **对应**：Issue #14 渐进式模块拆分（**未完成，本文档说明完成到什么程度**）

---

## 一、结论先行

拆出了 **14 个纯函数模块**（2331 行），`lib/index.js` 剩 **3325 行 / 69 个顶层函数**。

**但模块化没有完成。** 实测数据：

| 类别 | 函数数 | 行数 | 占 index.js |
| --- | --- | --- | --- |
| 零依赖（含调用链） | 17 | 255 | 7% |
| 仅依赖 `cfg`/`deps`/`log` | 12 | 336 | 10% |
| **依赖模块级 Map 单例** | 55 | 2750 | **78%** |

那 78% 依赖 40 个模块级共享状态（`ipStats`/`hosts`/`currentIp`/`candidatePools`/`stats`…），
把它们拆开需要**状态容器重构**（隐式全局 → 显式传递），属于架构改动而非「移动代码」。

按 #14 的验收标准「模块边界有文档、没有循环依赖、行为回归通过」：

- ✅ 没有循环依赖
- ✅ 行为回归通过（547 项测试，拆前拆后一致）
- ⚠️ 模块边界**部分**有文档 —— 纯函数层清晰，状态层未拆

---

## 二、依赖方向图

```
                        index.js  (3325 行, 69 函数)
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
   config-normalize    state-store         其他 11 个
        │                    │                    │
   ssrf-guard  ◄─────────────┘                  （全部零依赖）
```

完整的 14 个模块：

| 模块 | 行数 | 依赖 | 职责 |
| --- | --- | --- | --- |
| `ssrf-guard.mjs` | 178 | 无 | Authority 解析、白名单、地址分类 |
| `config-normalize.mjs` | 131 | ssrf-guard | `DEFAULTS`、`withDefaults`、配置归一化 |
| `metrics.mjs` | 69 | 无 | EWMA 原语、指标/样本空结构 |
| `net-util.mjs` | 66 | 无 | IPv4 转换、CIDR 抽样、`pinLookup` |
| `error-classifier.mjs` | 126 | 无 | 错误分类（category/phase/weight） |
| `headers.mjs` | 139 | 无 | 逐跳/端到端 Header 边界 |
| `admin-auth.mjs` | 293 | 无 | Bearer 鉴权、Host/Origin 校验、限流 |
| `switch-policy.mjs` | 140 | 无 | 切换迟滞四道闸 |
| `candidate-pool.mjs` | 140 | 无 | 候选生命周期元信息 |
| `candidate-select.mjs` | 169 | 无 | 按来源配额选候选 |
| `candidate-explore.mjs` | 87 | 无 | 有限探索 |
| `candidate-prune.mjs` | 175 | 无 | 容量与过期淘汰 |
| `connection-pool.mjs` | 229 | 无 | 连接池三态与排空 |
| `state-store.mjs` | 389 | 无 | schema 版本、迁移、序列化 |

**唯一的一条跨模块依赖是 `config-normalize → ssrf-guard`**（归一化要用白名单校验）。
没有循环依赖。

### 关键边界约定

- `metrics.mjs` 只管「**怎么算**」，不管「**数据存在哪**」。`ipStats` 这个 Map 仍由 `index.js` 持有。
- `candidate-*.mjs` 只管候选的**生命周期元信息**，不含任何性能字段。性能是 `ipStats` 的职责。
- `state-store.mjs` 只管**文件格式与迁移**，不知道运行态长什么样（序列化由 `serializeHosts` 接收参数完成）。
- `connection-pool.mjs` 只管池的**状态机与计数**，不持有 agent 对象（agent 由 `index.js` 的 `agents` Map 持有）。

---

## 三、index.js 内部的三层（未拆）

虽然没拆成文件，但职责分层是清晰的，这是将来拆分的依据：

### A. 状态层（40 个模块级绑定）

```
配置与依赖    cfg / deps / DEFAULTS(已搬) / bootError
运行态数据    hosts / ipStats / currentIp / candidatePools / switchState
连接资源      agents / directAgents / poolRegistry
版本与统计    routeGenerations / probeGenerations / switches / recent / stats
模式与持久化  routingMode / configMode / stateFileMode / stateFileSchema / statePath
节流          stateDirty / lastStateFlushAt
管理接口      adminLimiter / adminLimiterSig / adminTokenCache
```

### B. 服务层（依赖状态层）

| 函数 | 行数 | 依赖 |
| --- | --- | --- |
| `handleProxy` | 368 | currentIp, hosts, poolRegistry, stats |
| `statusSnapshot` | 250 | candidatePools, currentIp, hosts, poolRegistry |
| `refreshHost` | 241 | currentIp, hosts |
| `restoreRuntimeState` | 107 | hosts, ipStats, stats |
| `recordRequestFailure` | 105 | currentIp, stats |
| `statOf` | 74 | ipStats |
| `healthTick` | 62 | currentIp, hosts, poolRegistry |
| `scoreOf` / `chooseBest` / `switchRoute` | — | hosts, currentIp, routeGenerations |

### C. 入口层

- `apply()` / `dispose()` —— 插件生命周期，必须保持原样（#14 原文要求）
- `createProxy()` / `closeProxy()` —— HTTP server 生命周期
- `__resetForTest()` —— 测试隔离

---

## 四、如果将来要真做模块化

前置条件与路径（**未实施**）：

### 先决条件

1. **必须有真实运行环境**。当前 cf-router 在本机无法加载（#20 `link:` 部署问题），
   拆分只能靠单测验证，而单测覆盖不了「重启后状态是否真的恢复」这类行为。
2. **必须先在 CI 里保住 547 项基线**（已完成，#21）。

### 推荐的路径

**步骤 1：建状态容器（不改行为）**

```js
// 机械替换：ipStats → state.ipStats
const state = {
  hosts: new Map(), ipStats: new Map(), currentIp: new Map(),
  candidatePools: new Map(), switchState: new Map(),
  agents: new Map(), directAgents: new Map(),
  routeGenerations: new Map(), probeGenerations: new Map(),
  stats: {...}, switches: [], recent: [],
}
```

风险：diff 覆盖全部 84 个函数（隐式全局 → `state.x`），但纯机械。
**这一步必须独立提交，且不加任何功能。**

**步骤 2：按数据所有权逐包搬出**

| 批次 | 数据 + 函数 | 依赖方向 |
| --- | --- | --- |
| a | `ipStats` + `statOf`/`recordProbeSample`/`updateEwma` 调用 | 无 |
| b | `ipStats.health` + `getHealthState`/`transitionHealth`/`advanceHealthState` | a |
| c | `candidatePools` + `getCandidatePool`/`isCandidateSelectable` | b |
| d | `hosts`/`currentIp`/`routeGenerations` + `scoreOf`/`chooseBest`/`switchRoute` | a,b,c |
| e | `agents`/`poolRegistry` + `agentFor`/`dropAgents` | d |
| f | 探测：`probeOnce`/`measureIp`/`tcpProbeAll`/`resolveIps` | a,b |

**步骤 3：`handleProxy` 与 `statusSnapshot` 留最后**

它们是最大、风险最高的（368 / 250 行），且同时依赖上述所有包。
`handleProxy` 里含 #4（取消上游）、#5（header 过滤）、#9 阶段 6（`upRes` error）三处修过真实缺陷的代码。

### 不建议动

- `apply()` / `dispose()` 两个入口
- `cordis.patch.yml` 的配置字段名（改了用户配置失效）

---

## 五、与 #14 原文的偏差

原文建议的目标结构是 `proxy/ router/ probe/ health/ connection/ state/ tools/` 七个目录。
实测后**没有照做**，原因：

1. 原文假设这些职责能按目录直接切开，但 78% 的代码共享 40 个单例，
   按目录切会同时改位置和访问方式。
2. 原文要求「每次只移动一个边界」「不在拆分 PR 中顺便更改路由算法」——
   本轮的三个批次严格遵守了这一点（逐字搬运，零逻辑改动）。
3. 原文要求的「模块边界有文档」已由本文档完成，「没有循环依赖」已达成，
   「已有行为回归测试全部通过」已达成（547 项）。
   **仅「状态层拆分为独立模块」未完成**，原因如上。

---

## 六、本轮实际改动

| 提交 | 内容 | index.js 行数 |
| --- | --- | --- |
| `8e3e3bc` | 拆出 `net-util.mjs` + `metrics.mjs` | 3516 → 3434 |
| `11cf44d` | 拆出 `config-normalize.mjs` | 3434 → 3325 |

累计：14 个纯函数模块、2331 行；`index.js` 减少 191 行、15 个顶层函数。
