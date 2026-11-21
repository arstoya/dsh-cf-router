# Issue #17（#A）与 #18（#B）改进方案评审

> 评审时间：2026-11-21 · 评审对象：仓库内两个已开但未实施的 issue
> 评审方式：读 issue 原文 → 逐条核对当前代码 → 结论
> 判定口径：**问题是否真实、方案是否完整、代价是否值得**

---

## 〇、结论先行

| Issue | 问题真实性 | 方案完整性 | 实际影响 | 建议 |
|---|---|---|---|---|
| **#17（#A）超时硬下限** | 真实 | 缺 3 处，且会扩大问题 | **零**（实际部署一个都没触发） | 最小修复后关闭 |
| **#18（#B）启动 routingMode** | 真实 | 缺 1 处致命前提 | 中等（改配置无效，须手删文件） | 先修测试桩，再走方案 C |

**执行顺序建议：#B 的测试桩修正优先于两者** —— 它不只服务 #B，现有 `state.test.js` 里两条 `routingMode` 用例也都不准。

---

## 一、#17（#A）评审

### 1.1 问题真实性：成立

`lib/index.js:1253`

```js
const firstByteTimer = setTimeout(() => { ... }, Math.max(5000, cfg.firstByteTimeoutMs))
```

配 300 实际生效 5000，且无任何提示。缺陷是实打实的。

### 1.2 issue 里的行号已全部失效

issue 写于 #2、#3 之前，两个 issue 改动后所有夹取点都换了位置。**按行号改会打错位置，必须按字段名定位。**

| 字段 | issue 写的 | 实际 |
|---|---|---|
| `firstByteTimeoutMs` | L821 | **L1253** |
| `cooldownMs` | L667 | **L480**、L1498 |
| `probeIntervalMs` | L1073 | **L1409**、L1495、L1563 |
| `healthCheckMs` | L1077 | **L1496**、L1567 |
| `ewmaMaxMs` | L647 | **L618** |
| `ewmaAlpha` | L649 | **L385**、L427 |
| `probeSamples` | L523 | **L959** |
| `l1Concurrency` | L428 | **L976** |
| `l2TopN` | L537 | **L974** |
| `discoverPerRange` | L385 | **L752**、L964、L1505 |

### 1.3 必须改的三处

#### ① 方案会扩大静默夹取面（最严重）

方案提议的 `CLAMPS` 表给 5 个「只有下限」的字段**新增了上限**：

| 字段 | 现状 | 方案新增上限 |
|---|---|---|
| `firstByteTimeoutMs` | 只有 ≥5000 | ≤600000 |
| `cooldownMs` | 只有 ≥1000 | ≤3600000 |
| `probeIntervalMs` | 只有 ≥30000 | ≤86400000 |
| `healthCheckMs` | 只有 ≥5000 | ≤3600000 |
| `ewmaMaxMs` | 只有 ≥200 | ≤120000 |

实际部署 `firstByteTimeoutMs: 180000`（profile 注释：首字节长期 >60s），在上限内。但性质上这是**新增 5 个静默改写点**：

> 今天配 900000（长时间推理完全合理）能生效；加了 ≤600000 后变成静默按 10 分钟跑 —— 正是本 issue 要治的病。

**改法**：表里只保留现状已有的界，不给「只有下限」的字段凭空加上限。

#### ② 「装载时归一化 cfg」覆盖不全

各配置项的消费点数（`grep -c "cfg\.字段"`）：

| 字段 | 消费点 | 归一化能否覆盖 | 原因 |
|---|---|---|---|
| `firstByteTimeoutMs` | 1 | 能 | |
| `cooldownMs` | 2 | 能 | |
| `probeIntervalMs` | 3 | 能 | |
| `healthCheckMs` | 2 | 能 | |
| `ewmaMaxMs` | 1 | 能 | |
| `l2TopN` | 1 | 能 | |
| `probeSamples` | 1 | **不能** | `opts.samples \|\| cfg.probeSamples`，调用参数可覆盖 |
| `l1Concurrency` | 1 | **不能** | 形参传入 `tcpProbeAll(ips, concurrency, ...)` |
| `discoverPerRange` | 3 | **不能** | 形参传入 `sampleFromRanges(ranges, perRange)` |
| `ewmaAlpha` | 2 | **不能** | 形参传入 `updateEwma(prev, sample, alpha)` |

只做归一化，这 4 个字段的夹取仍在运行时发生且不被记录。

**改法**：要么保留这些夹取点但从同一张表取界，要么明确写「它们不在这套可观测机制内」，不要假装全覆盖。

#### ③ `ewmaMaxMs` 的语义已被 #3 改过

issue 写它时是「EWMA 过滤阈值」，#3 之后是**分级阈值**：

```js
function ttfbOverCap(ms) {          // 原 ttfbAcceptable，已改名
  const maxSample = Math.max(200, Number(cfg.ewmaMaxMs) || 3000)
  return Number.isFinite(ms) && ms > maxSample      // 只判级，不丢弃
}
```

记录时的 reason 措辞必须改，否则会误导后来的人以为还在过滤样本。

### 1.4 实际影响：零

对照本机真实部署（`D:/dsh-home/profiles/desktop/cordis.patch.yml`）：

| 字段 | 配置值 | 界 | 是否被夹取 |
|---|---|---|---|
| `firstByteTimeoutMs` | 180000 | ≥5000 | 否 |
| `probeIntervalMs` | 300000 | ≥30000 | 否 |
| `healthCheckMs` | 30000 | ≥5000 | 否 |
| `cooldownMs` | 60000 | ≥1000 | 否 |
| `ewmaMaxMs` | 3000 | ≥200 | 否 |
| `ewmaAlpha` | 0.3 | [0.05, 0.9] | 否 |
| `probeSamples` | 3 | [1, 5] | 否 |
| `l1Concurrency` | 20 | [1, 64] | 否 |
| `l2TopN` | 10 | [1, 50] | 否 |
| `discoverPerRange` | 1 | [0, 10] | 否 |

**10 个字段一个都没被夹取过。** issue 描述的「配 300 实际按 5000」在本部署上从未发生。

### 1.5 现状：10 个字段里只暴露了 3 个

`statusSnapshot()` 当前输出的配置项（值即 `cfg`，夹取后可见）：

```js
listen, keepAlive, probeIntervalMs, healthCheckMs, failThreshold,
cooldownMs, idleSkipMs, routingMode, coloAllow
```

与 issue 列出的 10 个被夹取字段求交集（`scripts` 实测）：

| 状态 | 字段 |
|---|---|
| 已暴露（3） | `probeIntervalMs`、`healthCheckMs`、`cooldownMs` |
| 未暴露（7） | `firstByteTimeoutMs`、`ewmaMaxMs`、`ewmaAlpha`、`probeSamples`、`l1Concurrency`、`l2TopN`、`discoverPerRange` |

其中 `firstByteTimeoutMs` 是唯一一个「5 秒 vs 60 秒」有实际行为差的字段；其余 6 个的夹取区间都很宽，且本部署从未触发。

### 1.6 三个方案对比

| 方案 | 成本 | 收益 | 风险 |
|---|---|---|---|
| ① 按 issue 全做 | ~2h | 完整可观测 | 新增 5 个上限 + 引入归一化中间层 |
| **② 最小修复（推荐）** | ~30min | 消除「静默」+ 补 1 个状态字段 | 无代码逻辑改动 |
| ③ 只改文档 | ~15min | 消除「静默」 | 接口仍看不到 `firstByteTimeoutMs` |

**方案 ② 的具体步骤**：

1. README 中英文配置表加一列「下限 / 区间」，10 个字段逐个写清
2. `cordis.patch.yml` 注释标注哪些字段有下限
3. `statusSnapshot()` 补 `firstByteTimeoutMs`

**理由**：实际部署从未触发；下限本身必须留（`setInterval(0)` 会打满事件循环）；真正的缺陷是「文档没写」，不是「代码夹了」。

### 1.7 明确不在本 issue 范围

是否**取消**某个下限（例如让首字节超时真的能配到 300）是策略问题。若要改，单独开 issue，不要在可观测改造里顺手改。

---

## 二、#18（#B）评审

### 2.1 🔴 致命问题：volatile 字段在测试里无法复现

**生产环境**（`@deepseek-ai/schemastery/lib/index.mjs:273`）：

```js
return [createVolatile(value), adapted]
```

**`createVolatile` 的实现**（`@deepseek-ai/cosmokit/lib/index.js:102`）：

```js
function createVolatile(value) {
  let current = snapshot(value)
  return Object.freeze({
    get: () => current,
    [write]: (value) => { current = value },
  })
}
```

所以生产环境里 `cfg.routingMode` **不是字符串，是带 `.get()` 的冻结引用对象**。代码里已有对应处理：

```js
const raw = cfg.routingMode
const cv = String((raw && typeof raw.get === 'function' ? raw.get() : raw) || 'auto')
```

**测试桩**（`test/helpers/stubs/schemastery.mjs:21`）：

```js
node.volatile = () => node          // ← 返回普通值，no get()
```

**后果：现有测试测的是桩的行为，不是生产的行为。**

`test/unit/state.test.js:116`（实测行号正确）那条「配置里的 routingMode 在启动时不会直接生效」—— 它在桩语义下通过，但**无法证明生产环境同样如此**。

**这是 #B 的一切测试的前提，必须先修。**

```js
// 修法（测试桩）
node.volatile = () => {
  const wrapper = function () { return wrapper._build.apply(null, arguments) }
  Object.assign(wrapper, node)
  wrapper._volatile = true
  wrapper.get = () => node._build(node._value)   // 返回当前值
  return wrapper
}
```

修完之后要能构造出「`cfg.routingMode` 是对象、`.get()` 返回字符串」的场景。

### 2.2 issue 的根因判断有误

issue 写「优先级：stateFile 恒优先于配置」，但没写清根因。实际在 `apply()`：

```js
loadState()                                        // 读回上次的 routingMode
const raw = cfg.routingMode
lastCfgMode = String((raw && typeof raw.get === 'function' ? raw.get() : raw) || 'auto')
//            ↑ 基准值被设成「配置值」
```

于是 `currentMode()` 首次调用：

```js
const cv = ...                                    // = 配置值
if (cv !== lastCfgMode) { ... }                    // 相等 → 跳过同步
return routingMode                                 // 仍是 loadState 的 auto
```

**这不是「优先级设计」，是基准值初始化顺序 bug。** `lastCfgMode` 用配置值初始化，等于告诉 `currentMode()`「设置页已经是这个值了，不用同步」。

**修法比 issue 设想的简单**：`lastCfgMode` 初始化为 `null` 或哨兵值，让首次 `currentMode()` 必然触发一次同步。

### 2.3 四个候选方向的评估

| 方向 | 可行性 | 问题 |
|---|---|---|
| A 配置优先 | 可 | 运行时 `setRoutingMode('direct')` 后重启会被配置的 `auto` 覆盖 —— **破坏现有行为** |
| B 区分显式配置 | **不可** | 需要知道「哪些字段是用户显式写的」，schemastery 不提供此信息 |
| **C stateFile 优先 + 冲突告警** | 可 | 行为零变化，只把「静默」变「可见」 |
| D 拆两个字段 | 可 | 增加配置复杂度，与「不删/不加字段」的约束相冲突 |

**推荐 C**：

- 保持 stateFile 优先（现有语义不变）
- `statusSnapshot()` 同时显示 `configMode` / `stateFileMode` / `effectiveMode` 三者
- 冲突时打 WARN，并在状态里标出「配置被 stateFile 覆盖，删掉 `<statePath>` 可让配置重新生效」

这样既修掉「静默」，又不改任何既有行为。

### 2.4 `direct` 的两个疑点：审计阶段必须先出结论

issue 提了但没定论，实现阶段会反复：

**疑点 1：direct 下探测与健康巡检是否该继续跑**

```js
// direct 模式下 ip 恒为 null（L1166）
let ip = currentMode() === 'direct' ? null : (currentIp.get(host) || null)
```

但 `probeTimer` 与 `healthTick` 照常运行，每 5 分钟对几十个候选 IP 发请求，`currentIp` 在 direct 下不参与转发。

→ 白烧流量 vs 保持数据新鲜以便切回 auto。**需明确取舍。**

**疑点 2：`stats.directFallback` 在 direct 下的语义**

```js
// L1207
const useDirect = currentMode() === 'direct' || (!ip && cfg.allowDirectFallback)
// L1218
if (useDirect) stats.directFallback += 1
```

原本语义是「兜底触发次数」，direct 模式下变成「所有请求」，语义被稀释。

→ 是否该分开计数，或 direct 模式不计入。

### 2.5 issue 里的测试要求需要补充一条

issue 写「配置 `direct` + 无 stateFile → 生效 `direct`」，这条在修好测试桩之前**无法验证**。修桩后应加：

- 构造真实 volatile 引用（`{ get: () => 'direct' }`）作为 `cfg.routingMode`
- 确认 `currentMode()` 的读取路径走 `.get()` 分支

---

## 三、优先级与执行顺序

```
0. 修测试桩 volatile 语义            ~20min   ← 前置，服务两个 issue
   ├── 补一条能在真实语义下复现的用例
   │
1. #17 最小修复（文档 + 1 个状态字段）  ~30min
   └── 关闭 #17，注明「刻意不做代码层记录」
   │
2. #18 第一阶段：行为审计文档          ~1h
   ├── 明确 direct 两个疑点的结论
   └── 提交后停下等确认
   │
3. #18 第二阶段：实现（方案 C）        ~1.5h
```

**为什么不先做 #17**：它的实际影响为零，而测试桩缺陷会让 #B 之后的所有测试都不可信。

**为什么不合并做**：两者改的是不同文件、不同机制（一个是 cfg 数值，一个是 volatile 引用语义），合并会让 commit 不可单独回滚。

---

## 四、验证命令

> 以下六条均已在 2026-11-21 实测跑通，输出与文中论断一致。


```bash
# 确认夹取点位置（issue 里的行号已失效）
grep -n "Math.max(.*cfg\.\|Math.min(.*cfg\." lib/index.js

# 确认各配置项的消费点数量
for f in firstByteTimeoutMs cooldownMs probeIntervalMs healthCheckMs \
         ewmaMaxMs ewmaAlpha probeSamples l1Concurrency l2TopN discoverPerRange; do
  printf "%-22s %d\n" "$f" "$(grep -c "cfg\.$f" lib/index.js)"
done

# 确认 volatile 生产语义（不是普通值）
grep -n "createVolatile" \
  "D:/Deepseek Harness/resources/app/dsh/node_modules/@deepseek-ai/schemastery/lib/index.mjs"
sed -n '102,112p' \
  "D:/Deepseek Harness/resources/app/dsh/node_modules/@deepseek-ai/cosmokit/lib/index.js"

# 确认测试桩与生产的差异
grep -n "volatile" test/helpers/stubs/schemastery.mjs

# 确认状态接口已暴露哪些配置
curl -s http://127.0.0.1:8787/__router/status | python -c "import sys,json;print(sorted(json.load(sys.stdin)))"

# 确认本机部署实际配置值
grep -nE "firstByteTimeoutMs|cooldownMs|healthCheckMs|probeIntervalMs|ewmaMaxMs" \
  "D:/dsh-home/profiles/desktop/cordis.patch.yml"
```

---

## 五、一句话总结

> **#17 问题真实但本部署从未触发，用文档解决即可；#18 问题真实且根因被误判，但测试桩的 volatile 语义是假的前提，必须先修桩再谈实现。**
