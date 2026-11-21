# v0.2.1 开发基准（Issue #1 结束后）

> 记录时间：2026-11-20 · 目的：给 Issue #2 / #3 留一份「改造前是什么样」的可核对基线。
> 原则：**改造前就存在的问题不记为回归**。

---

## 一、运行环境

| 项 | 值 |
|---|---|
| Node.js | v26.13.0 |
| npm | 11.20.0 |
| OS | Windows 10 22H2（构建号 19045） |
| DSH | 0.2.1-rc.5 |
| 基准 Commit | `2651539`（v0.1.0 tag 指向同一提交） |

---

## 二、Issue #1 开工前的状态

| 检查 | 结果 |
|---|---|
| `git status --short` | 空（工作区干净） |
| `git branch --show-current` | `main` |
| `npm test` | 实际执行 `node scripts/doctor.mjs` —— **没有真正的测试** |
| `npm run doctor` | FAIL 0 · WARN 1 · 17 项（WARN 是端口 8787 被运行中的插件占用，正常） |
| 插件加载 | 正常，注册 4 个工具 |

---

## 三、Issue #1 结束后的状态

| 检查 | 结果 |
|---|---|
| `npm test` | **106 tests / 106 pass / 0 fail**，约 18 秒（含一个约 9 秒的首字节超时用例） |
| `npm run doctor` | FAIL 0 · WARN 1 · 17 项（与开工前一致，未被破坏） |
| 连续三次 `npm test` | 三次均 106/106，结果一致 |
| 外网依赖 | 无。全部走本地 HTTPS fixture（自签证书） |
| 真实 API Key | 不需要 |
| 真实 DSH_HOME 写入 | 无（见 §六 的隔离机制） |

用例分布：

| 文件 | 用例数 | 覆盖 |
|---|---|---|
| `test/unit/router.test.js` | 12 | 选路、冷却、切换、direct 模式、reset |
| `test/unit/metrics.test.js` | 13 | EWMA、alpha 夹取、脏样本、scoreOf 语义 |
| `test/unit/state.test.js` | 9 | 快照结构、DEFAULTS 一致性、测试隔离 |
| `test/integration/probe.test.js` | 18 | DNS 成败、TCP 成败、TLS 校验、HTTP 200/401/404/429/500/503、超时、重置 |
| `test/integration/proxy.test.js` | 16 | GET/POST/JSON/SSE/gzip/客户端断开/首字节超时(真实触发)/上游重置/Keep-Alive/direct/控制端点 |
| `test/regression/router-race.test.js` | 11 | 旧请求迟到成功/失败、旧探测覆盖、100 并发交错（Issue #2） |
| `test/integration/probe-metrics.test.js` | 15 | 四段计时边界、状态码、超时/中断/重置、measureIp 聚合（Issue #3） |
| **合计** | **106** | |

---

## 四、现有配置字段与默认值（改造前，未改动）

`DEFAULTS`（`lib/index.js`）与 `Config`（schemastery）逐字段一致，由 `test/unit/state.test.js` 的「DEFAULTS 与 Config 默认值逐字段一致」用例守护。

| 字段 | 默认值 |
|---|---|
| `targets` | `[]` |
| `listenHost` / `listenPort` | `127.0.0.1` / `8787` |
| `probePath` | `/` |
| `probeSamples` | `3` |
| `probeTimeoutMs` | `6000` |
| `probeIntervalMs` | `300000` |
| `discoverEnabled` / `discoverPerRange` | `true` / `2` |
| `discoverRanges` | 15 个 CF 网段 |
| `coloAllow` | `[]` |
| `l1Concurrency` / `l1TimeoutMs` / `l2TopN` | `20` / `1200` / `10` |
| `idleSkipMs` | `1800000` |
| `healthCheckMs` | `30000` |
| `maxSockets` | `16` |
| `keepAlive` | `true` |
| `failThreshold` | `2` |
| `cooldownMs` | `60000` |
| `ewmaAlpha` | `0.3` |
| `ewmaMaxMs` | `3000` |
| `firstByteTimeoutMs` | `60000` |
| `upstreamTimeoutMs` | `600000` |
| `allowDirectFallback` | `true` |
| `routingMode` | `"auto"` |
| `stateFile` | `""` |
| `verbose` | `false` |

**Issue #1 没有增删任何配置字段。**

---

## 五、为可测试性做的改造（Issue #1 范围内）

`lib/index.js` 只加了三样东西，生产行为不变：

1. **`deps` 依赖注入对象**（4 个字段）：`resolve4` / `now` / `upstreamPort` / `tlsOptions`。
   默认值全部与原实现等价（`dns.resolve4`、`Date.now()`、`443`、`{}`）。
   替换原因：测试要能伪造 DNS、控制时钟、指向本地端口、接受自签证书。
2. **`DEFAULTS` + `withDefaults()`**：`Config` 默认值的纯数据副本，供测试装配用。
   一致性由测试守护，不会悄悄漂移。
3. **`__resetForTest()` + `__testApi`**：清空模块级状态、复位注入依赖、暴露内部函数给测试。
   生产代码不引用它们。

改造后 `Date.now()` 在文件里只剩 2 处（`deps` 的默认实现与其复位），`port: 443` 为 0 处，`dns.resolve4` 只剩同样的 2 处。

---

## 六、测试隔离机制（踩过的坑）

**事故**：第一版测试直接调用 `setRoutingMode()`，而 `stateFile` 默认解析到 `$DSH_HOME/cf-router-state.json` —— 那是**正在运行的插件**的真实状态文件。结果把本机的 `D:\dsh-home\cf-router-state.json` 写成了 `{"routingMode":"direct"}`（该文件原本不存在）。

**处置**：删除该文件恢复原状，运行中的插件内存态仍是 `auto`，未受影响。

**修法**（两道防线）：

1. `test/helpers/setup.mjs` 的 `setupPlugin()` 强制注入进程级临时 `stateFile`，收尾删除。
2. `lib/index.js` 的 `resolveStatePath()` 增加逃生分支：`process.env.CFR_TEST_MODE === '1'` 时兜底到 `os.tmpdir()`。
   该变量由 `test/helpers/stub-register.mjs` 设置，只在 `npm test` 时存在。

**验证**：跑完全量测试后 `D:\dsh-home\cf-router-state.json` 不存在（原本就不存在）。

---

## 七、改造前就存在的已知问题（**不是本轮引入**）

Issue #2 / #3 会处理其中一部分；未列入的应单独开 issue。

### 7.1 与 Issue #2 相关

| 问题 | 位置 | 状态 |
|---|---|---|
| `noteSuccess()` 直接改 `currentIp` | `noteSuccess` | **已修复（Issue #2）**：`recordRequestSuccess` 只更新统计，永不碰路由 |
| 无路由版本号 | 全局 | **已修复（Issue #2）**：`routeGenerations`，只在真切换时递增 |
| 探测结果无版本保护 | `refreshHost` | **已修复（Issue #2）**：`probeGenerations` + `commitProbeResult` 丢弃过期结果 |

Issue #2 落地后的契约（`test/regression/router-race.test.js` 守护）：

- `switchRoute()` 是修改当前路由的**唯一入口**；目标与当前相同时不递增、不记切换
- `recordRequestSuccess()` 签名改为 `(host, ip, metrics, generation)`，**不回写 currentIp**
- `recordRequestFailure()` 判死照记，但只有「该 IP 仍是当前线路」才触发切换
- `refreshHost()` 开头 `beginProbe()` 取版本，落库前 `commitProbeResult()` 校验
- `noteSuccess` / `noteFailure` 保留为薄封装，向后兼容

### 7.2 与 Issue #3 相关

| 问题 | 位置 | 状态 |
|---|---|---|
| 探测耗时含响应体下载 | `probeOnce` | **已修复（Issue #3）**：TTFB 在 `response` 事件记录，total 在 `end` 单独记录 |
| TLS 与 TTFB 混进同一个 EWMA | `handleProxy` | **已修复（Issue #3）**：拆成六个独立指标，各自由单一事件产生 |
| 新连接/复用连接 TTFB 不区分 | `handleProxy` | **已修复（Issue #3）**：`freshTtfbEwmaMs` / `reusedTtfbEwmaMs` 分开 |
| `scoreOf` 对不同量纲取 min | `scoreOf` | **已修复（Issue #3）**：只用探测 TTFB 中位数排序 |

Issue #3 落地后的指标契约（`test/unit/metrics.test.js` 与
`test/integration/probe-metrics.test.js` 守护）：

| 字段 | 起点 | 终点 | 来源 |
|---|---|---|---|
| `tcpEwmaMs` | socket 创建 | `connect` | 探测 |
| `tlsEwmaMs` | TCP 完成 | `secureConnect` | 探测 / 新建连接的真实请求 |
| `probeTtfbEwmaMs` | 请求发出 | 收到响应头 | 探测 |
| `probeTotalEwmaMs` | 请求发出 | 响应体结束 | 探测 |
| `freshTtfbEwmaMs` | 请求发出 | 收到响应头 | 真实请求，新连接 |
| `reusedTtfbEwmaMs` | 请求发出 | 收到响应头 | 真实请求，复用连接 |

- `ewmaMaxMs` **只过滤 TTFB 类样本**；TCP/TLS 是纯网络指标，不受该阈值影响
- `updateEwma()` 只接受真正的 number，刻意不做隐式转换（避免掩盖类型错误）
- `ewmaMs` 字段已移除；`probeMs` / `probeBestMs` 保留但语义改为探测 TTFB
- `handleProxy` 的耗时测量改回 `process.hrtime.bigint()`（`deps.now()` 是墙钟，会受系统时间调整影响）

### 7.3 与本轮无关、但测出来的

| 问题 | 说明 | 建议 |
|---|---|---|
| `firstByteTimeoutMs` 有 5000ms 硬下限 | `Math.max(5000, cfg.firstByteTimeoutMs)`，配 300 实际按 5000 生效 | 要可配置就得改这行。当前两条用例钉住行为：一条验证下限存在，一条真实触发超时 |
| 配置里的 `routingMode` 启动时不生效 | `apply()` 把 `cfg.routingMode` 记成 `lastCfgMode` 基准，导致首次 `currentMode()` 认为「设置页没动过」，沿用 `loadState()` 的 `auto` | 要修就是改基准语义，属行为变更，需单独立项 |
| 请求/响应头未做 hop-by-hop 过滤 | `{ ...req.headers }` 与 `res.writeHead(..., upRes.headers)` 直接透传 | Issue #5 处理 |

---

## 七点六、Issue #4 的实测证据（先行取证，未实施）

在补测试缺口时实测到一个确凿现象：**客户端断开后，上游并没有被取消。**

取证方法：上游发 8MB 响应体，客户端收到首块数据后立即 `destroy()`。
若代理取消上游，上游 socket 应在写完前关闭（`res.writableFinished === false`）；
若没取消，上游会继续把 8MB 写完。

实测结果：

```
aborted=0  completed=2     ← 上游把 8MB 写完，没有观察到中断
```

用例已加入 `test/integration/proxy.test.js` 并标记 skip，理由写在 skip 描述里：

```js
test('客户端中途断开：上游确实观察到响应被中断（Issue #4 验收）',
  { skip: '#4 未实施：当前 aborted=0、上游把 8MB 写完了' }, ...)
```

**为什么用 8MB 而不是几百字节**：小 payload 会整个进内核缓冲区，上游瞬间就"写完"了，
`writableFinished` 为 true，测不出任何东西 —— 第一版就是这么假通过的。

实施 #4 后去掉 skip，这条即为验收依据。

---

## 七点五、两条设计原则（评审后补强）

### 1. 路由保护是「结构性禁止」优先，版本号只是第二道

Issue #2 的核心不是 generation，而是**请求回调本来就没有写 `currentIp` 的权限**：

- `recordRequestSuccess()` 只更新统计与指标，签名里带 `generation` 但**不参与任何判断**（`void generation`）。
- 所有路由变更必须经 `switchRoute()` 显式发起。
- `generation` 的第二道作用在失败路径：请求出发时的版本若已过期，说明它在飞行期间线路被改过，它只能更新统计，无权驱动切换。典型场景是 **A→B→A** —— 光比「该 IP 是否仍是当前线路」会认为「还是当前」，但这个请求代表的是更早一轮的观测。

`test/regression/router-race.test.js` 里三条用例分别锁定：
- 「结构性优先」：generation 给成完全正确的值，成功回调照样改不了路由
- 「A→B→A 后过期失败不切换」：IP 比对通过但版本过期，仍不得切换
- 「当前版本的失败可正常驱动切换」：确认兜底没有把正常路径也堵死

### 2. TTFB 不做丢弃式过滤

`ewmaMaxMs` 的语义是**分级阈值，不是过滤器**：

- 超额样本**照样记录**、照样进 EWMA
- 只是额外计入 `samples.*OverCap` 计数
- 原始值进 20 条的 `recentTtfbMs` 环（带 `source` 标记）
- 是否「因为被 prefill 污染而降低权重」由**评分层**决定，采集层不做丢弃决定

评分层的处理方式：取原始环里**干净样本的中位数**，而不是 EWMA。实测对比（5×120ms + 1×5000ms）：

| 指标 | 值 |
|---|---|
| EWMA（含污染，保留事实） | 2560 ms |
| 评分（干净样本中位数） | 120 ms |

用 EWMA 会让这条 120ms 的线路被单条尖刺拉到 2560ms 而误判。若全部样本都超额，该线路判为不可评分（`Infinity`），而不是拿被污染的数据排序。

---

## 八、复现方式

```bash
git checkout v0.1.0        # 回到本基准
npm test                   # 106 tests / 106 pass
npm run doctor             # FAIL 0 · WARN 1（端口占用）
```

单跑某一层：

```bash
npm run test:unit
npm run test:integration
```
