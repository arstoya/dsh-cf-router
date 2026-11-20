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
| `npm test` | **79 tests / 79 pass / 0 fail**，约 15 秒（含一个约 9 秒的首字节超时用例） |
| `npm run doctor` | FAIL 0 · WARN 1 · 17 项（与开工前一致，未被破坏） |
| 连续三次 `npm test` | 三次均 79/79，结果一致 |
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
| **合计** | **79** | |

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

| 问题 | 位置 | 现状 |
|---|---|---|
| 探测耗时含响应体下载 | `probeOnce` | `finish()` 在 `res.end` 之后，`median` 不是纯 TTFB |
| TLS 与 TTFB 混进同一个 EWMA | `handleProxy` | `noteSuccess(host, ip, tlsMs ?? ttfb)` |
| 新连接/复用连接 TTFB 不区分 | `handleProxy` | 同一个 `ewmaMs` |
| `scoreOf` 对不同量纲取 min | `scoreOf` | `min(ewma, probeMedian)` 缺乏统计意义 |

### 7.3 与本轮无关、但测出来的

| 问题 | 说明 | 建议 |
|---|---|---|
| `firstByteTimeoutMs` 有 5000ms 硬下限 | `Math.max(5000, cfg.firstByteTimeoutMs)`，配 300 实际按 5000 生效 | 要可配置就得改这行。当前两条用例钉住行为：一条验证下限存在，一条真实触发超时 |
| 配置里的 `routingMode` 启动时不生效 | `apply()` 把 `cfg.routingMode` 记成 `lastCfgMode` 基准，导致首次 `currentMode()` 认为「设置页没动过」，沿用 `loadState()` 的 `auto` | 要修就是改基准语义，属行为变更，需单独立项 |
| 请求/响应头未做 hop-by-hop 过滤 | `{ ...req.headers }` 与 `res.writeHead(..., upRes.headers)` 直接透传 | Issue #5 处理 |

---

## 八、复现方式

```bash
git checkout v0.1.0        # 回到本基准
npm test                   # 79 tests / 79 pass
npm run doctor             # FAIL 0 · WARN 1（端口占用）
```

单跑某一层：

```bash
npm run test:unit
npm run test:integration
```
