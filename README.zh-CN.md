# dsh-cf-router

一个 DSH 插件：把 Cloudflare 前置的 API 上游钉在**最快的 IPv4 边缘**上，并把 TLS 连接复用起来。

它**不是**独立代理程序，运行在 DeepSeek Harness 宿主进程里。

[English](README.md) · 简体中文

## 它解决什么问题

在优先走 IPv6 的机器上，双栈域名会同时解析出 A 和 AAAA，系统默认选 AAAA。如果这条 IPv6 路由从很远的边缘出去，每个请求都要多付一次长握手。在一个家庭宽带上针对某个 Cloudflare 前置的 API 端点实测（2026-11-06）：

| 路径 | 落地边缘 | TLS 握手 | 首字节 |
| --- | --- | --- | --- |
| IPv6（系统默认） | LAX 洛杉矶 | 0.92 – 2.68 s | 1.20 – 4.44 s |
| IPv4 | HKG 香港 | 0.60 – 0.63 s | 0.81 – 0.85 s |
| IPv4 + 连接复用 | HKG | 0（复用） | **0.30 s** |

Windows 的 IPv6 前缀优先级是 `::/0` = 40、`::ffff:0:0/96` = 35，只要 AAAA 存在就一定优先，所以这不是加个 `curl` 参数能全局解决的。

这个插件自动化两件事：**选对 IP**，**记住连接**。

## 机制

1. 每 `probeIntervalMs`（默认 5 分钟）对目标域名的每个 IPv4 发 `probeSamples` 次真请求，取 TCP + TLS + 首字节耗时的中位数；
2. 本地 HTTP 代理（默认 `127.0.0.1:8787`）转发时用 `https.Agent` 的 `lookup` 把连接钉在最优 IP 上，`servername` 保持原域名 —— SNI 和证书校验都不受影响；
3. Agent 开启 `keepAlive`，同一 IP 上的后续请求完全跳过握手；
4. 某个 IP 连续失败 `failThreshold` 次就判死并进入冷却，立刻重新探测。

探测分两级：候选多时先用便宜的 TCP 连接快速筛（`l1Concurrency` / `l1TimeoutMs`），只对最快的 `l2TopN` 个做完整 HTTP 实测。候选池从 DNS 起步，还可以从 Cloudflare 公开的 IPv4 网段抽样扩充（`discoverEnabled`）—— DNS 常常只给三个地址，不够挑出真正最快的边缘。

## 安装

这是 DSH 插件，装进 DSH profile。

**方式 A —— 链接本地检出（开发推荐）**

```bash
git clone https://github.com/arstoya/dsh-cf-router.git
```

加进 profile 的 `package.json`：

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

重启 DSH（或重载 profile）生效。

**方式 B —— 直接放进 profile**

把本目录复制到 `$DSH_HOME/profiles/<profile>/node_modules/dsh-cf-router`，再按上面在 `dsh.profile.bundles` 里登记 `dsh-cf-router`。

不需要 `npm install`。插件依赖 `@deepseek-ai/dsh-tools` 与 `@deepseek-ai/schemastery`，这两个随 DSH 安装包提供，由宿主解析。

装之前先自检：

```bash
node scripts/doctor.mjs
```

## 配置

把 [`cordis.patch.yml`](cordis.patch.yml) 里的配置块抄进 profile 的 patch 层。**必须改 `targets` 和 `probePath`** —— 包里给的是占位值。

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `targets` | `[]` | 要优选的域名。留空则代理一律回 `400 no_target`，不会瞎转发 |
| `listenHost` / `listenPort` | `127.0.0.1` / `8787` | 本地代理监听地址 |
| `probePath` | `/` | 探测用路径。任何返回响应的路径都算通（200 / 401 / 404 都行） |
| `probeSamples` | `3` | 每个 IP 的取样次数，取中位数 |
| `probeIntervalMs` | `300000` | 重新探测的间隔 |
| `discoverEnabled` / `discoverPerRange` | `true` / `2` | 从 CF 公开网段抽样补充候选 |
| `l1Concurrency` / `l1TimeoutMs` / `l2TopN` | `20` / `1200` / `10` | 两级测速 |
| `coloAllow` | `[]` | 只保留落在这些边缘的 IP（如 `["HKG"]`）；留空不限制 |
| `idleSkipMs` | `1800000` | 空闲这么久就跳过探测轮次（`0` = 永不跳过） |
| `maxSockets` / `keepAlive` | `16` / `true` | 连接复用 |
| `failThreshold` / `cooldownMs` | `2` / `60000` | 连续失败几次判死、冷却多久 |
| `ewmaAlpha` / `ewmaMaxMs` | `0.3` / `3000` | EWMA 权重。`ewmaMaxMs` 是**分级阈值，不是过滤器**：超额样本照样记录、照样进 EWMA，只是额外计入 `*OverCap` 计数，让评分层自己判断数据质量 |
| `firstByteTimeoutMs` | `60000` | 上游迟迟不给首字节就放弃 |
| `upstreamTimeoutMs` | `600000` | 上游整体超时（长推理要放宽） |
| `allowDirectFallback` | `true` | 所有候选都在冷却时退回普通 DNS 连接 |
| `routingMode` | `"auto"` | `auto` = 优选；`direct` = 不钉 IP（仍经过代理，用于排查优选本身是否有问题） |
| `stateFile` | `""` | 运行时模式的落盘路径，留空用 `$DSH_HOME/cf-router-state.json` |
| `verbose` | `false` | 记录每次转发与切换 |

## 用法

把 provider 的 baseURL 指到代理，路径保持不变：

```
原来：https://api.example.com/v1/chat/completions
现在：http://127.0.0.1:8787/v1/chat/completions
```

目标从 `Host` 头判断。当 `Host` 就是本地代理地址时，退回 `targets` 的第一项。也可以用 `x-cf-target: <域名>` 逐请求指定。

**`x-cf-target` 本身不构成授权。** `Host` 和 `x-cf-target` 走同一套四层校验，且解析出的域名必须与 `targets` 中的某一项**精确匹配** —— 不做后缀或通配：

| 层 | 作用 |
| --- | --- |
| Authority 解析 | 结构化解析而非 `split(':')`。拒绝协议、路径、query、userinfo、IPv6 字面量、IP 字面量、十进制/十六进制 IP 伪装、非法端口、多值 Host、控制字符。统一小写、去掉末尾点。 |
| 白名单 | 与规范化后的 `targets` 精确匹配。未配置的域名一律拒绝，不存在「任意公网 Host 都转发」。 |
| 地址分类 | 每条解析结果都必须是全球可路由地址。回环、RFC1918、链路本地、CGNAT、组播、保留段、文档段全部拒绝 —— 且**混合结果整体拒绝**，不挑安全的那个用。 |
| 防 rebinding | 验证过的解析结果就是连接时使用的地址。首次公网、随后私网的域名会在第二轮被重新校验并拒绝。 |

`direct` 模式**不是豁免** —— 它改的是 IP 钉定策略，不是授权。两种模式都走同一套校验。

被拒目标返回 `403 target_not_allowed`（不在白名单）或 `400 invalid_target`（格式非法），且**不会建立任何上游 socket**。

确有本地/内网目标需求时（本地开发、受信内网）设 `allowPrivateTargets: true`。白名单与格式校验仍然生效。

转发上游一律走 `https.request` + 443 端口 + 设置 `servername`，代码里没有任何跟随重定向的逻辑，所以请求不会被悄悄降级，也不会丢 `Authorization` 头。

### 注册的工具

| 工具 | 作用 |
| --- | --- |
| `cf_router_status` | 代理地址、每个域名选中的 IP、各候选的指标明细（见下）、成败次数、冷却剩余、最近的切换事件、转发统计 |
| `cf_router_probe` | 立即重测（可指定域名、可指定取样次数） |
| `cf_router_reset` | 清空失败计数、冷却与连接池 |
| `cf_router_mode` | 切换 `auto` / `direct` 并持久化；不传参则查询当前值 |

### 配置下限

部分配置项有硬下限。它们**不再是静默生效** —— `GET /__router/status` 的 `configEffective` 同时给出「你写的值」和「实际跑的值」：

```json
"configEffective": {
  "firstByteTimeoutMs": { "configured": 300, "effective": 5000, "floorMs": 5000 }
}
```

| 字段 | 下限 | 为什么 |
| --- | --- | --- |
| `firstByteTimeoutMs` | 5000 ms | `setTimeout(0)` 会立刻掐断每个请求 |
| `cooldownMs` | 1000 ms | 冷却过短会让候选之间反复横跳 |
| `probeIntervalMs` | 30000 ms | 每秒探测一次会被边缘当成扫描 |
| `healthCheckMs` | 5000 ms | 同上 |
| `ewmaMaxMs` | 200 ms | `*OverCap` 的分级阈值；低于它所有样本都算「超额」 |

**没有上线。** 长推理确实可能把 `firstByteTimeoutMs` 配到几百秒；给它加上限，就是制造一个与这些下限同类的静默改写。

所有数值单位均为毫秒。

### routingMode 的解析

`routingMode` 有三个来源，`GET /__router/status` 的 `routingModeSources` 三者都给出：

```json
"routingModeSources": {
  "configMode": "direct",
  "stateFileMode": "auto",
  "effectiveMode": "auto",
  "stateFileWins": true
}
```

启动时的解析规则：

| stateFile | 配置 | 生效 |
| --- | --- | --- |
| 不存在 / 无有效值 | `direct` | `direct` |
| `auto` | `direct` | `auto`（stateFile 赢） |
| `direct` | `auto` | `direct`（stateFile 赢） |

`stateFileWins` 为 true 时，运行时值来自之前某次 `setRoutingMode()`。想让配置重新生效，请调用 `resetRoutingMode`（只移除 `routingMode` 这一个键，文件里其它状态保留），**不要**整个删掉 `stateFile`。

`direct` 模式下后台探测与健康巡检照常运行，这样切回 `auto` 时能立刻用上最新数据。这是刻意设计，不是泄漏。

### 每个候选的指标

v0.2.1 起每个候选上报六个独立 EWMA。每一个都只由一对明确的起止事件产生，互不混杂；采不到就返回 `null`，不拿别的指标顶替。

| 字段 | 起点 | 终点 | 来源 |
| --- | --- | --- | --- |
| `tcpEwmaMs` | socket 创建 | `connect` | 探测 |
| `tlsEwmaMs` | TCP 连接完成 | `secureConnect` | 探测 / 新建连接的真实请求 |
| `probeTtfbEwmaMs` | 请求发出 | 收到响应头 | 探测 |
| `probeTotalEwmaMs` | 请求发出 | 响应体结束 | 探测 |
| `freshTtfbEwmaMs` | 请求发出 | 收到响应头 | 真实请求，新连接 |
| `reusedTtfbEwmaMs` | 请求发出 | 收到响应头 | 真实请求，复用连接 |

`samples` 记录每个 EWMA 收到多少样本，另有 `<指标>OverCap` 计数记录超出 `ewmaMaxMs` 的条数。

**任何原始观测都不会被丢弃。** 每条 TTFB 都进 EWMA，同时进一个 20 条的 `recentTtfbMs` 环形记录（带 `source: probe | fresh | reused`），用来分辨「稳定的慢」和「偶尔被一个大 prompt 拖慢」。大 TTFB 是信号，不是垃圾 —— 一个真的要 10 秒才吐首字的上游，那是这条线路的真实属性。

**路由评分只用 `probeTtfbMs`** —— TCP/TLS 是建连成本，真实请求 TTFB 会被模型 prefill 拉偏。当没有探测中位数时，评分取**原始环里干净样本的中位数**，而不是 EWMA：否则一条 5000ms 尖刺就能把 120ms 的线路拉到 2500ms。若全部样本都超额，该线路判为不可评分（`null`），而不是拿被污染的数据去排序。

两处兼容性说明：

- `probeMs` / `probeBestMs` 保留，但语义改为**探测 TTFB**（改造前含响应体下载时间）。
- `ewmaMs` **已移除** —— 它正是本次拆分掉的「TLS 或 TTFB」混指标。

### HTTP 控制端点

不想用工具、想脚本化时用：

| 端点 | 效果 |
| --- | --- |
方法语义遵循 HTTP 约定：读用 `GET`，任何有副作用的操作用 `POST`。

| 方法 | 路径 | 请求体 | 作用 |
| --- | --- | --- | --- |
| `GET` | `/__router/status` | — | 与 `cf_router_status` 相同的载荷 |
| `GET` | `/__router/mode` | — | 报告当前模式与它的三个来源 |
| `POST` | `/__router/mode` | `{"mode":"direct"}` | 切换模式并持久化 |
| `POST` | `/__router/probe` | 空 | 重新探测，然后返回状态 |
| `POST` | `/__router/reset` | 空 | 清空运行时统计、冷却与连接池 |
| `POST` | `/__router/reset-mode` | 空 | 只清持久化的 `routingMode` |

旧的 `GET /__router/mode?value=direct` 写法返回 `405` 且 `Allow: GET, POST` —— 这条路径本身两种方法都支持，被拒的是「用 GET 改状态」这种**写法**。

```bash
curl -X POST -H 'content-type: application/json'      -d '{"mode":"direct"}' http://127.0.0.1:8787/__router/mode
```

错误响应统一格式：

```json
{ "ok": false, "error": "invalid_value", "message": "mode 必须是 auto 或 direct", "field": "mode" }
```

| 状态 | `error` | 触发条件 |
| --- | --- | --- |
| 400 | `invalid_json` | 请求体不是合法 JSON / 不是对象 |
| 400 | `missing_field` | 必填字段缺失（或为 `undefined`） |
| 400 | `unknown_field` | 该接口不接受的字段 |
| 400 | `invalid_value` | 提供了字段但值非法（如 `mode: null`） |
| 405 | `method_not_allowed` | 方法不对；`Allow` 头列出可用方法 |
| 413 | `payload_too_large` | 管理接口请求体超过 64 KiB |
| 415 | `unsupported_media_type` | 带了非 JSON 的 `Content-Type` |
| 401 / 403 | `unauthorized` / `forbidden` | 为鉴权层保留（Issue #8） |

### 管理接口鉴权

修改型端点需要 Bearer Token：

```bash
node scripts/generate-admin-token.mjs --write /仓库外的路径/admin.token
# 然后在 profile patch 里：
#   adminTokenFile: /仓库外的路径/admin.token

curl -X POST -H 'content-type: application/json'      -H "Authorization: Bearer $(cat /仓库外的路径/admin.token)"      -d '{"mode":"direct"}' http://127.0.0.1:8787/__router/mode
```

**不要把这个 Token 写进 `cordis.patch.yml`。** 用 `adminTokenFile` 指向仓库外的文件。只有在文件未被版本控制且你清楚风险时，才直接填 `adminToken`。Token 用 `crypto.timingSafeEqual` 比较，且**不会**出现在日志、错误信息或 `/__router/status` 里。

**安全默认：没配 Token 时修改型端点直接禁用**（`403 admin_token_not_configured`），不是静默开放。`allowUnauthenticatedLocalAdmin: true` 是受信开发机上的显式逃生舱。

只读端点（`/status`、`/mode`）默认开放，因为 DSH 工具与监控需要读；要一并保护就设 `adminProtectStatus: true`。

三层防护：

| 层 | 行为 | 为什么 |
| --- | --- | --- |
| `Host` | 监听回环时只接受回环/本机 Host | 挡 DNS rebinding：攻击者域名解析到 127.0.0.1，但它的 `Host` 仍自带攻击者域名 |
| `Origin` | 任何浏览器来源都拒绝，除非列在 `adminAllowedOrigins` | 挡住「你恰好开着的某个网页」发起的跨站调用。**不带** `Origin` 的请求（curl / DSH / 服务端脚本）不受影响 —— 它们的凭据是 Token |
| 频率限制 | `adminRateWindowMs` 窗口内 `adminRateLimit` 次，按来源 **与读写** 分桶 | 挡住跑飞的脚本，又不会误锁正常操作：狂打写接口不影响读 |

进程内的 DSH 工具调用（`cf_router_*`）不经过 HTTP，不受以上任何一条影响。

## 候选池

候选不再每轮重新随机（旧实现下一次刷新就可能丢掉优质 IP）。每个 host 一个候选池，记录生命周期元信息并决定「哪些值得探测」：

| 来源 | 为什么保留 |
| --- | --- |
| `current` | 此刻正在承载流量的 IP |
| `dns` | DNS 解析得到的基础兜底 |
| `historical` | 有成功探测记录的 IP |
| `exploration` | 新 IP，受比例与最小刷新间隔双重约束 |

**容量上限绝不压过 DNS 兜底。** 如果 DNS 返回数量超过 `candidatePoolMaxSize`，候选池会临时超出配置上限 —— 为了一个数字丢掉真实兜底，是拿实质换形式。当前线路同理。`statusSnapshot().candidatePools[].overCapacity` 如实报告超出多少，不隐藏。

**淘汰候选不删历史。** 性能数据在 `ipStats`，有独立生命周期；候选池只记 `firstSeenAt` / `lastProbeAt` / `lastSuccessAt` / `probeCount` 这类元信息。掉出候选池后又出现的 IP，会沿用之前的 EWMA 与失败计数，而不是当成全新节点。Agent 复用是另一回事（#12）。

过期判据取 `lastSeenAt` / `lastProbeAt` / `lastSuccessAt` 三者的最新值 —— 一个历史优秀但近期不在 DNS 里的 IP，不会因为「最近没被看见」就被丢掉。

四个比例在装载期归一化；若全为 0 则退化为「只用 DNS 兜底」而非空池。实际生效值见 `statusSnapshot().candidatePools[].ratios`。

## Header 处理

代理夹在客户端与上游之间，必须守住**端到端 / 逐跳**边界（RFC 7230 §6.1），而不是「看着特殊就删」。

| 类别 | 例子 | 行为 |
| --- | --- | --- |
| 端到端 | `content-encoding`、`content-type`、`authorization`、`accept-encoding`、`x-request-id` | 原样转发 —— 删掉 `content-encoding` 客户端就解不开 gzip |
| 逐跳 | `connection`、`keep-alive`、`proxy-authenticate`、`proxy-authorization`、`te`、`trailer`、`transfer-encoding`、`upgrade` | 双向剥离 |
| 动态声明 | `Connection: X-Internal` 里列出的任意字段 | 同样剥离 —— 那是逐跳声明，`X-Internal` 不该泄漏 |

`transfer-encoding` 两边都不出现：framing 由 Node 根据实际流重新决定。上游声明 chunked 时，同时出现的 `content-length` 一律丢弃，不予采信。

`Expect: 100-continue` **不转发**。请求体立即开始流动，没有与上游协商 `100` 的窗口；透传这个头会让客户端等待一个已经不存在的跳。`x-cf-target` 在上游之前剥掉。

SSE 额外加 `x-accel-buffering: no`、缺省补 `cache-control: no-cache`、并 `setNoDelay` —— 否则事件会攒批到达而不是边产生边发。

## 版本

`0.2.1` —— 变更与升级注意事项见 [CHANGELOG.md](CHANGELOG.md)。

## 局限

- 只做 IPv4 边缘优选。不碰系统网络栈、不改 `hosts`、不动前缀策略。
- 只有 `targets` 里的域名会被转发。`x-cf-target` 只在这些域名里选，不能指定新域名。
- 请求体不压缩（压缩需要上游支持）。
- 代理活在宿主进程内，DSH 重启后由 `apply()` 自动重建。
- 依赖宿主提供的 `@deepseek-ai/*`，无法脱离 DSH 独立运行。

## 许可

MIT
