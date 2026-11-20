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
| `ewmaAlpha` / `ewmaMaxMs` | `0.3` / `3000` | 真实 TTFB 的 EWMA；超过上限的样本丢弃，避免把大 prompt 的 prefill 当成网络延迟 |
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

转发上游一律走 `https.request` + 443 端口 + 设置 `servername`，代码里没有任何跟随重定向的逻辑，所以请求不会被悄悄降级，也不会丢 `Authorization` 头。

### 注册的工具

| 工具 | 作用 |
| --- | --- |
| `cf_router_status` | 代理地址、每个域名选中的 IP、各候选的握手中位数 / TTFB EWMA / 成败次数 / 冷却剩余、最近的切换事件、转发统计 |
| `cf_router_probe` | 立即重测（可指定域名、可指定取样次数） |
| `cf_router_reset` | 清空失败计数、冷却与连接池 |
| `cf_router_mode` | 切换 `auto` / `direct` 并持久化；不传参则查询当前值 |

### HTTP 控制端点

不想用工具、想脚本化时用：

| 端点 | 效果 |
| --- | --- |
| `GET /__router/status` | 与 `cf_router_status` 相同的载荷 |
| `GET /__router/probe` | 重新探测，然后返回状态 |
| `GET /__router/reset` | 清空计数与连接池 |
| `GET /__router/mode` | 报告当前模式 |
| `GET /__router/mode?value=direct` | 切换模式 |

## 局限

- 只做 IPv4 边缘优选。不碰系统网络栈、不改 `hosts`、不动前缀策略。
- 只有 `targets` 里的域名（或被 `x-cf-target` 点名的域名）会被优选，其它域名原样转发。
- 请求体不压缩（压缩需要上游支持）。
- 代理活在宿主进程内，DSH 重启后由 `apply()` 自动重建。
- 依赖宿主提供的 `@deepseek-ai/*`，无法脱离 DSH 独立运行。

## 许可

MIT
