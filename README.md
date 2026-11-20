# dsh-cf-router

给 Cloudflare 前置的 API 上游挑最快的 IPv4 边缘，并把长连接复用起来。**DSH 插件**，不是独立代理程序。

## 它解决什么

实测 `api.commandcode.ai`（2026-11-06，本机家宽）：

| 路径 | 落地边缘 | TLS 握手 | 首字节 |
| --- | --- | --- | --- |
| IPv6（系统默认优先） | LAX 洛杉矶 | 0.92 – 2.68s | 1.20 – 4.44s |
| IPv4 | HKG 香港 | 0.60 – 0.63s | 0.81 – 0.85s |
| IPv4 + 连接复用 | HKG | 0（复用） | **0.30s** |

Windows 的 IPv6 前缀优先级（`::/0` = 40 > `::ffff:0:0/96` = 35）导致 DNS 同时有 A/AAAA 时永远先走 IPv6，而这条路的出口绕道洛杉矶，还偶发 2.7s 的握手尖刺。

这个插件把两件事自动化：**选对 IP**，**记住连接**。

## 机制

1. 每 `probeIntervalMs`（默认 5 分钟）对目标域名的每个 IPv4 做 `probeSamples` 次真请求探测，记录 TCP + TLS + 首字节的总耗时，按中位数排序；
2. 本地 HTTP 代理（默认 `127.0.0.1:8787`）转发时用 `https.Agent` 的 `lookup` 把连接钉在最优 IP 上，`servername` 保持原域名（SNI 正常）；
3. Agent 开启 `keepAlive`，同一 IP 上的后续请求不再握手；
4. 连接失败累计到 `failThreshold` 次，丢弃该 IP 的连接池并立即重探测。

两级测速：候选多时先用纯 TCP 快速筛（`l1Concurrency` / `l1TimeoutMs`），只对最快的 `l2TopN` 个做完整 HTTP 实测。候选池除 DNS 返回的地址外，还能从 Cloudflare 公开网段抽样补充（`discoverEnabled`）—— DNS 常常只给 3 个 IP，挑不出真正更快的。

## 安装

作为 DSH 插件安装，两种方式选一种。

**方式 A：本地目录（开发/自用推荐）**

```bash
git clone https://github.com/arstoya/dsh-cf-router.git
```

然后在 DSH profile 的 `package.json` 里加依赖，并在 `dsh.profile.bundles` 里登记：

```json
{
  "dependencies": {
    "dsh-cf-router": "link:/path/to/dsh-cf-router"
  },
  "dsh": {
    "profile": {
      "bundles": [ "...", "dsh-cf-router" ]
    }
  }
}
```

重启 DSH 生效。

**方式 B：直接放进 profile 的 node_modules**

把整个目录复制到 `$DSH_HOME/profiles/<profile>/node_modules/dsh-cf-router`，再按方式 A 在 `dsh.profile.bundles` 里登记 `dsh-cf-router`。

> 插件依赖宿主提供的 `@deepseek-ai/dsh-tools` 与 `@deepseek-ai/schemastery`（都在 DSH 安装包内），所以它**不能**用 `npm install` 单独跑起来，也不需要 `npm install`。

装完自查：

```bash
node scripts/doctor.mjs
```

## 工具

插件注册四个工具：

| 工具 | 作用 |
| --- | --- |
| `cf_router_status` | 本地代理地址、每个域名选中的 IP、各候选的握手中位数 / 真实 TTFB EWMA / 成功失败数 / 冷却剩余、最近的自动切换事件、转发统计 |
| `cf_router_probe` | 立即重测（可指定域名与取样次数），并据结果更新当前最优 IP |
| `cf_router_reset` | 清空失败计数、冷却状态与连接池（换网络或怀疑连接池卡住时用） |
| `cf_router_mode` | 切换 `auto` / `direct` 并持久化；不传参则查询当前值 |

## 接法

把要用它的 provider 的 baseURL 换成代理地址，路径不变：

```
原：https://api.commandcode.ai/provider/v1
新：http://127.0.0.1:8787/provider/v1
```

代理按 `Host` 头决定转给谁；本地 `Host` 是 `127.0.0.1:8787` 时退回配置里的第一个 `targets`。也可以用 `x-cf-target: <域名>` 头显式指定。

> 转发上游一律走 `https.request` + `port 443` + `servername`，代码里没有任何 301/302 跟随逻辑，所以不存在跨协议重定向，也不会丢 `Authorization` 头。实测带假 key 打 `http://127.0.0.1:8787/provider/v1/chat/completions`，上游正确回 401，链路完好。

## 配置

`cordis.patch.yml` 里是一份带注释的完整配置，可以直接抄进 profile 的 patch 层。要点：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `targets` | `["api.commandcode.ai"]` | 要优选的域名列表 |
| `listenHost` / `listenPort` | `127.0.0.1` / `8787` | 本地代理监听 |
| `probePath` | `/provider/v1/models` | 探测用路径（返回 200 或 401 都算通） |
| `probeSamples` | `3` | 每个 IP 取样次数，取中位数 |
| `probeIntervalMs` | `300000` | 定期重探测间隔 |
| `discoverEnabled` / `discoverPerRange` | `true` / `2` | 从 CF 公开网段抽样补充候选池 |
| `l1Concurrency` / `l1TimeoutMs` / `l2TopN` | `20` / `1200` / `10` | 两级测速：先 TCP 筛，再 HTTP 实测 |
| `coloAllow` | `[]` | 只保留落在这些边缘节点的 IP（如 `["HKG"]`），留空不限制 |
| `idleSkipMs` | `1800000` | 这么久没有真实请求就跳过探测轮次（0 = 不跳过） |
| `maxSockets` / `keepAlive` | `16` / `true` | 连接复用 |
| `failThreshold` / `cooldownMs` | `2` / `60000` | 连续失败几次判死、冷却多久 |
| `ewmaAlpha` / `ewmaMaxMs` | `0.3` / `3000` | 真实 TTFB 的 EWMA 权重与上限（超限不计入，避免 prefill 污染） |
| `firstByteTimeoutMs` | `60000` | 上游首字节超时，超时即换 IP |
| `upstreamTimeoutMs` | `600000` | 上游整体无响应超时（长推理要放宽） |
| `allowDirectFallback` | `true` | 所有候选都在冷却时退回系统 DNS 直连 |
| `routingMode` | `"auto"` | `auto` 优选 / `direct` 不优选（仍经过代理，用于排查优选本身的问题） |
| `stateFile` | `""` | 运行时选择的落盘路径，留空用 `$DSH_HOME/cf-router-state.json` |
| `verbose` | `false` | 记录每次转发与切换 |

## 局限

- 只处理 IPv4 优选，不碰系统网络栈，不动 hosts，不改前缀策略；
- 只对 `targets` 里的域名生效，其它域名原样直连；
- 请求体不压缩（压缩要上游支持，未验证）；
- 代理在宿主进程内，DSH 重启后由 `apply()` 自动重建；
- 依赖宿主的 `@deepseek-ai/dsh-tools` 与 `@deepseek-ai/schemastery`，无法脱离 DSH 独立运行。

## 许可

MIT
