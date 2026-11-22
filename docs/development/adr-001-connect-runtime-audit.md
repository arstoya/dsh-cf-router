# ADR-001：DSH Runtime Gate —— CONNECT 隧道能力审计

- **状态**：已通过（有条件）
- **日期**：2026-11-22
- **对应**：v0.4.0 A1（DSH Architecture ADR and Runtime Audit）
- **文档依据**：《v0.3.0 / v0.4.0 实施构建方案》§4.3、§5.6 D2

---

## 一、为什么必须先做这件事

方案 §4.3 的原话：

> 在实现 CONNECT 前必须先验证 DSH 插件宿主是否允许原始双向 Socket/TCP 隧道。
> **不能假设一个普通 HTTP Request Handler 就能实现 CONNECT。**
> ……如果宿主不支持，记录结论并调整交付：v0.4.0 可先交付 HTTP Forward + Reverse，
> CONNECT 作为受宿主能力约束的独立子版本；**不得伪造 CONNECT 已支持**。

即：D2 能否进入开发，取决于这份审计。如果结论是 FAIL，v0.4.0 的范围要缩。

---

## 二、审计项与结果

| # | 检查项 | 结果 | 证据 |
|---|---|---|---|
| 1 | `http.Server` 是否触发 `'connect'` 事件 | **PASS** | Node v26.13.0，事件正常触发 |
| 2 | 插件进程内能否绑定监听端口 | **PASS** | 实测 `127.0.0.1:63703`（本机 cf-router 现役即监听 8787） |
| 3 | 能否建立上游隧道并双向透传字节 | **PASS** | `CONNECT` 握手返回 `200 Connection Established`，回显 `R:hello` |
| 4 | 半关闭 / socket 释放 | **PASS** | 客户端 `end()` 后 socket 正常释放 |
| 5 | 大流量与背压 | **PASS** | 256 KiB 透传 262152 字节，heap 增量仅 85 KiB |
| 6 | 非白名单目标拒绝 | **PASS** | `CONNECT evil.example:443` → `403 Forbidden` |
| 7 | **在 DSH `apply()` 调用链之后**仍可建隧道 server | **PASS** | apply() 后新建 server，`'connect'` 事件仍触发 |
| 8 | 宿主 sandbox 是否限制插件的 `net` 能力 | **未受限** | 本机 sandbox 插件仅覆盖 bash / fs / pwsh，不作用于插件的 Node 能力 |

审计脚本：
- `tmp/a1-connect-audit.mjs` —— Node 层能力（10 项全 PASS）
- `tmp/a1-in-plugin.mjs` —— 插件上下文（3 项全 PASS）
- `apply()` 调用链验证 —— 内联执行，2 项 PASS

---

## 三、结论

**D2（HTTPS CONNECT Tunnel）可以进入开发。** 不存在宿主能力阻塞。

但结论**带条件**，必须记清：

### 条件 1：这只证明了「本机、当前 DSH 0.2.1-rc.5」

审计在 `@deepseek-ai/dsh-desktop-runtime 0.2.1-rc.5` + Node v26.13.0 上完成。
DSH 升级后必须重跑这三个脚本，不能把这次结论当成永久有效的通行证。

### 条件 2：证明了「能」，没有证明「允许」

技术上插件能建任何 socket，但这**不等于**这是一个受支持的扩展点。
方案要求的是「宿主是否允许」，而「允许」的判据在 DSH 侧（有没有官方 API、会不会在升级后失效）。
本审计只能证明「当前没有东西阻止它」。

**因此 D2 的实现必须做到**：
- 不依赖任何未文档化的 DSH 内部行为
- 自己监听独立端口（不劫持 DSH 端口）
- 宿主不提供该能力时能**优雅降级**（D1 HTTP Forward 与 E1/E2 Reverse 不受影响）

### 条件 3：没有验证真实对外可达性

审计全在 `127.0.0.1` 完成。若 D2 要对外提供服务，还需要验证：
- 防火墙 / NAT 是否放行
- 部署环境是否在容器内
- 端口是否被其他进程占用

这三条属于部署环节，不改变代码可行性。

---

## 四、对 v0.4.0 交付的影响

原文的 D2 标记是 `P0*`（受宿主能力门控）。现在门控通过，D2 转为正常 P0。

但方案 §9.2 的注解仍然有效，必须保留：

> \* 如果 DSH 无法提供 CONNECT 所需原始隧道能力，D2 标记为 blocked 或从 v0.4.0 正式支持范围移出；
> **不能用普通 HTTP 转发替代并宣称完成**。

本次审计让这个「如果」不成立，但**没有**取消这条禁令本身。

---

## 五、给 B1（目标验证）的额外约束

CONNECT 模式有一个与 HTTP Forward 不同的安全特性（方案 §5.6 D2 第 4 条）：

> 不解密 TLS，不检查加密后的 HTTP 路径和状态码；**CONNECT 模式的路由粒度只能是连接建立前可见的信息**。

这意味着 CONNECT 下**只能**按 `host:port` 做白名单与 DNS/IP 校验，无法看到路径。
所以 B1 的 Target Validator 必须提供两个层级的接口：

| 层级 | 输入 | 用于 |
|---|---|---|
| authority 级 | `host` + `port` | CONNECT |
| 完整 URL 级 | `scheme` + `authority` + `path` + `query` | HTTP Forward / Reverse |

**不能让 CONNECT 复用「完整 URL 级」校验并放宽它** —— 那等于用弱的输入过强的检查。

---

## 六、尚未审计的项（A1 未覆盖，留给后续）

| 项 | 归属 |
|---|---|
| DSH 是否提供官方代理扩展点 | A1 后续（需读 DSH 插件 API 文档，非本仓库能力） |
| 多客户端 / RouteGroup 隔离如何接入 DSH 认证 | B3 |
| 配置 schema 迁移到新结构 | F2 |
| HTTP/2 协商与降级 | C1（方案 §5.3 明确「不要宣称支持 HTTP/2，除非实际握手与并发测试通过」） |
