# 插件市场提交材料

> **状态：未采用。** 2026-11-23 决定不走 npm 发布 + 市场收录这条路，
> 改为每个版本打 tag 并创建 GitHub Release。
>
> 本文件保留，因为其中的 **capabilities / category 分析**仍然有用
> （尤其是「为什么不声明 `credentials`」那一段，将来若重新考虑上架可直接复用）。
> 下面的「待执行」步骤**不要照做**。

---

## 前置条件（两件事，缺一不可）

| # | 事项 | 状态 |
| --- | --- | --- |
| 1 | 发布到 npm（`dsh-cf-router`） | ⬜ 待做 —— 需要 npm 登录 |
| 2 | 提交条目到 awesome-dsh-plugin.com | ⬜ 待做 —— 需按其流程 |

包名在 registry.npmjs.org 上**未被占用**（实测 404），可以直接发布。

---

## 条目内容（按清单字段）

```json
{
  "name": "dsh-cf-router",
  "owner": "arstoya",
  "url": "https://github.com/arstoya/dsh-cf-router",
  "category": "dev",
  "npm": "dsh-cf-router",
  "version": "0.3.0",
  "install": "dsh plugin --profile web add dsh-cf-router",
  "capabilities": ["fs-read", "fs-write", "network", "env"],
  "capabilityRedLines": [],
  "added": "2026-11-23"
}
```

### category 选择说明

清单现有分类里，`dev`（Development & Runtime）最贴切。备选：

- `remote`（Remote & Mobile）—— 若更看重「代理/连接」属性
- `model`（Models & Providers）—— 若更看重「服务 API 上游」属性

`dev` 的理由：它不改 UI、不改模型配置，只是优化与上游的连接路径。

### capabilities 逐项依据

| 能力 | 是否需要 | 依据 |
| --- | --- | --- |
| `network` | ✅ | 连 Cloudflare 边缘节点做探测与转发 |
| `fs-read` | ✅ | 读状态文件、profile 配置 |
| `fs-write` | ✅ | 写状态文件（节流 60s，退出强制写） |
| `env` | ✅ | 读 `DSH_HOME` 解析状态文件默认路径 |
| `shell` | ❌ | 不执行任何子进程 |
| `credentials` | ❌ | **不读 API key**，只转发已带凭据的请求 |
| `llm` | ❌ | 自己不调 LLM API（代理别人的调用） |
| `dynamic-code` | ❌ | 不 eval、不动态加载 |

### capabilityRedLines：空

清单里最常见的红线是 `reads credentials/secrets AND has network access`（962 条中招）。

cf-router **不读凭据**：它转发客户端已带上的 `Authorization`，不解析、不存储、不落日志。所以这条红线不适用。

---

## 描述文案

### 英文（description.en）

```
Local reverse proxy that pins Cloudflare-fronted API upstreams to the fastest IPv4 edge. Probes TCP + TLS + TTFB across candidate IPs, keeps connections alive for reuse, and fails over automatically when a route degrades. Works entirely on loopback: no traffic leaves your machine except to the upstream you already configured.
```

### 中文（description.zh）

```
本地反向代理，把 Cloudflare 前置的 API 上游钉到最快的 IPv4 边缘节点。跨候选 IP 探测 TCP + TLS + TTFB，保持连接复用，线路劣化时自动切换。全程只监听回环地址：除你已配置的上游外，没有任何流量离开本机。
```

---

## 为什么这个插件值得上架（给审核者看的）

1. **解决真实问题**：Cloudflare 边缘节点的延迟差异可达 2–3 倍，手工选 IP 无法持续。
2. **不改变业务协议**：纯 HTTP 反向代理，不理解也不修改 API 语义。
3. **安全默认**：
   - 只监听 `127.0.0.1`
   - 目标白名单精确匹配，未配置的域名一律 403
   - 修改型管理端点默认禁用（未配 Token 时返回 403）
   - 不读凭据、不落敏感日志
4. **测试基线**：588 项自动化测试，零第三方依赖。
5. **可观测**：`statusSnapshot()` 暴露 30 个字段，含候选池、健康状态、连接池、切换迟滞。

---

## npm 发布步骤（待执行）

```bash
cd D:/Deepseek Workspace/repos/dsh-cf-router

# 1. 登录（需要 npm 账号；也可用 token）
npm login
# 或：npm config set //registry.npmjs.org/:_authToken=<TOKEN>

# 2. 最后确认打包内容
npm pack --dry-run
# 预期：22 个文件 / 约 106 kB，含 scripts/generate-admin-token.mjs

# 3. 发布
npm publish --access public

# 4. 验证
curl -s https://registry.npmjs.org/dsh-cf-router/latest | head -c 200
```

### 发布前必查三项

- [ ] `npm pack --dry-run` 里**没有** `test/`、`logs/`、`.plugin-backups`
- [ ] 没有 `*.token` / `admin-token*` 之类的文件
- [ ] `dsh.bundle.patch` 指向的 `cordis.patch.yml` 在包里（已确认）

---

## 上架后的注意事项

1. **首次安装后 `targets` 是空的**（`cordis.patch.yml` 里是 `api.example.com` 占位符）。
   用户必须在 profile patch 里配自己的上游，否则所有请求 403。
   → 市场页面需要显著提示这一点。

2. **管理 Token 必须先生成**，否则修改型端点不可用：
   ```bash
   npx dsh-cf-router-token --write <仓库外路径>/admin.token
   ```

3. **`drainTimeoutMs` 默认 120s**。若用户的上游是长 SSE（AI 流式接口），
   需要调大到超过最长流时长，否则线路切换会切断进行中的流。

---

## 已知限制（如实披露，不要藏）

- **模块化未完成**：`lib/index.js` 3325 行，78% 依赖模块级单例；纯函数层已拆出 14 个模块
- **24 小时长稳未实跑**：监测脚本已交付（`npm run watch:stability`），判据有 18 项测试
- **IPv6 目标未支持**：只做 IPv4 优选，IPv6 字面量在第一层校验就被拒
- **`Expect: 100-continue` 不转发**：请求体立即流动，没有与上游协商 100 的窗口
