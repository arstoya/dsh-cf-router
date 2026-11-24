# A2 设计草案：统一 Request/Upstream 接口冻结

- **对应**：Issue #26（v0.4.0 阶段一第二步）
- **状态**：**已实施**（2026-11-24）
- **前置**：A1 已完成（ADR-001）
- **结果**：`lib/contract/` 4 个模块，测试 588 → 663，类型检查 0 错误

---

## 一、一个必须首先定的技术选择

方案 §5.1 写的是 `interface RequestContext { ... }` —— TypeScript 语法。

但本仓库的实际情况：

| 事实 | 影响 |
| --- | --- |
| 纯 ESM `.mjs`，无构建步骤 | 加 TS 需要引入 tsc/esbuild，破坏「零第三方依赖」 |
| 没有 `.d.ts`，`package.json` 无 typescript | 现有 14 个模块全靠 JSDoc 注释 |
| CI 只跑 `node --check` 与 `node --test` | 加类型检查要改 CI |

**结论：接口用「JSDoc 类型 + 运行时工厂函数 + 契约测试」三件套表达，不引入 TypeScript。**

这不是降级，是等价替换：

| TS 提供 | 这里的替代 |
| --- | --- |
| 编译期字段检查 | JSDoc —— 编辑器能提示，`@ts-check` 可在需要时开启 |
| 构造时保证结构完整 | 工厂函数运行时校验并填默认值 |
| 接口不会被误用 | 契约测试 —— 可执行，CI 里会红 |

代价是：字段拼错在运行前不报错。用契约测试覆盖关键路径可以接受，而引入 TS 的代价（构建、依赖、CI 改造）更大。

---

## 二、文件布局

```
lib/contract/
├── errors.mjs        9 个具名错误类型
├── request-context.mjs   makeRequestContext() + 校验
├── upstream.mjs       makeUpstream() / makeUpstreamGroup() / makeProxyClient()
└── index.mjs          统一出口
```

为什么开子目录而不是平铺：v0.4.0 会新增 20+ 模块，`lib/` 现在已有 14 个 `.mjs`，
再平铺下去会难以分辨「现有 cf-router 的」与「新架构的」。子目录本身就是边界。

---

## 三、错误类型

现有代码用普通对象：`{ error: 'target_not_allowed', message }`。
新架构方案要求 9 个具名类型。**建议改用 class**，理由：

- C3（重试决策）需要按类型分支，`instanceof` 比字符串可靠
- `Error` 子类自动带 `stack`，排查时有用
- 同时保留 `code` 字段，字符串判断仍然可用

```js
class ProxyError extends Error {
  constructor(code, message, details = {}) {
    super(message)
    this.name = 'ProxyError'
    this.code = code           // 稳定标识，如 'target_denied'
    this.details = details     // 不含敏感值
  }
  toJSON() { return { code: this.code, message: this.message, ...this.details } }
}

// 9 个子类，code 固定
TargetDenied       → 'target_denied'
ClientUnauthorized → 'client_unauthorized'
DnsFailure         → 'dns_failure'
ConnectFailure     → 'connect_failure'
TlsFailure         → 'tls_failure'
UpstreamTimeout    → 'upstream_timeout'
ClientCancelled    → 'client_cancelled'
StreamFailure      → 'stream_failure'
RetryNotAllowed    → 'retry_not_allowed'
```

**关键约束**：`details` 不得包含 Token / Authorization / Cookie / 完整敏感 URL。
用一个测试断言 `JSON.stringify(err)` 不匹配 token 模式。

---

## 四、RequestContext

```js
/**
 * @typedef {object} RequestContext
 * @property {string} requestId      唯一标识，用于日志关联
 * @property {string} clientId       由服务端认证确定，不来自请求头
 * @property {string} routeGroupId   由服务端绑定关系确定
 * @property {'forward'|'reverse'} mode
 * @property {string} method
 * @property {string} originalUrl
 * @property {object} headers        已规范化为小写键
 * @property {ReadableStream|null} [body]
 * @property {AbortSignal} signal
 * @property {number} startedAt
 */
export function makeRequestContext(input) { /* 校验 + 填默认 + freeze */ }
```

### 校验规则（工厂函数内）

| 字段 | 规则 | 不满足时 |
| --- | --- | --- |
| `requestId` | 非空字符串 | 抛 `TypeError` |
| `clientId` / `routeGroupId` | 非空字符串 | 抛 `TypeError` |
| `mode` | 必须是 `'forward'` 或 `'reverse'` | 抛 `TypeError` |
| `method` | 非空，规范化为大写 | 自动大写 |
| `headers` | 对象，键规范化为小写 | 自动规范化 |
| `signal` | 实例化时若未提供，新建一个 | 自动创建 |
| `startedAt` | 未提供则 `Date.now()` | 自动填 |

### 为什么 `clientId` / `routeGroupId` 不允许为空

这两个字段是**授权决定的结果**，不是请求输入。B2 明确：客户端自报的身份 Header 必须被忽略。
如果工厂允许传空，调用方就可能传 `''` 并在下游被当成「未认证」处理 —— 那正是要避免的模糊状态。
空值应该在调用工厂**之前**就被拒绝（认证失败 → 抛 `ClientUnauthorized`）。

`Object.freeze` 的理由：Core 的各个阶段（验证 → 路由 → 传输）都读这个对象，
任何一处就地改写都会让后面的阶段看到被篡改的上下文。

---

## 五、Upstream / UpstreamGroup / ProxyClient

```js
Upstream {
  id: string            // 全局唯一，Registry 的主键
  name: string
  hostname: string
  port: number          // 1..65535
  protocol: 'https'     // 当前只支持 https（方案 §1.2）
  enabled: boolean
  priority: number      // 越小越优先，用于同 weight 时排序
  weight: number        // 加权轮询用，>= 0
  timeoutMs?: number    // 覆盖 Transport 的默认超时
}

UpstreamGroup {
  id, name
  upstreamIds: string[] // 引用 Upstream.id
  routingMode: 'auto' | 'direct'
  retryPolicy: RetryPolicy
}

ProxyClient {
  id, name
  enabled: boolean
  routeGroupId: string  // 绑定关系
  authTokenHash: string // 只存哈希，永不存明文
}
```

### 校验要点

- `port` 必须是 1–65535 的整数
- `protocol` 只接受 `'https'` —— 方案 §1.2 明确「不做明文 HTTP 到上游」
- `weight >= 0`；全部为 0 时视为等权
- `upstreamIds` 去重
- `authTokenHash` 不能是明文 Token —— 加一个**启发式检查**：
  若长度 < 32 或匹配常见明文 Token 前缀（`sk-` / `ghp_` / `github_pat_`）则拒绝。
  这不是密码学保证，是防手滑。

### RetryPolicy（C3 会细化，这里先定形状）

```js
{
  maxAttempts: number,        // 含首次，>= 1
  totalBudgetMs: number,      // 整次请求（含重试）的时间上限
  baseDelayMs: number,        // 退避基数
  maxDelayMs: number,
  retryOn: string[],          // ProxyError.code 的白名单
}
```

**注意**：`retryOn` 是 code 白名单，不是「retryable 布尔」。C3 的核心结论是
「重试资格由上下文决定」，所以策略只声明「哪些错误类别原则上可重试」，
最终决定还要看 `failurePhase` / `bodyReplayable` / `responseCommitted`。

---

## 六、契约测试设计（这是 A2 的核心交付）

方案 §5.1 要求两条：
> 至少验证两种入口能生成相同 RequestContext 语义，且 Core 不依赖代理入口类型。

### 测试 1：两种入口产出结构一致

写两个**假 Adapter**（不实现真实代理，只构造 context）：

```js
function fakeForwardAdapter(input) {
  return makeRequestContext({ mode: 'forward', ...input })
}
function fakeReverseAdapter(input) {
  return makeRequestContext({ mode: 'reverse', ...input })
}
```

断言：
- 两者除 `mode` 外，字段集合与类型完全相同
- 两者的 `headers` 都已被规范化为小写键
- 两者都拒绝空 `clientId`

这条证明「两种入口能生成相同语义的 context」。

### 测试 2：Core 不依赖入口类型 —— 用静态检查

```js
test('Core 模块不 import 任何 Adapter', () => {
  const coreFiles = readdirSync(coreDir).filter(f => f.endsWith('.mjs'))
  for (const f of coreFiles) {
    const src = readFileSync(join(coreDir, f), 'utf8')
    assert.equal(/from\s+['"].*adapter/.test(src), false,
      `${f} 不该 import adapter`)
  }
})
```

这比运行时 mock 更硬：**import 图是静态事实**，改不了。

### 测试 3：Core 只读 context，不读 mode 以外的东西

用 Proxy（`new Proxy(ctx, {get})`）记录 Core 实际访问了哪些字段，
断言它没有访问 `req` / `res` / `socket` 这类入口专有对象。

### 测试 4：错误类型

- 9 个子类的 `code` 固定、`instanceof` 正确
- `toJSON()` 不含敏感字段
- 从 `code` 能找回对应 class（`errorFromCode()`）

---

## 七、与现有代码的衔接

**A2 不改 `lib/index.js` 一行。**

新契约是并行生长的：
- `lib/contract/` 是纯新增
- 现有 cf-router（单 host 优选）继续用自己的一套
- 直到 D1/E1 真正接入，才出现第一处调用

这也意味着 A2 完成后：
- 现有 588 项测试不受影响
- 新增契约测试（预计 25–30 项）

---

## 八、三个已确定的选择

**1. JSDoc + 工厂函数，不引入 TypeScript 源码** —— 理由见 §一。
另加 `tsc --noEmit` 做编译期检查（见 §九）。

**2. 错误用 `class`** —— 与现有风格不同，但 C3 需要可靠的分支判断。

**3. `lib/contract/` 子目录** —— 而不是平铺进 `lib/`。

---

## 九、实施记录（2026-11-24）

### 交付

| 文件 | 内容 |
| --- | --- |
| `lib/contract/errors.mjs` | 9 个具名错误类型 + `errorFromCode` / `isProxyError` |
| `lib/contract/request-context.mjs` | `makeRequestContext` / `isRequestContext` |
| `lib/contract/upstream.mjs` | 4 个工厂 + `validateGroupReferences` |
| `lib/contract/index.mjs` | 统一出口 |
| `test/contract/*.test.js` | 4 个文件 / 75 项 |

测试 588 → **663**。

### 实施中发现的三个问题

**1. sha256 十六进制被误判为明文 Token**

`authTokenHash` 的明文检测里有一条「长 base64」模式 `/^[A-Za-z0-9+/=]{40,}$/`，
而 sha256 hex 是 64 位字母数字 —— **每次正常配置都会报「看起来是明文 Token」**。

测试抓到的。修法：先认 `HEX_DIGEST`（纯十六进制，32–128 位）形态再跑明文检测。

**2. bash 的 `**` 不递归**

CI 的语法检查原来写 `lib/*.mjs`，加子目录后漏检。改成 `**` 之后又踩另一个坑：
bash 默认不开 globstar，`lib/**/*.mjs` 被当成 `lib/*/*.mjs`，反而漏掉 `lib/index.js`。
最终改用 `find`。

**3. JSDoc 与实现不符**

`retryOn` / `upstreamIds` 的 JSDoc 写的是 `string[]`，实现返回的是
`Object.freeze` 的只读数组。`tsc` 第一次跑就报了这个 —— 运行时没影响，
但类型声明是错的。改成 `ReadonlyArray<string>`。

### 类型检查的边界

`jsconfig.json` 只 `include: ["lib/contract/**/*.mjs"]`。

存量代码（`lib/index.js` 3325 行 + 14 个旧模块）没有 JSDoc，全量纳入会一次报出
上百个错，把检查变成噪音。v0.4.0 起每新增一个模块纳入一个目录，逐步扩大。

### 未做

- **没有 Core 实现**。契约测试里的 `fakeCore` 只用于证明隔离性，
  真正的 Core 属于 C1。
- **没有 Adapter 实现**。`fakeForwardAdapter` / `fakeReverseAdapter` 是测试用的
  最小构造器，不做真实代理。真实 Adapter 属于 D1 / E1。
