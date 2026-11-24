/**
 * admin-api.mjs — 管理 API 的授权、校验、脱敏与审计（v0.4.0 / B3）
 *
 * 方案 §5.9：「管理接口需要独立的管理员身份、方法限制、schema 校验与审计日志。」
 * 本模块提供这四件事，外加分页、乐观锁冲突检测与删除前的引用检查。
 *
 * ## 为什么没有复用宿主认证（不是「假装复用了」）
 *
 * 宿主确实带 `@deepseek-ai/dsh-authorization`（`ctx.authorization`），但它的语义是
 * **「通过一次与人的对话去取得某个外部服务的凭证」**（package.json 的 peer 依赖是
 * `dsh-credentials` + `dsh-llm`，README 的定位是 plugin-owned flows that obtain a
 * credential through a conversation with the human）。它解决的是「插件怎么拿到第三方
 * 的 key」，与「校验一个入站 HTTP 管理请求是谁发的」是两回事：管理请求的凭据来自
 * `Authorization: Bearer`，不来自对话，也没有可交互的人类在场。
 *
 * 而且物理上也拿不到：
 *   1. 本插件从 profile 的解析树加载，`D:/dsh-home/profiles/desktop/node_modules/@deepseek-ai/`
 *      实测只有 `cosmokit` 与 `schemastery`。裸 `import` 任何其它宿主包都会解析失败，
 *      装载器会**静默丢弃整条 entry**（#20 踩过：不是 failed，是列表里根本不存在）。
 *   2. 想经 `ctx` 拿服务，就得把校验逻辑塞进 `apply()` 的闭包里，管理校验便无法脱离
 *      宿主上下文做单测 —— 而这个模块的每一条规则都必须能在纯 Node 下断言。
 *
 * 所以这里明确基于 `lib/admin-auth.mjs` 已有的三层（Host/Origin、Bearer + 时序安全
 * 比较、固定窗口限速）扩展，不新增一套并行的凭据机制。
 *
 * ## 错误映射（为什么不新造错误类）
 *
 * `lib/contract/errors.mjs` 是 A2 冻结的九个类型，里面没有 403/405/409/429。本模块
 * **不往契约层加类**，而是复用最近的那个并把 HTTP 语义放在 `details` 里：
 *
 *   · 认证/来源/限速被拒 → `ClientUnauthorized`，`details.status` 取 401 / 403 / 429
 *   · 删除被引用拒绝     → `TargetDenied`，`details.status = 409`
 *
 * 这样调用方仍是按 `err.code` 分支（不会退化成字符串比较），又不必修改已冻结的契约。
 * 参数本身不合法（漏传 adminId、list 不是数组）属于**调用方编程错误**，用内置
 * `TypeError`，不套业务错误类型 —— 那类错误不该被上层当成「请求被拒」来处理。
 *
 * @module admin-api
 */

import {
  checkHost,
  checkOrigin,
  extractBearer,
  safeTokenEqual,
  createRateLimiter,
} from './admin-auth.mjs'
import { ClientUnauthorized, TargetDenied } from './contract/errors.mjs'

/* ============================================================
 * 一、常量
 * ============================================================ */

/**
 * 管理端点允许的方法。刻意只有这四个：
 * 管理面是给运维做 CRUD 的，`PUT`（整体替换）与 `OPTIONS`（预检）都不提供 ——
 * 少一个动词就少一条「半实现的语义」。
 *
 * @type {ReadonlyArray<string>}
 */
export const ADMIN_METHODS = Object.freeze(['GET', 'POST', 'PATCH', 'DELETE'])

/** 会带请求体的方法。GET / DELETE 带体一律视为调用方搞错了端点。 */
const BODY_METHODS = Object.freeze(['POST', 'PATCH'])

/** 脱敏占位符。统一一个常量，测试与日志解析都能直接对齐。 */
const REDACTED = '[REDACTED]'

/** 循环引用占位符。JSON.stringify 遇到环会抛错，脱敏产物必须仍可序列化。 */
const CIRCULAR = '[Circular]'

/**
 * 敏感键名的**精确**集合（已归一化：小写、去掉非字母数字）。
 *
 * `authTokenHash` / `adminToken` 这类驼峰名归一化后不会以 `token` 结尾
 * （`authtokenhash` 以 `hash` 结尾），所以必须显式列出，不能只靠后缀规则。
 */
const SENSITIVE_EXACT = new Set([
  'authorization',
  'proxyauthorization',
  'cookie',
  'setcookie',
  'token',
  'authtoken',
  'admintoken',
  'authtokenhash',
  'apikey',
  'xapikey',
  'password',
  'passwd',
  'secret',
  'clientsecret',
  'credential',
  'credentials',
])

/**
 * 敏感键名的**后缀**规则。用后缀而不是「包含」是为了不误伤
 * `tokenizer` / `secretary` / `cookiejarPolicy` 这类正常字段 ——
 * 过度脱敏会让日志失去排查价值，而日志的价值就在于能看出「哪条 cookie 丢了」。
 *
 * @type {ReadonlyArray<string>}
 */
const SENSITIVE_SUFFIXES = Object.freeze([
  'token',
  'secret',
  'password',
  'passwd',
  'apikey',
  'cookie',
  'credential',
  'credentials',
])

/**
 * 值级指纹：键名不敏感、但值本身就是凭据的情况。
 *
 * 真实场景：错误对象把整行请求头塞进 `message`；`target` 里带 `?access_token=...`。
 * 这里只匹配**整串**，子串替换交给下面的 `CREDENTIAL_IN_TEXT` ——
 * 两者的区别是「这个值整体就是一个凭据」与「这段文字里夹了一句凭据」。
 *
 * @type {ReadonlyArray<RegExp>}
 */
const VALUE_FINGERPRINTS = Object.freeze([
  /^\s*bearer\s+\S+\s*$/i,
  /^\s*basic\s+[A-Za-z0-9+/=]{4,}\s*$/i,
  /^(sk|ghp|github_pat|xox[abprs]|AKIA)[-_A-Za-z0-9]{8,}$/,
])

/**
 * 文本里夹带的凭据。**必须处理这一种**：把 `err.message` 或 `target` 描述
 * 拼成「失败原因 Bearer xxx」是很常见的写法，而那时键名不敏感、整串也不匹配，
 * 只靠键名规则会整条漏出去。
 *
 * 限定为「方案名 + 至少 8 个 token 字符」才替换，避免把
 * 「basic 用法说明」这类正常文案切坏。
 */
const CREDENTIAL_IN_TEXT = /\b(bearer|basic)\s+([A-Za-z0-9._~+/=:-]{8,})/gi

/* ============================================================
 * 二、脱敏
 * ============================================================ */

/**
 * 键名归一化：小写 + 去掉所有非字母数字。
 *
 * `Set-Cookie` / `set_cookie` / `setCookie` 归一化后同为 `setcookie`，
 * 这样「大小写不敏感」不是靠调用方记得写三个分支。
 *
 * @param {string} key
 * @returns {string}
 */
function normalizeKey(key) {
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, '')
}

/**
 * 判断一个键名是否必须脱敏。
 *
 * @param {string} key
 * @returns {boolean}
 */
function isSensitiveKey(key) {
  const norm = normalizeKey(key)
  if (!norm) return false
  if (SENSITIVE_EXACT.has(norm)) return true
  for (const suffix of SENSITIVE_SUFFIXES) {
    if (norm.endsWith(suffix)) return true
  }
  return false
}

/**
 * 值是否像一个凭据。命中时整串替换，不做部分遮盖。
 *
 * @param {string} text
 * @returns {boolean}
 */
function looksLikeCredential(text) {
  const s = String(text)
  if (s.length < 8) return false
  return VALUE_FINGERPRINTS.some((re) => re.test(s))
}

/**
 * Cookie 串的遮盖：**保留名字、遮盖值**。
 *
 * 整串替换成 `[REDACTED]` 也能满足「不泄露」，但排查「客户端没带 session cookie」
 * 时就完全看不出是哪条丢了。名字不是秘密，值才是。
 *
 * @param {string} text
 * @returns {string}
 */
function maskCookieString(text) {
  return String(text)
    .split(';')
    .map((part) => {
      const eq = part.indexOf('=')
      if (eq < 0) return REDACTED
      const name = part.slice(0, eq).trim()
      if (!name) return REDACTED
      return `${name}=${REDACTED}`
    })
    .join('; ')
}

/**
 * 按键名遮盖一个值。
 *
 * @param {string} keyName
 * @param {unknown} value
 * @param {'log'|'response'} mode
 * @returns {unknown}
 */
function maskByKey(keyName, value, mode) {
  // 响应侧一律「什么都不给」：调用方拿到的结构本身就是契约的一部分，
  // 一旦开始按字段返回「保留了多少字符」之类的线索，就等于把响应面变成了旁路。
  if (mode === 'response') return REDACTED

  const norm = normalizeKey(keyName)
  if (norm === 'authorization' || norm === 'proxyauthorization') {
    // 只留方案名（Bearer / Basic）：日志里「客户端为什么发 Basic」是有用信息，
    // 而方案名后面那一段才是凭据。
    if (typeof value === 'string') {
      const m = /^\s*([A-Za-z]+)\s+\S+/.exec(value)
      return m ? `${m[1]} ${REDACTED}` : REDACTED
    }
    return REDACTED
  }

  if (norm === 'cookie' || norm === 'setcookie') {
    if (Array.isArray(value)) {
      return value.map((v) => (typeof v === 'string' ? maskCookieString(v) : REDACTED))
    }
    if (typeof value === 'string') return maskCookieString(value)
    return REDACTED
  }

  return REDACTED
}

/**
 * 清洗一段普通文本里夹带的凭据。
 *
 * 日志侧保留方案名（`Bearer [REDACTED]`），响应侧连方案名都不给 ——
 * 与 `maskByKey` 保持同一条强度规则。
 *
 * @param {string} text
 * @param {'log'|'response'} mode
 * @returns {string}
 */
function scrubCredentialText(text, mode) {
  return String(text).replace(CREDENTIAL_IN_TEXT, (_match, scheme) => (
    mode === 'log' ? `${scheme} ${REDACTED}` : REDACTED
  ))
}

/**
 * 递归脱敏的核心。
 *
 * 三条硬约束：
 *   1. **不就地修改**：入参是调用方还要继续用的对象（典型的 `req.headers`），
 *      就地改会把真实请求头洗掉，后续逻辑拿到的就不是原来的东西了。
 *   2. **可序列化**：产物要能直接进 JSON 日志，所以环要变成 `[Circular]`，
 *      Date 要变成 ISO 串，Error 只留 name/message/code。
 *   3. **键名敏感就不再往下递归**：敏感键的值整体替换，避免 `{ token: { value: '...' } }`
 *      这种嵌套形式从内层漏出去。
 *
 * 两处刻意的保守取舍（写清楚，不让调用方猜）：
 *   · `seen` 是整次调用的共享集合，所以**同一个对象出现在两个键下也会变成 `[Circular]`**。
 *     代价是日志里少一份重复副本，好处是产物大小有界、不会因共享结构爆炸。
 *   · 只有 `Date` / `Error` / 数组 / 普通对象有专门处理；`Map` / `Set` 会按可枚举属性
 *     退化成 `{}`。要记这类结构请先自行 `Array.from()` —— 脱敏层不猜业务语义。
 *
 * @param {unknown} value
 * @param {'log'|'response'} mode
 * @param {WeakSet<object>} seen
 * @param {string} keyName 当前值所属的键名（用于判断敏感）
 * @returns {unknown}
 */
function redactValue(value, mode, seen, keyName) {
  if (value === null) return null
  if (typeof value !== 'object') {
    if (typeof value === 'string') {
      // 整串就是一个凭据 → 整条替换；否则只清洗文本里夹带的那几段
      if (looksLikeCredential(value)) return REDACTED
      return scrubCredentialText(value, mode)
    }
    // number / boolean / undefined / bigint / symbol / function：
    // 函数与 symbol 无法序列化，替换成占位符，避免 JSON.stringify 静默丢键。
    if (typeof value === 'function' || typeof value === 'symbol') return '[Unserializable]'
    return value
  }

  if (seen.has(value)) return CIRCULAR
  seen.add(value)

  if (Array.isArray(value)) {
    /** @type {Array<unknown>} */
    const arr = []
    for (const item of value) arr.push(redactValue(item, mode, seen, keyName))
    return arr
  }

  if (value instanceof Date) return value.toISOString()

  if (value instanceof Error) {
    /** @type {Record<string, unknown>} */
    const e = { name: value.name, message: redactValue(value.message, mode, seen, keyName) }
    const code = /** @type {{code?: unknown}} */ (value).code
    if (typeof code === 'string') e.code = code
    return e
  }

  /** @type {Record<string, unknown>} */
  const out = {}
  for (const [k, v] of Object.entries(value)) {
    out[k] = isSensitiveKey(k) ? maskByKey(k, v, mode) : redactValue(v, mode, seen, k)
  }
  return out
}

/**
 * 给**日志**用的脱敏副本：保留结构线索（认证方案名、cookie 名），仅遮盖凭据本体。
 *
 * 为什么日志侧不干脆全遮：排查 401 时第一个要回答的问题就是「客户端到底发了什么方案、
 * 带了哪条 cookie」，全遮会让日志只剩「被拒了」三个字，等于没有日志。
 *
 * @param {unknown} value
 * @returns {unknown} 全新对象，入参不被修改
 */
export function redactForLog(value) {
  return redactValue(value, 'log', new WeakSet(), '')
}

/**
 * 给**响应**用的脱敏副本：敏感键一律替换成 `[REDACTED]`，不保留任何原文片段。
 *
 * 与 `redactForLog` 的差别只有强度：响应是给外部调用方看的，任何「保留了多少」
 * 的线索都是不必要的信息暴露；日志是给运维看的，线索越多越好。
 *
 * @param {unknown} value
 * @returns {unknown} 全新对象，入参不被修改
 */
export function redactForResponse(value) {
  return redactValue(value, 'response', new WeakSet(), '')
}

/* ============================================================
 * 三、管理员身份
 * ============================================================ */

/**
 * 构造一个管理请求被拒的错误。
 *
 * 细节（Token 片段、Origin 全文）一概不进 details —— 与 `contract/errors.mjs`
 * 的硬约束一致：`JSON.stringify(err)` 不得含敏感值。
 *
 * @param {number} status HTTP 语义状态码
 * @param {string} reason 稳定的小写原因码
 * @param {string} message 中文描述
 * @param {Record<string, unknown>} [extra]
 * @returns {ClientUnauthorized}
 */
function deny(status, reason, message, extra) {
  return new ClientUnauthorized(message, { status, reason, ...(extra || {}) })
}

/**
 * @typedef {object} AdminGuardOptions
 * @property {string} [token] 单管理员 Token（也可由 getToken 延迟提供）
 * @property {() => string} [getToken] 延迟取 Token 的函数：避免每个请求读盘
 * @property {Array<{adminId?: string, token: string}>} [credentials] 多管理员表，优先于 token
 * @property {string} [adminId] 单管理员的身份标识，默认 'admin'
 * @property {string} [listenHost] 监听地址，决定 Host 校验是否生效，默认回环
 * @property {string[]} [allowedOrigins] 允许的浏览器来源；不配 = 不接受任何跨源
 * @property {number} [maxFailures] 窗口内允许的失败次数，默认 5
 * @property {number} [windowMs] 限速窗口，默认 60000
 * @property {() => number} [now] 时钟注入，仅测试用
 */

/**
 * @typedef {object} AdminGuard
 * @property {(req: {headers?: Record<string, unknown>, remoteAddr?: string, method?: string, route?: string}) => {adminId: string}} authorize
 * @property {() => {authorized: number, unauthorized: number, rateLimited: number, deniedHost: number, deniedOrigin: number, failureBuckets: number, maxFailures: number, windowMs: number}} stats
 */

/**
 * 建立管理员身份闸门。
 *
 * 顺序是刻意的，四层从便宜到贵、从粗到细：
 *   Host → Origin → 频率 → 凭据
 * 频率闸放在凭据校验**之前**：一旦某个来源已经打满失败次数，就不该再让它触发一次
 * Token 比较，也不该让它从「响应快慢」里读出「这次差了几个字节」。
 *
 * @param {AdminGuardOptions} [options]
 * @returns {AdminGuard}
 */
export function createAdminGuard(options = {}) {
  const cfg = options && typeof options === 'object' ? options : {}
  const now = typeof cfg.now === 'function' ? cfg.now : () => Date.now()
  const listenHost = String(cfg.listenHost || '127.0.0.1')
  const allowedOrigins = Array.isArray(cfg.allowedOrigins) ? cfg.allowedOrigins.map(String) : []
  const defaultAdminId = String(cfg.adminId || 'admin')
  const maxFailures = Number.isFinite(cfg.maxFailures) && Number(cfg.maxFailures) >= 1
    ? Math.floor(Number(cfg.maxFailures))
    : 5
  const windowMs = Number.isFinite(cfg.windowMs) && Number(cfg.windowMs) > 0
    ? Math.floor(Number(cfg.windowMs))
    : 60_000
  const getToken = typeof cfg.getToken === 'function' ? cfg.getToken : () => String(cfg.token || '')

  /**
   * 多管理员表。归一化到 `{adminId, token}`，跳过空条目 ——
   * 配置写错时宁可直接没有这个管理员（会被判 401），也不要留一个 token 为空的
   * 条目去和任何输入做比较。
   *
   * @type {Array<{adminId: string, token: string}>}
   */
  const credentials = []
  if (Array.isArray(cfg.credentials)) {
    for (const raw of cfg.credentials) {
      if (!raw || typeof raw !== 'object') continue
      const item = /** @type {{adminId?: unknown, token?: unknown}} */ (raw)
      const token = String(item.token || '')
      if (!token) continue
      credentials.push({ adminId: String(item.adminId || defaultAdminId), token })
    }
  }

  /**
   * 失败计数闸门。复用 admin-auth 的固定窗口限流器，不另写一套计数：
   * 管理面本来就只有一个管理员、一个来源，固定窗口的边界多放行几次无所谓。
   *
   * **`route` 必须是服务端常量（如 `'upstream.delete'`），不能是 `req.url`。**
   * 桶键是 `来源|route`，如果把带 query 的原始 URL 传进来，攻击者换一个 query 就换一个桶，
   * 限速会被「每个 URL 各打满一次」稀释掉。这条约束没法在代码里强制（函数签名收的是
   * 字符串），所以写在这里当调用契约。
   *
   * 另一处必须在注释里说清的局限：这个限流器只有 `reset()`（全清），没有「按 key 清零」。
   * 这里成功认证后直接全清 —— 代价是别的来源在同一瞬间的失败计数被抹掉。
   * 但这只可能由**持有有效凭据的请求**触发，攻击者要能清自己的计数就得先拿到正确
   * Token，而到那一步他已经不需要绕限速了。所以这个代价不值得再写一套按 key 的窗口。
   */
  const limiter = createRateLimiter({ limit: maxFailures, windowMs, now })

  const counters = {
    authorized: 0,
    unauthorized: 0,
    rateLimited: 0,
    deniedHost: 0,
    deniedOrigin: 0,
  }

  /**
   * 在凭据表里找出匹配的管理员。
   *
   * **不短路**：即使已经命中也要把整张表比较完。理由是用 `break` / `find` 时，
   * 「第几条命中」会体现在总耗时上，多管理员部署下等于把管理员顺序泄露成排序侧信道。
   *
   * @param {string} provided
   * @returns {string|null}
   */
  function matchCredential(provided) {
    /** @type {Array<{adminId: string, token: string}>} */
    let table = credentials
    if (!table.length) {
      const delayed = String(getToken() || '')
      table = delayed ? [{ adminId: defaultAdminId, token: delayed }] : []
    }
    /** @type {string|null} */
    let matched = null
    for (const entry of table) {
      // 先把比较结果算出来再决定是否记录，保证每条都真的比过
      const hit = safeTokenEqual(provided, entry.token)
      if (hit && matched === null) matched = entry.adminId
    }
    return matched
  }

  /**
   * 判定一次管理请求是否放行，通过时返回请求者身份。
   *
   * `method` 不参与这里的分支：方法限制属于**端点语义**（走 `validateAdminRequest`），
   * 而身份与来源判定和方法无关 —— 把两者混在一起会让「GET 放行、DELETE 要二次认证」
   * 这类策略散落在两层里，改一边忘一边。
   *
   * @param {{headers?: Record<string, unknown>, remoteAddr?: string, method?: string, route?: string}} request
   * @returns {{adminId: string}}
   */
  function authorize(request) {
    const req = request && typeof request === 'object' ? request : {}
    const headers = req.headers && typeof req.headers === 'object'
      ? /** @type {Record<string, unknown>} */ (req.headers)
      : {}
    const remoteAddr = String(req.remoteAddr || '')
    const route = String(req.route || '')
    const bucketKey = `${remoteAddr || 'unknown'}|${route || '-'}`

    // ---- 1. Host：防 DNS rebinding，任何管理请求都要过 ----
    const hostVerdict = checkHost(headers.host, listenHost)
    if (hostVerdict) {
      counters.deniedHost += 1
      throw deny(403, 'forbidden_host', `Host 校验失败（${hostVerdict}）：监听回环时只接受回环/本机 Host`)
    }

    // ---- 2. Origin：只对浏览器请求生效，无 Origin 的服务端调用交给 Token ----
    const originVerdict = checkOrigin(headers.origin, allowedOrigins)
    if (originVerdict) {
      counters.deniedOrigin += 1
      throw deny(403, 'forbidden_origin', '该来源未被 allowedOrigins 允许')
    }

    // ---- 3. 频率闸：先闸后验，超限时不再透露凭据对错 ----
    const gate = limiter.hit(bucketKey)
    if (!gate.ok) {
      counters.rateLimited += 1
      throw deny(429, 'rate_limited', `该来源的认证失败次数已达上限（${maxFailures} 次 / ${windowMs}ms）`, {
        retryAfterMs: gate.retryAfterMs,
      })
    }

    // ---- 4. 凭据 ----
    const provided = extractBearer(headers)
    if (!provided) {
      counters.unauthorized += 1
      throw deny(401, 'unauthorized', '需要 Authorization: Bearer <adminToken>', { authRequired: true })
    }

    const adminId = matchCredential(provided)
    if (!adminId) {
      // 不把 Token 写进任何地方：错误信息只说「不匹配」
      counters.unauthorized += 1
      throw deny(401, 'unauthorized', 'Token 不匹配')
    }

    limiter.reset()
    counters.authorized += 1
    return { adminId }
  }

  /**
   * 观测用计数。**只含数字与配置值**：这个对象会被状态接口原样返回，
   * 任何 Token 片段或来源 IP 都不该出现在这里。
   *
   * @returns {{authorized: number, unauthorized: number, rateLimited: number, deniedHost: number, deniedOrigin: number, failureBuckets: number, maxFailures: number, windowMs: number}}
   */
  function stats() {
    return {
      authorized: counters.authorized,
      unauthorized: counters.unauthorized,
      rateLimited: counters.rateLimited,
      deniedHost: counters.deniedHost,
      deniedOrigin: counters.deniedOrigin,
      failureBuckets: limiter.size(),
      maxFailures,
      windowMs,
    }
  }

  return { authorize, stats }
}

/* ============================================================
 * 四、方法限制 + schema 校验
 * ============================================================ */

/**
 * @typedef {object} FieldSpec
 * @property {'string'|'number'|'integer'|'boolean'|'array'|'object'} [type]
 * @property {boolean} [required] 缺字段即拒绝，不做「缺了就用默认值」的静默填充
 * @property {boolean} [nullable] 显式允许 null；不写时 null 视为类型不符
 * @property {ReadonlyArray<unknown>} [enum] 取值白名单
 * @property {number} [min] number/integer 的下界
 * @property {number} [max] number/integer 的上界
 * @property {number} [minLength] string/array 的长度下界
 * @property {number} [maxLength] string/array 的长度上界
 * @property {'string'|'number'|'boolean'} [items] array 元素类型
 */

/**
 * @typedef {object} AdminSchema
 * @property {Record<string, FieldSpec>} [fields] 字段表；省略时把对象本身当字段表
 * @property {boolean} [allowUnknown] 默认 false：未知字段直接拒绝，不静默忽略
 */

/**
 * @typedef {object} ValidationError
 * @property {string} path JSON Pointer 风格的位置（`#/name`）
 * @property {string} code 稳定原因码
 * @property {string} message 中文描述
 */

/**
 * 判断请求体是否「事实上为空」。`{}` 与 `undefined` 都算空：
 * 多数 handler 会把缺失的 body 归一化成空对象，把它当错误只会误伤。
 *
 * @param {unknown} body
 * @returns {boolean}
 */
function isEmptyBody(body) {
  if (body === undefined || body === null) return true
  if (typeof body === 'string') return body.trim() === ''
  if (typeof body === 'object' && !Array.isArray(body)) return Object.keys(body).length === 0
  return false
}

/**
 * 单个字段的类型与约束校验。
 *
 * @param {unknown} value
 * @param {FieldSpec} spec
 * @param {string} path
 * @returns {ValidationError|null}
 */
function checkField(value, spec, path) {
  const expected = spec.type
  if (expected) {
    const ok = (() => {
      switch (expected) {
        case 'string': return typeof value === 'string'
        case 'number': return typeof value === 'number' && Number.isFinite(value)
        case 'integer': return typeof value === 'number' && Number.isInteger(value)
        case 'boolean': return typeof value === 'boolean'
        case 'array': return Array.isArray(value)
        case 'object': return typeof value === 'object' && value !== null && !Array.isArray(value)
        default: return true
      }
    })()
    if (!ok) {
      return { path, code: 'type_mismatch', message: `${path} 应为 ${expected}，实际是 ${describeType(value)}` }
    }
  }

  if (spec.enum && !spec.enum.includes(value)) {
    return {
      path,
      code: 'not_in_enum',
      message: `${path} 只接受 ${spec.enum.map((v) => JSON.stringify(v)).join(' / ')}`,
    }
  }

  if (typeof value === 'number') {
    if (typeof spec.min === 'number' && value < spec.min) {
      return { path, code: 'out_of_range', message: `${path} 不得小于 ${spec.min}` }
    }
    if (typeof spec.max === 'number' && value > spec.max) {
      return { path, code: 'out_of_range', message: `${path} 不得大于 ${spec.max}` }
    }
  }

  if (typeof value === 'string' || Array.isArray(value)) {
    const len = value.length
    if (typeof spec.minLength === 'number' && len < spec.minLength) {
      return { path, code: 'too_short', message: `${path} 长度不得小于 ${spec.minLength}` }
    }
    if (typeof spec.maxLength === 'number' && len > spec.maxLength) {
      return { path, code: 'too_long', message: `${path} 长度不得大于 ${spec.maxLength}` }
    }
  }

  if (Array.isArray(value) && spec.items) {
    const want = spec.items
    for (let i = 0; i < value.length; i += 1) {
      const item = value[i]
      const ok = want === 'string' ? typeof item === 'string'
        : want === 'number' ? typeof item === 'number' && Number.isFinite(item)
          : typeof item === 'boolean'
      if (!ok) {
        return { path: `${path}/${i}`, code: 'type_mismatch', message: `${path}/${i} 应为 ${want}` }
      }
    }
  }

  return null
}

/**
 * 给错误信息用的类型名。`null` 与数组要单独说，
 * 因为 `typeof null === 'object'` 会让「明明传了 null 却说 object」变成一条无法排查的信息。
 *
 * @param {unknown} value
 * @returns {string}
 */
function describeType(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (Number.isNaN(value)) return 'NaN'
  return typeof value
}

/**
 * 管理请求校验：方法限制 + 未知字段 + 必填 + 类型/取值/范围。
 *
 * **返回结构化结果而不是抛错**：调用方要一次把所有问题回给使用者，
 * 而 `throw` 只能带出第一个。抛错留给「凭据不对」这种单点判定。
 *
 * @param {string} method HTTP 方法
 * @param {unknown} body 已解析的请求体
 * @param {AdminSchema | Record<string, FieldSpec>} [schema] 字段表或 {fields, allowUnknown}
 * @returns {{ok: boolean, errors: ValidationError[]}}
 */
export function validateAdminRequest(method, body, schema) {
  /** @type {ValidationError[]} */
  const errors = []
  const upper = String(method || '').trim().toUpperCase()

  if (!ADMIN_METHODS.includes(upper)) {
    return {
      ok: false,
      errors: [{
        path: '#/method',
        code: 'method_not_allowed',
        message: `管理端点只接受 ${ADMIN_METHODS.join(' / ')}，收到 ${upper || '(空)'}`,
      }],
    }
  }

  if (!BODY_METHODS.includes(upper)) {
    // GET / DELETE 带非空请求体：要么调用方把参数放错了地方，要么它以为有 PUT 语义。
    // 静默忽略会让人以为参数生效了，所以直接拒绝。
    if (!isEmptyBody(body)) {
      errors.push({ path: '#', code: 'body_not_allowed', message: `${upper} 不接受请求体` })
    }
    return { ok: errors.length === 0, errors }
  }

  const spec = schema && typeof schema === 'object' ? schema : {}
  const fields = (() => {
    const maybe = /** @type {{fields?: unknown}} */ (spec).fields
    if (maybe && typeof maybe === 'object') return /** @type {Record<string, FieldSpec>} */ (maybe)
    return /** @type {Record<string, FieldSpec>} */ (spec)
  })()
  const allowUnknown = /** @type {{allowUnknown?: unknown}} */ (spec).allowUnknown === true

  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    errors.push({ path: '#', code: 'body_not_object', message: `${upper} 的请求体必须是 JSON 对象` })
    return { ok: false, errors }
  }

  const input = /** @type {Record<string, unknown>} */ (body)

  for (const key of Object.keys(input)) {
    if (!Object.prototype.hasOwnProperty.call(fields, key) && !allowUnknown) {
      errors.push({
        path: `#/${key}`,
        code: 'unknown_field',
        message: `未知字段 ${key}：管理端点不接受未在 schema 里声明的字段`,
      })
    }
  }

  for (const [name, rawSpec] of Object.entries(fields)) {
    const fieldSpec = rawSpec && typeof rawSpec === 'object' ? rawSpec : {}
    const present = Object.prototype.hasOwnProperty.call(input, name) && input[name] !== undefined
    const path = `#/${name}`

    if (!present) {
      if (fieldSpec.required === true) {
        errors.push({ path, code: 'missing_required', message: `缺少必填字段 ${name}` })
      }
      continue
    }

    const value = input[name]
    if (value === null) {
      // null 不等同于「未提供」：显式写 null 却又不允许，是配置意图不一致，要报出来
      if (fieldSpec.nullable !== true) {
        errors.push({ path, code: 'type_mismatch', message: `${name} 不接受 null（如需清空请用允许的默认值）` })
      }
      continue
    }

    const err = checkField(value, fieldSpec, path)
    if (err) errors.push(err)
  }

  return { ok: errors.length === 0, errors }
}

/* ============================================================
 * 五、分页
 * ============================================================ */

/** 分页默认值与上限。上限是硬钳制而非报错，理由见 paginate。 */
export const PAGINATION = Object.freeze({ defaultLimit: 20, maxLimit: 200 })

/**
 * 把一个数钳制到区间内。非数字/NaN 用默认值 ——
 * 查询串里出现 `limit=abc` 时给出默认页比 500 更有用。
 *
 * @param {unknown} raw
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function clampInt(raw, fallback, min, max) {
  const n = typeof raw === 'number' ? raw : Number(raw)
  if (!Number.isFinite(n)) return fallback
  const i = Math.trunc(n)
  if (i < min) return min
  if (i > max) return max
  return i
}

/**
 * 列表分页。
 *
 * 越界不报错：`offset` 超过总数返回空页 + `hasMore: false`，这是分页的终态而不是
 * 客户端错误。`limit` 超上限**钳制**到 `maxLimit`：报 400 会让「前端写死 limit=1000」
 * 直接不可用，而静默返回 200 条对调用方仍然可用、对服务端仍然有界。
 *
 * `limit` 小于 1 一律钳到 1，不给 0 任何特殊语义 —— 否则会有人用它当
 * 「只要 total」的开关，而那个语义在响应里已经由 `total` 表达了。
 *
 * @param {ReadonlyArray<unknown>} list
 * @param {{limit?: unknown, offset?: unknown}} [options]
 * @returns {{items: Array<unknown>, total: number, limit: number, offset: number, hasMore: boolean, nextOffset: number|null}}
 */
export function paginate(list, options = {}) {
  if (!Array.isArray(list)) throw new TypeError('paginate 的第一个参数必须是数组')
  const opts = options && typeof options === 'object' ? options : {}
  const limit = clampInt(opts.limit, PAGINATION.defaultLimit, 1, PAGINATION.maxLimit)
  const offset = clampInt(opts.offset, 0, 0, Number.MAX_SAFE_INTEGER)

  const total = list.length
  const start = offset >= total ? total : offset
  const end = start + limit
  const items = /** @type {Array<unknown>} */ (list.slice(start, end))
  const consumed = start + items.length
  const hasMore = consumed < total

  return {
    items,
    total,
    limit,
    offset,
    hasMore,
    nextOffset: hasMore ? consumed : null,
  }
}

/* ============================================================
 * 六、乐观锁冲突检测
 * ============================================================ */

/**
 * 版本比对。
 *
 * 缺 `expected` 一律视为冲突（返回 false）：更新类操作必须带上「客户端看到的版本」，
 * 否则两个管理员同时改同一条时会后写覆盖前写，而这正是乐观锁要防的事。
 *
 * 比较用 `String()` 而不是 `===`：版本可能以数字（`3`）或 ETag 字符串（`"v3"`）形式
 * 从不同入口进来，类型不同但值相同应当算「没变」。
 *
 * @param {unknown} current 服务端当前版本
 * @param {unknown} expected 客户端提交的版本
 * @returns {boolean} true = 版本一致，可以写入
 */
export function checkVersion(current, expected) {
  if (expected === undefined || expected === null || expected === '') return false
  if (current === undefined || current === null || current === '') return false
  return String(current) === String(expected)
}

/* ============================================================
 * 七、删除引用检查
 * ============================================================ */

/**
 * 删除前的引用检查。
 *
 * 「删上游」和「删分组」的区别在于：上游被分组引用时删掉它，分组会留下一个指向
 * 不存在的 id —— 运行时读配置只会在下次选路时才炸，而且报的是「没有可用上游」
 * 这种与根因无关的信息。所以这一类删除必须当场拒绝。
 *
 * 用 `TargetDenied`（`details.status = 409`）而不是新类型：契约层冻结，
 * 且语义上确实是「这个目标不允许被这样操作」。
 *
 * @param {string} upstreamId 待删除的上游 id
 * @param {ReadonlyArray<{id?: unknown, name?: unknown, upstreamIds?: unknown, upstreamId?: unknown}>} groups 现有分组
 * @returns {true} 未被引用（引用时抛错，不会返回 false）
 */
export function assertNotReferenced(upstreamId, groups) {
  const id = String(upstreamId || '').trim()
  if (!id) throw new TypeError('assertNotReferenced 需要非空的 upstreamId')
  const list = Array.isArray(groups) ? groups : []

  /** @type {Array<{id: string, name: string}>} */
  const referencedBy = []
  for (const raw of list) {
    if (!raw || typeof raw !== 'object') continue
    const group = /** @type {{id?: unknown, name?: unknown, upstreamIds?: unknown, upstreamId?: unknown}} */ (raw)
    const ids = Array.isArray(group.upstreamIds) ? group.upstreamIds : []
    const hit = ids.some((v) => String(v) === id) || String(group.upstreamId || '') === id
    if (hit) {
      referencedBy.push({ id: String(group.id || ''), name: String(group.name || '') })
    }
  }

  if (referencedBy.length) {
    throw new TargetDenied(
      `上游 ${id} 仍被 ${referencedBy.length} 个分组引用，拒绝删除（HTTP 409）`,
      { upstreamId: id, referencedBy, status: 409, conflict: true },
    )
  }
  return true
}

/* ============================================================
 * 八、审计日志
 * ============================================================ */

/**
 * @typedef {object} AuditInput
 * @property {string} adminId 操作者身份（来自 createAdminGuard 的返回值）
 * @property {string} action 动作名，如 `upstream.delete`
 * @property {unknown} [target] 被操作对象（id 或描述对象）
 * @property {unknown} [result] 结果，如 `ok` / `denied` / `{status: 200}`
 * @property {unknown} [at] 毫秒时间戳；省略取当前时间，测试注入用
 */

/**
 * 构造一条可序列化的审计记录。
 *
 * **不含任何敏感值**：`target` / `result` 都过一遍 `redactForLog`，因为审计最容易
 * 泄露的地方就是「有人顺手把整个请求对象塞进 target」。adminId 也过一遍脱敏 ——
 * 它是字符串，值级指纹会拦下「拿 Token 当 id 传」这种手滑。
 *
 * `at` 输出 ISO 串而不是毫秒数：跨日志系统（本地文件 + 远端采集）时，
 * 裸时间戳要靠约定解释时区，ISO 串自带偏移。
 *
 * 参数缺失直接抛 `TypeError`：没有操作者的审计记录不成立，静默写一条
 * `adminId: 'unknown'` 会让审计失去意义。
 *
 * @param {AuditInput} input
 * @returns {{at: string, adminId: string, action: string, target: unknown, result: unknown}}
 */
export function makeAuditEntry(input) {
  const entry = input && typeof input === 'object' ? input : {}
  const adminId = String(entry.adminId || '').trim()
  const action = String(entry.action || '').trim()
  if (!adminId) throw new TypeError('makeAuditEntry 需要 adminId：审计记录不允许匿名')
  if (!action) throw new TypeError('makeAuditEntry 需要 action：没有动作名的审计记录无法追溯')

  const atRaw = typeof entry.at === 'number' && Number.isFinite(entry.at) ? entry.at : Date.now()

  return {
    at: new Date(atRaw).toISOString(),
    // 脱敏后仍在正常情形下等于原值；只有「adminId 长得像凭据」时才会变成占位符
    adminId: String(redactForLog(adminId)),
    action,
    target: redactForLog(entry.target === undefined ? null : entry.target),
    result: redactForLog(entry.result === undefined ? null : entry.result),
  }
}
