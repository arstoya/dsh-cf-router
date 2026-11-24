/**
 * forward-proxy.mjs — 正向代理 Adapter（v0.4.0 / D1）
 *
 * 职责边界（方案 §5.8 的硬约束）：Adapter 只做**协议解析、客户端识别、
 * 上下文构建**；不挑 DNS IP、不做健康判断、不更新 Cooling —— 那些是
 * Core 的事。所以 Core 是**注入**的（options.core），本文件对上游一无所知。
 *
 * 处理管线（每一步失败的去向都不同，这是顺序不能换的原因）：
 *   解析(400) → 剥自报身份头 → 认证(401) → 验证目标(403)
 *   → 构造 RequestContext → 调 Core → 流式写回
 *
 * 几个刻意的设计决定：
 *
 * 1. **absolute-form 之外一律拒绝。** 正向代理的请求行是
 *    `GET http://host/path HTTP/1.1`；origin-form（`GET /path`）是反向
 *    代理的形态，authority-form（`host:443`）属于 CONNECT。把三种形态
 *    混在同一个入口里解析，迟早会把「该走 CONNECT 的请求当成普通 GET
 *    转发出去」—— 所以在解析层就分流，而不是靠下游兜底。
 *
 * 2. **畸形请求用 TypeError，不占用 ProxyError。** contract/errors.mjs 的
 *    9 个类型语义都是「转发过程中的运行时故障」（目标被拒、上游超时、
 *    断流…），而 origin-form / userinfo 是**协议层畸形**，不属于任何
 *    一类运行时故障。硬塞进 9 类之一会污染 C3 的重试分支。TypeError 带
 *    `reason` 字段与 `forwardReject` 标记，供测试与日志定位。
 *
 * 3. **Host 由目标决定。** 客户端发来的 Host 头不参与任何决策：RFC 7230
 *    §5.4 规定 absolute-form 请求以请求行里的 authority 为准，两者不一致
 *    时（伪造 Host 是最常见的一种）必须信请求行。转发前一律改写。
 *
 * 4. **请求体全程流式。** parseForwardRequest 把带体的 IncomingMessage
 *    包成 Web ReadableStream（Readable.toWeb），不缓冲。客户端中途断开
 *    时，Node 侧的 aborted 会变成流的错误 —— Core 读到的就是一次失败，
 *    而不是一段静默截断的数据。
 *
 * @module forward-proxy
 */

import { Readable } from 'node:stream'

import { ClientCancelled, StreamFailure, isProxyError } from './contract/errors.mjs'
import { makeRequestContext } from './contract/request-context.mjs'
import {
  authenticateClient,
  sanitizeIdentityHeaders,
  assertRouteGroupBinding,
} from './client-auth.mjs'
import { validateTargetUrl } from './target-validator.mjs'
import { pipeWithBackpressure } from './streaming.mjs'
import { filterRequestHeaders, filterResponseHeaders } from './headers.mjs'

// headers.mjs 的 filterRequestHeaders 曾经在它自己的默认值上报 TS2741
// （@param {string} opts.targetHost 标成必填，但默认参数是 {}）。
// 2026-11-24 已把该 JSDoc 改成可选项，运行时本来就允许省略（实现是
// `if (targetHost) out.host = targetHost`），所以这里改回静态 import —— 
// 动态 import 只是当时为了绕过那个文档缺陷，现在没有理由保留。

/* ============================================================
 * 类型
 * ============================================================ */

/** @typedef {import('node:http').IncomingMessage} NodeIncomingMessage */
/** @typedef {import('node:http').ServerResponse} NodeServerResponse */
/** @typedef {import('node:http').OutgoingHttpHeaders} OutgoingHttpHeaders */
/** @typedef {import('./contract/request-context.mjs').RequestContext} RequestContext */
/** @typedef {import('./client-auth.mjs').ClientCollection} ClientCollection */
/** @typedef {import('./client-auth.mjs').ClientIdentity} ClientIdentity */
/** @typedef {import('./target-validator.mjs').ValidatorOptions} ValidatorOptions */
/** @typedef {import('./target-validator.mjs').ValidatedTarget} ValidatedTarget */

/**
 * 响应 Core 应该返回的形状。
 *
 * body 是 Web 流（transport.send 的产物）—— Adapter 只负责把它接到
 * 客户端 socket 上，不做任何缓冲。
 *
 * @typedef {object} CoreResult
 * @property {number} statusCode
 * @property {Record<string, unknown>} [headers]
 * @property {ReadableStream<Uint8Array>|null} [body]
 */

/**
 * @callback CoreFn
 * @param {RequestContext} ctx
 * @returns {CoreResult | Promise<CoreResult>}
 */

/**
 * 客户端认证函数。默认实现是 authenticateClient —— 第一参收**整个
 * headers 对象**（它会自己读 authorization），这样注入的自定义认证
 * 函数拿得到完整上下文，而不是只有一条拼好的字符串。
 *
 * @callback AuthFn
 * @param {Record<string, unknown>} headers 已经剥掉自报身份头的请求头
 * @param {ClientCollection} [clients]
 * @returns {ClientIdentity | Promise<ClientIdentity>}
 * @throws {ClientUnauthorized} 认证失败（Adapter 统一回 401）
 */

/**
 * 目标验证函数。默认 validateTargetUrl；注入假实现时必须给出
 * ValidatedTarget 同形结构（Adapter 只读 scheme/host/port 之外的
 * 不多字段，host 与 port 参与策略判断）。
 *
 * @callback TargetValidatorFn
 * @param {string} url absolute-form URL 字符串
 * @param {ValidatorOptions} [options]
 * @returns {Promise<ValidatedTarget>}
 * @throws {TargetDenied} 目标被拒（Adapter 统一回 403）
 */

/**
 * 日志钩子。刻意按方法名取用而不是 log(level, msg)：
 * 调用方传 console 风格对象即可，缺失的级别自动静默。
 *
 * @typedef {object} LoggerLike
 * @property {(msg: string) => void} [debug]
 * @property {(msg: string) => void} [info]
 * @property {(msg: string) => void} [warn]
 * @property {(msg: string) => void} [error]
 */

/**
 * @typedef {object} ForwardAdapterOptions
 * @property {CoreFn} core 注入的 Routing Core（§5.8：Adapter 不自己选路）
 * @property {AuthFn} [auth] 认证函数，默认 authenticateClient
 * @property {ClientCollection} [clients] 客户端集合（默认认证函数需要）
 * @property {TargetValidatorFn} [targetValidator] 目标验证，默认 validateTargetUrl
 * @property {ValidatorOptions} [validatorOptions] 透传给 targetValidator 的选项
 * @property {LoggerLike} [logger]
 */

/**
 * parseForwardRequest 的产物。
 *
 * body 只在请求**声明了体**时才有（Content-Length > 0 或
 * Transfer-Encoding 存在）；GET/HEAD 等无体请求是 null，避免给 Core
 * 一个「读不到结尾、也没有字节」的空流。
 *
 * @typedef {object} ParsedForwardRequest
 * @property {string} method 已规范化为大写
 * @property {string} url 原始 absolute-form 字符串（不重编码）
 * @property {Record<string, string|string[]>} headers 键已小写
 * @property {ReadableStream<Uint8Array>|null} body
 */

/**
 * @typedef {object} ForwardAdapterStats
 * @property {number} total 收到的请求数
 * @property {number} ok 成功完成转发的请求数
 * @property {number} rejected 在 Adapter 层被拒（400/401/403）的请求数
 * @property {number} upstreamError Core 抛出非取消错误 / 写回失败的请求数
 * @property {number} clientCancelled 客户端中途断开的请求数
 * @property {number} active 正在处理中的请求数
 */

/**
 * 最小等价入参：与 IncomingMessage 同名字段即可。声明了请求体的
 * 最小对象没有流可包，会被显式拒绝 —— 带体的转发必须传真实流。
 *
 * @typedef {object} MinimalRequest
 * @property {string} [method]
 * @property {string} [url]
 * @property {Record<string, unknown>} [headers]
 */

/* ============================================================
 * 常量与小工具
 * ============================================================ */

/** RFC 7230 token 字符集。方法名超界说明请求行本身已经畸形 */
const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/

/** absolute-form 判据：只认 http/https。ws/wss 等不走这个 Adapter */
const SCHEME_RE = /^https?:\/\//i

/** 控制字符（C0 + DEL）。必须在 trim 之前判：WHATWG 解析器会静默剥掉首尾 C0 */
const CONTROL_RE = /[\u0000-\u001f\u007f]/

/**
 * 非法百分号编码：`%` 后面不足两位十六进制。
 *
 * 必须在 new URL() 之前判：WHATWG 解析器对非法序列是**保留原样**而不是
 * 报错（`/p%zz` 解析成 pathname `/p%zz`），不拦这一层，畸形序列就会
 * 被原样送给上游 —— 不同上游对它的解释不一致，正是请求走私的入口。
 */
const BAD_PERCENT_RE = /%(?![0-9A-Fa-f]{2})/

/** 声明路由分组的头。值在剥头**之前**读出来，供绑定一致性检查 */
const CLAIMED_GROUP_HEADERS = Object.freeze(['x-route-group', 'x-route-group-id'])

/**
 * Core 运行时故障 → HTTP 状态码。
 *
 * 只列「响应还没开始写」时才有意义的映射：一旦开始流式写回，
 * 状态码已经发出去，任何后续失败都只能断开连接。
 * client_cancelled 刻意不在表里 —— 客户端已经不在了，没有可写的对象。
 */
const STATUS_BY_CODE = Object.freeze({
  client_unauthorized: 401,
  target_denied: 403,
  dns_failure: 502,
  connect_failure: 502,
  tls_failure: 502,
  stream_failure: 502,
  retry_not_allowed: 502,
  upstream_timeout: 504,
})

/**
 * 取 ProxyError 的 code。isProxyError 是跨实例安全的判断
 * （插件可能被加载两次），所以按它的结果取 code，不直接 instanceof。
 *
 * @param {unknown} err
 * @returns {string}
 */
function codeOf(err) {
  if (!isProxyError(err)) return ''
  return /** @type {{ code: string }} */ (err).code
}

/**
 * @param {unknown} err
 * @returns {string}
 */
function messageOf(err) {
  return err instanceof Error && err.message ? err.message : String(err)
}

/**
 * 取 ProxyError details 里的稳定 reason（如 target_denied 的
 * not_allowlisted）。客户端排障需要「为什么被拒」，而 details 契约
 * 保证它不含敏感值，可以安全外发。
 *
 * @param {unknown} err
 * @returns {Record<string, unknown>|undefined}
 */
function reasonOf(err) {
  if (!isProxyError(err)) return undefined
  const details = /** @type {{ details?: Record<string, unknown> }} */ (err).details
  const reason = details && typeof details.reason === 'string' ? details.reason : undefined
  return reason ? { reason } : undefined
}

/**
 * 构造协议层拒绝。`forwardReject` 标记用于把「我们主动拒绝的畸形请求」
 * 与「代码里意外的 TypeError（那是 bug，该 500）」区分开。
 *
 * @param {string} reason 稳定的机器可读原因
 * @param {string} message 人类可读描述
 * @returns {TypeError & { forwardReject: true, reason: string }}
 */
function parseReject(reason, message) {
  const err = /** @type {any} */ (new TypeError(message))
  err.forwardReject = true
  err.reason = reason
  return err
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isParseReject(err) {
  return err instanceof TypeError && /** @type {any} */ (err).forwardReject === true
}

/**
 * 大小写不敏感地取第一个非空字符串头值。与 client-auth 内部的
 * pickHeader 同语义，但那份实现刻意未导出（代理面不依赖内部细节），
 * 这里只读两个已知头，重复三行比引出内部函数便宜。
 *
 * @param {Record<string, unknown>} headers
 * @param {readonly string[]} names 小写头名
 * @returns {string}
 */
function pickFirstHeaderValue(headers, names) {
  const wanted = new Set(names)
  for (const [key, value] of Object.entries(headers)) {
    if (!wanted.has(key.toLowerCase())) continue
    if (typeof value === 'string' && value.trim() !== '') return value.trim()
    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string' && item.trim() !== '') return item.trim()
      }
    }
  }
  return ''
}

/**
 * 判断入站请求是否声明了请求体。
 *
 * 判「声明」而不是判「实际有没有字节」：Content-Length: 0 的 POST
 * 没有可读字节，包一个流只会让 Core 挂在 read() 上，所以视为无体。
 *
 * @param {Record<string, unknown>} headers
 * @returns {boolean}
 */
function hasDeclaredBody(headers) {
  if (headers['transfer-encoding'] !== undefined) return true
  const raw = headers['content-length']
  const first = Array.isArray(raw) ? raw[0] : raw
  if (typeof first === 'string' && first !== '') {
    const n = Number(first)
    if (Number.isFinite(n) && n > 0) return true
  }
  return false
}

/**
 * 由目标 URL 推导 Host 头的值。
 *
 * 非默认端口必须带上端口（否则上游按 80/443 处理，连到别处）；
 * IPv6 字面量要补方括号（Host 头的 ABNF 要求，WHATWG hostname 给的是
 * 去括号形式）。
 *
 * @param {URL} u
 * @returns {string}
 */
function hostForTarget(u) {
  const bareHost = u.hostname.includes(':') ? `[${u.hostname}]` : u.hostname
  const scheme = u.protocol.slice(0, -1)
  const port = u.port === '' ? null : Number(u.port)
  const defaultPort = scheme === 'https' ? 443 : scheme === 'http' ? 80 : null
  if (port == null) return bareHost
  if (defaultPort != null && port === defaultPort) return bareHost
  return `${bareHost}:${port}`
}

/* ============================================================
 * 1. 协议解析（纯函数）
 * ============================================================ */

/**
 * 解析正向代理请求：只接受 absolute-form。
 *
 * 纯函数的边界：**不认证、不验目标、不碰网络** —— 身份与目标是否被
 * 允许是授权决定，属于 Adapter 管线的后续步骤；这里只回答「这串东西
 * 是不是一个语法上可转发的 absolute-form 请求」。
 *
 * 拒绝项（各自独立，原因可定位）：
 *   · origin-form（`/path`）—— 反向代理形态，不是这里的事
 *   · authority-form / 其它无 scheme 形态 —— CONNECT 走另一条入口
 *   · CONNECT 方法 —— 本 Adapter 不做隧道
 *   · userinfo（`http://user:pass@host/`）—— 合法代理请求不需要凭据
 *   · 非法百分号编码、控制字符、fragment
 *
 * @param {NodeIncomingMessage|MinimalRequest} req
 * @returns {ParsedForwardRequest}
 * @throws {TypeError & { forwardReject: true, reason: string }} 语法畸形
 */
export function parseForwardRequest(req) {
  if (req == null || typeof req !== 'object') {
    throw parseReject('not_request', '入参必须是请求对象')
  }

  const rawMethod = typeof req.method === 'string' ? req.method.trim() : ''
  if (rawMethod === '' || !TOKEN_RE.test(rawMethod.toUpperCase())) {
    throw parseReject('bad_method', '方法名不是合法的 HTTP token')
  }
  const method = rawMethod.toUpperCase()
  if (method === 'CONNECT') {
    throw parseReject('connect_not_supported', '本 Adapter 不处理 CONNECT 隧道')
  }

  const rawUrl = typeof req.url === 'string' ? req.url : ''
  if (rawUrl === '') throw parseReject('empty_url', '缺少请求目标')
  // 控制字符先于一切判断：它们可能把一条请求拆成两条（HTTP 走私的第一步）
  if (CONTROL_RE.test(rawUrl)) throw parseReject('control_chars', '请求目标含控制字符')
  if (rawUrl.startsWith('/')) {
    throw parseReject('origin_form', 'origin-form 是反向代理的形态，正向代理只接受 absolute-form')
  }
  if (!SCHEME_RE.test(rawUrl)) {
    throw parseReject('not_absolute_form', '请求目标必须是 http(s):// 开头的 absolute-form')
  }
  if (BAD_PERCENT_RE.test(rawUrl)) {
    throw parseReject('bad_percent_encoding', '请求目标含非法百分号编码')
  }

  /** @type {URL} */
  let u
  try {
    u = new URL(rawUrl)
  } catch {
    throw parseReject('malformed_url', '请求目标无法解析为 URL')
  }
  // userinfo 是「看起来连 A、实际连 B」的经典写法（http://trusted.com@evil.com/）。
  // validateTargetUrl 也会拦，但那是 403（授权否决）；这里是 400（语法畸形），
  // 两层都拦是因为它们的语义不同：一个说「你不许」，一个说「这不是合法请求」。
  if (u.username || u.password) throw parseReject('userinfo', '请求目标不允许携带 userinfo')
  if (u.hash) throw parseReject('has_fragment', '请求目标不允许携带 fragment')
  if (u.hostname === '') throw parseReject('empty_host', '请求目标缺少主机名')

  /** @type {Record<string, string|string[]>} */
  const headers = {}
  for (const [key, value] of Object.entries(req.headers || {})) {
    if (key === '') continue
    headers[key.toLowerCase()] = /** @type {any} */ (value)
  }

  let body = null
  if (hasDeclaredBody(headers)) {
    // 带体的请求必须有真实流可包。最小等价对象没有流 —— 与其包出一个
    // 读不到数据的假流，不如在这里就明说。
    if (typeof (/** @type {any} */ (req)).on !== 'function') {
      throw parseReject('body_requires_stream', '带请求体的转发必须传入真实 IncomingMessage')
    }
    body = /** @type {ReadableStream<Uint8Array>} */ (Readable.toWeb(/** @type {NodeIncomingMessage} */ (req)))
  }

  return { method, url: rawUrl, headers, body }
}

/* ============================================================
 * 2. Adapter
 * ============================================================ */

/**
 * 构造正向代理 Adapter。
 *
 * @param {ForwardAdapterOptions} options
 * @returns {{ handle: (req: NodeIncomingMessage, res: NodeServerResponse) => Promise<void>, stats: () => ForwardAdapterStats }}
 * @throws {TypeError} core 缺失或认证/验证函数不是函数
 */
export function createForwardAdapter(options) {
  if (options == null || typeof options !== 'object') {
    throw new TypeError('createForwardAdapter: 需要对象参数')
  }
  // core 是这条管线里唯一知道「去哪儿、怎么走」的角色。它不是可选的：
  // 没有 core 的 Adapter 等于一个只会回错误页的空壳，与其让它在运行时
  // 每个请求都 502，不如在装配时就报错。
  if (typeof options.core !== 'function') {
    throw new TypeError('createForwardAdapter: core 必须是函数（方案 §5.8：Core 注入，Adapter 不选路）')
  }

  const core = options.core
  const auth = options.auth === undefined ? authenticateClient : options.auth
  const targetValidator = options.targetValidator === undefined ? validateTargetUrl : options.targetValidator
  if (typeof auth !== 'function') throw new TypeError('createForwardAdapter: auth 必须是函数')
  if (typeof targetValidator !== 'function') throw new TypeError('createForwardAdapter: targetValidator 必须是函数')

  const clients = options.clients ?? null
  const validatorOptions = options.validatorOptions ?? {}
  const logger = options.logger ?? null

  /** @type {ForwardAdapterStats} */
  const statsState = {
    total: 0,
    ok: 0,
    rejected: 0,
    upstreamError: 0,
    clientCancelled: 0,
    active: 0,
  }

  /**
   * @param {keyof LoggerLike} level
   * @param {string} msg
   */
  function log(level, msg) {
    const fn = logger ? logger[level] : undefined
    if (typeof fn === 'function') {
      try {
        fn(msg)
      } catch {
        /* 日志自身的问题不能打断转发 */
      }
    }
  }

  /**
   * 发 JSON 错误响应。响应已开始写时只能销毁 —— 半个响应加一个
   * 状态码重写只会造成协议层的双重响应。
   *
   * @param {NodeServerResponse} res
   * @param {number} statusCode
   * @param {Record<string, unknown>} payload
   */
  function sendJson(res, statusCode, payload) {
    if (res.headersSent || res.writableEnded || res.destroyed) {
      res.destroy()
      return
    }
    const body = Buffer.from(JSON.stringify(payload), 'utf8')
    res.writeHead(statusCode, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': String(body.length),
    })
    res.end(body)
  }

  /**
   * @param {NodeServerResponse} res
   * @param {number} statusCode
   * @param {string} code
   * @param {string} message
   * @param {Record<string, unknown>} [extra]
   */
  function reject(res, statusCode, code, message, extra) {
    statsState.rejected += 1
    log('info', `forward rejected ${statusCode} ${code}: ${message}`)
    sendJson(res, statusCode, { code, message, ...extra })
  }

  /**
   * Core 返回值形状校验。Core 是注入的，契约违背不该表现为「给客户端
   * 发一个 undefined 状态码」这类隐晦故障，而应该是一条能定位的 502。
   *
   * @param {unknown} upstream
   * @returns {void}
   * @throws {StreamFailure}
   */
  function assertCoreResult(upstream) {
    const u = /** @type {{ statusCode?: unknown, body?: unknown }} */ (upstream)
    if (u == null || typeof u !== 'object') {
      throw new StreamFailure('Core 返回值不是对象，无法写回客户端', { phase: 'core' })
    }
    if (typeof u.statusCode !== 'number' || !Number.isInteger(u.statusCode)
      || u.statusCode < 100 || u.statusCode > 599) {
      throw new StreamFailure(`Core 返回的 statusCode 不合法：${JSON.stringify(u.statusCode)}`, { phase: 'core' })
    }
    if (u.body != null && typeof (/** @type {any} */ (u.body)).getReader !== 'function') {
      throw new StreamFailure('Core 返回的 body 不是 Web ReadableStream，无法流式转发', { phase: 'core' })
    }
  }

  /**
   * @param {NodeIncomingMessage} req
   * @param {NodeServerResponse} res
   * @returns {Promise<void>}
   */
  async function handle(req, res) {
    statsState.total += 1
    statsState.active += 1

    // 每个请求一个 AbortController：客户端断开的唯一权威信号。
    // ctx.signal 由它派生，Core 与流式转发都看同一个信号源，避免
    // 「req 的断开事件」与「ctx 的取消信号」出现两套不一致的状态。
    const ac = new AbortController()
    let cancelled = false
    /**
     * @param {string} why
     */
    const cancel = (why) => {
      if (cancelled) return
      cancelled = true
      ac.abort(new ClientCancelled(`客户端断开（${why}）`))
    }

    // 摘监听器在 finally 里做：请求对象可能被复用（keep-alive 的下一跳
    // 是新对象，但测试桩不一定），挂着的监听器会跨请求泄漏计数。
    /** @type {Array<[NodeIncomingMessage | NodeServerResponse, string, (...args: any[]) => void]>} */
    const listeners = []
    const track = (
      /** @type {NodeIncomingMessage | NodeServerResponse} */ emitter,
      /** @type {string} */ event,
      /** @type {(...args: any[]) => void} */ fn,
    ) => {
      emitter.on(/** @type {any} */ (event), fn)
      listeners.push([emitter, event, fn])
    }

    track(req, 'aborted', () => cancel('请求被中断'))
    track(req, 'error', () => cancel('请求流出错'))
    // 'close' 正常收尾也会触发：只有「请求没收完」的 close 才是断开
    track(req, 'close', () => {
      if (!req.complete) cancel('请求未收完就关闭')
    })
    track(res, 'close', () => {
      if (!res.writableEnded) cancel('客户端在响应写完前离开')
    })

    // 提升到 try 之外：finally 需要在**所有**失败路径上清理请求体流
    // （见 finally 的说明）。在 try 内声明会因作用域够不到而漏掉清理。
    /** @type {ParsedForwardRequest|null} */
    let parsed = null

    try {
      /* ---- 1. 解析（400） ---- */
      try {
        parsed = parseForwardRequest(req)
      } catch (err) {
        if (isParseReject(err)) {
          const typed = /** @type {TypeError & { reason: string }} */ (err)
          reject(res, 400, 'bad_request', typed.message, { reason: typed.reason })
          return
        }
        throw err
      }

      /* ---- 2. 剥自报身份头（必须先于认证：认证函数不许看到它们） ---- */
      const claimedGroup = pickFirstHeaderValue(parsed.headers, CLAIMED_GROUP_HEADERS)
      const { headers: cleanHeaders, removed } = sanitizeIdentityHeaders(parsed.headers)
      if (removed.length > 0) log('info', `forward 剥除自报身份头：${removed.join(', ')}`)

      /* ---- 3. 认证（401） ---- */
      /** @type {ClientIdentity} */
      let identity
      try {
        identity = await auth(cleanHeaders, clients)
        // 声明分组与服务端绑定冲突 = 调用方在试探或配错，拒绝比静默纠正更醒目
        identity = assertRouteGroupBinding(identity, claimedGroup)
      } catch (err) {
        reject(res, 401, 'client_unauthorized', isProxyError(err) ? messageOf(err) : '客户端认证失败',
          reasonOf(err))
        return
      }

      /* ---- 4. 验证目标（403） ---- */
      try {
        await targetValidator(parsed.url, validatorOptions)
      } catch (err) {
        reject(res, 403, 'target_denied', isProxyError(err) ? messageOf(err) : '目标验证失败',
          reasonOf(err))
        return
      }

      /* ---- 5. Host 由目标决定 + 逐跳头清理 ---- */
      const targetHost = hostForTarget(new URL(parsed.url))
      // opts 参数走 any 收窄：headers.mjs 的参数带 `opts = {}` 默认值，
      // 从调用点推断参数类型会让那个默认值不满足「必须含 targetHost」，
      // 在它自身的定义行报错（文件所有权不归本模块，只能从调用侧规避）。
      const coreHeaders = /** @type {Record<string, string|string[]>} */ (
        filterRequestHeaders(cleanHeaders, { targetHost })
      )

      /* ---- 6. 构造上下文 ---- */
      const ctx = makeRequestContext({
        clientId: identity.clientId,
        routeGroupId: identity.routeGroupId,
        mode: 'forward',
        method: parsed.method,
        originalUrl: parsed.url,
        headers: coreHeaders,
        body: parsed.body,
        signal: ac.signal,
      })

      /* ---- 7. 调 Core ---- */
      const upstream = await core(ctx)
      assertCoreResult(upstream)
      const u = /** @type {{ statusCode: number, headers?: unknown, body?: ReadableStream<Uint8Array>|null }} */ (upstream)

      /* ---- 8. 流式写回 ---- */
      // 客户端可能在 Core 工作期间离开（res 已销毁）。此时写状态码只会
      // 抛协议错误，正确动作是当作一次客户端取消收场。
      if (cancelled || res.destroyed || res.writableEnded) {
        throw new ClientCancelled('客户端在 Core 响应前已离开', { phase: 'downstream' })
      }

      const outHeaders = /** @type {OutgoingHttpHeaders} */ (
        filterResponseHeaders(/** @type {object} */ (u.headers ?? {}))
      )
      res.writeHead(u.statusCode, outHeaders)

      if (u.body == null) {
        statsState.ok += 1
        res.end()
        return
      }

      const pipe = pipeWithBackpressure(u.body, res, { signal: ac.signal })
      try {
        await pipe.done
        statsState.ok += 1
      } catch (err) {
        // pipe 的失败语义：下游断开 = ClientCancelled（客户端取消，
        // 不惩罚上游）；其余是上游读失败或写失败。响应已提交，
        // 状态码改不了，唯一能做的是别把连接挂着。
        if (codeOf(err) === 'client_cancelled') statsState.clientCancelled += 1
        else statsState.upstreamError += 1
        log('warn', `forward 写回失败：${messageOf(err)}`)
        res.destroy()
      }
    } catch (err) {
      if (cancelled || codeOf(err) === 'client_cancelled') {
        statsState.clientCancelled += 1
        res.destroy()
      } else if (res.headersSent) {
        // 响应已开始但中途失败：状态码已发出，只能断开
        statsState.upstreamError += 1
        log('error', `forward 响应中途失败：${messageOf(err)}`)
        res.destroy()
      } else {
        statsState.upstreamError += 1
        const code = codeOf(err)
        const status = STATUS_BY_CODE[code] ?? 500
        log('error', `forward 转发失败 ${status} ${code || 'internal_error'}: ${messageOf(err)}`)
        sendJson(res, status, {
          code: code || 'internal_error',
          message: isProxyError(err) ? messageOf(err) : '内部错误',
        })
      }
    } finally {
      statsState.active -= 1
      for (const [emitter, event, fn] of listeners) {
        emitter.removeListener(/** @type {any} */ (event), fn)
      }

      // 失败路径（认证 401 / 验证 403 / Core 抛错）下，请求体可能从未被读取。
      // `Readable.toWeb(req)` 不会主动消费 req，不读它就一直是 paused：
      // 一个未认证的客户端可以持续声明巨大的 Content-Length 而永远不发送完，
      // 连接因此无法复用，累积下去能压满连接池 —— 这是**不需要凭据**就能触发的。
      //
      // 成功路径下流已被 Core 读完，cancel() 对已关闭的流是 no-op，不会误伤。
      // Core 正在读时流被锁住，cancel() 会抛 TypeError，那也只能忽略：
      // 此时资源由 Core 自己负责收尾。
      // **先取 socket 引用**：下面 cancel() 会把 req.socket 置为 null，
      // 之后再去读就拿不到了（实测踩到：destroyed 恒为 undefined）。
      const socketAtExit = req.socket

      if (parsed && parsed.body) {
        try {
          await parsed.body.cancel()
        } catch { /* 已关闭 / 已锁定，忽略 */ }
      }

      // cancel() 只清理 Web 流，**不会断开 TCP**。若客户端还在发请求体
      // （req.complete 为 false），连接会一直挂着等剩余 Content-Length ——
      // 这正是那条 DoS 路径：一个**不需要凭据**的客户端声明巨大的
      // Content-Length、只发一小段，就能让连接无法复用。
      //
      // 三个实测过的坑（`node` 上逐个试出来的，别改回去）：
      //   1. `req.destroy()` 只销毁请求流，socket 仍在 —— 连接照样挂着；
      //   2. `web.cancel()` 会把 `req.socket` 置为 null，所以**必须先取 socket**；
      //   3. 立刻 `socket.destroy()` 会丢掉还压在写缓冲里的 401 —— 客户端
      //      收到的是连接关闭而不是响应。必须等 `finish`。
      if (!req.complete) {
        const kill = () => { try { socketAtExit?.destroy() } catch { /* 已关 */ } }
        // writableFinished 为 true 说明响应已交给 OS，可以立刻断；
        // 否则等 finish —— 否则客户端看不到 401。
        if (res.writableFinished) kill()
        else res.once('finish', kill)
      }
    }
  }

  /**
   * @returns {ForwardAdapterStats}
   */
  function stats() {
    return { ...statsState }
  }

  return { handle, stats }
}
