/**
 * reverse-proxy.mjs — 通用反向代理 Adapter（v0.4.0 / E1）
 *
 * Forward 入口由客户端指定目标，Reverse 入口由**服务端的绑定关系**决定目标：
 * 入口 URL 形如 `/__proxy/r/{groupId}/{path}`，但 URL 里的 `groupId` 只是
 * 一个「查询键」，不是授权结论。攻击者能随便改 URL，却改不了服务端的
 * 客户端绑定表 —— 所以授权只有一条路：先用 Bearer 凭据确定客户端身份，
 * 再拿「身份 + URL 里的分组名」去查绑定关系，查不出来就 403。
 *
 * ## 为什么 URL 里的分组名绝不直接当授权依据
 *
 * 反向代理的入口暴露在公网路径上，`groupId` 出现在每一个能被转发、
 * 被收藏、被日志记录的 URL 里。如果把「URL 写了什么」当「有权访问什么」，
 * 那么知道分组名就等于拿到权限 —— 等于没有授权。本模块把 URL 分组名
 * 命名为 `groupFromUrl` 并只喂给 `resolveGroup()`，由注入方（持有绑定表
 * 的一方）裁决：返回真正的 group id，或 `null` 表示越权。
 *
 * ## 两条不能省的入口卫生
 *
 * 1. **先剥自报身份头，再认证。** `x-client-id` / `x-route-group` 这类头
 *    完全由请求方控制；留着它们转发给上游，等于替冒名者背书。
 * 2. **Host 与 X-Forwarded-* 只认服务端事实。** 客户端可以伪造
 *    `X-Forwarded-Host: evil.example` 试图把「原始站点」指向别处；
 *    这两个字段在转发前一律删除，再按目标 URL 重写成服务端算出的事实。
 *
 * ## 路径处理为什么不能全托付给 WHATWG URL
 *
 * `new URL('https://h/a/../b').pathname === '/b'`：URL 构造这一步就会把
 * `..` 消化掉。如果入口解析阶段就先建 URL，穿越段在到达任何检测之前
 * 已经「被规范化成了合法路径」，后面再检查永远查不到。所以
 * `parseReversePath()` 在**原始字符串**上拆段（保留 `..` 的原貌），
 * `buildTargetUrl()` 在拼接前对每一段做多层解码检测，两层都过才允许
 * 交给 URL 构造，构造后还有一次段级复查兜底。
 *
 * @module reverse-proxy
 */

import { Readable } from 'node:stream'

import {
  ClientCancelled,
  ProxyError,
  TargetDenied,
  isProxyError,
} from './contract/errors.mjs'
import { makeRequestContext } from './contract/request-context.mjs'
import { authenticateClient, sanitizeIdentityHeaders } from './client-auth.mjs'
import { validateTargetUrl } from './target-validator.mjs'
import { createCleanup, pipeWithBackpressure } from './streaming.mjs'
import { filterRequestHeaders, filterResponseHeaders } from './headers.mjs'

/* ============================================================
 * 类型
 * ============================================================ */

/**
 * 上游对象的最小形状。生产里是 A2 的 `Upstream`（makeUpstream 工厂产出），
 * 这里只声明本模块实际读取的字段，避免把整个 Registry 拖进类型。
 *
 * @typedef {object} UpstreamLike
 * @property {string} hostname
 * @property {number} port
 * @property {'https'} protocol
 */

/**
 * 入口路径解析结果。
 *
 * @typedef {object} ReversePath
 * @property {string} groupFromUrl URL 里的分组名，**只用于查表**
 * @property {string} restPath 分组名之后的路径，以 `/` 开头
 * @property {string} query 原样保留的查询串（含 `?`，无则空串）
 */

/**
 * 客户端提供的路由提示。默认关闭两个改写：语义是「路径原样透传」，
 * 打开任何一个都必须显式写 —— 隐式改写会让人排查「上游为什么收到
 * 不一样的路径」时无从下手。
 *
 * @typedef {object} BuildOptions
 * @property {string|null} [stripPrefix] 从入口路径剥离的前缀
 * @property {string|null} [upstreamPathPrefix] 追加到上游路径前的前缀
 * @property {string} [query] 原样拼接的查询串（含 `?`）
 */

/**
 * 适配器选项。
 *
 * @typedef {object} ReverseAdapterOptions
 * @property {(ctx: import('./contract/request-context.mjs').RequestContext) =>
 *   Promise<{ statusCode: number, headers?: object, body?: ReadableStream<Uint8Array>|null }>} core
 *   注入的 Routing Core：只认 RequestContext，不认 req/res
 * @property {(clientId: string, groupFromUrl: string) => string|null} resolveGroup
 *   由服务端绑定关系裁决真正的 RouteGroup id；返回 null 表示越权
 * @property {(groupId: string) => UpstreamLike|null} resolveUpstream
 *   group id → Upstream；返回 null 表示分组没有可用上游
 * @property {string} [routePrefix] 入口前缀，默认 `/__proxy/r`
 * @property {import('./client-auth.mjs').ClientCollection} [auth]
 *   客户端集合（认证凭据来源）。缺省时跳过认证、以 `anonymous` 身份进入
 *   授权裁决 —— 只适合完全内网的部署，显式声明比默默打开更诚实
 * @property {(msg: string) => void} [logger]
 * @property {object} [validatorOptions] 透传给 validateTargetUrl 的选项
 *   （allowlist / allowPrivate / resolve…）
 * @property {string|null} [stripPrefix] 透传给 buildTargetUrl
 * @property {string|null} [upstreamPathPrefix] 透传给 buildTargetUrl
 */

/**
 * @typedef {object} ReverseStats
 * @property {number} requests 收到的请求数
 * @property {number} ok 成功完成响应的请求数
 * @property {number} errors 以错误响应收场的请求数
 * @property {number} bytesOut 已流式写回下游的字节数
 */

/* ============================================================
 * 内部工具
 * ============================================================ */

/**
 * 多层百分号解码。
 *
 * 一层 `decodeURIComponent` 抓得住 `%2e%2e%2f`，抓不住 `%252e%252e`
 * （双重编码）。服务端栈（Nginx、应用框架、上游路由）解码层数各不相同，
 * 只查一层等于赌上游恰好也只解一层。这里固定解到第 3 层：
 * 常见的走私载荷（单层、双重、`%25%32%35` 这类三层嵌套）都会显形，
 * 而正常业务路径出现三层嵌套编码本身就该怀疑。
 *
 * @param {string} raw
 * @param {number} [maxDepth]
 * @returns {string|null} 解码结果；出现畸形转义（如孤立 `%`）时返回 null
 */
function deepDecode(raw, maxDepth = 3) {
  let current = raw
  for (let depth = 0; depth < maxDepth; depth += 1) {
    if (!/%[0-9a-fA-F]{2}/.test(current)) return current
    try {
      current = decodeURIComponent(current)
    } catch {
      return null
    }
  }
  return current
}

/**
 * 判断一个（可能已解码的）路径段是否安全。
 *
 * 「安全」的定义刻意从严：
 *   - `.` / `..`：无论原文还是解码后出现，都是穿越语义；
 *   - 段内出现 `/` 或 `\`：解码后塞进来一个分隔符，说明有人在段里藏路径；
 *   - 控制字符：不同的 HTTP 栈对 C0 的处理不一致，是走私的经典载体。
 *
 * 返回拒绝原因而不是抛错：调用方有两处使用（原始段、URL 构造后的段），
 * 各自决定用什么错误语义包装。
 *
 * @param {string|null} decoded
 * @returns {string|null} 拒绝原因；null 表示通过
 */
function unsafeSegmentReason(decoded) {
  if (decoded === null) return 'bad_percent_escape'
  if (decoded === '.' || decoded === '..') return 'path_traversal'
  if (decoded.includes('/') || decoded.includes('\\')) return 'embedded_separator'
  for (let i = 0; i < decoded.length; i += 1) {
    const c = decoded.charCodeAt(i)
    if (c < 0x20 || c === 0x7f) return 'control_char'
  }
  return null
}

/* ============================================================
 * 1. 入口路径解析（纯函数）
 * ============================================================ */

/**
 * 解析反向代理入口路径 `/__proxy/r/{groupId}/{path}?query`。
 *
 * **关键实现决定：段拆分在原始字符串上做，不经过 `new URL()`。**
 * WHATWG URL 构造会把 `..` 段规范化掉（见文件头），而「拒绝穿越」
 * 是本模块的职责之一 —— 输入先于规范化丢失，检查就成了摆设。
 * URL 对象只用来解析 query 部分（query 不会产生路径语义，交给
 * WHATWG 归一化是安全的）。
 *
 * 失败一律返回 `null` 而不是抛错：解析失败只是「这不是本代理的入口
 * 形态」，如何回话（400 / 404）是调用方的策略；真正的安全否决在
 * `buildTargetUrl()`，那里抛 `TargetDenied`。
 *
 * @param {unknown} rawUrl 请求行里的 URL（origin-form）
 * @param {{ routePrefix?: string }} [opts]
 * @returns {ReversePath|null} 形态不合法（前缀不匹配 / 分组段为空或含
 *   非法字符）时返回 null
 */
export function parseReversePath(rawUrl, opts = {}) {
  if (typeof rawUrl !== 'string' || rawUrl === '') return null

  const qIdx = rawUrl.indexOf('?')
  const rawPath = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx)

  // 前缀规范化：容忍调用方写 `/__proxy/r/` 或 `__proxy/r` 这类形态，
  // 统一成 `/a/b`。逐段比较而不是 startsWith 字符串：`/__proxy/rect`
  // 不能命中 `/__proxy/r` 的前缀。
  const prefixSegs = String(opts.routePrefix ?? '/__proxy/r')
    .split('/')
    .filter((s) => s !== '')

  const segs = rawPath.split('/')
  // rawPath 以 `/` 开头（origin-form），split 后首段必是空串：`/__proxy/r`
  // → ['', '__proxy', 'r']。跳过这个空段，从 segs[1] 开始对齐前缀，
  // 否则 '' !== '__proxy' 永远失配（实测第一版就栽在这里）。
  if (segs[0] !== '') return null
  let idx = 1
  for (const ps of prefixSegs) {
    if (segs[idx] !== ps) return null
    idx += 1
  }

  // rawPath 形如 `/__proxy/r/g1/...`：split 后首段必是 ''（开头是 `/`），
  // prefix 逐段吃掉后，idx 应停在分组段上。若只剩 `?`（无分组段），
  // segs[idx] 是 undefined —— 那不是合法入口。
  const groupFromUrl = segs[idx] ?? ''
  if (groupFromUrl === '') return null

  // 分组段本身也要过一遍解码检查：`%2f` 会让「一个段」在某个中间层
  // 变成两个段，`..` 则是赤裸的穿越。不合格直接返回 null。
  const decodedGroup = deepDecode(groupFromUrl)
  if (unsafeSegmentReason(decodedGroup) !== null) return null

  const restSegs = segs.slice(idx + 1)
  const restPath = '/' + restSegs.join('/')

  let query = ''
  try {
    query = new URL(rawUrl, 'http://entry.invalid').search
  } catch {
    query = ''
  }

  return { groupFromUrl, restPath, query }
}

/* ============================================================
 * 2. 目标 URL 构造（纯函数）
 * ============================================================ */

/**
 * 对一段完整路径做安全检查（按 `/` 拆段，逐段多层解码）。
 *
 * 必须在 `new URL()` **之前**调用：URL 构造会消化 `..` 与 `%2e` 段，
 * 到那时再查，穿越已经完成了。构造之后的那次复查只是兜底，
 * 防的是本模块自己在拼接时引入问题。
 *
 * @param {string} path
 * @returns {void}
 * @throws {TargetDenied} 出现穿越段 / 内嵌分隔符 / 控制字符 / 畸形转义
 */
function assertPathSegmentsSafe(path) {
  const segs = path.split('/')
  for (const seg of segs) {
    if (seg === '') continue
    // 原始段里出现反斜杠必须拒：WHATWG 把 `\` 当 `/` 处理，
    // `a\b` 到了 URL 构造就变成两个段 —— 拼接前看着是一个段，
    // 发出去就是另一个路径。
    if (seg.includes('\\')) {
      throw new TargetDenied('路径段包含反斜杠，已拒绝', { reason: 'backslash_in_segment' })
    }
    const reason = unsafeSegmentReason(deepDecode(seg))
    if (reason !== null) {
      throw new TargetDenied('路径包含穿越或非法编码段，已拒绝', { reason })
    }
  }
}

/**
 * 由 Upstream 与入口剩余路径构造上游目标 URL。
 *
 * 协议与 Host **完全由 upstream 决定**：入口方传来的任何主机信息
 * 都不参与这一步。路径的组装顺序是：
 *
 *   1. `stripPrefix`：从 restPath 头部剥离（restPath 必须以它开头，
 *      否则视为入口与分组配置不一致，拒绝而不是硬转发）；
 *   2. `upstreamPathPrefix`：追加到剩余路径前。
 *
 * 拼接全程使用 WHATWG `URL` API。字符串相加拼 URL 看似等价，但
 * 它不经过任何规范化 —— 恰恰是「`..` 逃过所有检测」的通道。
 *
 * @param {UpstreamLike} upstream
 * @param {string} restPath 以 `/` 开头的剩余路径
 * @param {BuildOptions} [opts]
 * @returns {URL} 构造好的目标 URL（协议、host、路径、query 均已定型）
 * @throws {TargetDenied} 前缀不匹配、路径穿越、畸形编码
 */
export function buildTargetUrl(upstream, restPath, opts = {}) {
  if (restPath == null || typeof restPath !== 'string' || !restPath.startsWith('/')) {
    throw new TargetDenied('剩余路径必须以 / 开头', { reason: 'bad_rest_path' })
  }

  let pathPart = restPath

  const stripPrefix = opts.stripPrefix ?? null
  if (stripPrefix != null && stripPrefix !== '') {
    // 规范化成 `/x/y` 形态；`/` 或空串语义等于「不剥离」
    const norm = '/' + String(stripPrefix).split('/').filter((s) => s !== '').join('/')
    if (norm !== '/' && norm !== '//') {
      if (pathPart !== norm && !pathPart.startsWith(norm + '/')) {
        throw new TargetDenied(
          '入口路径与分组配置的剥离前缀不一致',
          { reason: 'strip_prefix_mismatch', prefix: norm },
        )
      }
      pathPart = pathPart.slice(norm.length) || '/'
    }
  }

  const upstreamPathPrefix = opts.upstreamPathPrefix ?? null
  let outPath = pathPart
  if (upstreamPathPrefix != null && upstreamPathPrefix !== '') {
    const norm = '/' + String(upstreamPathPrefix).split('/').filter((s) => s !== '').join('/')
    if (norm !== '/' && norm !== '//') {
      outPath = norm + (pathPart === '/' ? '' : pathPart)
    }
  }

  assertPathSegmentsSafe(outPath)

  const authority = `${upstream.protocol}://${upstream.hostname}:${upstream.port}`
  /** @type {URL} */
  let target
  try {
    target = new URL(authority + outPath + (opts.query ?? ''))
  } catch {
    // host 里有非法字符等情况。这是服务端配置问题，但对外的语义
    // 与穿越一致：这个目标不允许访问。
    throw new TargetDenied('目标 URL 构造失败', { reason: 'malformed_target' })
  }

  // 兜底复查：URL 规范化之后的段再过一遍解码检测。正常情况下
  // 前面的 assert 已经全部拦下；这一步防的是拼接逻辑自身出 bug。
  const postSegs = target.pathname.split('/')
  for (const seg of postSegs) {
    if (seg === '') continue
    const reason = unsafeSegmentReason(deepDecode(seg))
    if (reason !== null) {
      throw new TargetDenied('URL 规范化后出现非法路径段，已拒绝', { reason })
    }
  }

  return target
}

/* ============================================================
 * 3. 反向代理 Adapter
 * ============================================================ */

/**
 * 把一个 ProxyError 映射成 HTTP 状态码。
 *
 * 只有三类有自然对应：401（凭据）、403（目标否决）、以及「其它一切
 * 上游侧故障 → 502」。其余 9 类错误在反向入口的语义都是
 * 「代理替客户端去上游，上游这一侧出了问题」，统一 502 比编造
 * 一张五颜六色的对照表更容易被客户端正确处理。
 *
 * @param {ProxyError} err
 * @returns {number}
 */
function statusForProxyError(err) {
  if (err.code === 'client_unauthorized') return 401
  if (err.code === 'target_denied') return 403
  return 502
}

/**
 * 统一的错误响应出口。
 *
 * 已经开始写响应头（或连接已断）时什么都不做：半途插入一个 500
 * 只会把合法的前半个响应污染成非法的。此时唯一有意义的动作是
 * 掐断连接，交由调用方处理。
 *
 * @param {import('node:http').ServerResponse} res
 * @param {number} statusCode
 * @param {string} code 稳定错误标识（复用契约 code 或入口专有 code）
 * @param {string} message 人类可读描述，不含敏感值
 * @returns {void}
 */
function sendJsonError(res, statusCode, code, message) {
  if (res.headersSent || res.writableEnded || res.destroyed) return
  const body = Buffer.from(JSON.stringify({ error: code, message }), 'utf8')
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(body.byteLength),
  })
  res.end(body)
}

/**
 * 创建反向代理 Adapter。
 *
 * 处理顺序（每一步的失败都会立即短路，后面的步骤不会再执行）：
 *
 *   解析路径 → 剥自报身份头 → 认证(401) → resolveGroup(null 则 403)
 *   → resolveUpstream(空则 404) → buildTargetUrl(路径否决则 403)
 *   → validateTargetUrl(否决则 403) → 构造 RequestContext(mode:'reverse')
 *   → core → 流式写回。
 *
 * `resolveGroup` 收到的是**客户端身份**与 **URL 分组名**两个独立来源，
 * 它必须去查服务端绑定表 —— 这是整个入口唯一的授权点。
 *
 * @param {ReverseAdapterOptions} options
 * @returns {{ handle: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => Promise<void>, stats: () => ReverseStats }}
 * @throws {TypeError} core / resolveGroup / resolveUpstream 缺失或不是函数
 */
export function createReverseAdapter(options) {
  if (options == null || typeof options !== 'object') {
    throw new TypeError('createReverseAdapter: 需要对象参数')
  }
  const { core, resolveGroup, resolveUpstream } = options
  if (typeof core !== 'function') {
    throw new TypeError('createReverseAdapter: core 必须是函数')
  }
  if (typeof resolveGroup !== 'function') {
    throw new TypeError('createReverseAdapter: resolveGroup 必须是函数')
  }
  if (typeof resolveUpstream !== 'function') {
    throw new TypeError('createReverseAdapter: resolveUpstream 必须是函数')
  }

  const routePrefix = options.routePrefix ?? '/__proxy/r'
  const auth = options.auth ?? null
  const logger = typeof options.logger === 'function' ? options.logger : () => {}
  const validatorOptions = options.validatorOptions ?? {}
  const stripPrefix = options.stripPrefix ?? null
  const upstreamPathPrefix = options.upstreamPathPrefix ?? null

  /** @type {{ requests: number, ok: number, errors: number, bytesOut: number }} */
  const counters = { requests: 0, ok: 0, errors: 0, bytesOut: 0 }

  /**
   * 处理一次入口请求。
   *
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @returns {Promise<void>}
   */
  async function handle(req, res) {
    counters.requests += 1
    let cleanup = null

    try {
      /* ---- ① 解析入口路径 ---- */
      const parsed = parseReversePath(req.url ?? '', { routePrefix })
      if (parsed === null) {
        counters.errors += 1
        sendJsonError(res, 400, 'bad_reverse_path', '入口路径不符合反向代理形态')
        return
      }

      /* ---- ② 剥自报身份头 ----
       * 必须发生在认证之前：这些头是请求方可控的，若先认证后剥离，
       * 认证逻辑就可能（哪怕无意间）读到它们。剥离动作只对**转发的
       * 头集合**生效，Authorization 是端到端字段，不在名单里。 */
      const { headers: clean, removed } = sanitizeIdentityHeaders(req.headers)
      if (removed.length > 0) {
        logger(`[reverse] 已剥离自报身份头: ${removed.join(', ')}`)
      }

      /* ---- ③ 认证（auth 未配置时以 anonymous 进入授权裁决）---- */
      let clientId = 'anonymous'
      if (auth !== null) {
        try {
          const identity = authenticateClient(clean, auth)
          clientId = identity.clientId
        } catch (err) {
          if (isProxyError(err) && err.code === 'client_unauthorized') {
            counters.errors += 1
            sendJsonError(res, 401, err.code, err.message)
            return
          }
          throw err
        }
      }

      /* ---- ④ 授权：URL 分组名只是查询键，绑定关系才是答案 ---- */
      const groupId = resolveGroup(clientId, parsed.groupFromUrl)
      if (groupId == null) {
        counters.errors += 1
        // 刻意在 core 之前短路：越权请求连上游的影子都不该看到
        sendJsonError(res, 403, 'group_denied', '客户端未绑定该路由分组')
        return
      }

      /* ---- ⑤ 上游 ---- */
      const upstream = resolveUpstream(groupId)
      if (upstream == null) {
        counters.errors += 1
        sendJsonError(res, 404, 'group_not_found', '路由分组没有可用的上游')
        return
      }

      /* ---- ⑥ 目标 URL 构造（穿越在这里被拒）---- */
      const target = buildTargetUrl(upstream, parsed.restPath, {
        stripPrefix,
        upstreamPathPrefix,
        query: parsed.query,
      })

      /* ---- ⑦ 目标验证（白名单 / 私网 / 端口）---- */
      try {
        await validateTargetUrl(target.toString(), validatorOptions)
      } catch (err) {
        if (isProxyError(err)) {
          counters.errors += 1
          sendJsonError(res, statusForProxyError(/** @type {ProxyError} */ (err)), err.code, err.message)
          return
        }
        throw err
      }

      /* ---- ⑧ Header 事实重写 ----
       * X-Forwarded-Host / X-Forwarded-Proto 是客户端可伪造字段，
       * 先删掉再按服务端算出的事实重写；Host 由目标决定，交给
       * filterRequestHeaders 统一处理。 */
      const factHost = target.host
      delete clean['x-forwarded-host']
      delete clean['x-forwarded-proto']
      clean['x-forwarded-host'] = factHost
      clean['x-forwarded-proto'] = upstream.protocol

      const forwardHeaders = /** @type {Record<string, string|string[]>} */ (
        filterRequestHeaders(clean, { targetHost: factHost })
      )

      /* ---- ⑨ 客户端取消信号 ----
       * 断连必须立刻转化为 abort：泵（pipeWithBackpressure）靠它
       * 在任何挂起点上醒来并取消上游，而不是等下一块数据到来。 */
      const ac = new AbortController()
      // onClose 先定义再注册清理：清理函数引用它，声明顺序反了会踩 TDZ
      const onClose = () => {
        if (!res.writableEnded) {
          ac.abort(new ClientCancelled('客户端断开连接', { phase: 'downstream' }))
        }
      }
      cleanup = createCleanup()
      cleanup.add(() => res.removeListener('close', onClose))
      res.on('close', onClose)

      /* ---- ⑩ 请求体（有体才包流，GET 等无体请求保持 null）---- */
      const hasBody = req.headers['content-length'] !== undefined
        || req.headers['transfer-encoding'] !== undefined
      const body = hasBody
        ? /** @type {ReadableStream<Uint8Array>} */ (/** @type {unknown} */ (Readable.toWeb(req)))
        : null

      const ctx = makeRequestContext({
        clientId,
        routeGroupId: groupId,
        mode: 'reverse',
        method: req.method ?? 'GET',
        originalUrl: req.url ?? '',
        headers: forwardHeaders,
        body,
        signal: ac.signal,
      })

      /* ---- ⑪ core ---- */
      const out = await core(ctx)
      const status = Number(out?.statusCode ?? 200)
      if (!Number.isInteger(status) || status < 100 || status > 599) {
        throw new ProxyError('stream_failure', `core 返回了非法状态码 ${String(out?.statusCode)}`)
      }

      /* ---- ⑫ 流式写回 ---- */
      const responseHeaders = filterResponseHeaders(out?.headers ?? {}, { statusCode: status })
      res.writeHead(status, responseHeaders)
      // 先收进局部常量再判空：tsc 对 `out?.body` 的可选链收窄不完整，
      // 直接把 `out.body` 传下去会被判成可能为 null
      const upstreamBody = out?.body ?? null
      if (!upstreamBody) {
        res.end()
        counters.ok += 1
        return
      }

      const pipe = pipeWithBackpressure(upstreamBody, res, { signal: ac.signal })
      const done = await pipe.done
      counters.bytesOut += done.bytes
      counters.ok += 1
    } catch (err) {
      counters.errors += 1
      if (res.headersSent) {
        // 响应已经开始：没有第二条合法出路，只有断开。
        try { res.destroy(err instanceof Error ? err : undefined) } catch { /* 已断 */ }
        return
      }
      if (isProxyError(err)) {
        const pe = /** @type {ProxyError} */ (err)
        // 客户端已取消：socket 大概率不在了，只记账不强行写响应
        if (pe.code === 'client_cancelled') {
          try { res.destroy() } catch { /* 已断 */ }
          return
        }
        sendJsonError(res, statusForProxyError(pe), pe.code, pe.message)
        return
      }
      sendJsonError(res, 500, 'internal_error', '反向代理内部错误')
    } finally {
      try { cleanup?.run() } catch { /* 清理失败不影响主流程 */ }
    }
  }

  return {
    handle,
    stats() {
      return { ...counters }
    },
  }
}
