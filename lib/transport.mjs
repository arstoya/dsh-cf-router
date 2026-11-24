/**
 * transport.mjs — 统一传输层（v0.4.0 / C1）
 *
 * Routing Core 只认 `transport.send(request, upstream, timeoutPolicy)`，
 * 不再自己 `new https.Agent()`、不再自己挂 `https.request`。这一层的职责边界是：
 *
 *   · 只做「怎么把字节发到某个上游、怎么把响应交回来」
 *   · 不做选路、不做重试、不做熔断 —— 那些是 Routing Core / C3 的事
 *
 * ## 为什么包住 connection-pool，而不是重写一套连接管理
 *
 * #12 的连接池回答了最难的那个问题：**切线路时怎么不掐断正在跑的 SSE**。
 * 它给出的三态生命周期（active → draining → destroyed）+ 同 key 多代共存，
 * 是审查过并已在生产路径上跑着的。传输层真正需要新增的只有「请求级槽位计数」
 * 与「按 hostname:port 而不是 host|ip 建池」两件事，两者都能套在现有 API 上：
 * `pool.get()` 建池、`pool.acquire/release()` 记在途、`pool.drainAll/destroyAll()`
 * 负责停机。重写一份只会把「排空」这件事又实现一遍、再多一处漂移。
 *
 * ## 本实现只支持 HTTP/1.1 —— 不做 HTTP/2，也不宣称支持
 *
 * 方案原文特别强调过这一条：**没实测过握手与并发，就不要写在能力清单里**。
 * 具体到本模块，HTTP/2 不是「加个 flag」：
 *
 *   1. 连接复用模型冲突。HTTP/1.1 的语义是「一条 socket 同时只跑一个请求」，
 *      所以 connection-pool 的「一代 socket 一个池、inFlight 计数归零才排空」
 *      是成立的；HTTP/2 是一条 socket 上多路复用 N 个流，inFlight 归零的判据
 *      要换成「所有 streamId 关闭」，排空超时的语义也随之变形。
 *   2. 六段超时要多一段流控窗口等待，且 h2 的 `RST_STREAM` / `GOAWAY` 与
 *      h1 的 `ECONNRESET` 在「谁的错」上完全不同，错误分类器要重做一套映射。
 *   3. ALPN 协商本身要验证：上游是否真支持 h2、`http2.connect` 的会话复用、
 *      `maxConcurrentStreams` 与 maxSockets 的关系，一条都没在本仓库实测过。
 *
 * 所以这里只用 `node:https`（HTTP/1.1）建连。将来要加 h2，正确做法是新开一个
 * adapter 走同一套 `send()` 契约，而不是在本文件里偷偷协商 ALPN —— 悄悄升级成
 * h2 会让上面第 1 条的排空逻辑在无人察觉的情况下失效。
 *
 * ## 六段超时为什么不用 Node 自带的 timeout
 *
 * `https.request({timeout})` 只有一个计时器，且挂在 socket 上：它既区分不了
 * 「DNS 卡住」和「TLS 握手卡住」，又会在 socket 被复用时留下残留定时器。
 * 排空阶段被这种残留定时器打断，表现出来就是「排空中突然 ECONNRESET」。
 * 因此本模块自己按阶段起表：进入某一段就起该段的表，离开就清掉，任何一段
 * 触发都抛 `UpstreamTimeout` 且 details 里带 `{ phase, limitMs }`。
 *
 * ## 取消的物理边界（写清楚，不假装）
 *
 * `getaddrinfo` 是 libuv 的线程池阻塞调用，**无法真正中断**。客户端取消时本模块
 * 能做到的是：不再等待解析结果、销毁已建立的 socket、把 body 流传给调用方的错误
 * 换成 `ClientCancelled`。已经交给线程池的那次解析会自己跑完再把结果丢掉 ——
 * 这不是「没做」，是 Node 没有提供中断原语。除此之外 DNS 之后的所有阶段
 * （连接、TLS、首字节、流）都会被真正销毁。
 *
 * @module transport
 */

import https from 'node:https'
import net from 'node:net'
import dns from 'node:dns'
import { Transform, Readable } from 'node:stream'

import { createPoolRegistry, DEFAULT_DRAIN_TIMEOUT_MS } from './connection-pool.mjs'
import {
  ProxyError, DnsFailure, ConnectFailure, TlsFailure,
  UpstreamTimeout, ClientCancelled, StreamFailure, isProxyError,
} from './contract/errors.mjs'

/**
 * 六段超时的默认值（毫秒）。`null` / `0` 表示**关闭该段**。
 *
 * `totalMs` 默认关闭：SSE 流式响应的合法时长可以到几十分钟，
 * 给一个默认总上限等于给正常业务埋一个定时炸弹。需要总预算的调用方
 * 显式传 `timeoutPolicy.totalMs`，或在上游上配 `timeoutMs`。
 *
 * @type {Readonly<{dnsMs:number, connectMs:number, tlsMs:number, firstByteMs:number, streamIdleMs:number, totalMs:number|null}>}
 */
export const DEFAULT_TIMEOUTS = Object.freeze({
  dnsMs: 5_000,
  connectMs: 5_000,
  tlsMs: 5_000,
  firstByteMs: 30_000,
  streamIdleMs: 60_000,
  totalMs: null,
})

/**
 * 字段名 → 上报/报错里用的阶段名。两套名字必须一起改，所以放同一张表。
 *
 * 阶段名与 `error-classifier.mjs` 的 `phase` 取值保持一致
 * （dns / connect / tls / first_byte / stream_idle / total），
 * 这样 C3 拿 `UpstreamTimeout.details.phase` 就能直接喂给分类器。
 */
export const TIMEOUT_SEGMENTS = Object.freeze({
  dnsMs: 'dns',
  connectMs: 'connect',
  tlsMs: 'tls',
  firstByteMs: 'first_byte',
  streamIdleMs: 'stream_idle',
  totalMs: 'total',
})

/** 解析失败的错误码（决定抛 DnsFailure 而不是笼统的网络错误） */
const DNS_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN', 'EAI_FAIL', 'EAI_NONAME', 'EAI_NODATA'])

/** 建连失败的错误码 */
const CONNECT_CODES = new Set([
  'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EADDRNOTAVAIL', 'ECONNABORTED',
])

/** TLS 层错误码。证书类错误不重试、不吞掉（方案 §5.5） */
const TLS_CODES = new Set([
  'ERR_TLS_CERT_ALTNAME_INVALID', 'ERR_TLS_HANDSHAKE_TIMEOUT', 'ERR_SSL_WRONG_VERSION_NUMBER',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'EPROTO',
])

/* ============================================================================
 * 对外工厂
 * ========================================================================== */

/**
 * @typedef {object} TimeoutPolicy
 * @property {number|null} [dnsMs]
 * @property {number|null} [connectMs]
 * @property {number|null} [tlsMs]
 * @property {number|null} [firstByteMs]
 * @property {number|null} [streamIdleMs]
 * @property {number|null} [totalMs]
 */

/**
 * @typedef {object} TransportRequest
 * @property {string} [method] 默认 GET，自动大写
 * @property {string} [path] 默认 `/`（含 query）
 * @property {Record<string, string|string[]>} [headers]
 * @property {ReadableStream<Uint8Array>|import('node:stream').Readable|string|Buffer|null} [body]
 * @property {AbortSignal|null} [signal] 客户端取消信号
 */

/**
 * @typedef {object} TransportResponse
 * @property {number} statusCode
 * @property {string} statusText
 * @property {Record<string, string|string[]>} headers 已小写键名
 * @property {ReadableStream<Uint8Array>|null} body HEAD / 204 / 304 为 null
 * @property {boolean} socketReused 本次是否跑在复用连接上
 * @property {{dnsMs:number|null, connectMs:number|null, tlsMs:number|null, firstByteMs:number|null, totalMs:number|null}} timings
 *   `totalMs` 要等 body 读完后才有值（同一个对象，晚读得到的是终值）
 * @property {() => void} cancel 调用方主动放弃（换线路重试时用），body 会收到 ClientCancelled
 */

/**
 * @typedef {object} TransportOptions
 * @property {Partial<TimeoutPolicy>} [timeouts] 覆盖 DEFAULT_TIMEOUTS
 * @property {number} [maxSockets] 每个上游的最大并发连接，默认 16
 * @property {number} [maxFreeSockets] 每个上游的空闲连接上限，默认 4
 * @property {boolean} [keepAlive] 默认 true
 * @property {number} [drainTimeoutMs] close() 等待在途请求的上限，默认 120s
 * @property {number} [dnsCacheTtlMs] 解析结果缓存时长，默认 30s；0 = 每次都解析
 * @property {number} [family] 解析的首选地址族，默认 4（本插件整体是 IPv4 选路）
 * @property {Record<string, unknown>} [tls] 透传给 https.Agent 的 TLS 参数（ca / rejectUnauthorized…）
 * @property {(hostname: string, ctx: { signal?: AbortSignal|null }) => Promise<{address: string, family: number}>} [resolve]
 *   自定义解析器（测试注入 / 将来接 IP 固定）。默认走 dns.promises.lookup
 * @property {Function} [createConnection] 底层 socket 创建器，仅测试注入用
 * @property {object} [pool] 复用外部 connection-pool 实例（不传则自建）
 * @property {() => number} [now]
 * @property {(msg: string) => void} [log]
 */

/**
 * 创建传输层实例。
 *
 * @param {TransportOptions} [options]
 * @returns {{ send: (request: TransportRequest, upstream: object, timeoutPolicy?: TimeoutPolicy) => Promise<TransportResponse>, close: () => Promise<void>, stats: () => object }}
 */
export function createTransport(options = {}) {
  const defaults = { ...DEFAULT_TIMEOUTS, ...(options.timeouts || {}) }
  // 默认值在构造期就校验：配置错了要在装载时炸，而不是等第一个请求进来
  for (const field of Object.keys(TIMEOUT_SEGMENTS)) normalizeLimit(defaults[field], field)

  const maxSockets = positiveInt(options.maxSockets, 16, 'maxSockets')
  const maxFreeSockets = positiveInt(options.maxFreeSockets, 4, 'maxFreeSockets')
  const keepAlive = options.keepAlive !== false
  const drainTimeoutMs = positiveInt(options.drainTimeoutMs, DEFAULT_DRAIN_TIMEOUT_MS, 'drainTimeoutMs')
  const dnsCacheTtlMs = normalizeLimit(options.dnsCacheTtlMs ?? 30_000, 'dnsCacheTtlMs')
  const family = options.family === 6 ? 6 : 4
  const tlsOptions = options.tls && typeof options.tls === 'object' ? { ...options.tls } : {}
  const createConnection = typeof options.createConnection === 'function' ? options.createConnection : null
  // 自定义 createConnection 必须靠子类实现：http.Agent 只调用 `this.createConnection`，
  // 构造函数里的同名 option 不会被采用（这点与 net.connect 的 options 不同，实测踩过）。
  // 生产路径永远用标准 https.Agent —— 这个分支只为测试注入 socket 层故障。
  const AgentClass = createConnection
    ? class InjectedAgent extends https.Agent {
      /** @param {object} opts @param {(err: Error|null, socket?: any) => void} cb */
      createConnection(opts, cb) { return createConnection(opts, cb) }
    }
    : https.Agent
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  const log = typeof options.log === 'function' ? options.log : () => {}
  const resolveHost = typeof options.resolve === 'function'
    ? options.resolve
    : (hostname) => dns.promises.lookup(hostname, { family })

  const pool = options.pool && typeof options.pool.get === 'function'
    ? options.pool
    : createPoolRegistry({ now, log })

  /** key(`hostname:port`) → agent。只是为了停机时能一起清掉与观测 */
  const agents = new Map()
  /**
   * 见过的 socket 对象 → 用来判「这次是复用还是新建」。
   *
   * 不用 `req.reusedSocket`：那个标记只在 Agent 于 `addRequest` 里**当场**摘一个
   * 空闲 socket 时才会置位。被 maxSockets 排进队列、等别人跑完才拿到 socket 的请求
   * 走的是另一条派发路径，socket 确实复用了，标记却仍是 false（实测：4 并发、
   * maxSockets=2 时真实只开了 2 条连接，而 reusedSocket 全是 false）。
   * 复用率是要给容量决策用的指标，必须按 socket 身份计数，不能按 Node 的标记。
   */
  const seenSockets = new WeakSet()
  /** key → 解析结果缓存（TTL 内直接命中，避免每次请求重新解析把复用打散） */
  const dnsCache = new Map()
  /** key → 每上游统计 */
  const upstreamStats = new Map()
  /** 在途请求：close() 要等它们，超时后要能逐个终止 */
  const live = new Set()

  let closed = false
  /** close() 的幂等锁：并发/重复调用拿同一个 promise */
  let closing = null

  const counters = { requests: 0, completed: 0, failed: 0, timedOut: 0, cancelled: 0, reused: 0, opened: 0 }

  /* ------------------------------------------------------------------ 统计 */

  function statFor(key) {
    let s = upstreamStats.get(key)
    if (!s) {
      s = {
        key,
        requests: 0,
        completed: 0,
        reused: 0,
        opened: 0,
        inFlight: 0,
        peakInFlight: 0,
        last: { dnsMs: null, connectMs: null, tlsMs: null, firstByteMs: null, totalMs: null },
      }
      upstreamStats.set(key, s)
    }
    return s
  }

  /* ------------------------------------------------------------------ 发送 */

  /**
   * 发一个请求。首字节（响应头）到达即 resolve；响应体通过 `response.body` 流出。
   *
   * 「首字节就 resolve」是刻意的：Routing Core 需要在拿到响应头后立刻决定
   * 「这次算成功、可以把客户端请求粘在这条线路上」，而不是等整个 body 下完。
   * 因此 `streamIdleMs` / `totalMs` 的违规只能体现在 **body 流上的错误**，
   * 不可能再改 send() 的决议 —— 这点在 close/重试逻辑里必须知道。
   *
   * @param {TransportRequest} request
   * @param {object} upstream contract 层 Upstream
   * @param {TimeoutPolicy} [timeoutPolicy]
   * @returns {Promise<TransportResponse>}
   */
  function send(request, upstream, timeoutPolicy) {
    // 同步校验/同步建表必须变成 rejection。之所以不写成 `async`：
    // DNS 是异步的，一旦在 async 函数里 `await` 它，函数返回的 promise 就要等
    // 解析结束才交给调用方 —— 而超时/取消是在那之前就决议的，会出现
    // 「调用方拿到一个永不决议的 promise，同时内部 promise 未捕获地 reject」。
    // 所以这里同步返回内部 promise，异步只负责推它。
    try {
      return startSend(request, upstream, timeoutPolicy)
    } catch (err) {
      return Promise.reject(err)
    }
  }

  /**
   * 真正的发送流程。**必须同步返回 promise**（原因见 send()）。
   *
   * @param {TransportRequest} request
   * @param {object} upstream
   * @param {TimeoutPolicy|undefined} timeoutPolicy
   * @returns {Promise<TransportResponse>}
   */
  function startSend(request, upstream, timeoutPolicy) {
    if (closed) throw closedError()

    const spec = normalizeRequest(request)
    const up = requireUpstream(upstream)
    const limits = resolveLimits(defaults, up, timeoutPolicy)
    const key = upstreamKey(up)
    const st = statFor(key)
    const signal = spec.signal

    if (signal && signal.aborted) {
      throw new ClientCancelled('客户端在请求发出前已取消', { phase: 'queue', upstreamId: up.id })
    }

    counters.requests += 1
    st.requests += 1

    const startedAt = now()
    /** @type {{dnsMs:number|null, connectMs:number|null, tlsMs:number|null, firstByteMs:number|null, totalMs:number|null}} */
    const timings = { dnsMs: null, connectMs: null, tlsMs: null, firstByteMs: null, totalMs: null }

    let phase = 'queue'
    let phaseTimer = null
    let idleTimer = null
    let totalTimer = null
    let req = null
    let res = null
    let meter = null
    let bodySource = null
    let pooledAgent = null
    let pooled = false
    let delivered = false
    let rejected = false
    let closedOut = false
    let reused = false
    let secureReady = false
    let flushed = false
    let firstByteStarted = false
    let flushAt = 0
    let connectStartAt = 0

    // 显式标注类型：不写 JSDoc 时 tsc 会把这两个变量推成 `() => void`，
    // 后面 resolvePromise(response) / rejectPromise(err) 都会报「期望 0 个参数」。
    /** @type {(value: any) => void} */
    let resolvePromise = () => {}
    /** @type {(reason?: any) => void} */
    let rejectPromise = () => {}
    const promise = new Promise((resolve, reject) => {
      resolvePromise = resolve
      rejectPromise = reject
    })

    const record = { key, fail: (err) => fail(err) }
    live.add(record)
    if (signal) signal.addEventListener('abort', onAbort, { once: true })

    /* ---------------------------------------------------------- 计时与收尾 */

    function timeoutError(name, limitMs) {
      return new UpstreamTimeout(`上游超时：${name} 段超过 ${limitMs}ms`, {
        phase: name, limitMs, upstreamId: up.id,
      })
    }

    function clearPhaseTimer() {
      if (phaseTimer) { clearTimeout(phaseTimer); phaseTimer = null }
    }

    /**
     * 进入某个阶段：清掉上一段的表，起这一段自己的表。
     * 这就是「六段能分别配置和观测」的实现点 —— 同一时刻只有一段在计时。
     */
    function enterPhase(name, limitMs) {
      phase = name
      clearPhaseTimer()
      if (!(limitMs > 0)) return
      phaseTimer = setTimeout(() => {
        phaseTimer = null
        fail(timeoutError(name, limitMs))
      }, limitMs)
    }

    /** 流空闲计时：每收到一块数据就重置 */
    function touchIdle() {
      if (closedOut) return
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null }
      if (!(limits.streamIdleMs > 0)) return
      idleTimer = setTimeout(() => {
        idleTimer = null
        fail(timeoutError('stream_idle', limits.streamIdleMs))
      }, limits.streamIdleMs)
    }

    /** 整次请求（含响应体）收尾。**只跑一次**：池槽与在途表都靠这个守卫 */
    function finish() {
      if (closedOut) return
      closedOut = true
      clearPhaseTimer()
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null }
      if (totalTimer) { clearTimeout(totalTimer); totalTimer = null }
      if (signal) signal.removeEventListener('abort', onAbort)
      if (pooled && pooledAgent) {
        pooled = false
        // 归还必须幂等：成功、失败、取消、调用方丢弃 body 都会走到这里
        pool.release(pooledAgent)
      }
      st.inFlight = Math.max(0, st.inFlight - 1)
      live.delete(record)
    }

    /**
     * 统一失败入口。
     *
     * 两件事分开做：**已经交给调用方的响应**只能让 body 流报错（send 的 promise
     * 已经决议，改不了），**还没交付的**走 reject。这两条路都要销毁底层资源，
     * 否则排空永远等不到归零。
     */
    function fail(err) {
      if (closedOut) return
      const e = isProxyError(err) ? err : mapError(err, phase, up.id)
      if (meter) { try { meter.destroy(e) } catch { /* ignore */ } }
      if (res && !res.destroyed) { try { res.destroy(e) } catch { /* ignore */ } }
      if (req && !req.destroyed) { try { req.destroy(e) } catch { /* ignore */ } }
      if (bodySource && typeof bodySource.destroy === 'function') {
        try { bodySource.destroy(e) } catch { /* ignore */ }
      }
      // 建连失败说明缓存的地址可能已经失效，下次重新解析
      if (e instanceof ConnectFailure) dnsCache.delete(key)
      if (!delivered && !rejected) {
        rejected = true
        rejectPromise(e)
      }
      if (e instanceof ClientCancelled) counters.cancelled += 1
      else if (e instanceof UpstreamTimeout) counters.timedOut += 1
      else counters.failed += 1
      finish()
    }

    function onAbort() {
      fail(new ClientCancelled('客户端取消了请求', { phase, upstreamId: up.id }))
    }

    function onBodyEnd() {
      if (closedOut) return
      counters.completed += 1
      st.completed += 1
      timings.totalMs = now() - startedAt
      st.last.totalMs = timings.totalMs
      finish()
    }

    /* -------------------------------------------------------------- 解析 */

    async function resolveAddress() {
      const cached = dnsCache.get(key)
      if (dnsCacheTtlMs > 0 && cached && now() - cached.at <= dnsCacheTtlMs) return cached

      enterPhase('dns', limits.dnsMs)
      const t0 = now()
      const value = await raceAbort(
        Promise.resolve().then(() => resolveHost(up.hostname, { signal })),
      )
      timings.dnsMs = now() - t0
      st.last.dnsMs = timings.dnsMs
      if (!value || typeof value.address !== 'string') {
        throw new DnsFailure('解析结果不可用', { phase: 'dns', upstreamId: up.id })
      }
      const entry = { at: now(), address: value.address, family: value.family || family }
      if (dnsCacheTtlMs > 0) dnsCache.set(key, entry)
      return entry
    }

    /**
     * 让一个 promise 与「客户端取消」赛跑。
     * 解析器本身无法被中断（见文件头），这里能保证的是**不再等待**它的结果。
     * @template T
     * @param {Promise<T>} p
     * @returns {Promise<T>}
     */
    function raceAbort(p) {
      if (!signal) return p
      return new Promise((resolve, reject) => {
        let done = false
        const onAbortOnce = () => {
          if (done) return
          done = true
          reject(new ClientCancelled('客户端在 DNS 阶段取消', { phase: 'dns', upstreamId: up.id }))
        }
        signal.addEventListener('abort', onAbortOnce, { once: true })
        p.then(
          (v) => { if (!done) { done = true; signal.removeEventListener('abort', onAbortOnce); resolve(v) } },
          (e) => { if (!done) { done = true; signal.removeEventListener('abort', onAbortOnce); reject(e) } },
        )
      })
    }

    /* ------------------------------------------------------------ 发请求 */

    function agentFor(poolKey) {
      const rec = pool.get(poolKey, () => {
        const agent = new AgentClass({
          keepAlive,
          maxSockets,
          maxFreeSockets,
          // 刻意不设 agent.timeout / options.timeout：超时由本模块六段计时器负责。
          // socket 级残留定时器会在排空（draining）阶段突然触发 ETIMEDOUT，
          // 而那时我们正在等一个正常的慢响应。
          ...tlsOptions,
        })
        agents.set(poolKey, agent)
        return agent
      })
      return rec ? rec.agent : null
    }

    function maybeFirstByte() {
      if (closedOut || firstByteStarted || !flushed || !secureReady) return
      firstByteStarted = true
      flushAt = now()
      enterPhase('first_byte', limits.firstByteMs)
    }

    function startRequest(addr) {
      connectStartAt = now()
      const agent = agentFor(key)
      if (!agent) { fail(new StreamFailure('无法为该上游创建连接池', { phase: 'connect', upstreamId: up.id })); return }
      pooledAgent = agent
      pool.acquire(agent)
      pooled = true
      st.inFlight += 1
      if (st.inFlight > st.peakInFlight) st.peakInFlight = st.inFlight

      const headers = { ...spec.headers }
      if (!hasHeader(headers, 'host')) headers.host = hostHeader(up)

      /** @type {Record<string, unknown>} */
      const opts = {
        // 连接目标是**已解析的地址**：Agent 的 socket 池按 ip:port 归组，
        // 解析结果稳定时复用才稳定（配合 dnsCache 的 TTL）。
        host: addr.address,
        port: up.port,
        method: spec.method,
        path: spec.path,
        headers,
        agent,
      }
      // SNI 与证书校验仍按域名：host 是 IP，但 servername 必须是主机名。
      // IP 字面量不能做 SNI，交给 Node 自然省略。
      if (!net.isIP(up.hostname)) opts.servername = up.hostname

      enterPhase('connect', limits.connectMs)

      try {
        req = https.request(opts)
      } catch (err) {
        // 同步抛错基本是调用方给的 path / header 非法（非法字符、非法头名）。
        // 这类错误必须**原样交回调用方**：走 fail() 会被 mapError 归成上游故障，
        // 让 C3 去惩罚一个完全无辜的上游。这里自己把 promise 决议掉。
        if (!delivered && !rejected) {
          rejected = true
          rejectPromise(err)
        }
        finish()
        return
      }

      req.on('socket', (socket) => {
        // 判复用按 socket 身份，理由见 createTransport 里 seenSockets 的注释
        const fresh = !seenSockets.has(socket)
        if (!fresh) {
          reused = true
          secureReady = true
          counters.reused += 1
          st.reused += 1
          maybeFirstByte()
          return
        }
        counters.opened += 1
        st.opened += 1
        seenSockets.add(socket)
        socket.once('connect', () => {
          if (closedOut) return
          timings.connectMs = now() - connectStartAt
          st.last.connectMs = timings.connectMs
          enterPhase('tls', limits.tlsMs)
        })
        socket.once('secureConnect', () => {
          if (closedOut) return
          if (timings.connectMs !== null) {
            timings.tlsMs = now() - connectStartAt - timings.connectMs
            st.last.tlsMs = timings.tlsMs
          }
          secureReady = true
          maybeFirstByte()
        })
      })

      req.on('finish', () => {
        flushed = true
        maybeFirstByte()
      })

      req.on('response', (upRes) => {
        if (closedOut) { upRes.resume(); return }
        res = upRes
        clearPhaseTimer()
        phase = 'stream'
        // 极端情况下 'finish' 没等到（比如对端在请求体写完前就回了响应），用整体耗时兜底
        timings.firstByteMs = now() - (flushAt || startedAt)
        st.last.firstByteMs = timings.firstByteMs

        upRes.on('error', (err) => { if (!closedOut) fail(err) })
        upRes.on('close', () => {
          if (closedOut) return
          // `complete` 才是「整条消息收全了」的权威判据。
          // 不能拿 res 的 close 当失败信号：正常响应也会 close，只是 complete=true。
          if (!upRes.complete) {
            fail(new StreamFailure('响应传输中断（未收到完整响应体）', {
              phase: 'stream', upstreamId: up.id, reason: 'response_incomplete',
            }))
          }
        })

        const status = upRes.statusCode || 0
        const headless = spec.method === 'HEAD' || status === 204 || status === 304

        if (headless) {
          // 语义上没有 body：把底层读空以释放 socket，但不向调用方伪造一个空流
          upRes.resume()
          upRes.on('end', onBodyEnd)
          delivered = true
          resolvePromise(makeResponse(upRes, null))
          return
        }

        // 用 Transform 而不是直接给 IncomingMessage：
        // ① 空闲计时需要在「有人消费」的路径上逐块重置（写 data 监听会把流切到
        //    flowing，调用方再读就会丢数据）；
        // ② 交给调用方的必须是 Web ReadableStream，两种入口（Forward/Reverse）
        //    共用同一套词汇。
        meter = new Transform({
          transform(chunk, _enc, cb) {
            touchIdle()
            cb(null, chunk)
          },
        })
        // 调用方还没开始读时也可能出错；先挂一个空监听避免 uncaught，
        // toWeb 适配器同样会收到这个错误。
        meter.on('error', () => {})
        meter.on('end', onBodyEnd)
        meter.on('close', () => {
          if (closedOut) return
          // 没有 end 就 close = 调用方把 body 丢了（或 reader.cancel()）
          fail(new ClientCancelled('响应体被调用方丢弃', { phase: 'stream', upstreamId: up.id }))
        })
        upRes.pipe(meter)
        touchIdle()
        delivered = true
        resolvePromise(makeResponse(upRes, Readable.toWeb(meter)))
      })

      req.on('error', (err) => {
        if (closedOut) return
        fail(err)
      })

      // 请求体：Web ReadableStream / Node Readable / 字符串三者都吃。
      // 注意 request 上**不做**压缩与 content-length 推断 —— 那是调用方的事，
      // 传输层擅自改写请求体会让上游签名校验（比如 OpenAI 的 body 校验）失败。
      if (spec.body == null) {
        req.end()
      } else if (typeof spec.body.getReader === 'function') {
        bodySource = Readable.fromWeb(spec.body)
        bodySource.on('error', (err) => {
          if (closedOut) return
          fail(new StreamFailure('请求体读取失败', { phase: 'request_body', upstreamId: up.id, code: String(/** @type {{ code?: unknown }} */ (err)?.code || '') }))
        })
        bodySource.pipe(req)
      } else if (typeof spec.body.pipe === 'function') {
        bodySource = spec.body
        bodySource.on('error', (err) => {
          if (closedOut) return
          fail(new StreamFailure('请求体读取失败', { phase: 'request_body', upstreamId: up.id, code: String(/** @type {{ code?: unknown }} */ (err)?.code || '') }))
        })
        bodySource.pipe(req)
      } else {
        req.end(spec.body)
      }
    }

    function makeResponse(upRes, body) {
      return {
        statusCode: upRes.statusCode || 0,
        statusText: upRes.statusMessage || '',
        headers: { ...upRes.headers },
        body,
        socketReused: reused,
        timings,
        cancel() {
          fail(new ClientCancelled('调用方放弃了响应', { phase: 'stream', upstreamId: up.id }))
        },
      }
    }

    /* ------------------------------------------------------------ 启动 */

    if (limits.totalMs > 0) {
      totalTimer = setTimeout(() => {
        totalTimer = null
        fail(timeoutError('total', limits.totalMs))
      }, limits.totalMs)
    }

    // 解析 → 发请求。这段是唯一异步的入口，失败一律走 fail()，
    // 保证 promise 只有一条决议路径。
    void (async () => {
      try {
        const addr = await resolveAddress()
        if (closedOut) return
        if (signal && signal.aborted) {
          fail(new ClientCancelled('客户端在解析后取消', { phase: 'connect', upstreamId: up.id }))
          return
        }
        startRequest(addr)
      } catch (err) {
        fail(err)
      }
    })()

    return promise
  }

  /* ------------------------------------------------------------------ 停机 */

  /**
   * 停机。三步：拒绝新请求 → 排空（或到点强杀）在途 → 销毁空闲连接。
   * **幂等**：重复调用、并发调用都拿到同一个 promise，且不会抛。
   *
   * @returns {Promise<void>}
   */
  function close() {
    if (closing) return closing
    closed = true
    closing = (async () => {
      // 所有 active 池转 draining：不再分配新请求，但允许已有请求跑完
      pool.drainAll()
      const deadline = now() + drainTimeoutMs
      while (live.size > 0 && now() < deadline) {
        await sleep(10)
      }
      // 排空到点还有残余：逐个终止（这是超时保护，不是默认行为）
      for (const rec of [...live]) {
        rec.fail(new StreamFailure('传输层已关闭，在途请求被终止', {
          phase: 'unknown', reason: 'transport_closed',
        }))
      }
      // 先把已排空的池销毁（关掉空闲 socket），再做一次全量清扫
      pool.reclaim(0)
      pool.destroyAll()
      agents.clear()
      log('transport closed')
    })()
    return closing
  }

  /* ------------------------------------------------------------------ 观测 */

  /**
   * 观测快照。复用率是 `reused / (reused + opened)`：
   * 只有真的拿到了 socket 的请求才进分母，被排队期间就取消的不算。
   *
   * @returns {object}
   */
  function stats() {
    const totalSockets = counters.reused + counters.opened
    return {
      closed: closed || Boolean(closing),
      requests: counters.requests,
      completed: counters.completed,
      failed: counters.failed,
      timedOut: counters.timedOut,
      cancelled: counters.cancelled,
      inFlight: live.size,
      sockets: {
        reused: counters.reused,
        opened: counters.opened,
        reuseRate: totalSockets === 0 ? 0 : counters.reused / totalSockets,
      },
      upstreams: [...upstreamStats.values()].map((s) => ({ ...s, last: { ...s.last } })),
      pool: pool.stats(),
    }
  }

  return { send, close, stats }
}

/* ============================================================================
 * 纯函数与校验
 * ========================================================================== */

/**
 * 上游在池里的键。**按 hostname:port 分池**，不按 IP：
 * 一个上游可能因为 DNS 变化换到另一个地址，但「同一个上游」的连接池应该是同一个，
 * 否则 Routing Core 每次拿到新地址就多一代池，draining 的池永远收不完。
 *
 * @param {{hostname: string, port: number}} upstream
 */
function upstreamKey(upstream) {
  return `${upstream.hostname}:${upstream.port}`
}

/** 默认端口不进 Host 头，保持与直连一致 */
function hostHeader(upstream) {
  const host = net.isIP(upstream.hostname) === 6 ? `[${upstream.hostname}]` : upstream.hostname
  return upstream.port === 443 ? host : `${host}:${upstream.port}`
}

/** @param {Record<string, unknown>} headers */
function hasHeader(headers, name) {
  const lower = name.toLowerCase()
  return Object.keys(headers).some((k) => k.toLowerCase() === lower)
}

/**
 * 归一化六段超时。优先级：调用方 timeoutPolicy > upstream.timeoutMs（只覆盖 total）
 * > Transport 默认值。
 *
 * @param {object} defaults
 * @param {{timeoutMs?: number|null}} upstream
 * @param {TimeoutPolicy|undefined} policy
 * @returns {Record<keyof typeof TIMEOUT_SEGMENTS, number>}
 */
function resolveLimits(defaults, upstream, policy) {
  /** @type {any} */
  const out = {}
  for (const field of Object.keys(TIMEOUT_SEGMENTS)) {
    let value = policy && policy[field] !== undefined ? policy[field] : undefined
    // upstream.timeoutMs 的契约就是「覆盖 Transport 默认超时」，但它只该限制总时长，
    // 不该顺手改小 DNS/建连的预算（否则一个 5s 的上游会把 DNS 压到 5s 以下）。
    if (value === undefined && field === 'totalMs' && upstream.timeoutMs != null) value = upstream.timeoutMs
    if (value === undefined) value = defaults[field]
    out[field] = normalizeLimit(value, field)
  }
  return out
}

/**
 * `null` / `0` = 关闭；正数 = 该段上限。负数与非数字一律在配置期报错。
 *
 * @param {unknown} value
 * @param {string} field
 * @returns {number}
 */
function normalizeLimit(value, field) {
  if (value == null) return 0
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`transport: ${field} 必须是 >= 0 的有限数字或 null，实际 ${JSON.stringify(value)}`)
  }
  return value
}

function positiveInt(value, fallback, field) {
  if (value == null) return fallback
  if (!Number.isInteger(value) || value < 1) {
    throw new TypeError(`transport: ${field} 必须是 >= 1 的整数，实际 ${JSON.stringify(value)}`)
  }
  return value
}

/**
 * @param {TransportRequest} request
 * @returns {{method: string, path: string, headers: Record<string, string|string[]>, body: any, signal: AbortSignal|null}}
 */
function normalizeRequest(request) {
  if (request == null || typeof request !== 'object') {
    throw new TypeError('transport.send: request 必须是对象')
  }
  const method = typeof request.method === 'string' && request.method
    ? request.method.toUpperCase()
    : 'GET'
  const path = typeof request.path === 'string' && request.path ? request.path : '/'
  const headers = request.headers && typeof request.headers === 'object' ? { ...request.headers } : {}
  const body = request.body == null ? null : request.body
  const signal = request.signal == null ? null : request.signal
  if (signal && typeof signal.addEventListener !== 'function') {
    throw new TypeError('transport.send: request.signal 必须是 AbortSignal')
  }
  return { method, path, headers, body, signal }
}

/**
 * 校验上游。只做「传输层能不能发」的检查 —— 白名单、SSRF 是别的模块的事。
 *
 * @param {any} upstream
 */
function requireUpstream(upstream) {
  if (upstream == null || typeof upstream !== 'object') {
    throw new TypeError('transport.send: upstream 必须是对象')
  }
  if (typeof upstream.hostname !== 'string' || upstream.hostname === '') {
    throw new TypeError('transport.send: upstream.hostname 必须是非空字符串')
  }
  if (!Number.isInteger(upstream.port) || upstream.port < 1 || upstream.port > 65535) {
    throw new TypeError('transport.send: upstream.port 必须是 1..65535 的整数')
  }
  if (upstream.protocol != null && upstream.protocol !== 'https') {
    // 与 contract/upstream.mjs 同一条理由：明文 HTTP 会把凭据发在明面上
    throw new TypeError(`transport.send: 只支持 https 上游，实际 ${JSON.stringify(upstream.protocol)}`)
  }
  return upstream
}

/**
 * 把底层错误映射到契约层的 9 个具名类型。
 *
 * 判据顺序有讲究：**先看我们自己造的错误**（超时/取消已经是 ProxyError），
 * 再按错误码判 TLS/DNS/建连，最后才用阶段兜底。反过来会让一个证书错误
 * 因为「阶段是 connect」被误判成可重试的建连失败。
 *
 * @param {unknown} err
 * @param {string} phase
 * @param {string} upstreamId
 * @returns {ProxyError}
 */
function mapError(err, phase, upstreamId) {
  if (isProxyError(err)) return /** @type {ProxyError} */ (err)

  const code = err && typeof err === 'object' ? String(/** @type {any} */ (err).code || '') : ''
  const message = err && typeof err === 'object'
    ? String(/** @type {any} */ (err).message || '上游错误')
    : String(err || '上游错误')
  /** @type {Record<string, unknown>} */
  const details = { phase: phase || 'unknown', upstreamId }
  if (code) details.code = code

  const library = err && typeof err === 'object' ? String(/** @type {any} */ (err).library || '') : ''
  const looksTls = TLS_CODES.has(code) || code.startsWith('ERR_SSL') || library.includes('SSL')

  if (looksTls) return new TlsFailure(`上游 TLS 失败：${message}`, details)
  if (DNS_CODES.has(code) || phase === 'dns') return new DnsFailure(`上游解析失败：${message}`, details)
  if (phase === 'tls') return new TlsFailure(`上游 TLS 失败：${message}`, details)
  if (CONNECT_CODES.has(code) || phase === 'connect') {
    return new ConnectFailure(`上游建连失败：${message}`, details)
  }
  return new StreamFailure(`上游传输中断：${message}`, details)
}

/**
 * 停机后拒绝新请求用的错误。
 *
 * 为什么不复用 9 个契约类型里的任何一个：`ClientCancelled` 的语义是「客户端取消」，
 * 拿它表示「本端已停机」会让日志与指标失真；其余 8 个都指向上游行为。
 * 但 code 又必须是**稳定且可判**的，否则 error-classifier 会把它落到 `unknown`
 * 并因此惩罚上游 —— 停机不是上游的错。所以这里固定为 `transport_closed`，
 * C3 在做重试判定前先看传输层状态即可短路。
 */
function closedError() {
  return new ProxyError('transport_closed', '传输层已关闭，拒绝新请求', { reason: 'transport_closed' })
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
