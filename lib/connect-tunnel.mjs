/**
 * connect-tunnel.mjs — HTTPS CONNECT 隧道（v0.4.0 / D2）
 *
 * CONNECT 的 target 是 authority-form（`host:port`）。TLS 还没解开，
 * **路径、query、加密后的状态码一概看不到** —— 所以本模块只做两件事：
 * 把「这个 host:port 允不允许连」审清楚，然后把自己降级成一根盲管。
 *
 * ## 管线的顺序为什么不能换
 *
 *   解析(400) → 认证(407) → 目标验证(403) → 上游连接(502/504) → 200
 *
 * 每一步都必须在下一步**之前**完成，尤其是「先连接、后 200」：
 * 一旦把 `200 Connection Established` 写给客户端，客户端立刻开始往里灌
 * TLS ClientHello —— 此时再发现目标连不上，除了粗暴断开没有任何补救，
 * 客户端看到的是「TLS 握手莫名失败」，排查方向会被带偏。所以上游 socket
 * 建立成功之前，客户端一个确认字节都收不到。
 *
 * ## 与 streaming.mjs（C2）刻意不同的地方
 *
 * C2 的泵读的是 Web ReadableStream、写的是 ServerResponse；隧道的两端
 * 都是裸 socket，还要各自支持半关闭（一端 FIN 之后另一端的数据继续送达）。
 * pipeWithBackpressure 的收尾语义是「双向全关」，会提前掐断半关闭的
 * 下行方向 —— 所以这里手写泵，只保留它最核心的思想：
 * **write() 返回 false 就 pause()，drain 了再 resume()**。
 *
 * ## 隐私边界（测试钉死的一条）
 *
 * 隧道内容是别人的加密流量，代理既读不懂也不该留痕。本模块的所有日志
 * 只含 host / port / 耗时 / 字节数 / 关闭原因，**任何 chunk 都不落日志**。
 *
 * ## 认证失败为什么回 407 而不是 401（D1 用的是 401）
 *
 * RFC 9110 把 401 定义为「源服务器要求认证」，407 定义为「代理要求认证」。
 * CONNECT 的响应由代理自己发出、没有可携带错误体的 JSON 响应，
 * 客户端（浏览器/curl）只有在看到 407 时才会触发「代理凭据」提示。
 * 403 留给目标策略否决，两个语义不混用。
 *
 * @module connect-tunnel
 */

import net from 'node:net'

import { authenticateClient } from './client-auth.mjs'
import { parseAuthorityTarget, validateAuthority } from './target-validator.mjs'
import { ConnectFailure, UpstreamTimeout, isProxyError } from './contract/errors.mjs'

/* ============================================================
 * 类型
 * ============================================================ */

/** @typedef {import('node:http').IncomingMessage} NodeIncomingMessage */
/** @typedef {import('node:net').Socket} NodeSocket */
/** @typedef {import('./contract/errors.mjs').ProxyError} ProxyErrorType */
/** @typedef {import('./client-auth.mjs').ClientCollection} ClientCollection */
/** @typedef {import('./client-auth.mjs').ClientIdentity} ClientIdentity */
/** @typedef {import('./target-validator.mjs').ValidatorOptions} ValidatorOptions */
/** @typedef {import('./target-validator.mjs').ValidatedAuthority} ValidatedAuthority */

/**
 * 日志钩子。与 forward-proxy 同一约定：按方法名取用，缺失级别自动静默。
 *
 * @typedef {object} LoggerLike
 * @property {(msg: string) => void} [debug]
 * @property {(msg: string) => void} [info]
 * @property {(msg: string) => void} [warn]
 * @property {(msg: string) => void} [error]
 */

/**
 * 目标验证函数。默认 validateAuthority；CONNECT 只能拿到 host + port，
 * **不允许**换成 validateTargetUrl（那需要编造 URL，等于假装看过路径）。
 *
 * @callback AuthorityValidatorFn
 * @param {string} host
 * @param {number|string|null} port
 * @param {ValidatorOptions} [options]
 * @returns {Promise<ValidatedAuthority>}
 * @throws {import('./contract/errors.mjs').TargetDenied} 目标被拒
 */

/**
 * 客户端认证函数。默认 authenticateClient，第一参收整个 headers 对象
 * （它自己读 authorization）。
 *
 * @callback AuthFn
 * @param {Record<string, unknown>} headers
 * @param {ClientCollection} [clients]
 * @returns {ClientIdentity | Promise<ClientIdentity>}
 * @throws {Error} 约定：抛错即拒绝（Adapter 统一回 407）
 */

/**
 * @typedef {object} ConnectTunnelOptions
 * @property {AuthFn} [auth] 认证函数，默认 authenticateClient
 * @property {ClientCollection} [clients] 客户端集合
 * @property {AuthorityValidatorFn} [targetValidator] 目标验证，默认 validateAuthority
 * @property {ValidatorOptions} [validatorOptions] 透传给 targetValidator 的选项
 * @property {LoggerLike} [logger]
 * @property {number} [connectTimeoutMs] 上游 TCP 建连超时，默认 10000；到期回 504
 * @property {number} [idleTimeoutMs] 建立后无任何字节的空闲超时；0 = 关闭（默认）
 */

/**
 * 单条已完成隧道的记账。不含任何内容字节，只有计量。
 *
 * @typedef {object} TunnelRecord
 * @property {string} host
 * @property {number} port
 * @property {number} connectMs 上游建连耗时
 * @property {number} durationMs 从收到 CONNECT 到双向关闭的持续时间
 * @property {number} bytesUp 客户端 → 上游字节数（含 head）
 * @property {number} bytesDown 上游 → 客户端字节数
 * @property {string} closeReason 关闭原因（稳定英文标识）
 */

/**
 * @typedef {object} ConnectTunnelStats
 * @property {number} total 收到的 CONNECT 总数
 * @property {number} established 建立成功的隧道数（累计）
 * @property {number} rejected Adapter 层否决（400/403/407/503）数
 * @property {number} failed 上游连接失败 / 内部错误（502/504/500）数
 * @property {number} active 正在进行的隧道数
 * @property {number} bytesUp 已结束隧道的上行字节合计
 * @property {number} bytesDown 已结束隧道的下行字节合计
 * @property {number} connectMsTotal 已建立隧道的建连耗时合计
 * @property {TunnelRecord[]} records 最近完成的隧道记录（上限 64，新的在后）
 */

/**
 * @typedef {object} ConnectTunnel
 * @property {(req: NodeIncomingMessage, clientSocket: NodeSocket, head?: Buffer) => Promise<void>} handle
 *   挂到 `server.on('connect', tunnel.handle)`
 * @property {() => ConnectTunnelStats} stats
 * @property {() => Promise<void>} close 幂等；关闭后新 CONNECT 一律 503
 */

/* ============================================================
 * 常量与小工具
 * ============================================================ */

/**
 * ProxyError code → CONNECT 响应状态码。与 forward-proxy 同表不同用途：
 * CONNECT 的响应是手写状态行，不能带体。未知 code 一律 502 ——
 * 从客户端视角「代理没法建立这条隧道」，比暴露内部细节的 500 更诚实。
 */
const STATUS_BY_CODE = Object.freeze({
  target_denied: 403,
  client_unauthorized: 407,
  dns_failure: 502,
  connect_failure: 502,
  tls_failure: 502,
  stream_failure: 502,
  retry_not_allowed: 502,
  upstream_timeout: 504,
})

/** 手写状态行用（非 ProxyError 场景的固定文本） */
const STATUS_TEXT = Object.freeze({
  400: 'Bad Request',
  403: 'Forbidden',
  407: 'Proxy Authentication Required',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
})

/**
 * 关闭原因的稳定标识。日志与 records 里只出现这些词，便于聚合统计。
 * 取值规则：先到先得（第一个非 unknown 的原因留下），
 * 但 abort 类（closed_by_adapter / idle_timeout）是外部权威指令，允许覆盖。
 */
const ABORT_REASONS = Object.freeze(new Set(['closed_by_adapter', 'idle_timeout']))

/**
 * 取 ProxyError 的 code。isProxyError 是跨实例安全的判断，按它的结果取。
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
 * 取 details.reason（TargetDenied / ClientUnauthorized 的稳定拒绝原因）。
 *
 * @param {unknown} err
 * @returns {string}
 */
function reasonOf(err) {
  if (!isProxyError(err)) return ''
  const details = /** @type {{ details?: { reason?: unknown } }} */ (err).details
  return details && typeof details.reason === 'string' ? details.reason : ''
}

/* ============================================================
 * 1. authority-form 解析
 * ============================================================ */

/**
 * 解析 CONNECT 的 authority-form target（`host:port`）。
 *
 * 底层用 target-validator 的 parseAuthorityTarget：它**先找 `]` 再认端口**，
 * 不会把 `[::1]:443` 按冒号切碎。CONNECT 的 target 必须带端口
 * （浏览器与 RFC 惯例一致），所以 defaultPort 传 null：没有端口即 missing_port。
 *
 * 失败抛 TypeError（带 `reason` 稳定标识），与 forward-proxy 的
 * parseForwardRequest 同一模式：畸形请求不是运行时故障，不该占用
 * ProxyError 的语义。
 *
 * @param {unknown} rawTarget req.url 原文（CONNECT 场景即 authority-form）
 * @returns {{ host: string, port: number }}
 * @throws {TypeError & { forwardReject: true, reason: string }} 语法畸形
 */
export function parseConnectTarget(rawTarget) {
  const parsed = parseAuthorityTarget(rawTarget, null)
  if (parsed.ok) {
    // 端口缺省时 parseAuthorityTarget 原样透传 defaultPort（null），
    // 对 CONNECT 来说就是「没写端口」，按畸形处理而不是替客户端猜 443。
    if (parsed.port == null) {
      throw rejectParse('missing_port', `CONNECT target 缺少端口（missing_port）`)
    }
    return { host: parsed.host, port: parsed.port }
  }
  throw rejectParse(parsed.reason, `CONNECT target 无法解析：${parsed.reason}`)
}

/**
 * 构造协议层拒绝异常。
 *
 * @param {string} reason 稳定机器可读原因
 * @param {string} message 人类可读描述
 * @returns {TypeError & { forwardReject: true, reason: string }}
 */
function rejectParse(reason, message) {
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

/* ============================================================
 * 2. Adapter
 * ============================================================ */

/**
 * 构造 CONNECT 隧道 Adapter。
 *
 * @param {ConnectTunnelOptions} [options]
 * @returns {ConnectTunnel}
 * @throws {TypeError} auth / targetValidator 不是函数，或超时参数不合法
 */
export function createConnectTunnel(options = {}) {
  if (options == null || typeof options !== 'object') {
    throw new TypeError('createConnectTunnel: 需要对象参数')
  }

  const auth = options.auth === undefined ? authenticateClient : options.auth
  const targetValidator = options.targetValidator === undefined
    ? validateAuthority
    : options.targetValidator
  if (typeof auth !== 'function') throw new TypeError('createConnectTunnel: auth 必须是函数')
  if (typeof targetValidator !== 'function') {
    throw new TypeError('createConnectTunnel: targetValidator 必须是函数')
  }

  const clients = options.clients ?? null
  const validatorOptions = options.validatorOptions ?? {}
  const logger = options.logger ?? null

  const connectTimeoutMs = options.connectTimeoutMs === undefined ? 10_000 : options.connectTimeoutMs
  if (typeof connectTimeoutMs !== 'number' || !Number.isFinite(connectTimeoutMs) || connectTimeoutMs <= 0) {
    throw new TypeError('createConnectTunnel: connectTimeoutMs 必须是正数')
  }
  const idleTimeoutMs = options.idleTimeoutMs ?? 0
  if (typeof idleTimeoutMs !== 'number' || !Number.isFinite(idleTimeoutMs) || idleTimeoutMs < 0) {
    throw new TypeError('createConnectTunnel: idleTimeoutMs 必须是非负数')
  }

  /** 单条记录上限。records 是计量历史不是审计流水，只留最近的可排障样本。 */
  const RECORD_LIMIT = 64

  /** @type {{ total: number, established: number, rejected: number, failed: number, active: number, bytesUp: number, bytesDown: number, connectMsTotal: number, records: TunnelRecord[] }} */
  const state = {
    total: 0,
    established: 0,
    rejected: 0,
    failed: 0,
    active: 0,
    bytesUp: 0,
    bytesDown: 0,
    connectMsTotal: 0,
    records: [],
  }

  /** @type {Set<Session>} */
  const activeSessions = new Set()
  let closedFlag = false
  /** @type {Promise<void>|null} */
  let closePromise = null

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
        /* 日志自身的问题不能打断隧道 */
      }
    }
  }

  /**
   * 单条 CONNECT 尝试的全部状态。独立成对象是为了 close() 能精确清场，
   * 也避免散落的闭包变量在多阶段之间被误用。
   */
  class Session {
    constructor() {
      this.host = ''
      this.port = 0
      this.startedAt = Date.now()
      this.connectMs = 0
      this.bytesUp = 0
      this.bytesDown = 0
      this.closeReason = 'unknown'
      this.responded = false
      this.established = false
      this.finalized = false
      /** @type {NodeSocket|null} */
      this.clientSocket = null
      /** @type {NodeSocket|null} */
      this.upstream = null
      this.clientClosed = false
      this.upstreamClosed = false
      /** @type {Buffer|undefined} */
      this.head = undefined
      /** @type {(() => void)|null} */
      this.abortHook = null
      /** @type {NodeJS.Timeout|null} */
      this.idleTimer = null
      /** @type {Promise<void>} 收场通知，close() 靠它等清场完成 */
      this.closed = new Promise((resolve) => { this.resolveClosed = resolve })
    }

    /** @type {(value: void) => void} */
    resolveClosed = () => {}

    /** 空闲计时：双向任一来字节都重置。 */
    touchIdle() {
      if (idleTimeoutMs <= 0 || this.finalized) return
      if (this.idleTimer) clearTimeout(this.idleTimer)
      this.idleTimer = setTimeout(() => {
        this.teardown('idle_timeout')
      }, idleTimeoutMs)
      // 不阻塞进程退出：隧道闲着不该是进程存活理由
      if (typeof this.idleTimer.unref === 'function') this.idleTimer.unref()
    }

    stopIdle() {
      if (this.idleTimer) {
        clearTimeout(this.idleTimer)
        this.idleTimer = null
      }
    }

    /**
     * 统一收场：只执行一次。destroy 两个方向的 socket，记账，resolve close()。
     * @param {string} reason
     */
    teardown(reason) {
      this.stopIdle()
      if (ABORT_REASONS.has(reason) || this.closeReason === 'unknown') {
        this.closeReason = reason
      }
      if (!this.finalized) {
        this.finalized = true
        activeSessions.delete(this)
        state.active -= 1
        if (this.established) {
          state.bytesUp += this.bytesUp
          state.bytesDown += this.bytesDown
          const durationMs = Date.now() - this.startedAt
          state.records.push({
            host: this.host,
            port: this.port,
            connectMs: this.connectMs,
            durationMs,
            bytesUp: this.bytesUp,
            bytesDown: this.bytesDown,
            closeReason: this.closeReason,
          })
          if (state.records.length > RECORD_LIMIT) state.records.shift()
          log('info', `connect closed reason=${this.closeReason} host=${this.host} port=${this.port}`
            + ` bytesUp=${this.bytesUp} bytesDown=${this.bytesDown} durationMs=${durationMs}`)
        }
      }
      // destroy 在记账之外无条件做：即使 finalize 早已跑过，
      // abort 路径仍需要能把挂着的 socket 拆掉
      this.destroyUpstream()
      this.resolveClosed()
    }

    destroyUpstream() {
      if (this.upstream) {
        try { this.upstream.destroy() } catch { /* 已关 */ }
      }
    }

    /** 两个方向都关干净了才 finalize；socket destroy 会补发 close 事件。 */
    maybeFinalize() {
      if (this.clientClosed && (this.upstreamClosed || this.upstream === null)) {
        this.teardown(this.closeReason)
      }
    }

    /** 外部权威指令（close()）：拆客户端、给收场一个明确原因。 */
    abort() {
      if (this.clientSocket) {
        try { this.clientSocket.destroy() } catch { /* 已关 */ }
      }
      this.teardown('closed_by_adapter')
    }
  }

  /**
   * 手写 HTTP 状态行。CONNECT 之后 socket 变成裸字节流，不能走
   * res.writeHead（CONNECT 处理器里根本没有 res 对象）。
   *
   * @param {NodeSocket} socket
   * @param {number} statusCode
   */
  /**
   * 写一个拒绝响应，并**主动收尾**对应的 Session。
   *
   * ## 为什么必须主动收尾，而不是等客户端 close
   *
   * 原实现靠 `socket.once('close')` 释放，但客户端的 close 不保证会来 ——
   * 一个保持连接、等着看后续响应的客户端可以永远不发 FIN。那样 Session
   * 会永久留在 `activeSessions` 里，`state.active` 永不递减。反复触发
   * 拒绝（比如反复发非法 target）就能把这个集合撑大。
   *
   * ## 为什么不能写完就 destroy
   *
   * `socket.end()` 只是排入写队列。立刻 `destroy()` 会把还没交给 OS 的
   * 状态行一起丢掉 —— 客户端收到的是连接重置而不是 403/407/502。
   * 必须等 `finish`（D1 踩过同一个坑）。
   *
   * @param {NodeSocket} socket
   * @param {number} statusCode
   * @param {Session} [session] 省略则只写响应不收尾
   * @param {string} [reason] 收尾原因
   */
  function respondRaw(socket, statusCode, session, reason) {
    const finalize = () => {
      if (session) session.teardown(reason ?? 'rejected')
    }
    try {
      if (!socket || socket.destroyed || socket.writableEnded) {
        finalize()
        return
      }
      socket.write(`HTTP/1.1 ${statusCode} ${STATUS_TEXT[statusCode] ?? 'Error'}\r\n\r\n`)
      socket.end()
      // finish = 状态行已交给 OS，此时 destroy 不会丢数据
      if (socket.writableFinished) finalize()
      else socket.once('finish', finalize)
      socket.once('close', () => {
        try { socket.destroy() } catch { /* 已关 */ }
      })
    } catch {
      try { socket.destroy() } catch { /* 已关 */ }
      finalize()
    }
  }

  /**
   * 上游 TCP 连接：把验证阶段钉死的 IP 直接拨号，**不再做第二次解析**
   * （防 DNS rebinding 的 TOCTOU）。失败/超时都以 ProxyError 收场。
   *
   * @param {ValidatedAuthority} validated 验证产物，取 pinned
   * @param {number} port
   * @param {Session} session
   * @returns {Promise<NodeSocket>}
   */
  function connectUpstream(validated, port, session) {
    return new Promise((resolve, reject) => {
      // allowHalfOpen：上游先 FIN 时我们要把剩余数据送回客户端再收尾，
      // 不能让默认的「对端 FIN 就自动 end 自己」抢在前面。
      const socket = net.connect({ host: validated.pinned, port, allowHalfOpen: true })
      session.upstream = socket
      let settled = false
      const timer = setTimeout(() => {
        finish(new UpstreamTimeout(`上游建连超时（${connectTimeoutMs}ms）`, { phase: 'connect' }))
      }, connectTimeoutMs)

      /**
       * @param {ProxyErrorType|null} err
       * @returns {void}
       */
      function finish(err) {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (err) {
          try { socket.destroy() } catch { /* 已关 */ }
          reject(err)
        } else {
          resolve(socket)
        }
      }
      session.abortHook = () => {
        finish(new ConnectFailure('隧道在建立过程中被适配器关闭', { phase: 'connect' }))
      }

      socket.once('connect', () => {
        if (settled) return
        session.connectMs = Date.now() - session.startedAt
        finish(null)
      })
      socket.once('error', (err) => {
        if (settled) return
        const code = err && typeof err === 'object' && 'code' in err
          ? /** @type {{ code: unknown }} */ (err).code
          : ''
        if (code === 'ETIMEDOUT') {
          finish(new UpstreamTimeout('上游建连超时（操作系统层）', { phase: 'connect' }))
        } else {
          finish(new ConnectFailure(`上游连接失败（${typeof code === 'string' ? code : 'unknown'}）`,
            { phase: 'connect' }))
        }
      })
      socket.once('close', () => {
        // 连接建立前就被 abort / destroy：给挂着的 promise 一个出口
        if (!settled) finish(new ConnectFailure('上游连接在建立前被关闭', { phase: 'connect' }))
      })
    })
  }

  /**
   * 实际处理一条 CONNECT。挂在 server.on('connect') 上。
   *
   * @param {NodeIncomingMessage} req
   * @param {NodeSocket} clientSocket
   * @param {Buffer|undefined} head
   * @returns {Promise<void>}
   */
  async function handle(req, clientSocket, head) {
    state.total += 1
    state.active += 1
    const session = new Session()
    session.clientSocket = clientSocket
    session.head = head
    activeSessions.add(session)

    // 半关闭支持要赶在 FIN 之前声明：net 对「对端 FIN」的默认反应是
    // 自动 end 自己的写侧，那会把半关闭测试的下行数据一起掐掉。
    clientSocket.allowHalfOpen = true
    // error 事件没人接会崩进程。先挂兜底：正常路径的错误在专门 handler
    // 里已带原因收场，这里只兜漏网（吞掉，不崩代理）。
    clientSocket.on('error', () => { /* 收场路径已记录 */ })
    clientSocket.on('close', () => {
      session.clientClosed = true
      if (session.upstream && !session.upstreamClosed) {
        session.destroyUpstream()
      }
      session.maybeFinalize()
    })

    try {
      /* ---- 0. 非 CONNECT 方法不应出现在这个入口 ---- */
      if (req.method !== undefined && req.method.toUpperCase() !== 'CONNECT') {
        state.rejected += 1
        session.responded = true
        respondRaw(clientSocket, 400, session, 'rejected_not_connect')
        log('info', 'connect rejected 400 not_connect: connect 入口只接受 CONNECT')
        return
      }

      /* ---- 1. 适配器已关闭（503） ---- */
      if (closedFlag) {
        state.rejected += 1
        session.responded = true
        respondRaw(clientSocket, 503, session, 'rejected_closed')
        log('info', 'connect rejected 503 tunnel_closed: 适配器已关闭')
        return
      }

      /* ---- 2. 解析 authority-form（400） ---- */
      /** @type {{ host: string, port: number }} */
      let target
      try {
        target = parseConnectTarget(req.url)
      } catch (err) {
        if (isParseReject(err)) {
          state.rejected += 1
          session.responded = true
          respondRaw(clientSocket, 400, session, 'rejected_bad_target')
          log('info', `connect rejected 400 ${/** @type {{ reason: string }} */ (err).reason}: ${messageOf(err)}`)
          return
        }
        throw err
      }
      session.host = target.host
      session.port = target.port

      /* ---- 3. 认证（407） ---- */
      /** @type {ClientIdentity} */
      let identity
      try {
        // req.headers 的键已是小写。auth 抛错即拒绝，约定见 AuthFn 的 JSDoc。
        identity = await auth(/** @type {Record<string, unknown>} */ (req.headers ?? {}), clients)
      } catch (err) {
        state.rejected += 1
        session.responded = true
        respondRaw(clientSocket, 407, session, 'rejected_auth')
        log('info', `connect rejected 407 ${codeOf(err) || 'auth_failed'}`
          + ` reason=${reasonOf(err) || 'unspecified'}`)
        return
      }

      /* ---- 4. 目标验证（403） ---- */
      /** @type {ValidatedAuthority} */
      let validated
      try {
        // 刻意传 host + port：CONNECT 看不到路径，URL 级验证在这里是伪校验。
        validated = await targetValidator(target.host, target.port, validatorOptions)
      } catch (err) {
        if (isProxyError(err)) {
          const code = codeOf(err)
          const status = STATUS_BY_CODE[code] ?? 502
          state.rejected += 1
          session.responded = true
          respondRaw(clientSocket, status, session, 'rejected_target')
          log('info', `connect rejected ${status} ${code} reason=${reasonOf(err) || 'unspecified'}`)
          return
        }
        // 验证函数抛出非契约错误 = 调用方 bug，500 明示而不是伪装成网关故障
        state.failed += 1
        session.responded = true
        respondRaw(clientSocket, 500, session, 'validator_threw')
        log('error', `connect validator threw: ${messageOf(err)}`)
        return
      }

      /* ---- 5. 客户端中途消失就不必再连上游 ---- */
      if (clientSocket.destroyed || clientSocket.writableEnded) {
        session.teardown('client_error')
        return
      }

      /* ---- 6. 上游连接（502 / 504）——成功之前一个确认字节都不发 ---- */
      /** @type {NodeSocket} */
      let upstream
      try {
        upstream = await connectUpstream(validated, target.port, session)
      } catch (err) {
        const code = codeOf(err)
        const status = STATUS_BY_CODE[code] ?? 502
        state.failed += 1
        session.responded = true
        // 双保险之一：connectUpstream 在拨号**之前**就把 socket 赋给了
        // session.upstream，失败时 socket 被 destroy 但字段仍指向那个对象，
        // 于是 maybeFinalize 的 `upstreamClosed || upstream === null` 不成立。
        //
        // 主要修复是下面 respondRaw 的主动收尾（它会直接 teardown）。
        // 这里清空是第二道防线：万一将来改动了 respondRaw 的收尾逻辑，
        // 客户端 close 触发的 maybeFinalize 仍能兜住，不会退回泄漏状态。
        session.upstream = null
        if (!clientSocket.destroyed) {
          respondRaw(clientSocket, status, session, 'upstream_connect_failed')
        } else {
          session.teardown('upstream_connect_failed')
        }
        log('warn', `connect upstream ${status} ${code || 'connect_error'}: ${messageOf(err)}`)
        return
      }

      /* ---- 7. 200 Connection Established（手写状态行） ---- */
      try {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      } catch {
        session.teardown('client_error')
        return
      }
      session.responded = true
      session.established = true
      state.established += 1
      state.connectMsTotal += session.connectMs
      log('info', `connect established host=${validated.host} port=${target.port}`
        + ` connectMs=${session.connectMs} client=${identity.clientId}`)

      // head 是客户端在 CONNECT 之后、还没等到 200 就塞进管道的字节
      // （TLS ClientHello 提前到货的常见形态），属于隧道内容，转交上游。
      if (session.head && session.head.length > 0 && !upstream.destroyed) {
        upstream.write(session.head)
        session.bytesUp += session.head.length
      }

      wireTunnel(clientSocket, upstream, session)
    } catch (err) {
      // 管线之外的意外（bug）：不能让一个请求把代理进程带崩
      state.failed += 1
      log('error', `connect internal error: ${messageOf(err)}`)
      if (!session.responded && !clientSocket.destroyed) {
        respondRaw(clientSocket, 500, session, 'unknown')
      }
      session.teardown('unknown')
    }
  }

  /**
   * 建立后的双向字节管道。每个方向独立处理：
   *   data → write（write false 则对向 pause）
   *   drain → 对向 resume
   *   end  → 对向 end（半关闭传播，**不**销毁）
   *   error/close → 双向销毁（RST / 异常收尾）
   *
   * @param {NodeSocket} clientSocket
   * @param {NodeSocket} upstream
   * @param {Session} session
   */
  function wireTunnel(clientSocket, upstream, session) {
    session.touchIdle()

    /**
     * @param {NodeSocket} from 数据来源端
     * @param {NodeSocket} to 数据去向端
     * @param {'up'|'down'} dir up = 客户端→上游；down = 上游→客户端
     */
    function link(from, to, dir) {
      const fromIsClient = dir === 'up'
      from.on('data', (chunk) => {
        session.touchIdle()
        if (to.writableEnded || to.destroyed) return
        if (fromIsClient) session.bytesUp += chunk.length
        else session.bytesDown += chunk.length
        // 背压的物理落点：内核缓冲满 → 暂停读，等 drain 再放行。
        // 不等 drain 就会把整条流量灌进内存。
        if (!to.write(chunk)) from.pause()
      })
      to.on('drain', () => {
        if (!from.destroyed) from.resume()
      })
      // 半关闭：一端 FIN 只关闭「它 → 我们」方向，反方向数据继续走。
      // 传播方式是对向 end()（发 FIN），**不是** destroy()。
      from.on('end', () => {
        if (session.closeReason === 'unknown') {
          session.closeReason = fromIsClient ? 'client_eof' : 'upstream_eof'
        }
        if (!to.writableEnded && !to.destroyed) to.end()
      })
      from.on('error', () => {
        if (session.closeReason === 'unknown') {
          session.closeReason = fromIsClient ? 'client_error' : 'upstream_error'
        }
        // RST 之后对端缓冲不可信，直接拆掉整条隧道
        try { to.destroy() } catch { /* 已关 */ }
        try { from.destroy() } catch { /* 已关 */ }
        session.teardown(session.closeReason)
      })
      from.on('close', () => {
        if (fromIsClient) session.clientClosed = true
        else session.upstreamClosed = true
        // 对端还在就拆：一端彻底关了，隧道没有继续存在的意义
        try { to.destroy() } catch { /* 已关 */ }
        session.maybeFinalize()
      })
    }

    link(clientSocket, upstream, 'up')
    link(upstream, clientSocket, 'down')
  }

  /**
   * 关闭适配器：幂等。正在进行的隧道被立刻拆掉，
   * 返回的 Promise 在全部隧道收场后决议。
   *
   * @returns {Promise<void>}
   */
  function close() {
    if (closePromise) return closePromise
    closedFlag = true
    const waits = []
    for (const session of [...activeSessions]) {
      session.abort()
      waits.push(session.closed)
    }
    closePromise = Promise.all(waits).then(() => undefined)
    return closePromise
  }

  /**
   * @returns {ConnectTunnelStats}
   */
  function stats() {
    return {
      total: state.total,
      established: state.established,
      rejected: state.rejected,
      failed: state.failed,
      active: state.active,
      bytesUp: state.bytesUp,
      bytesDown: state.bytesDown,
      connectMsTotal: state.connectMsTotal,
      records: state.records.slice(),
    }
  }

  return { handle, stats, close }
}
