/**
 * reverse-streaming.mjs — Reverse 入口的流式与 SSE 支持（v0.5.0 / E2）
 *
 * 现网踩过的坑（本模块存在的理由）：`drainTimeoutMs` 默认 120s 小于
 * `firstByteTimeoutMs` 180s 时，一次路由切换就会错杀一条还在正常出数据的
 * 长流。根因是**给「会长期沉默/长期出数据的流」套了为普通请求设计的
 * 总时长上限**。所以这里的硬要求只有一句：
 *
 *   SSE 与长连接采用独立的 `streamIdleTimeout`，绝不复用普通请求的
 *   `totalMs` —— 就算调用方显式配了 totalMs，流式路径也不使用它。
 *
 * 三件交付物：
 *   1. `resolveStreamTimeouts()` —— 按响应头决定走流式路径还是普通路径，
 *      并给出两条路径各自的超时值。
 *   2. `createStreamingForwarder()` —— 带「已提交」保护的流式转发器：
 *      第一个字节写给客户端之后，上游再出错只能终止流并记录，绝不重放。
 *   3. `buildRetryInput()` —— 与 C3（retry-policy.decideRetry）之间**唯一**
 *      的接缝：把「响应是否已提交」从严映射到 `responseCommitted` 字段。
 *      映射错了就会在已提交的响应上重放，在客户端侧拼出两份响应体，
 *      这是不可修复的协议损坏，所以判定方向必须是从严（宁可错杀重试机会，
 *      不可漏放一次重放）。
 *
 * ## 为什么 committed 要在「write 成功之后」才置位
 *
 * 「已提交」的物理含义是**客户端已经收到了字节**。write() 返回失败时
 * 字节并没有出去（或已经随连接一起死了），此时重试与否由其它条件决定；
 * 把「尝试写」当成「已提交」会让从未收到任何字节的客户端失去一次
 * 本来安全的重试。所以置位点放在泵的 onChunk 回调里 —— 它只在
 * `await adapter.write(chunk)` 成功之后被调用。
 *
 * ## 取消传播为什么在这里做而不是只依赖调用方
 *
 * E1 的 Adapter 会把 res 'close' 转成 AbortSignal 传下来，但本模块是
 * 独立可用的流式层（E1/G1 接线时组合），不能假设每个调用方都接好了
 * signal。转发器自己再挂一层 res 'close' → pump.cancel，两层同时存在
 * 也无害（cancel 内部幂等）；少接一层就是长连接泄漏。
 *
 * @module reverse-streaming
 */

import {
  ClientCancelled,
  ERROR_CODES,
  StreamFailure,
  UpstreamTimeout,
  isProxyError,
} from './contract/errors.mjs'
import { isRequestContext } from './contract/request-context.mjs'
import { isEventStream, pipeWithBackpressure, streamEvents, createCleanup } from './streaming.mjs'
import { isIdempotentMethod } from './retry-policy.mjs'

/* ============================================================================
 * 类型
 * ========================================================================== */

/** @typedef {import('./contract/errors.mjs').ProxyError} ProxyErrorType */

/**
 * 流式超时策略。与 `transport.mjs` 的 TimeoutPolicy 同形状，
 * 这里只取本模块关心的两段，其余字段忽略。
 *
 * @typedef {object} StreamTimeoutPolicy
 * @property {number|null} [streamIdleMs] 流空闲超时（毫秒）；null/缺省用
 *   `DEFAULT_STREAM_IDLE_MS`；0 = 关闭空闲判定
 * @property {number|null} [totalMs] 普通响应总时长（毫秒）；null/缺省 = 不限
 */

/**
 * 超时策略解析结果。
 *
 * @typedef {object} StreamTimeouts
 * @property {boolean} isStream 是否走流式路径（SSE / 长连接 / 无定长）
 * @property {number|null} streamIdleMs 流空闲超时；非流式路径为 null
 * @property {number|null} totalMs 普通响应总时长；流式路径恒为 null
 */

/**
 * 头部容器：普通对象（键任意大小写）、Web Headers、Node OutgoingHttpHeaders 都算。
 *
 * @typedef {{ get?: (name: string) => string | null | undefined } &
 *   Record<string, string | string[] | undefined | null>} HeaderBag
 */

/**
 * 单次转发选项。
 *
 * @typedef {object} ForwardOptions
 * @property {HeaderBag} [headers] 上游响应头；缺省时读 clientRes.getHeaders()，
 *   都没有则按「未知定长 → 流式」处理（保守方向：不会错杀长流）
 * @property {AbortSignal|null} [signal] 下游取消信号（E1 的客户端断开信号）
 * @property {number|null} [streamIdleMs] 逐次覆盖流空闲超时
 * @property {number|null} [totalMs] 逐次覆盖普通响应总时长
 */

/**
 * 转发结果。**forward 永不 reject**：失败也是结果的一部分，
 * 调用方拿 `{ bytes, committed, error }` 去记账与决策，不用再包一层 try/catch
 * 把「失败」和「取消」混在一起。
 *
 * @typedef {object} ForwardResult
 * @property {number} bytes 已成功交给下游的字节数
 * @property {boolean} committed 是否已向下游提交过至少一个字节（提交后上游
 *   错误只能终止流并记录，不可重放）
 * @property {ProxyErrorType|null} error 失败原因；成功为 null
 */

/**
 * C3 决策的现场状态。三个「已提交」来源必须一起给：
 * 转发器记账（committed / bytes）与调用方事实（headersSent）。
 *
 * @typedef {object} RetryState
 * @property {boolean} [committed] 转发器记录的已提交状态
 * @property {number} [bytes] 已提交字节数（>0 与 committed 等价，双保险）
 * @property {boolean} [headersSent] 响应头是否已发给客户端（发出即已提交：
 *   客户端已经看到状态码，重放会在其侧拼出第二份响应）
 * @property {boolean} [clientCancelled] 调用方额外确认的客户端取消
 * @property {number} [attemptIndex] 当前是第几次尝试（从 1 开始），缺省 1
 * @property {number} [elapsedMs] 已耗时（毫秒），缺省按 ctx.startedAt 计算
 * @property {number} [statusCode] 上游 HTTP 状态码（已收到响应头时才有）
 */

/* ============================================================================
 * 常量与小工具
 * ========================================================================== */

/**
 * 流空闲超时的默认值（毫秒）。
 *
 * 与 `transport.mjs` 的 `DEFAULT_TIMEOUTS.streamIdleMs` 对齐：60s 内一个字节
 * 都不来，对 SSE/LLM 流式接口已经可以判定为卡死；而普通请求不该用它 ——
 * 它只描述「流的沉默容忍度」，不描述「整个请求能活多久」。
 */
export const DEFAULT_STREAM_IDLE_MS = 60_000

/**
 * 除 SSE 外判定为「长连接 / 流」的媒体类型。
 *
 * 刻意只收增量型 JSON（ndjson / stream+json）：它们的语义就是「行数未知、
 * 可能一直来」。普通 `application/json` 不在此列 —— 那是一次性完整文档，
 * 有定长时应该走普通路径。
 */
const STREAM_MEDIA_TYPES = new Set(['application/x-ndjson', 'application/stream+json'])

/**
 * failure.details.phase → C3 的 FailurePhase。
 *
 * 泵与守卫用的 phase 名（upstream / downstream / body / pipe / events）不是
 * C3 认识的阶段名；转发层能看到的失败全部发生在「响应体已经在传输」之后，
 * 所以一律归 `response_body`。这条映射是接缝语义的一半：
 * phase 归错类，C3 的幂等性判断就会跟着错。
 *
 * @type {Record<string, import('./retry-policy.mjs').FailurePhase>}
 */
const FAILURE_PHASE_MAP = Object.freeze({
  // C3 原生阶段名：原样透传
  dns: 'dns',
  connect: 'connect',
  tls: 'tls',
  first_byte: 'first_byte',
  stream_idle: 'stream_idle',
  total: 'total',
  request_body: 'request_body',
  response_body: 'response_body',
  // 泵 / 守卫的 phase 名：全部发生在响应体阶段
  body: 'response_body',
  upstream: 'response_body',
  downstream: 'response_body',
  pipe: 'response_body',
  events: 'response_body',
})

/**
 * 从各种头部容器里读一个字段（大小写不敏感，兼容 get() 形态）。
 *
 * 为什么不用 `new Headers(obj)` 转一道：普通对象的值可能是数组
 * （Node 的 set-cookie 风格）也可能是数字（Node 的 content-length 风格），
 * 转换会引入新的语义分歧；按三种形状直取最诚实。
 *
 * @param {HeaderBag} headers
 * @param {string} name
 * @returns {string|null}
 */
function readHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return null
  const getter = headers.get
  if (typeof getter === 'function') {
    const raw = /** @type {(n: string) => unknown} */ (getter).call(headers, name)
    if (typeof raw === 'string') return raw
    if (Array.isArray(raw)) return raw.map(String).join(', ')
    return null
  }
  const bag = /** @type {Record<string, unknown>} */ (/** @type {unknown} */ (headers))
  const wanted = name.toLowerCase()
  for (const key of Object.keys(bag)) {
    if (key.toLowerCase() !== wanted) continue
    const raw = bag[key]
    if (typeof raw === 'string') return raw
    if (Array.isArray(raw)) return raw.map(String).join(', ')
    if (raw === undefined || raw === null) return null
    return String(raw)
  }
  return null
}

/**
 * 归一一个超时字段。
 *
 * null / undefined / 空串 → fallback；0 → 0（语义是「关闭该判定」）；
 * 其余必须是非负有限数字。字符串数字刻意不收：配置层（config-normalize）
 * 已经负责把配置值收敛成数字，这里再偷偷 `Number()` 会把 `"abc" → NaN`
 * 这类垃圾静默放进来。
 *
 * @param {unknown} value
 * @param {string} name 报错用字段名
 * @param {number|null} fallback
 * @returns {number|null}
 */
function normalizeLimitField(value, name, fallback) {
  if (value === undefined || value === null || value === '') return fallback
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError(
      `reverse-streaming: ${name} 必须是非负有限数字或 null，实际 ${JSON.stringify(value)}`,
    )
  }
  return value
}

/* ============================================================================
 * 1. 超时策略
 * ========================================================================== */

/**
 * 按响应头与策略解析流式超时。
 *
 * 判定规则（从严方向：拿不准就当流）：
 *
 *   · `content-type: text/event-stream`（大小写/参数不敏感）→ 流式；
 *   · `application/x-ndjson` / `application/stream+json` → 流式；
 *   · **没有 content-length（或值不合法）→ 流式**：定长响应才敢用总时长
 *     兜底；长度未知时「普通请求的 totalMs」随时可能错杀一条合法长流，
 *     宁可只按空闲判定。
 *
 * 硬要求落地点：`isStream === true` 时 `totalMs` **恒为 null** ——
 * 即使策略里显式给了值也不返回。调用方拿不到值，就不可能误用。
 *
 * @param {HeaderBag|null} headers 上游响应头（可空，空按流式处理）
 * @param {StreamTimeoutPolicy} [policy]
 * @returns {StreamTimeouts}
 * @throws {TypeError} 策略字段非法
 */
export function resolveStreamTimeouts(headers, policy = {}) {
  if (policy === null || Array.isArray(policy) || typeof policy !== 'object') {
    throw new TypeError('resolveStreamTimeouts: policy 必须是对象')
  }

  const bag = headers ?? {}
  const contentType = readHeader(bag, 'content-type')
  const mediaType = contentType == null
    ? ''
    : contentType.split(';')[0].trim().toLowerCase()
  const declaredStream = isEventStream(bag) || STREAM_MEDIA_TYPES.has(mediaType)

  const lengthRaw = readHeader(bag, 'content-length')
  // content-length 必须是纯数字才算「定长」：`"12, 34"` 这类重复头不是定长，
  // 是上游栈配置出错的信号，按未知长度处理（→ 流式）。
  const lengthKnown = lengthRaw != null && /^\d+$/.test(lengthRaw.trim())
  const isStream = declaredStream || !lengthKnown

  if (isStream) {
    const idle = normalizeLimitField(policy.streamIdleMs, 'policy.streamIdleMs', DEFAULT_STREAM_IDLE_MS)
    // totalMs 对流被忽略（硬要求），但**非法值仍要报错**：配置错误应在解析层
    // 显形，而不是因为「反正不用」被静默吞掉，等普通请求用到时再炸。
    normalizeLimitField(policy.totalMs, 'policy.totalMs', null)
    return { isStream: true, streamIdleMs: idle, totalMs: null }
  }

  const total = normalizeLimitField(policy.totalMs, 'policy.totalMs', null)
  return { isStream: false, streamIdleMs: null, totalMs: total }
}

/* ============================================================================
 * 2. 流式转发（含「已提交」保护）
 * ========================================================================== */

/**
 * 创建流式转发器。
 *
 * 转发器本身无跨请求状态：`committed` / `bytes` 每次调用从零开始，
 * 同一个转发器可以安全地服务并发与顺序的多个请求。会话级的重试记账
 * 属于调用方（E1 Adapter + C3 预算），不在这里。
 *
 * 错误路径的完整行为（每一条都有测试钉住）：
 *
 *   · 上游错误 + 未提交 → 返回 `{ committed:false, error }`，调用方可以重试；
 *   · 上游错误 + 已提交 → **只终止流并记录**：泵会 cancel 上游、destroy 下游，
 *     返回 `{ committed:true, error }`；`buildRetryInput` 会把它映射成
 *     `responseCommitted:true`，`decideRetry` 因此永远拒绝重试；
 *   · 客户端断开 → 取消传播到上游（reader.cancel → 底层连接销毁），
 *     error 为 `ClientCancelled`。
 *
 * @param {object} [options]
 * @param {(msg: string) => void} [options.logger] 记账日志（已提交后被错误终止等）
 * @param {StreamTimeoutPolicy} [options.timeouts] 兜底超时策略；forward 可逐次覆盖
 * @returns {{ forward: (upstreamBody: ReadableStream<Uint8Array>,
 *   clientRes: import('node:http').ServerResponse, fwdOptions?: ForwardOptions)
 *   => Promise<ForwardResult> }}
 * @throws {TypeError} options 形状非法
 */
export function createStreamingForwarder(options = {}) {
  if (options === null || Array.isArray(options) || typeof options !== 'object') {
    throw new TypeError('createStreamingForwarder: 需要对象参数')
  }
  const logger = typeof options.logger === 'function' ? options.logger : () => {}
  const fallbackPolicy = (options.timeouts != null && typeof options.timeouts === 'object')
    ? options.timeouts
    : {}

  /**
   * 执行一次流式转发。
   *
   * @param {ReadableStream<Uint8Array>} upstreamBody 上游响应体（Web 流）
   * @param {import('node:http').ServerResponse} clientRes 下游响应
   *   （响应头由调用方在此之前写出；本模块只负责 body 与监听器清理）
   * @param {ForwardOptions} [fwdOptions]
   * @returns {Promise<ForwardResult>}
   * @throws {TypeError} 参数形状非法
   */
  async function forward(upstreamBody, clientRes, fwdOptions = {}) {
    if (fwdOptions === null || Array.isArray(fwdOptions) || typeof fwdOptions !== 'object') {
      throw new TypeError('forward: 第三个参数必须是对象')
    }

    const fromRes = typeof clientRes.getHeaders === 'function'
      ? /** @type {HeaderBag} */ (/** @type {unknown} */ (clientRes.getHeaders()))
      : {}
    const headerBag = fwdOptions.headers ?? fromRes
    const policy = {
      streamIdleMs: fwdOptions.streamIdleMs !== undefined ? fwdOptions.streamIdleMs : fallbackPolicy.streamIdleMs,
      totalMs: fwdOptions.totalMs !== undefined ? fwdOptions.totalMs : fallbackPolicy.totalMs,
    }
    const timeouts = resolveStreamTimeouts(headerBag, policy)

    const cleanup = createCleanup()
    /** @type {{ committed: boolean, bytes: number }} */
    const state = { committed: false, bytes: 0 }

    /**
     * 泵选项。
     *
     * 流式路径：SSE 用 streamEvents（每块写完立即提交，不攒批），
     * 空闲判定用独立的 streamIdleMs；
     * 普通路径：不用空闲判定（它没有意义），总时长由下面的 totalTimer 兜底。
     */
    const pumpOptions = {
      signal: fwdOptions.signal ?? null,
      idleTimeoutMs: timeouts.isStream ? (timeouts.streamIdleMs ?? 0) : 0,
      onChunk: () => { state.committed = true },
    }
    const pump = timeouts.isStream
      ? streamEvents(upstreamBody, clientRes, pumpOptions)
      : pipeWithBackpressure(upstreamBody, clientRes, pumpOptions)

    /* ---- 客户端断开 → 取消传播到上游（硬要求）----
     * pump.cancel 内部幂等：调用方若已经通过 signal 触发过取消，这里再触发
     * 是无害的；反过来，调用方没接 signal 时这一层就是唯一的取消通道。 */
    const onClose = () => {
      if (!clientRes.writableEnded) {
        pump.cancel(new ClientCancelled('客户端断开连接，取消上游响应体', {
          phase: 'downstream',
          reason: 'client_disconnected',
        }))
      }
    }
    clientRes.on('close', onClose)
    cleanup.add(() => clientRes.removeListener('close', onClose))

    if (fwdOptions.signal) {
      const signal = fwdOptions.signal
      const onAbort = () => {
        pump.cancel(new ClientCancelled('下游取消信号已触发，取消上游响应体', {
          phase: 'downstream',
          reason: 'signal_aborted',
        }))
      }
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
      cleanup.add(() => signal.removeEventListener('abort', onAbort))
    }

    /* ---- 普通响应的总时长兜底 ----
     * 只对非流式路径生效：流式路径按硬要求不设 total（resolveStreamTimeouts
     * 对流恒返回 totalMs=null，这里拿不到值）。cancel 传入 UpstreamTimeout
     * 作为 reason，泵会把「调用方给的 ProxyError 原样透传」，C3 拿到的
     * 就是带 phase:'total' 的可分类错误而不是一个泛化取消。 */
    let totalTimer = null
    if (!timeouts.isStream && timeouts.totalMs != null && timeouts.totalMs > 0) {
      totalTimer = setTimeout(() => {
        totalTimer = null
        pump.cancel(new UpstreamTimeout(
          `响应总时长超过 ${timeouts.totalMs}ms，终止转发`,
          { phase: 'total', totalMs: timeouts.totalMs },
        ))
      }, timeouts.totalMs)
      // 兜底定时器不许拖着进程退出（测试与停机都会受影响）
      totalTimer.unref?.()
    }

    try {
      const done = await pump.done
      state.bytes = done.bytes
      if (state.bytes > 0) state.committed = true
      return { bytes: state.bytes, committed: state.committed, error: null }
    } catch (err) {
      // 契约错误原样保留（C3 靠 code 分类）；其它一律包成 StreamFailure，
      // 绝不让一个裸 Error 混进重试决策。
      const normalized = isProxyError(err)
        ? /** @type {ProxyErrorType} */ (err)
        : new StreamFailure(
          `流式转发失败：${err instanceof Error ? err.message : String(err)}`,
          { phase: 'response_body' },
        )
      state.bytes = pump.bytes
      if (state.bytes > 0) state.committed = true
      if (state.committed) {
        // 硬要求：已提交之后上游出错 —— 终止已由泵完成（cancel 上游 +
        // destroy 下游），这里只剩记录。日志里点名「不重试」，
        // 防止后来者看到 error 就顺手接上重试逻辑。
        logger(`[reverse-stream] 响应已提交（${state.bytes}B）后被上游错误终止`
          + `（code=${normalized.code}），仅记录不重试`)
      }
      return { bytes: state.bytes, committed: state.committed, error: normalized }
    } finally {
      if (totalTimer) clearTimeout(totalTimer)
      // createCleanup 自身幂等：重复 run 返回首轮报告；单条清理抛错不影响其余
      cleanup.run()
    }
  }

  return { forward }
}

/* ============================================================================
 * 3. 与 C3 的接缝
 * ========================================================================== */

/**
 * 把失败现场映射成 `decideRetry` 的输入。
 *
 * 这是 E2 与 C3 之间**唯一**的接缝。映射方向全部从严：
 *
 *   · responseCommitted = committed ‖ bytes>0 ‖ headersSent —— 三个来源
 *     命中任何一个就判「已提交」。宁可让一个本可重试的失败被拒，
 *     不可在已提交的响应上重放；
 *   · clientCancelled = 错误是 ClientCancelled ‖ signal 已中止 ‖ 调用方标记；
 *   · failurePhase 按 details.phase 查表，查不到归 `response_body` ——
 *     转发层能看到的失败都在响应体阶段，归 `dns`/`connect` 会给非幂等
 *     请求发放「重试通行证」。
 *
 * @param {import('./contract/request-context.mjs').RequestContext} ctx 请求上下文
 * @param {ProxyErrorType|null} [failure] 失败原因（forward 结果里的 error）
 * @param {RetryState} [state] 现场状态（forward 结果 + 调用方事实）
 * @returns {import('./retry-policy.mjs').RetryDecisionInput}
 * @throws {TypeError} ctx / state 形状非法
 */
export function buildRetryInput(ctx, failure, state = {}) {
  if (!isRequestContext(ctx)) {
    throw new TypeError('buildRetryInput: ctx 必须是 makeRequestContext 产出的 RequestContext')
  }
  if (state === null || Array.isArray(state) || typeof state !== 'object') {
    throw new TypeError('buildRetryInput: state 必须是对象')
  }

  const err = failure ?? null
  const rawCode = err != null && typeof err.code === 'string' ? err.code : ''
  // 非契约错误一律按 stream_failure 归类：decideRetry 会校验 code，
  // 传未知字符串会让决策层直接抛错，把「分类问题」升级成「崩溃」。
  const errorCode = ERROR_CODES.includes(rawCode) ? rawCode : 'stream_failure'

  const detailsPhase = err != null && err.details != null
    && typeof err.details.phase === 'string' ? err.details.phase : ''
  const failurePhase = FAILURE_PHASE_MAP[detailsPhase] ?? 'response_body'

  const responseCommitted = state.committed === true
    || (typeof state.bytes === 'number' && state.bytes > 0)
    || state.headersSent === true

  const clientCancelled = (err != null && err.code === 'client_cancelled')
    || ctx.signal.aborted === true
    || state.clientCancelled === true

  const attemptIndex = typeof state.attemptIndex === 'number'
    && Number.isInteger(state.attemptIndex) && state.attemptIndex >= 1
    ? state.attemptIndex
    : 1
  const elapsedMs = typeof state.elapsedMs === 'number'
    && Number.isFinite(state.elapsedMs) && state.elapsedMs >= 0
    ? state.elapsedMs
    : Math.max(0, Date.now() - ctx.startedAt)

  /** @type {import('./retry-policy.mjs').RetryDecisionInput} */
  const input = {
    method: ctx.method,
    errorCode,
    failurePhase,
    // 请求体为 null（GET 等）才可重放；有体的请求在本层视角一律不可重放
    // —— 它是流式发出的，读出来就没有了。
    bodyReplayable: ctx.body == null,
    idempotent: isIdempotentMethod(ctx.method),
    responseCommitted,
    clientCancelled,
    attemptIndex,
    elapsedMs,
  }
  if (typeof state.statusCode === 'number' && Number.isInteger(state.statusCode)
    && state.statusCode >= 100 && state.statusCode <= 599) {
    input.statusCode = state.statusCode
  }
  return input
}
