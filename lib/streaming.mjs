/**
 * streaming.mjs — 流式转发与背压（v0.4.0 / C2）
 *
 * 方案 §5.7 的硬要求只有一句：**请求与响应 Body 全程以流传递，禁止默认缓冲完整内容。**
 * 本模块只负责响应体这一侧（请求体由 transport 直接 pipe 给上游），
 * 交付四件东西：背压转发、清理幂等、SSE 语义保持、响应体终态记账。
 *
 * ## 为什么不用 `ReadableStream.pipeTo()`
 *
 * pipeTo 看着省事，但在三处与本项目的要求错位：
 *
 *   1. **错误归属会丢**：pipeTo 把下游错误统一压成一个 AbortError，丢掉
 *      「客户端断开」和「上游读失败」的区别。C3 的重试决策必须区分
 *      —— 客户端取消永不重试、永不惩罚上游（方案 §5.5）。
 *   2. **拿不到字节数**：日志、metrics、以及 C3 的「已提交多少」都要计数。
 *   3. **没有空闲兜底**：上游 SSE 静默、下游 socket 卡死时 pipeTo 会一直挂着，
 *      没有任何地方能插进「N 毫秒无字节就判定卡死」。
 *
 * 所以这里是手写泵：`read()` 一块 → `await write()` 一块。少了几层魔法，
 * 换来错误分类、字节计数、取消时机全部可见。
 *
 * ## 背压的物理落点（本文件最重要的一段）
 *
 * Web 流没有 `pause()` 这种原语。**背压就是「不调用 read()」**：
 * 上游 ReadableStream 的 `pull` 只在内部队列有需求时才会被调，
 * 我们停在 `await adapter.write()` 上，上游的泵自然也就停了。
 * 对 Node 侧的下游（http.ServerResponse / socket）来说，`write()` 返回 false
 * 表示内核缓冲已满，必须等 `drain` 再读下一块 —— 不等就一定会把上游灌进内存。
 *
 * 反过来说：本模块**不保留任何块**。除了正在写的那一块，内存里没有第二份数据。
 * 「大文件内存有界」的测试就是钉这一条（见 test/integration/streaming.test.js）。
 *
 * ## 取消的方向
 *
 * 两个方向都必须能断：
 *   · 下游断开 → 立刻 `reader.cancel()`（不能等下一块到达才反应，
 *     否则一条 SSE 长连接会在客户端早就走掉之后继续挂着读）
 *   · 调用方放弃（signal / handle.cancel）→ 同样取消上游，`done` 以 `ClientCancelled` 拒绝
 *
 * @module streaming
 */

import { StreamFailure, ClientCancelled, isProxyError } from './contract/errors.mjs'

/* ============================================================================
 * 类型
 * ========================================================================== */

/** @typedef {import('./contract/errors.mjs').ProxyError} ProxyErrorType */

/**
 * Node 侧可写对象（http.ServerResponse、socket、zlib 流…）。
 *
 * 为什么单列一份结构类型而不是 `import('node:stream').Writable`：
 * 生产中下游是 `http.ServerResponse`（OutgoingMessage，不是 Writable 子类），
 * 测试里则是手搓的假对象。按「用得到的那几个方法」描述，三者都能赋值进来。
 *
 * @typedef {object} NodeSinkLike
 * @property {(chunk: Uint8Array) => boolean} write 返回 false = 缓冲已满，等 drain
 * @property {() => void} [end] 正常收尾
 * @property {(err?: Error) => void} [destroy] 异常终止
 * @property {boolean} [destroyed]
 * @property {boolean} [writableEnded]
 * @property {boolean} [writableFinished]
 * @property {(event: string, listener: (...args: any[]) => void) => unknown} [on]
 * @property {(event: string, listener: (...args: any[]) => void) => unknown} [once]
 * @property {(event: string, listener: (...args: any[]) => void) => unknown} [removeListener]
 * @property {() => void} [flush] 中间层（zlib / 代理）才需要，裸 ServerResponse 无需
 */

/** @typedef {WritableStream<Uint8Array>|NodeSinkLike} SinkLike */

/**
 * 头部容器：普通对象（transport 给的是小写键）、Web Headers、Node IncomingHttpHeaders 都算。
 *
 * @typedef {{ get?: (name: string) => string | null | undefined } & Record<string, string | string[] | undefined | null>} HeaderBag
 */

/**
 * 转发选项。
 *
 * @typedef {object} PipeOptions
 * @property {AbortSignal|null} [signal] 下游取消信号（客户端断开、上层超时）
 * @property {boolean} [closeSink] 结束后是否关闭下游，默认 true；SSE 由上层自己收尾时传 false
 * @property {number} [idleTimeoutMs] 连续多少毫秒没有任何字节就判定卡死，0 = 关闭（默认）
 * @property {string} [phase] 出错时写进 details.phase，默认按模式取 pipe / events
 * @property {(chunk: Uint8Array) => void} [onChunk] 每块转发后的观测钩子，**不得**参与数据通路
 */

/**
 * 转发句柄。`bytes` / `chunks` 是活值（随传输增长），`done` 传完才决议。
 *
 * @typedef {object} PipeHandle
 * @property {number} bytes 已成功交给下游的字节数
 * @property {number} chunks 已成功交给下游的块数
 * @property {Promise<{ bytes: number, chunks: number }>} done 全部写完 resolve；任何失败 reject
 * @property {(reason?: unknown) => void} cancel 主动放弃：取消上游读取，done 以 ClientCancelled 拒绝
 */

/**
 * 下游适配器：把 Web WritableStream 与 Node 可写对象抹平成同一套词汇。
 *
 * @typedef {object} SinkAdapter
 * @property {(chunk: Uint8Array) => Promise<void>} write 写入并**等**下游接受（背压）
 * @property {() => Promise<void>} close 正常收尾
 * @property {(err: Error) => Promise<void>} abort 异常收尾（尽力而为，失败不再抛）
 * @property {(err: Error) => void} interrupt 叫醒所有「等待下游」的挂起点（空闲超时 / 外部取消用）
 * @property {(fn: (err: Error) => void) => void} onFailure 订阅「下游自己先坏了」
 * @property {() => void} flush SSE 模式下每块写完调用，用于中间层立即下发
 * @property {() => void} release 解除占用 / 摘监听
 */

/** @typedef {'pending'|'consumed'|'cancelled'|'errored'} BodyStatus */

/**
 * 响应体终态守卫。
 *
 * @typedef {object} BodyGuard
 * @property {BodyStatus} status 活值
 * @property {number} bytes 已读出的字节数（活值）
 * @property {() => Promise<{ bytes: number }>} consumeAll 读到流结束
 * @property {(reason?: unknown) => Promise<void>} cancel 放弃响应体（上层断开时用）
 */

/**
 * 清理汇总。
 *
 * @typedef {object} CleanupReport
 * @property {boolean} ok 所有清理函数都没抛
 * @property {Array<{ index: number, error: Error }>} errors 逐个记，不吞不合并
 */

/**
 * @typedef {object} Cleanup
 * @property {(fn: () => unknown) => void} add 注册一个清理函数
 * @property {() => CleanupReport} run 执行全部清理；重复调用返回首轮报告，不重复执行
 * @property {boolean} isDone 是否已经执行过
 */

/* ============================================================================
 * 小工具
 * ========================================================================== */

/** 把任意值收敛成 Error（清理函数里方便记账） */
function asError(err) {
  return err instanceof Error ? err : new Error(typeof err === 'string' ? err : String(err))
}

/** 取 Node 错误的 code（非字符串一律当没有） */
function errorCodeOf(err) {
  if (!err || typeof err !== 'object') return ''
  const code = /** @type {{ code?: unknown }} */ (err).code
  return typeof code === 'string' ? code : ''
}

/** 是否 thenable（清理函数允许返回 promise） */
function isThenable(value) {
  return Boolean(
    value
    && (typeof value === 'object' || typeof value === 'function')
    && typeof (/** @type {{ then?: unknown }} */ (value)).then === 'function',
  )
}

/** 错误 → 单行描述，用于中文消息。刻意只取 message，不取 stack（stack 带内部路径） */
function messageOf(err) {
  if (err instanceof Error) return err.message || err.name
  return String(err)
}

/**
 * 下游「对端已经走了」类错误码。命中即视为客户端取消 —— 而不是上游故障。
 * 这一条直接决定 C3 会不会因为客户端掉线去惩罚上游。
 */
const DOWNSTREAM_CLOSED_CODES = Object.freeze(new Set([
  'EPIPE',
  'ECONNRESET',
  'ECONNABORTED',
  'ERR_STREAM_DESTROYED',
  'ERR_STREAM_WRITE_AFTER_END',
  'ABORT_ERR',
]))

/* ============================================================================
 * 1. 背压转发
 * ========================================================================== */

/**
 * 把上游响应体流式转给下游，全程不缓冲。
 *
 * 语义要点（每一条都有对应测试）：
 *   · 下游慢 → 上游被暂停（不调用 read()），内存不随上游速度增长
 *   · 下游断开 / 报错 → 立刻取消上游，`done` 以 `ClientCancelled` 拒绝
 *   · 上游读失败 → `StreamFailure`（details.phase = 'upstream'）
 *   · `bytes` 只统计**已经交给下游**的数据，不统计已从上游读出的数据
 *
 * @param {ReadableStream<Uint8Array>} source transport.send() 返回的 Web 流
 * @param {SinkLike} sink 下游可写端（Web WritableStream 或 Node 可写对象）
 * @param {PipeOptions} [options]
 * @returns {PipeHandle}
 */
export function pipeWithBackpressure(source, sink, options) {
  return runPump(source, sink, options, 'pipe')
}

/**
 * 取得上游读端。刻意在运行时也校验形状：
 * `ReadableStream` 与 Node 的 `stream.Readable` 长得很像但 API 完全不同，
 * 混用时最小症状是「body 是空的」，最难查的症状是「读到一半就 done」。
 * 与其让调用方猜，不如在这里给一句明确的中文错误。
 *
 * @param {ReadableStream<Uint8Array>} source
 * @returns {ReadableStreamDefaultReader<Uint8Array>}
 */
function acquireReader(source) {
  const probe = /** @type {{ getReader?: () => ReadableStreamDefaultReader<Uint8Array> }} */ (
    /** @type {unknown} */ (source)
  )
  if (!probe || typeof probe.getReader !== 'function') {
    throw new StreamFailure(
      '上游响应体不是 Web ReadableStream，无法流式转发（Node stream.Readable 需先 Readable.toWeb()）',
      { phase: 'upstream' },
    )
  }
  return probe.getReader()
}

/**
 * 按形状挑下游适配器。
 *
 * @param {SinkLike} sink
 * @returns {SinkAdapter}
 */
function createSinkAdapter(sink) {
  const probe = /** @type {{ getWriter?: unknown, write?: unknown }} */ (/** @type {unknown} */ (sink))
  if (!probe || (typeof probe !== 'object' && typeof probe !== 'function')) {
    throw new StreamFailure('下游不可写：sink 既不是 WritableStream 也不是可写对象', { phase: 'downstream' })
  }
  if (typeof probe.getWriter === 'function') {
    return createWebSinkAdapter(/** @type {WritableStream<Uint8Array>} */ (sink))
  }
  if (typeof probe.write === 'function') {
    return createNodeSinkAdapter(/** @type {NodeSinkLike} */ (sink))
  }
  throw new StreamFailure('下游不可写：缺少 getWriter() 与 write()', { phase: 'downstream' })
}

/**
 * Web WritableStream 适配。
 *
 * `writer.write()` 的决议时机就是背压信号：只在「这块已被下游处理完（或进入队列
 * 且低于高水位）」时 resolve。所以这里不需要任何额外判断，await 它即可。
 *
 * @param {WritableStream<Uint8Array>} sink
 * @returns {SinkAdapter}
 */
function createWebSinkAdapter(sink) {
  const writer = sink.getWriter()
  /** @type {Array<(err: Error) => void>} */
  const failureHandlers = []
  return {
    async write(chunk) {
      await writer.write(chunk)
    },
    async close() {
      await writer.close()
    },
    async abort(err) {
      // 下游已经坏了（客户端断开、队列被 abort），这一步只求尽力，失败不再抛
      try { await writer.abort(err) } catch { /* 已终止 */ }
    },
    interrupt(err) {
      // 中止 WritableStream 会把挂着的 write() 决议成 reject —— 正是我们要的「拔掉等待点」
      void writer.abort(err).catch(() => { /* 已终止 */ })
    },
    onFailure(fn) {
      failureHandlers.push(fn)
    },
    flush() {
      // Web 流没有 flush 概念：write 的决议即「已提交给下游」
    },
    release() {
      try { writer.releaseLock() } catch { /* 已释放 */ }
    },
  }
}

/**
 * Node 可写对象适配。
 *
 * 两件事必须自己做，Node 不会代劳：
 *   1. `write()` 返回 false 时等 `drain` —— 这是背压；
 *   2. 听 `close` / `error` 并**主动**通知泵取消上游 —— 因为下游卡住时，
 *      泵正停在 `reader.read()` 上，没有这些事件就永远醒不过来（SSE 尤其明显）。
 *
 * @param {NodeSinkLike} sink
 * @returns {SinkAdapter}
 */
function createNodeSinkAdapter(sink) {
  /** @type {Array<(err: Error) => void>} */
  const failureHandlers = []
  /** @type {Set<(err: Error|null) => void>} */
  const drainWaiters = new Set()
  /** @type {Error|null} */
  let failure = null
  let finished = false

  const settleDrain = (err) => {
    for (const waiter of drainWaiters) waiter(err)
    drainWaiters.clear()
  }
  const emitFailure = (err) => {
    if (failure) return
    failure = err
    settleDrain(err)
    for (const fn of failureHandlers) {
      try { fn(err) } catch { /* 订阅方自己的问题，不能反过来打断转发 */ }
    }
  }

  const onDrain = () => settleDrain(null)
  const onFinish = () => { finished = true }
  const onError = (err) => { emitFailure(wrapDownstreamError(err)) }
  const onClose = () => {
    // 正常写完也会 trigger close（finish 之后），那不是失败
    if (finished || sink.writableFinished === true) return
    emitFailure(new ClientCancelled('下游在写入完成前关闭（客户端断开）', {
      phase: 'downstream', reason: 'downstream_closed',
    }))
  }

  sink.on?.('drain', onDrain)
  sink.on?.('finish', onFinish)
  sink.on?.('error', onError)
  sink.on?.('close', onClose)

  return {
    async write(chunk) {
      if (failure) throw failure
      if (sink.destroyed === true) {
        throw new ClientCancelled('下游已被销毁，停止转发', { phase: 'downstream', reason: 'downstream_destroyed' })
      }
      if (sink.writableEnded === true) {
        throw new ClientCancelled('下游已结束写入，停止转发', { phase: 'downstream', reason: 'downstream_ended' })
      }
      const accepted = sink.write(chunk) !== false
      if (accepted) return
      // ↓ 背压在这里落地：缓冲满了就停在这个 await 上，不再读上游
      /** @type {Promise<void>} */
      const drained = new Promise((resolve, reject) => {
        if (failure) { reject(failure); return }
        drainWaiters.add((err) => { if (err) reject(err); else resolve() })
      })
      await drained
    },
    async close() {
      if (failure) throw failure
      finished = true
      if (sink.writableEnded === true) return
      // 刻意不等 'finish'：所有块都已通过 drain 确认交付，end() 只是收尾；
      // 等 finish 会把「测试桩没有实现 finish」变成一次挂死。
      try { sink.end?.() } catch (err) { throw wrapDownstreamError(err) }
    },
    async abort(err) {
      try { sink.destroy?.(err instanceof Error ? err : undefined) } catch { /* 已坏 */ }
    },
    interrupt(err) {
      // 泵可能正停在「等 drain」上：只 cancel 上游不足以让它醒过来，
      // 必须把 drain 等待者一起拒绝了，否则空闲超时 / 外部取消会变成死锁。
      if (!failure) failure = err
      settleDrain(err)
    },
    onFailure(fn) {
      failureHandlers.push(fn)
    },
    flush() {
      // 裸 ServerResponse 的 write 本身就立即下发；只有套了 zlib / 代理中间层才需要显式 flush
      try { sink.flush?.() } catch { /* 中间层的 flush 失败由 write/error 路径兜住 */ }
    },
    release() {
      sink.removeListener?.('drain', onDrain)
      sink.removeListener?.('finish', onFinish)
      sink.removeListener?.('error', onError)
      sink.removeListener?.('close', onClose)
      settleDrain(null)
    },
  }
}

/**
 * Node 错误 → 契约错误。
 *
 * 「对端走了」类错误码一律归 `ClientCancelled`：这类断开的责任方是客户端，
 * 若归成 StreamFailure，C3 会去怀疑上游并可能换线重试 —— 毫无意义。
 *
 * @param {unknown} err
 * @returns {ProxyErrorType}
 */
function wrapDownstreamError(err) {
  if (isProxyError(err)) return /** @type {ProxyErrorType} */ (err)
  const code = errorCodeOf(err)
  if (code && DOWNSTREAM_CLOSED_CODES.has(code)) {
    return new ClientCancelled(`下游连接已断开（${code}），停止转发`, {
      phase: 'downstream', reason: 'downstream_closed', code,
    })
  }
  return new StreamFailure(`下游写入出错：${messageOf(err)}`, {
    phase: 'downstream',
    ...(code ? { code } : {}),
  })
}

/**
 * 泵本体。
 *
 * @param {ReadableStream<Uint8Array>} source
 * @param {SinkLike} sink
 * @param {PipeOptions|undefined} options
 * @param {'pipe'|'events'} mode
 * @returns {PipeHandle}
 */
function runPump(source, sink, options, mode) {
  const opts = options ?? {}
  const phase = opts.phase ?? mode
  const idleMs = normalizeIdle(opts.idleTimeoutMs)
  const signal = opts.signal ?? null

  const state = { bytes: 0, chunks: 0, cancelled: false, reason: /** @type {unknown} */ (null) }
  /** @type {ReadableStreamDefaultReader<Uint8Array>|null} */
  let reader = null
  /** @type {SinkAdapter|null} */
  let adapter = null
  /** @type {Error|null} */
  let failure = null
  /** @type {ReturnType<typeof setTimeout>|null} */
  let idleTimer = null

  const stopIdle = () => {
    if (idleTimer) {
      clearTimeout(idleTimer)
      idleTimer = null
    }
  }

  /** 主动放弃时用的错误：把调用方给的 reason 保留下来，方便日志定位是谁取消的 */
  const cancelError = () => {
    const reason = state.reason
    if (isProxyError(reason)) return /** @type {ProxyErrorType} */ (reason)
    return new ClientCancelled('转发被调用方主动放弃，已取消上游读取', {
      phase,
      ...(reason == null ? {} : { reason: String(reason).slice(0, 120) }),
    })
  }

  /**
   * 记下第一个致命错误，并**立刻**掐断上游。
   *
   * 为什么不等到下一块：下游断开时泵正停在 `reader.read()` 上，
   * 一条安静的 SSE 上游可能几十秒都不来数据，那段时间连接就一直白挂着。
   *
   * @param {unknown} err
   */
  const fail = (err) => {
    if (failure) return
    failure = asError(err)
    state.cancelled = true
    stopIdle()
    // 两个方向都要断：
    //   ① 上游不能再读（下一条 read 一律取消）
    //   ② 下游若正卡在「等 drain」，必须被叫醒 —— 否则 cancel 上游也解不开这个 await
    try { adapter?.interrupt(failure) } catch { /* 已坏 */ }
    void reader?.cancel(failure).catch(() => { /* 上游已坏，取消会再抛 */ })
  }

  const onAbort = () => {
    fail(new ClientCancelled('下游已取消（signal），停止转发并取消上游', { phase, reason: 'signal_aborted' }))
  }

  const touchIdle = () => {
    if (!idleMs) return
    stopIdle()
    idleTimer = setTimeout(() => {
      idleTimer = null
      fail(new StreamFailure(`流式转发空闲超时：${idleMs}ms 内没有任何字节流动`, { phase, idleMs }))
    }, idleMs)
    // 兜底定时器不该拖着进程退出（测试与停机都会受影响）
    idleTimer.unref?.()
  }

  const done = (async () => {
    try {
      reader = acquireReader(source)
      adapter = createSinkAdapter(sink)
      adapter.onFailure(fail)

      if (signal) {
        if (signal.aborted) {
          throw new ClientCancelled('转发尚未开始，下游已取消', { phase, reason: 'signal_aborted' })
        }
        signal.addEventListener('abort', onAbort, { once: true })
      }

      for (;;) {
        if (failure) throw failure
        if (state.cancelled) throw cancelError()
        touchIdle()
        const step = await readUpstream(reader)
        if (failure) throw failure
        if (state.cancelled) throw cancelError()
        if (step.done) break
        const chunk = step.value
        if (!(chunk instanceof Uint8Array)) {
          throw new StreamFailure('上游响应体给出了非字节块，无法转发', { phase: 'upstream', got: typeof chunk })
        }
        // 空块直接丢掉：写空块只会让下游多做一次无效唤醒，字节语义不变
        if (chunk.byteLength === 0) continue

        try {
          // ↓ 全文件最关键的一行：这一 await 就是背压本身
          await adapter.write(chunk)
        } catch (err) {
          throw wrapDownstreamError(err)
        }

        state.bytes += chunk.byteLength
        state.chunks += 1
        touchIdle()
        if (opts.onChunk) {
          try { opts.onChunk(chunk) } catch { /* 观测钩子不得影响传输 */ }
        }
        if (mode === 'events') adapter.flush()
      }

      if (opts.closeSink !== false) await adapter.close()
      stopIdle()
      return { bytes: state.bytes, chunks: state.chunks }
    } catch (err) {
      stopIdle()
      const normalized = normalizeStreamError(err, phase)
      // 下游断开 / 上游出错 / 空闲超时 —— 无论哪条，上游都不许再读下去
      try { await reader?.cancel(normalized) } catch { /* 已终止 */ }
      try { await adapter?.abort(normalized) } catch { /* 已终止 */ }
      throw normalized
    } finally {
      stopIdle()
      if (signal) signal.removeEventListener('abort', onAbort)
      try { adapter?.release() } catch { /* 已释放 */ }
      try { reader?.releaseLock() } catch { /* 有未决 read 时会抛，忽略 */ }
    }
  })()

  // 有人拿句柄只为 cancel、不 await done 时，别让 Node 报 unhandledRejection；
  // 原始 promise 仍然会把错误交给真正 await 它的调用方。
  void done.catch(() => {})

  return {
    get bytes() { return state.bytes },
    get chunks() { return state.chunks },
    done,
    cancel(reason) {
      if (state.cancelled) return
      state.cancelled = true
      state.reason = reason ?? null
      stopIdle()
      void reader?.cancel(state.reason ?? undefined).catch(() => { /* 已终止 */ })
    },
  }
}

/**
 * 统一的错误出口：保住契约错误，其它一律包成 StreamFailure。
 *
 * @param {unknown} err
 * @param {string} phase
 * @returns {ProxyErrorType}
 */
function normalizeStreamError(err, phase) {
  if (isProxyError(err)) return /** @type {ProxyErrorType} */ (err)
  return new StreamFailure(`流式转发失败：${messageOf(err)}`, {
    phase,
    ...(errorCodeOf(err) ? { code: errorCodeOf(err) } : {}),
  })
}

/**
 * 读上游一块，并把读取失败归成 `phase: 'upstream'`。
 *
 * 单独包一层是为了让「上游断了」和「下游断了」在 C3 眼里不是同一件事：
 * 上游失败可能值得换线重试，下游失败（客户端走了）永不重试。
 *
 * @param {ReadableStreamDefaultReader<Uint8Array>} reader
 */
async function readUpstream(reader) {
  try {
    return await reader.read()
  } catch (err) {
    if (isProxyError(err)) throw err
    throw new StreamFailure(`上游响应体读取失败：${messageOf(err)}`, {
      phase: 'upstream',
      ...(errorCodeOf(err) ? { code: errorCodeOf(err) } : {}),
    })
  }
}

/** @param {unknown} value @returns {number} */
function normalizeIdle(value) {
  if (value === undefined || value === null || value === 0) return 0
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError('idleTimeoutMs 必须是非负有限数字')
  }
  return value
}

/* ============================================================================
 * 2. SSE 语义保持
 * ========================================================================== */

/**
 * 判断一个响应是不是 SSE。
 *
 * 只看 `content-type` 的主类型，**不看 body**：上游用 `text/event-stream; charset=utf-8`
 * 或大写 `TEXT/EVENT-STREAM` 都合法，按 RFC 7231 媒体类型大小写不敏感。
 *
 * @param {HeaderBag} headers
 * @returns {boolean}
 */
export function isEventStream(headers) {
  const value = readHeader(headers, 'content-type')
  if (!value) return false
  return /^\s*text\/event-stream\s*(;|$)/i.test(value)
}

/**
 * 从各种头部容器里取一个值。
 *
 * 为什么不用 `new Headers(obj)`：普通对象的值可能是数组（Node 的 set-cookie 风格），
 * 也可能只给了一个大小写不同的键（手写测试桩）。这里按三种形状直取，不做转换。
 *
 * @param {HeaderBag} headers
 * @param {string} name
 * @returns {string|null}
 */
function readHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return null
  const getter = /** @type {{ get?: unknown }} */ (headers).get
  if (typeof getter === 'function') {
    const raw = /** @type {(n: string) => unknown} */ (getter).call(headers, name)
    if (typeof raw === 'string') return raw
    if (Array.isArray(raw)) return raw.map(String).join(', ')
    return null
  }
  const bag = /** @type {Record<string, unknown>} */ (headers)
  const wanted = name.toLowerCase()
  // 逐键做大小写不敏感匹配：手写桩常写成 Content-Type，
  // 只查小写键会让一条合法的 SSE 响应被当成普通响应（反之亦然）。
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
 * SSE 转发：与 pipeWithBackpressure 共用同一条泵，只改「提交时机」。
 *
 * 三条硬约束，一条都不能松：
 *   1. **不解析**：不找 `data:`、不拼事件、不看 `[DONE]`。上游的自然分块就是语义的一部分，
 *      解析一次就有可能把「多行 data」或注释行（`: keep-alive`）弄丢。
 *   2. **不重排、不合并**：按 read() 拿到的顺序逐块写，块边界也原样保留。
 *   3. **每块立即提交**：写完一块就 flush，不攒批。SSE 的价值就在「到达即见」，
 *      攒一批等于把实时性换成吞吐，方向反了。
 *
 * 刻意**不**校验 content-type：上游偶尔漏发/写错头，拒收会打断一条本来正常的流；
 * 判断是否 SSE 是调用方的事（`isEventStream`），转发只管字节。
 *
 * @param {ReadableStream<Uint8Array>} source
 * @param {SinkLike} sink
 * @param {PipeOptions} [options]
 * @returns {PipeHandle}
 */
export function streamEvents(source, sink, options) {
  return runPump(source, sink, options, 'events')
}

/* ============================================================================
 * 3. 资源释放的幂等性
 * ========================================================================== */

/**
 * 建一个「一次性清理」容器。
 *
 * Core 里一条路径上会挂好几个资源（上游流、下游流、计时器、监听器），
 * 任何一步出错都要全清。这里回答两个容易写错的问题：
 *
 *   · **重复 run() 不重复执行**：清理函数常常是「destory + 摘监听」，
 *     跑两遍在某些库上会抛，或者把刚重建的资源又关掉。
 *   · **单个清理函数抛错不影响其它**：清理阶段最忌讳「因为第一个抛了，
 *     后面三个再也没执行」—— 那才是真正的泄漏。
 *
 * 额外处理：`add()` 在 `run()` 之后调用时**立刻执行**。语义是
 * 「清理点已经过了，这个资源现在就关掉」，而不是悄悄挂在那儿等下次 run
 * （不会有下次 run，那才是泄漏）。
 *
 * @returns {Cleanup}
 */
export function createCleanup() {
  /** @type {Array<() => unknown>} */
  let tasks = []
  let executed = false
  /** @type {CleanupReport|null} */
  let report = null

  /** 执行一遍，逐个 try/catch 记账 */
  const execute = () => {
    /** @type {Array<{ index: number, error: Error }>} */
    const errors = []
    const pending = tasks
    tasks = []
    for (let i = 0; i < pending.length; i += 1) {
      try {
        const result = pending[i]()
        // 清理函数允许返回 promise：同步抛错立刻记账，异步拒绝对同一份报告补记
        if (isThenable(result)) {
          Promise.resolve(result).catch((err) => { errors.push({ index: i, error: asError(err) }) })
        }
      } catch (err) {
        errors.push({ index: i, error: asError(err) })
      }
    }
    return { ok: errors.length === 0, errors }
  }

  return {
    add(fn) {
      if (typeof fn !== 'function') throw new TypeError('createCleanup().add 需要函数')
      if (!executed) {
        tasks.push(fn)
        return
      }
      // 清理点已过：现在就执行，别再挂着
      try {
        const result = fn()
        if (isThenable(result)) Promise.resolve(result).catch(() => { /* 已结束，无处上报 */ })
      } catch { /* 已结束，无处上报 */ }
    },
    run() {
      if (executed && report) return report
      executed = true
      report = execute()
      return report
    },
    get isDone() { return executed },
  }
}

/* ============================================================================
 * 5. 响应体消费的三种终态
 * ========================================================================== */

/**
 * 包住一个响应体，记账它到底怎么结束的。
 *
 * 为什么 C3 需要这个：重试的前提是「响应还没提交给客户端」。而「响应体读到哪了」
 * 是唯一可靠的判据 —— 只要有一个字节被消费，就不能重放。所以这里把四种状态钉死：
 *
 *   pending   还没人读（唯一可以安全重放的状态）
 *   consumed  读到了流结束（内容已交付，不可重放）
 *   cancelled 被主动放弃（连接已在关闭，不可重放）
 *   errored   读的过程中出错（**未必**可重放：可能已交付部分字节，C3 必须当作不可重放）
 *
 * `body` 为 null（HEAD / 204 / 304）时直接 `consumed`：语义上就是「没有东西可读」，
 * 若停在 pending，C3 会误以为还能重放一个已经完整交付的响应。
 *
 * @param {ReadableStream<Uint8Array>|null|undefined} body
 * @returns {BodyGuard}
 */
export function createBodyGuard(body) {
  const stream = body ?? null
  /** @type {ReadableStreamDefaultReader<Uint8Array>|null} */
  const reader = stream ? acquireGuardReader(stream) : null
  /** @type {BodyStatus} */
  let status = stream ? 'pending' : 'consumed'
  let bytes = 0
  /** @type {Error|null} */
  let stored = null
  /** @type {Promise<{ bytes: number }>|null} */
  let running = null
  let abandoned = false

  const consumeAll = () => {
    if (status === 'cancelled') {
      return Promise.reject(new ClientCancelled('响应体已被取消，不能继续消费', { phase: 'body' }))
    }
    if (status === 'errored') {
      return Promise.reject(stored ?? new StreamFailure('响应体读取失败', { phase: 'body' }))
    }
    if (running) return running
    if (status === 'consumed' || !reader) return Promise.resolve({ bytes })

    running = (async () => {
      try {
        for (;;) {
          const step = await reader.read()
          if (abandoned) {
            throw new ClientCancelled('响应体消费过程中被放弃', { phase: 'body', reason: 'cancelled_midway' })
          }
          if (step.done) break
          if (step.value instanceof Uint8Array) bytes += step.value.byteLength
        }
        // 只有真的读到流结束才算 consumed；被中途取消的走上面的 throw
        if (!abandoned) status = 'consumed'
        return { bytes }
      } catch (err) {
        if (abandoned) {
          status = 'cancelled'
          throw err instanceof Error && isProxyError(err)
            ? /** @type {ProxyErrorType} */ (err)
            : new ClientCancelled('响应体消费过程中被放弃', { phase: 'body', reason: 'cancelled_midway' })
        }
        const normalized = isProxyError(err)
          ? /** @type {ProxyErrorType} */ (err)
          : new StreamFailure(`响应体读取失败：${messageOf(err)}`, {
            phase: 'body',
            ...(errorCodeOf(err) ? { code: errorCodeOf(err) } : {}),
          })
        stored = normalized
        status = 'errored'
        throw normalized
      }
    })()
    return running
  }

  const cancel = async (reason) => {
    if (status === 'cancelled') return
    if (status === 'consumed' || status === 'errored') {
      // 已经结束的流没有可取消的东西；状态保持原样，别把「读到过尾」改写成「放弃」
      return
    }
    abandoned = true
    status = 'cancelled'
    try {
      await reader?.cancel(reason)
    } catch { /* 流已坏或已释放，取消失败不影响终态判定 */ }
  }

  return {
    get status() { return status },
    get bytes() { return bytes },
    consumeAll: () => /** @type {Promise<{ bytes: number }>} */ (consumeAll()),
    cancel,
  }
}

/**
 * 守卫自己的读端获取：与泵同款校验，但消息更贴近「响应体」这个场景。
 *
 * @param {ReadableStream<Uint8Array>} body
 * @returns {ReadableStreamDefaultReader<Uint8Array>}
 */
function acquireGuardReader(body) {
  const probe = /** @type {{ getReader?: () => ReadableStreamDefaultReader<Uint8Array> }} */ (
    /** @type {unknown} */ (body)
  )
  if (!probe || typeof probe.getReader !== 'function') {
    throw new StreamFailure('createBodyGuard 需要 Web ReadableStream 或 null', { phase: 'body' })
  }
  return probe.getReader()
}
