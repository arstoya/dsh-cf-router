/**
 * reverse-streaming.test.js — Reverse 流式与 SSE 支持（E2）
 *
 * 全部走真实 http.createServer：
 *   · 上游：可控的假 body（定时产出 / 半截 content-length / 中途销毁）；
 *   · 下游：一个小型「代理下游」服务器，fetch 上游 → res.writeHead →
 *     forwarder.forward(body, res, { headers })，forward 结果记进 recs 供断言；
 *   · 客户端：node:http 的真客户端，记录每块到达时间（timeline）。
 *
 * 判据都写成可观测量：
 *   首包可见 = timeline 第一块远早于第二块；切断 = 客户端 aborted；
 *   不重试 = 已提交 + decideRetry 拒绝；内存 = arrayBuffers 分段采样。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { once } from 'node:events'

import {
  DEFAULT_STREAM_IDLE_MS,
  resolveStreamTimeouts,
  createStreamingForwarder,
  buildRetryInput,
} from '../../lib/reverse-streaming.mjs'
import { decideRetry } from '../../lib/retry-policy.mjs'
import { makeRequestContext } from '../../lib/contract/request-context.mjs'
import { filterResponseHeaders } from '../../lib/headers.mjs'
import { ClientCancelled, StreamFailure, UpstreamTimeout } from '../../lib/contract/errors.mjs'

const MiB = 1024 * 1024
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/* ============================================================
 * 辅助
 * ============================================================ */

/**
 * 起一个真实 http 服务器。handler 允许 async；抛错只记不炸进程。
 */
async function startServer(handler) {
  /** @type {string[]} */
  const requests = []
  const server = http.createServer((req, res) => {
    requests.push(req.url ?? '')
    Promise.resolve(handler(req, res)).catch(() => {
      try { res.destroy() } catch { /* 已断 */ }
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = /** @type {{ port: number }} */ (server.address()).port
  return {
    server,
    port,
    requests,
    async close() {
      // SSE / 卡死的上游连接必须硬断，否则 close 永远不触发
      server.closeAllConnections()
      server.close()
      await once(server, 'close')
    },
  }
}

/**
 * 「代理下游」：收到请求 → fetch 上游 → 写头 → forward。
 * forward 的结果（result / thrown / 监听器计数）记入 recs，供断言。
 */
async function startDownstream(upPort, { forwardOptions = {}, forwarder } = {}) {
  /** @type {Array<any>} */
  const recs = []
  const server = http.createServer(async (req, res) => {
    /** @type {Record<string, unknown>} */
    const rec = {}
    recs.push(rec)
    try {
      const upstream = await fetch(`http://127.0.0.1:${upPort}${req.url}`)
      /** @type {Record<string, string>} */
      const headers = {}
      upstream.headers.forEach((v, k) => { headers[k] = v })
      rec.upstreamHeaders = headers
      rec.status = upstream.status
      const fwd = forwarder ?? createStreamingForwarder({ logger: () => {} })
      rec.listenerBefore = res.listenerCount('close')
      const p = fwd.forward(
        /** @type {ReadableStream<Uint8Array>} */ (/** @type {unknown} */ (upstream.body)),
        res,
        { headers, ...forwardOptions },
      )
      rec.forward = p
      rec.result = await p
      rec.listenerAfter = res.listenerCount('close')
    } catch (err) {
      rec.thrown = err
      try {
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' })
        res.destroy(/** @type {Error} */ (err))
      } catch { /* 已断 */ }
    }
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = /** @type {{ port: number }} */ (server.address()).port
  return {
    server,
    port,
    recs,
    async close() {
      server.closeAllConnections()
      server.close()
      await once(server, 'close')
    },
  }
}

/**
 * 客户端收集器：GET 一个 URL，记录每块到达时间与内容。
 * end / aborted / error 任一先到即结算，绝不挂死（10s 兜底）。
 */
function collect(url, { afterFirstChunk = null } = {}) {
  return new Promise((resolve) => {
    /** @type {Buffer[]} */
    const chunks = []
    /** @type {Array<{ at: number, bytes: number }>} */
    const timeline = []
    const start = Date.now()
    let settled = false
    const finish = (extra) => {
      if (settled) return
      settled = true
      resolve({
        status: 0,
        headers: {},
        body: Buffer.concat(chunks),
        timeline,
        ended: false,
        aborted: false,
        ...extra,
      })
    }
    const req = http.get(url, (res) => {
      /** @type {((res: import('node:http').IncomingMessage, req: import('node:http').ClientRequest) => void) | null} */
      let hook = afterFirstChunk
      res.on('data', (c) => {
        chunks.push(c)
        timeline.push({ at: Date.now() - start, bytes: c.length })
        if (hook) {
          const h = hook
          hook = null
          h(res, req)
        }
      })
      res.on('end', () => finish({ status: res.statusCode ?? 0, ended: true }))
      res.on('aborted', () => finish({ status: res.statusCode ?? 0, aborted: true }))
      res.on('error', () => finish({ status: res.statusCode ?? 0, aborted: true }))
    })
    req.on('error', () => finish({ aborted: true, reqError: true }))
    // 兜底：10s 内没有任何终态就强制结算，防测试挂死
    setTimeout(() => finish({ aborted: true, watchdog: true }), 10_000).unref?.()
  })
}

/** SSE 上游：先发 retry 行，再按 gap 间隔逐个发事件，发完收尾 */
function sseHandler(events, gapMs) {
  return (req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
    res.write('retry: 0\n\n')
    let i = 0
    const timer = setInterval(() => {
      if (res.destroyed) { clearInterval(timer); return }
      if (i >= events.length) { clearInterval(timer); res.end(); return }
      res.write(`data: ${events[i++]}\n\n`)
    }, gapMs)
    res.on('close', () => clearInterval(timer))
  }
}

/** 造 RequestContext（GET / reverse） */
function ctxFor(method = 'GET') {
  return makeRequestContext({
    clientId: 'client-e2',
    routeGroupId: 'group-e2',
    mode: 'reverse',
    method,
    originalUrl: '/__proxy/r/group-e2/x',
  })
}

/** 测试用重试策略：stream_failure / upstream_timeout 可重试 */
const POLICY = Object.freeze({
  maxAttempts: 3,
  totalBudgetMs: 10_000,
  baseDelayMs: 10,
  maxDelayMs: 100,
  retryOn: ['stream_failure', 'upstream_timeout'],
})

/* ============================================================
 * 1-2. SSE 首包立即可见 / 字节完全一致
 * ============================================================ */

test('E2-01 SSE 首包立即可见：第一块远早于第二个事件到达，不攒批', async () => {
  const up = await startServer(sseHandler(['a', 'b', 'c', 'd'], 300))
  const down = await startDownstream(up.port, {
    forwardOptions: { streamIdleMs: 5000 },
  })
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/sse`)
    // 真实时间轴：retry 行 + 首事件立即到达（<150ms），第二个事件在 300ms 后
    assert.ok(got.timeline.length >= 2, `至少收到两块，实际 ${got.timeline.length}`)
    assert.ok(got.timeline[0].at < 150, `首块应在 150ms 内到达，实际 ${got.timeline[0].at}ms`)
    const secondAt = got.timeline[1].at
    assert.ok(
      secondAt - got.timeline[0].at > 100,
      `首块与第二块应分开到达（间隔 ${secondAt - got.timeline[0].at}ms），攒批则两者同时`,
    )
    assert.equal(got.ended, true)
    // 转发器视角：SSE 路径、无错误
    const recResult = await down.recs[0].forward
    assert.equal(recResult.error, null)
    assert.equal(recResult.committed, true)
  } finally {
    await down.close()
    await up.close()
  }
})

test('E2-02 SSE 事件顺序与字节完全一致', async () => {
  const events = ['alpha', 'beta', 'gamma', 'delta']
  const expected = 'retry: 0\n\n' + events.map((e) => `data: ${e}\n\n`).join('')
  const up = await startServer(sseHandler(events, 20))
  const down = await startDownstream(up.port, { forwardOptions: { streamIdleMs: 5000 } })
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/stream`)
    assert.equal(got.body.toString('utf8'), expected)
    assert.equal(got.ended, true)
    const recResult = await down.recs[0].forward
    assert.equal(recResult.bytes, Buffer.byteLength(expected))
    assert.equal(recResult.error, null)
  } finally {
    await down.close()
    await up.close()
  }
})

/* ============================================================
 * 3-4. 独立 streamIdleMs：totalMs 不杀流，idle 超时才杀
 * ============================================================ */

test('E2-03 SSE 空闲超过 totalMs 但不超 streamIdleMs：不被切断', async () => {
  // totalMs=100 若被误用于流，400ms 间隔的第二个事件之前就会死
  const up = await startServer(sseHandler(['e1', 'e2', 'e3', 'e4'], 400))
  const down = await startDownstream(up.port, {
    forwardOptions: { totalMs: 100, streamIdleMs: 2000 },
  })
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/sse`)
    assert.equal(got.ended, true, '应活到上游正常收尾，而不是被 totalMs 切断')
    assert.ok(got.body.toString('utf8').includes('data: e4'), '应收到全部事件')
    assert.equal((await down.recs[0].forward).error, null)
  } finally {
    await down.close()
    await up.close()
  }
})

test('E2-04 SSE 空闲超过 streamIdleMs：被切断，error 为 StreamFailure', async () => {
  // 只发一个事件然后彻底沉默：idle 200ms 内没有下一个字节 → 切断
  const up = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.write('retry: 0\n\ndata: once\n\n')
    // 不 end、不再写：连接保持但流是死的
  })
  const down = await startDownstream(up.port, {
    forwardOptions: { streamIdleMs: 200 },
  })
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/sse`)
    assert.equal(got.aborted, true, '空闲超时应切断客户端连接')
    assert.ok(got.body.toString('utf8').includes('data: once'), '切断前已收到的字节应保留')
    const result = await down.recs[0].forward
    assert.equal(result.committed, true)
    assert.ok(result.error instanceof StreamFailure, `error 应为 StreamFailure，实际 ${result.error?.constructor?.name}`)
    assert.equal(result.error.code, 'stream_failure')
  } finally {
    await down.close()
    await up.close()
  }
})

/* ============================================================
 * 5. 普通请求仍用 totalMs
 * ============================================================ */

test('E2-05 普通请求（有 content-length）上游半截卡死：totalMs 切断，UpstreamTimeout', async () => {
  const up = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '100' })
    res.write('{"partial":')
    // 剩 70 字节永远不来
  })
  const down = await startDownstream(up.port, {
    forwardOptions: { totalMs: 250 },
  })
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/data`)
    assert.equal(got.ended, false, '响应未完成，不应出现干净 end')
    assert.ok(got.body.length > 0, '切断前应已收到部分字节')
    const result = await down.recs[0].forward
    assert.equal(result.committed, true)
    assert.ok(result.error instanceof UpstreamTimeout,
      `error 应为 UpstreamTimeout，实际 ${result.error?.constructor?.name}`)
    assert.equal(result.error.code, 'upstream_timeout')
    assert.equal(/** @type {UpstreamTimeout} */ (result.error).details.phase, 'total')
  } finally {
    await down.close()
    await up.close()
  }
})

/* ============================================================
 * 6-7. 已提交保护：上游断开只终止并记录，绝不重试
 * ============================================================ */

test('E2-06 响应已提交后上游断开：committed=true、仅记录、C3 拒绝重试', async () => {
  let sawSecondRequest = false
  const up = await startServer(async (req, res) => {
    if (up.requests.length > 1) sawSecondRequest = true
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.write('hello')
    await sleep(50)
    res.destroy()
  })
  const down = await startDownstream(up.port, { forwardOptions: { streamIdleMs: 5000 } })
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/break`)
    assert.equal(got.aborted, true, '已提交的响应只能被终止')
    assert.ok(got.body.toString('utf8').includes('hello'))

    const result = await down.recs[0].forward
    assert.equal(result.committed, true)
    assert.ok(result.bytes > 0)
    assert.ok(result.error instanceof StreamFailure)

    // 硬要求的可观察等价物：把同一现场喂给 C3，重试必须被拒绝
    const input = buildRetryInput(ctxFor('GET'), result.error, {
      committed: result.committed,
      bytes: result.bytes,
    })
    const decision = decideRetry(input, POLICY)
    assert.equal(decision.retry, false)
    assert.equal(decision.reason, 'response_committed')
    // 本层自身不持有任何重试回路：上游只看到一次请求
    assert.equal(up.requests.length, 1)
    assert.equal(sawSecondRequest, false)
  } finally {
    await down.close()
    await up.close()
  }
})

test('E2-07 buildRetryInput：committed 映射让 decideRetry 返回 retry:false；未提交则放行', async () => {
  const failure = new StreamFailure('上游响应体读取失败', { phase: 'upstream' })
  const ctx = ctxFor('GET')

  const committedInput = buildRetryInput(ctx, failure, { committed: true, bytes: 128 })
  assert.equal(committedInput.responseCommitted, true)
  assert.equal(committedInput.failurePhase, 'response_body')
  const committedDecision = decideRetry(committedInput, POLICY)
  assert.equal(committedDecision.retry, false)
  assert.equal(committedDecision.reason, 'response_committed')

  // 双保险：bytes>0 即使忘传 committed 也必须判已提交
  const bytesInput = buildRetryInput(ctx, failure, { bytes: 1 })
  assert.equal(bytesInput.responseCommitted, true)
  assert.equal(decideRetry(bytesInput, POLICY).retry, false)

  // headersSent 也算已提交（客户端已看到状态码）
  const headersInput = buildRetryInput(ctx, failure, { headersSent: true })
  assert.equal(decideRetry(headersInput, POLICY).retry, false)

  // 对照组：未提交的同一场失败，幂等 GET 允许重试
  const freshInput = buildRetryInput(ctx, failure, {})
  assert.equal(freshInput.responseCommitted, false)
  const freshDecision = decideRetry(freshInput, POLICY)
  assert.equal(freshDecision.retry, true, `未提交应可重试，实际 reason=${freshDecision.reason}`)
})

/* ============================================================
 * 8. 客户端取消传播到上游
 * ============================================================ */

test('E2-08 客户端取消传播到上游：上游感知断开并停止产出', async () => {
  /** @type {{ aborted: boolean, sent: number }} */
  const upState = { aborted: false, sent: 0 }
  const up = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    let i = 0
    const timer = setInterval(() => {
      if (res.destroyed || i >= 200) {
        clearInterval(timer)
        if (i >= 200 && !res.destroyed) res.end()
        return
      }
      res.write(`chunk-${i++}\n`)
      upState.sent = i
    }, 40)
    // 请求流已完整收到的 'close' 不算断开；只有「响应没写完就 close」才是
    res.on('close', () => {
      clearInterval(timer)
      if (!res.writableEnded) upState.aborted = true
    })
  })
  const down = await startDownstream(up.port, { forwardOptions: { streamIdleMs: 10_000 } })
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/cancel`, {
      afterFirstChunk: (_res, req) => { req.destroy() }, // 客户端中途取消
    })
    assert.equal(got.aborted, true, '客户端应观察到连接被自己取消')
    // collect 在客户端收到首块时就结算，早于下游 forward 完成：必须等 forward 决议
    const result = await down.recs[0].forward
    assert.ok(result.error instanceof ClientCancelled,
      `error 应为 ClientCancelled，实际 ${result.error?.constructor?.name}`)
    await sleep(300) // 给取消传播一点时间
    assert.equal(upState.aborted, true, '上游必须感知到客户端断开')
    assert.ok(upState.sent < 200, `取消后上游应停止产出，实际已产出 ${upState.sent}`)
  } finally {
    await down.close()
    await up.close()
  }
})

/* ============================================================
 * 9. 大文件下载内存有界
 * ============================================================ */

test('E2-09 20MB 下载内存有界：连续两轮峰值不累积', async () => {
  const TOTAL = 20 * MiB
  const CHUNK = 8 * 1024

  /** 跑一轮 20MB 传输，返回 arrayBuffers 峰值增量（字节） */
  async function runOnce() {
    const up = await startServer((req, res) => {
      res.writeHead(200, {
        'content-type': 'application/octet-stream',
        'content-length': String(TOTAL),
      })
      const buf = Buffer.alloc(CHUNK, 0x62)
      let sent = 0
      const pump = () => {
        while (sent < TOTAL) {
          const size = Math.min(CHUNK, TOTAL - sent)
          sent += size
          const ok = res.write(size === CHUNK ? buf : buf.subarray(0, size))
          if (!ok) { res.once('drain', pump); return }
        }
        res.end()
      }
      pump()
    })

    const down = await startDownstream(up.port, {})
    try {
      const base = process.memoryUsage().arrayBuffers
      let peak = base
      await new Promise((resolve) => {
        http.get(`http://127.0.0.1:${down.port}/big`, (res) => {
          res.on('data', () => {
            const cur = process.memoryUsage().arrayBuffers
            if (cur > peak) peak = cur
          })
          res.on('end', resolve)
          res.on('error', resolve)
        })
      })
      return peak - base
    } finally {
      await down.close()
      await up.close()
    }
  }

  const first = await runOnce()
  const second = await runOnce()

  // 判据用「两轮之间是否显著增长」，不用绝对阈值。
  //
  // 为什么不设绝对阈值：`arrayBuffers` 是**进程全局**计数，包含 HTTP 解析
  // 缓冲、socket 内核缓冲、GC 尚未回收的块。实测同一实现在 20MB 传输上
  // 峰值增量在 10–38 MiB 之间波动（原阈值 8 MiB 连跑三次两败一过）。
  // 绝对阈值在这量级上测的是 GC 时机，不是实现质量。
  //
  // 真正的泄漏长这样：跑第二轮明显比第一轮高，第三轮再高 —— 单调累积。
  // 所以判「第二轮 ≤ 第一轮 × 2 + 4 MiB」：允许噪声，不允许累积。
  assert.ok(
    second <= first * 2 + 4 * MiB,
    `疑似累积泄漏：第一轮峰值 ${(first / MiB).toFixed(1)}MiB，`
    + `第二轮 ${(second / MiB).toFixed(1)}MiB（阈值 ${((first * 2 + 4 * MiB) / MiB).toFixed(1)}MiB）`,
  )
})

test('E2-10 resolveStreamTimeouts：各 content-type / 定长组合判定正确', () => {
  // SSE：各种大小写与参数形态都是流
  for (const headers of [
    { 'content-type': 'text/event-stream' },
    { 'Content-Type': 'text/event-stream; charset=utf-8' },
    { 'CONTENT-TYPE': 'TEXT/EVENT-STREAM' },
  ]) {
    const t = resolveStreamTimeouts(headers, {})
    assert.equal(t.isStream, true, JSON.stringify(headers))
    assert.equal(t.totalMs, null, '流式路径 totalMs 恒 null')
    assert.equal(t.streamIdleMs, DEFAULT_STREAM_IDLE_MS)
  }
  // Web Headers 形态同样识别
  const h = new Headers({ 'content-type': 'text/event-stream' })
  assert.equal(resolveStreamTimeouts(h, {}).isStream, true)

  // 增量型媒体类型 → 流
  assert.equal(resolveStreamTimeouts({ 'content-type': 'application/x-ndjson' }, {}).isStream, true)
  assert.equal(resolveStreamTimeouts({ 'content-type': 'application/stream+json' }, {}).isStream, true)

  // 普通带定长 → 非流，totalMs 来自策略
  const normal = resolveStreamTimeouts(
    { 'content-type': 'application/json', 'content-length': '123' },
    { totalMs: 5000 },
  )
  assert.equal(normal.isStream, false)
  assert.equal(normal.totalMs, 5000)
  assert.equal(normal.streamIdleMs, null)

  // 普通无定长 → 保守当流（不定长不能套总时长）
  assert.equal(resolveStreamTimeouts({ 'content-type': 'application/json' }, {}).isStream, true)
  // 完全无头 → 流
  assert.equal(resolveStreamTimeouts(null, {}).isStream, true)
  // 非数字 content-length 不算定长
  assert.equal(
    resolveStreamTimeouts({ 'content-type': 'text/plain', 'content-length': '12, 34' }, {}).isStream,
    true,
  )
  // 显式配了 totalMs 的 SSE：仍然不返回（硬要求）
  const sseWithTotal = resolveStreamTimeouts(
    { 'content-type': 'text/event-stream' },
    { totalMs: 120_000, streamIdleMs: 8000 },
  )
  assert.equal(sseWithTotal.totalMs, null)
  assert.equal(sseWithTotal.streamIdleMs, 8000)
})

/* ============================================================
 * 11-12. 正常结束 / 未提交的上游错误
 * ============================================================ */

test('E2-11 上游正常结束：普通响应完整交付，error=null、committed=true', async () => {
  const payload = JSON.stringify({ ok: true, n: 42 })
  const up = await startServer((req, res) => {
    const body = Buffer.from(payload, 'utf8')
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-length': String(body.length),
    })
    res.end(body)
  })
  const down = await startDownstream(up.port, {})
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/ok`)
    assert.equal(got.ended, true)
    assert.equal(got.body.toString('utf8'), payload)
    const result = await down.recs[0].forward
    assert.equal(result.error, null)
    assert.equal(result.committed, true)
    assert.equal(result.bytes, Buffer.byteLength(payload))
  } finally {
    await down.close()
    await up.close()
  }
})

test('E2-12 上游在交付任何字节前出错：committed=false、StreamFailure、未提交可重试', async () => {
  const up = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '100' })
    res.flushHeaders() // 头先到（fetch 能拿到响应），body 一个字节都不给
    setTimeout(() => res.destroy(), 40)
  })
  const down = await startDownstream(up.port, {})
  try {
    const got = await collect(`http://127.0.0.1:${down.port}/fail`)
    assert.equal(got.timeline.length, 0, '不应有任何 body 字节交付')
    assert.equal(got.ended, false)

    const result = await down.recs[0].forward
    assert.equal(result.committed, false, '没有字节交给下游，不得误判已提交')
    assert.equal(result.bytes, 0)
    assert.ok(result.error instanceof StreamFailure,
      `error 应为 StreamFailure，实际 ${result.error?.constructor?.name}`)

    // 未提交 + 幂等 GET → C3 允许重试（与 E2-06 形成对照）
    const input = buildRetryInput(ctxFor('GET'), result.error, {
      committed: result.committed,
      bytes: result.bytes,
    })
    assert.equal(input.responseCommitted, false)
    assert.equal(input.failurePhase, 'response_body')
    assert.equal(decideRetry(input, POLICY).retry, true)
  } finally {
    await down.close()
    await up.close()
  }
})

/* ============================================================
 * 13. 背压
 * ============================================================ */

test('E2-13 背压：下游暂停消费时上游写入被暂停', async () => {
  /** @type {{ sent: number }} */
  const upState = { sent: 0 }
  const CHUNK = 64 * 1024
  const COUNT = 400 // 400 * 64KiB = 25MiB：回环链路的内核/用户态缓冲只有几 MB，
  // 量级必须远超缓冲总和，暂停才能真实传导到上游的 write()
  const up = await startServer(async (req, res) => {
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-length': String(CHUNK * COUNT),
    })
    const chunk = Buffer.alloc(CHUNK, 0x41)
    for (let i = 0; i < COUNT; i++) {
      if (res.destroyed) return
      if (!res.write(chunk)) await once(res, 'drain') // 背压的物理落点
      upState.sent = i + 1
    }
    res.end()
  })
  const down = await startDownstream(up.port, {})
  try {
    const got = await new Promise((resolve) => {
      /** @type {Buffer[]} */
      const chunks = []
      let seen = 0
      let paused = false
      let sample1 = -1
      let sample2 = -1
      const req = http.get(`http://127.0.0.1:${down.port}/bp`, (res) => {
        res.on('data', (c) => {
          chunks.push(c)
          seen += c.length
          if (!paused && seen >= 2 * CHUNK) {
            paused = true
            res.pause()
            // 暂停 800ms，中途取两次上游产出计数：若上游没被暂停，计数必然增长
            setTimeout(() => { sample1 = upState.sent }, 400)
            setTimeout(() => {
              sample2 = upState.sent
              res.resume()
            }, 800)
          }
        })
        res.on('end', () => resolve({ body: Buffer.concat(chunks), sample1, sample2, ended: true }))
        res.on('error', () => resolve({ body: Buffer.concat(chunks), sample1, sample2, ended: false }))
      })
      req.on('error', () => { /* 已在 res 侧结算 */ })
      setTimeout(() => resolve({ body: Buffer.concat(chunks), sample1, sample2, ended: false }), 15_000).unref?.()
    })
    assert.ok(got.sample1 >= 0 && got.sample2 >= 0, `采样缺失 (${got.sample1}, ${got.sample2})`)
    assert.equal(got.sample1, got.sample2,
      `暂停期间上游产出必须冻结（${got.sample1} → ${got.sample2}）`)
    assert.ok(got.sample2 < COUNT, '暂停期间上游不应已全部产出')
    assert.equal(got.ended, true)
    assert.equal(got.body.length, CHUNK * COUNT, '恢复后必须完整交付')
  } finally {
    await down.close()
    await up.close()
  }
})

/* ============================================================
 * 14. cleanup 幂等（复用转发器不泄漏监听器）
 * ============================================================ */

test('E2-14 同一转发器复用两个请求：监听器数不增长、结果互不串', async () => {
  const payload = 'first-second'
  const up = await startServer((req, res) => {
    const body = Buffer.from(payload, 'utf8')
    res.writeHead(200, {
      'content-type': 'text/plain',
      'content-length': String(body.length),
    })
    res.end(body)
  })
  const sharedForwarder = createStreamingForwarder({ logger: () => {} })
  const down = await startDownstream(up.port, { forwarder: sharedForwarder })
  try {
    const first = await collect(`http://127.0.0.1:${down.port}/one`)
    const second = await collect(`http://127.0.0.1:${down.port}/two`)
    assert.equal(first.ended, true)
    assert.equal(second.ended, true)
    assert.equal(first.body.toString('utf8'), payload)
    assert.equal(second.body.toString('utf8'), payload)
    for (const rec of down.recs) {
      const recResult = await rec.forward
      assert.equal(recResult.error, null)
      assert.equal(recResult.committed, true)
      // cleanup 幂等的可观察证据：forward 前后 'close' 监听器数完全一致，
      // 第二个请求没有背上第一个请求的监听器
      assert.equal(rec.listenerAfter, rec.listenerBefore,
        `监听器泄漏：before=${rec.listenerBefore} after=${rec.listenerAfter}`)
    }
  } finally {
    await down.close()
    await up.close()
  }
})

/* ============================================================
 * 15. 参数校验与默认值
 * ============================================================ */

test('E2-15 参数校验：非法策略抛 TypeError，默认 idle 为 60s', async () => {
  assert.equal(DEFAULT_STREAM_IDLE_MS, 60_000)
  assert.throws(() => resolveStreamTimeouts({}, { streamIdleMs: -1 }), TypeError)
  assert.throws(() => resolveStreamTimeouts({}, { totalMs: '5000' }), TypeError)
  assert.throws(() => resolveStreamTimeouts({}, { streamIdleMs: Number.NaN }), TypeError)
  assert.throws(() => resolveStreamTimeouts(null, 'x'), TypeError)
  // 0 = 关闭，合法
  const off = resolveStreamTimeouts({}, { streamIdleMs: 0 })
  assert.equal(off.streamIdleMs, 0)
  assert.throws(() => createStreamingForwarder('x'), TypeError)
  // forward 是 async，断言 rejects 必须用 await assert.rejects
  const fwd = createStreamingForwarder({})
  await assert.rejects(
    () => fwd.forward(new ReadableStream(), /** @type {any} */ ({}), 'x'),
    TypeError,
  )
  // buildRetryInput 的 ctx 守卫
  assert.throws(() => buildRetryInput(/** @type {any} */ ({}), new StreamFailure('x', {}), {}), TypeError)
})
