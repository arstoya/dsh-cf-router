/**
 * streaming.test.js — 流式转发与背压（C2）
 *
 * 分两类：
 *   · **真实网络**：小数据 / SSE 首块 / 字节完整性 —— 走本机自签 HTTPS 上游，
 *     因为「首块立即可见」只有在真实的 socket 与真实的分块到达下才有意义。
 *   · **受控流**：背压、下游断开、100 MiB 内存、清理幂等、body 终态 ——
 *     用手搓的 ReadableStream / 假下游，好把「什么时候读、什么时候停」钉死。
 *
 * 判据都写成「可观测量」而不是「实现细节」：
 *   背压 = 上游被生产了多少块；
 *   断开 = 上游 cancel 有没有被调用、之后还产不产；
 *   内存 = process.memoryUsage 的 arrayBuffers / rss 采样。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'

import { createTransport } from '../../lib/transport.mjs'
import { makeUpstream } from '../../lib/contract/upstream.mjs'
import { ClientCancelled, StreamFailure } from '../../lib/contract/errors.mjs'
import {
  pipeWithBackpressure, streamEvents, isEventStream, createCleanup, createBodyGuard,
} from '../../lib/streaming.mjs'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { deferred, sleep, waitFor } from '../helpers/deferred.mjs'

const HOST = 'localhost'
const KiB = 1024
const MiB = 1024 * 1024
const encoder = new TextEncoder()
const decoder = new TextDecoder()

/* ============================================================
 * 辅助
 * ============================================================ */

const resolveLocal = async () => ({ address: '127.0.0.1', family: 4 })

function upstreamFor(port, id = 'up-c2') {
  return makeUpstream({ id, hostname: HOST, port })
}

function transportFor(fixture, options = {}) {
  return createTransport({
    resolve: resolveLocal,
    tls: { ca: fixture ? fixture.cert : undefined },
    drainTimeoutMs: 500,
    ...options,
  })
}

/** 收集型下游：记录每块内容，最后能拿到完整字节 */
function collectingSink() {
  /** @type {Buffer[]} */
  const chunks = []
  let closed = false
  const sink = new WritableStream({
    write(chunk) {
      chunks.push(Buffer.from(chunk))
    },
    close() {
      closed = true
    },
  })
  return {
    sink,
    chunks,
    get closed() { return closed },
    get bytes() { return chunks.reduce((sum, c) => sum + c.length, 0) },
    text() { return Buffer.concat(chunks).toString('utf8') },
  }
}

/**
 * 假的下游可写对象（模仿 http.ServerResponse）。
 *
 * · `write()` 返回 false 表示「内核缓冲满了」—— 背压测试就靠它把泵卡住；
 * · 达到 acceptBeforeClose 字节后自己 emit('close') —— 模拟客户端断开。
 */
class FakeDownstream extends EventEmitter {
  constructor({ acceptBeforeClose = Infinity, alwaysBackpressure = false } = {}) {
    super()
    this.written = 0
    this.chunks = 0
    this.destroyed = false
    this.writableEnded = false
    this.writableFinished = false
    this.acceptBeforeClose = acceptBeforeClose
    this.alwaysBackpressure = alwaysBackpressure
    this.endCalls = 0
  }

  write(chunk) {
    if (this.destroyed) throw new Error('向已销毁的下游写入')
    this.written += chunk.byteLength
    this.chunks += 1
    if (this.written >= this.acceptBeforeClose) {
      // 同步触发 close：真实的 destroy() 也发生在写入返回前后，
      // 这样测得到「写到一半对端没了」这一瞬间
      this.destroyed = true
      this.emit('close')
      return true
    }
    return !this.alwaysBackpressure
  }

  end() {
    this.endCalls += 1
    this.writableEnded = true
    this.writableFinished = true
    this.emit('finish')
  }

  destroy() {
    if (this.destroyed) return
    this.destroyed = true
    this.emit('close')
  }
}

/**
 * 计数型上游：pull 一次产一块，记录到底产了多少块、被取消时给的 reason。
 * 这是「背压有没有生效」的唯一客观判据 —— 内存曲线会被 GC 干扰，块计数不会。
 */
function countingSource({ chunkSize = 64 * KiB, totalChunks = 64, beforePull = null } = {}) {
  const counter = {
    produced: 0,
    /** @type {unknown} */
    cancelReason: 'unset',
    cancelled: false,
  }
  const stream = new ReadableStream({
    async pull(controller) {
      if (beforePull) await beforePull(counter)
      if (counter.produced >= totalChunks) {
        controller.close()
        return
      }
      counter.produced += 1
      controller.enqueue(new Uint8Array(chunkSize))
    },
    cancel(reason) {
      counter.cancelled = true
      counter.cancelReason = reason
    },
  })
  return { stream, counter }
}

/* ============================================================
 * 1. 正常路径（真实 HTTPS 上游）
 * ============================================================ */

test('小数据：transport 的响应体流式转给下游，字节数与内容一致', async () => {
  const payload = 'hello streaming world — 中文也不能被截断'
  const fixture = await startHttpsUpstream({ status: 200, body: payload })
  const t = transportFor(fixture)
  try {
    const res = await t.send({ method: 'GET', path: '/v1/small' }, upstreamFor(fixture.port))
    assert.ok(res.body, '响应体不应为空')
    const out = collectingSink()

    const handle = pipeWithBackpressure(res.body, out.sink)
    assert.equal(handle.bytes, 0, '未开始传输时计数应为 0')
    const result = await handle.done

    assert.equal(result.bytes, Buffer.byteLength(payload))
    assert.equal(handle.bytes, result.bytes)
    assert.ok(handle.chunks >= 1)
    assert.equal(out.text(), payload)
    assert.equal(out.bytes, Buffer.byteLength(payload))
    assert.equal(out.closed, true, '默认应关闭下游')
  } finally {
    await fixture.close()
  }
})

/* ============================================================
 * 2. 背压
 * ============================================================ */

test('背压：下游不接受时上游立刻被暂停，不再继续生产', async () => {
  const CHUNK = 64 * KiB
  const TOTAL = 32
  const { stream, counter } = countingSource({ chunkSize: CHUNK, totalChunks: TOTAL })
  const sink = new FakeDownstream({ alwaysBackpressure: true })

  const handle = pipeWithBackpressure(stream, sink)

  // 让泵跑到「写入被拒、等 drain」的位置
  await waitFor(() => sink.chunks === 1, { label: '第一块写入', timeoutMs: 2000 })
  await sleep(80)

  // 队列里最多再预取 1 块（ReadableStream 自身 HWM=1），绝不该一路读到底
  assert.equal(sink.chunks, 1, `下游只接了一块，实际 ${sink.chunks} 块`)
  assert.ok(counter.produced <= 2, `上游被暂停前最多预取 1 块，实际生产 ${counter.produced} 块`)

  const producedAtStall = counter.produced
  await sleep(120)
  assert.equal(counter.produced, producedAtStall, '等 drain 期间上游不得继续生产')
  assert.ok(handle.bytes < CHUNK * 3, `此刻只应交付 1 块，实际 ${handle.bytes} 字节`)

  // 放行 drain：每 1ms 一次，直到传完
  const driver = setInterval(() => sink.emit('drain'), 1)
  try {
    const result = await handle.done
    assert.equal(result.bytes, CHUNK * TOTAL)
    assert.equal(counter.produced, TOTAL)
    assert.equal(sink.endCalls, 1, '传完后应正常 end 下游')
  } finally {
    clearInterval(driver)
  }
})

/* ============================================================
 * 3. 下游断开 → 上游取消
 * ============================================================ */

test('下游断开：上游被 cancel，且停止生产（不会继续读完整条流）', async () => {
  const CHUNK = 64 * KiB
  const ACCEPT = 4
  const { stream, counter } = countingSource({ chunkSize: CHUNK, totalChunks: 4096 })
  const sink = new FakeDownstream({ acceptBeforeClose: CHUNK * ACCEPT })

  const handle = pipeWithBackpressure(stream, sink)
  const err = await handle.done.then(
    () => { throw new Error('下游断开了，done 不应 resolve') },
    (e) => e,
  )

  assert.ok(err instanceof ClientCancelled, `期望 ClientCancelled，实际 ${err?.name}：${err?.message}`)
  assert.equal(err.details?.phase, 'downstream')
  assert.equal(counter.cancelled, true, '上游必须被取消，而不是被默默丢掉')
  assert.ok(counter.cancelReason instanceof Error, 'cancel 应把错误原因交给上游')

  const producedAtStop = counter.produced
  await sleep(120)
  assert.equal(counter.produced, producedAtStop, '取消之后上游不得再被 pull')
  assert.ok(
    producedAtStop <= ACCEPT + 3,
    `断开发生在第 ${ACCEPT} 块，上游不该读到 ${producedAtStop} 块`,
  )
})

/* ============================================================
 * 4. 100 MiB：内存有界
 * ============================================================ */

test('100 MiB 传输：不缓冲，内存增长有界', async (t) => {
  const CHUNK = 64 * KiB
  const TOTAL_CHUNKS = (100 * MiB) / CHUNK // 1600
  let produced = 0

  // 每块都新分配：如果实现偷偷把块攒起来，arrayBuffers 会涨到 100 MiB 量级，
  // 复用同一块 buffer 反而会让「缓冲实现」看起来不占内存（所有块别名同一地址）。
  const stream = new ReadableStream({
    pull(controller) {
      if (produced >= TOTAL_CHUNKS) {
        controller.close()
        return
      }
      produced += 1
      controller.enqueue(new Uint8Array(CHUNK))
    },
  })

  const baseline = process.memoryUsage()
  let peakRss = baseline.rss
  let peakBuffers = baseline.arrayBuffers
  let written = 0

  const sink = new WritableStream({
    write(chunk) {
      written += chunk.byteLength
      if (written % (8 * MiB) === 0) {
        const m = process.memoryUsage()
        if (m.rss > peakRss) peakRss = m.rss
        if (m.arrayBuffers > peakBuffers) peakBuffers = m.arrayBuffers
      }
    },
  })

  const handle = pipeWithBackpressure(stream, sink)
  const result = await handle.done

  assert.equal(result.bytes, 100 * MiB)
  assert.equal(written, 100 * MiB)

  const rssGrowth = peakRss - baseline.rss
  const bufferGrowth = peakBuffers - baseline.arrayBuffers
  t.diagnostic(`100 MiB 传输：RSS 增长 ${(rssGrowth / MiB).toFixed(1)} MiB，arrayBuffers 增长 ${(bufferGrowth / MiB).toFixed(1)} MiB`)

  // 全缓冲实现会让 arrayBuffers 增长 ≥100 MiB；有界实现只持有「正在写的那一块」。
  // 留 2 倍余量：1600 次 64 KiB 分配，V8 不会逐块回收，未回收的块会累积到十几~几十 MiB
  assert.ok(
    bufferGrowth < 48 * MiB,
    `arrayBuffers 增长 ${(bufferGrowth / MiB).toFixed(1)} MiB，超过 48 MiB —— 说明在缓冲响应体`,
  )
  // RSS 受 GC 与分配器影响，给一个宽松但有意义的上限（远小于 100 MiB）
  assert.ok(
    rssGrowth < 160 * MiB,
    `RSS 增长 ${(rssGrowth / MiB).toFixed(1)} MiB，超过 160 MiB`,
  )
})

/* ============================================================
 * 5. SSE：首块立即可见
 * ============================================================ */

test('SSE 受控流：首块在下游收到后，上游才产下一块（没有攒批）', async () => {
  const firstSeen = deferred()
  let produced = 0
  /** @type {string[]} */
  const received = []

  const stream = new ReadableStream({
    start(controller) {
      produced += 1
      controller.enqueue(encoder.encode('data: first\n\n'))
    },
    async pull(controller) {
      // 第二块必须等下游真的看见第一块之后才产生：
      // 任何「攒够一批再发」的实现都会在这里死锁，测试直接超时失败
      await firstSeen.promise
      produced += 1
      controller.enqueue(encoder.encode('data: second\n\n'))
      controller.close()
    },
  })

  const sink = new WritableStream({
    write(chunk) {
      received.push(decoder.decode(chunk))
      if (received.length === 1) {
        assert.equal(produced, 1, '收到第一块时上游不该已经产了第二块（那说明在预取/攒批）')
        firstSeen.resolve()
      }
    },
  })

  const handle = streamEvents(stream, sink)
  const raced = await Promise.race([
    handle.done,
    sleep(2000).then(() => { throw new Error('首块没有立即下发（疑似攒批），2s 超时') }),
  ])
  assert.equal(raced.bytes, Buffer.byteLength('data: first\n\ndata: second\n\n'))
  assert.deepEqual(received, ['data: first\n\n', 'data: second\n\n'])
})

test('SSE 真实上游：分块到达即下发，不等整个流结束', async () => {
  const events = ['data: {"n":1}\n\n', 'data: {"n":2}\n\n', 'data: [DONE]\n\n']
  const delay = 250
  const fixture = await startHttpsUpstream({ sse: true, sseEvents: events, delayBodyMs: delay })
  const t = transportFor(fixture)
  try {
    const started = Date.now()
    const res = await t.send({ method: 'GET', path: '/v1/stream' }, upstreamFor(fixture.port))
    assert.equal(isEventStream(res.headers), true, 'content-type 应为 text/event-stream')

    /** @type {Array<{ at: number, text: string }>} */
    const arrivals = []
    const sink = new WritableStream({
      write(chunk) {
        arrivals.push({ at: Date.now(), text: decoder.decode(chunk, { stream: true }) })
      },
    })

    const handle = streamEvents(res.body, sink)
    const result = await handle.done

    assert.equal(result.bytes, Buffer.byteLength(events.join('')))
    assert.equal(arrivals.length, events.length, `应按上游分块逐块到达，实际 ${arrivals.length} 块`)
    assert.deepEqual(arrivals.map((a) => a.text), events)

    const firstDelay = arrivals[0].at - started
    const secondGap = arrivals[1].at - arrivals[0].at
    // 上游第 1 块之后才 sleep(delay)；首块若被攒到最后，firstDelay 会 ≈ 3*delay
    assert.ok(firstDelay < delay, `首块到达用了 ${firstDelay}ms，应该远早于 ${delay}ms`)
    assert.ok(secondGap >= delay * 0.5, `第 2 块应等上游 ${delay}ms，实际间隔 ${secondGap}ms`)
  } finally {
    await fixture.close()
  }
})

test('SSE 字节顺序与块边界完全保持：不解析、不重排、不合并', async () => {
  const pieces = [
    'data: {"a":1}\r\n\r\n',
    ': keep-alive\n\n',
    'data: 第一行\ndata: 第二行\n\n',
    'event: custom\nid: 7\ndata: {"b":2}\n\n',
    'data: {"c":3}\n\n',
  ]
  let index = 0
  const stream = new ReadableStream({
    pull(controller) {
      if (index >= pieces.length) {
        controller.close()
        return
      }
      controller.enqueue(encoder.encode(pieces[index]))
      index += 1
    },
  })

  const out = collectingSink()
  const handle = streamEvents(stream, out.sink)
  const result = await handle.done

  assert.equal(result.chunks, pieces.length, '块边界必须原样保留（不得合并）')
  assert.equal(out.chunks.length, pieces.length)
  const expected = Buffer.from(pieces.join(''), 'utf8')
  assert.equal(result.bytes, expected.length)
  assert.deepEqual(Buffer.concat(out.chunks), expected, '字节序列必须与上游完全一致')
  // 逐块比对：顺序也不能变
  pieces.forEach((piece, i) => {
    assert.equal(out.chunks[i].toString('utf8'), piece, `第 ${i} 块被改写了`)
  })
})

/* ============================================================
 * 6. 清理幂等
 * ============================================================ */

test('createCleanup：重复 run 只执行一次，并复用同一份报告', () => {
  const cleanup = createCleanup()
  let calls = 0
  cleanup.add(() => { calls += 1 })
  cleanup.add(() => { calls += 1 })

  assert.equal(cleanup.isDone, false)
  const first = cleanup.run()
  assert.equal(cleanup.isDone, true)
  assert.equal(first.ok, true)
  assert.equal(calls, 2)

  const second = cleanup.run()
  assert.equal(calls, 2, '第二次 run 不得重复执行清理函数')
  assert.equal(second, first, '重复 run 应返回同一份报告')
  assert.equal(cleanup.run(), first)
  assert.equal(calls, 2)
})

test('createCleanup：单个清理函数抛错不影响其它，且错误逐个记账', () => {
  const cleanup = createCleanup()
  /** @type {string[]} */
  const order = []
  cleanup.add(() => { order.push('a') })
  cleanup.add(() => { throw new Error('清理 a 的邻居炸了') })
  cleanup.add(() => { order.push('b') })
  cleanup.add(() => { throw '字符串错误' })

  const report = cleanup.run()
  assert.deepEqual(order, ['a', 'b'], '抛错的那一个不能挡住后面的清理')
  assert.equal(report.ok, false)
  assert.equal(report.errors.length, 2)
  assert.deepEqual(report.errors.map((e) => e.index), [1, 3])
  assert.ok(report.errors.every((e) => e.error instanceof Error), '非 Error 也要收敛成 Error')
})

test('createCleanup：run 之后 add 会立刻执行（清理点已过，不能挂着）', () => {
  const cleanup = createCleanup()
  cleanup.run()
  let late = 0
  cleanup.add(() => { late += 1 })
  assert.equal(late, 1)
  assert.equal(cleanup.isDone, true)
})

/* ============================================================
 * 7. 响应体终态
 * ============================================================ */

test('createBodyGuard：pending → consumed', async () => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('abc'))
      controller.enqueue(encoder.encode('defg'))
      controller.close()
    },
  })
  const guard = createBodyGuard(stream)
  assert.equal(guard.status, 'pending')
  assert.equal(guard.bytes, 0)

  const result = await guard.consumeAll()
  assert.equal(result.bytes, 7)
  assert.equal(guard.bytes, 7)
  assert.equal(guard.status, 'consumed')

  // 已消费完：重复调用不再读流，结果一致
  const again = await guard.consumeAll()
  assert.equal(again.bytes, 7)
})

test('createBodyGuard：pending → cancelled（取消后不能再消费）', async () => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('abc'))
    },
  })
  const guard = createBodyGuard(stream)
  await guard.cancel('client_gone')
  assert.equal(guard.status, 'cancelled')
  await guard.cancel('again') // 幂等
  assert.equal(guard.status, 'cancelled')

  await assert.rejects(guard.consumeAll(), (err) => {
    assert.ok(err instanceof ClientCancelled, `期望 ClientCancelled，实际 ${err?.name}`)
    return true
  })
})

test('createBodyGuard：消费中途被取消也记 cancelled，并以 ClientCancelled 拒绝', async () => {
  const gate = deferred()
  const stream = new ReadableStream({
    async pull(controller) {
      await gate.promise
      controller.enqueue(encoder.encode('late'))
      controller.close()
    },
  })
  const guard = createBodyGuard(stream)
  const running = guard.consumeAll()
  await sleep(10)
  await guard.cancel('aborted')
  await assert.rejects(running, (err) => {
    assert.ok(err instanceof ClientCancelled, `期望 ClientCancelled，实际 ${err?.name}`)
    return true
  })
  assert.equal(guard.status, 'cancelled')
  gate.resolve()
})

test('createBodyGuard：pending → errored（读流出错）', async () => {
  const stream = new ReadableStream({
    pull(controller) {
      controller.error(new Error('上游连接被重置'))
    },
  })
  const guard = createBodyGuard(stream)
  assert.equal(guard.status, 'pending')
  await assert.rejects(guard.consumeAll(), (err) => {
    assert.ok(err instanceof StreamFailure, `期望 StreamFailure，实际 ${err?.name}`)
    assert.equal(err.details?.phase, 'body')
    return true
  })
  assert.equal(guard.status, 'errored')
  await assert.rejects(guard.consumeAll(), (err) => {
    assert.ok(err instanceof StreamFailure)
    return true
  })
})

test('createBodyGuard：null body（HEAD/204/304）直接算已消费', async () => {
  const guard = createBodyGuard(null)
  assert.equal(guard.status, 'consumed')
  const result = await guard.consumeAll()
  assert.equal(result.bytes, 0)
  assert.equal(guard.status, 'consumed')
})

/* ============================================================
 * 8. 错误传播
 * ============================================================ */

test('上游流出错：以 StreamFailure 传播，并取消上游', async () => {
  let cancelled = false
  const stream = new ReadableStream({
    pull(controller) {
      controller.error(new Error('上游 TLS 连接被中断'))
    },
    cancel() { cancelled = true },
  })
  const out = collectingSink()
  const handle = pipeWithBackpressure(stream, out.sink)

  await assert.rejects(handle.done, (err) => {
    assert.ok(err instanceof StreamFailure, `期望 StreamFailure，实际 ${err?.name}`)
    assert.equal(err.details?.phase, 'upstream')
    assert.match(err.message, /上游/)
    return true
  })
  assert.equal(handle.bytes, 0)
  // 上游自己是 errored 状态，reader.cancel() 在规范里不再回调 source.cancel，
  // 所以这里不要求 cancelled=true —— 要求的是「错误没被吞、没被改型」，
  // 以及之后不会再有任何字节被交出去（bytes 停在 0）。
  assert.equal(handle.chunks, 0)
  assert.equal(cancelled, false, '流已 errored 时 cancel 回调不会触发（规范行为，记录在此防止误判）')
})

test('下游写入抛错：归为契约错误，且不重排成成功', async () => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(16))
    },
  })
  const sink = new WritableStream({
    write() { throw new Error('落盘失败') },
  })
  const handle = pipeWithBackpressure(stream, sink)
  await assert.rejects(handle.done, (err) => {
    assert.ok(err instanceof StreamFailure, `期望 StreamFailure，实际 ${err?.name}`)
    assert.equal(err.details?.phase, 'downstream')
    return true
  })
})

test('sink 传错类型：给出中文错误（Web ReadableStream 与 Node Readable 不能混用）', async () => {
  const { Readable } = await import('node:stream')
  const nodeStream = Readable.from([Buffer.from('x')])
  const out = collectingSink()
  const handle = pipeWithBackpressure(/** @type {any} */ (nodeStream), out.sink)
  await assert.rejects(handle.done, (err) => {
    assert.ok(err instanceof StreamFailure)
    assert.match(err.message, /Web ReadableStream/)
    assert.equal(err.details?.phase, 'upstream')
    return true
  })
})

/* ============================================================
 * 9. 其它契约
 * ============================================================ */

test('isEventStream：大小写、参数、数组头、Web Headers 都认', () => {
  assert.equal(isEventStream({ 'content-type': 'text/event-stream' }), true)
  assert.equal(isEventStream({ 'content-type': 'text/event-stream; charset=utf-8' }), true)
  assert.equal(isEventStream({ 'Content-Type': 'TEXT/EVENT-STREAM' }), true)
  assert.equal(isEventStream({ 'content-type': ['text/event-stream'] }), true)
  assert.equal(isEventStream(new Headers({ 'content-type': 'text/event-stream' })), true)
  assert.equal(isEventStream({ 'content-type': 'application/json' }), false)
  assert.equal(isEventStream({ 'content-type': 'text/event-streaming' }), false)
  assert.equal(isEventStream({}), false)
  assert.equal(isEventStream(null), false)
})

test('signal 取消：上游被取消，done 以 ClientCancelled 拒绝', async () => {
  const { stream, counter } = countingSource({ totalChunks: 1024 })
  const ac = new AbortController()
  const sink = new FakeDownstream({ alwaysBackpressure: true })
  const handle = pipeWithBackpressure(stream, sink, { signal: ac.signal })

  await waitFor(() => sink.chunks === 1, { label: '第一块写入' })
  ac.abort()

  await assert.rejects(handle.done, (err) => {
    assert.ok(err instanceof ClientCancelled, `期望 ClientCancelled，实际 ${err?.name}`)
    assert.equal(err.details?.reason, 'signal_aborted')
    return true
  })
  assert.equal(counter.cancelled, true)
})

test('closeSink=false：传完不关闭下游（SSE 由上层自己收尾）', async () => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('data: x\n\n'))
      controller.close()
    },
  })
  const sink = new FakeDownstream()
  const handle = streamEvents(stream, sink, { closeSink: false })
  const result = await handle.done
  assert.equal(result.bytes, 9)
  assert.equal(sink.endCalls, 0)
  assert.equal(sink.written, 9)
})

test('idleTimeoutMs：下游卡死时按空闲上限失败，不会永久挂着', async () => {
  const { stream, counter } = countingSource({ totalChunks: 8 })
  const sink = new FakeDownstream({ alwaysBackpressure: true })
  const handle = pipeWithBackpressure(stream, sink, { idleTimeoutMs: 60 })

  await assert.rejects(handle.done, (err) => {
    assert.ok(err instanceof StreamFailure, `期望 StreamFailure，实际 ${err?.name}`)
    assert.equal(err.details?.idleMs, 60)
    return true
  })
  assert.equal(counter.cancelled, true)
})
