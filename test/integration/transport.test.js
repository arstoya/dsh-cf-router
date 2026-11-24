/**
 * transport.test.js — 传输层集成测试（C1）
 *
 * 全部用例打本机自签 HTTPS 上游（test/fixtures/https-server.js），
 * 因为生产路径只会有 https，明文桩测不出 TLS 段的行为。
 *
 * 六段超时不能靠「等真的超时」来测：DNS 卡住、TLS 卡住在本机根本没有对端可以制造。
 * 所以每一种都用一个**确定的**手法把它钉住：
 *   · dns       注入一个永不返回的解析器
 *   · connect   注入一个永不回调的 createConnection（socket 迟迟建不起来）
 *   · tls       真实 TCP 连上一个只 accept、绝不说 TLS 的裸 socket 服务
 *   · firstByte 上游延迟响应头
 *   · streamIdle 上游发了第一块之后长时间沉默
 *   · total     总时长上限小于上游延迟
 *
 * 超时时间一律压到几十毫秒级，整套跑起来在秒级完成。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'

import { createTransport, DEFAULT_TIMEOUTS } from '../../lib/transport.mjs'
import { makeUpstream } from '../../lib/contract/upstream.mjs'
import {
  UpstreamTimeout, ClientCancelled, StreamFailure,
} from '../../lib/contract/errors.mjs'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { sleep, waitFor } from '../helpers/deferred.mjs'

const HOST = 'localhost'

/** 解析器：上游桩只监听 127.0.0.1，不能让 localhost 走到 ::1 上去 */
const resolveLocal = async () => ({ address: '127.0.0.1', family: 4 })

/** 建一个指向本机桩的 upstream */
function upstreamFor(port, id = 'up-1') {
  return makeUpstream({ id, hostname: HOST, port })
}

/**
 * 建一个传输层。tls.ca 注入桩的自签证书 —— 传输层**不允许**关闭证书校验，
 * 唯一的放行方式是显式给它信任的 CA，这一点与生产一致。
 */
function transportFor(fixture, options = {}) {
  return createTransport({
    resolve: resolveLocal,
    tls: { ca: fixture ? fixture.cert : undefined },
    drainTimeoutMs: 500,
    ...options,
  })
}

/** 读完整个响应体 */
async function readBody(res) {
  assert.ok(res.body, '响应体不应为空')
  const reader = res.body.getReader()
  const chunks = []
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(Buffer.from(value))
  }
  return Buffer.concat(chunks)
}

/** 断言 promise 以指定契约错误 reject，并返回该错误 */
async function expectReject(promise, Ctor, phase) {
  try {
    await promise
  } catch (err) {
    assert.ok(err instanceof Ctor, `期望 ${Ctor.name}，实际 ${err?.name}：${err?.message}`)
    if (phase !== undefined) assert.equal(err.details?.phase, phase)
    return err
  }
  assert.fail('期望 reject，实际 resolve 了')
  return null
}

/* ============================================================
 * 1. 正常路径
 * ============================================================ */

test('GET 200：状态码 / 头部 / 完整 body', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: '{"ok":true}' })
  const t = transportFor(fixture)
  try {
    const res = await t.send(
      { method: 'GET', path: '/v1/ping', headers: { accept: 'application/json' } },
      upstreamFor(fixture.port),
    )
    assert.equal(res.statusCode, 200)
    assert.equal(res.socketReused, false)

    const body = await readBody(res)
    assert.equal(body.toString('utf8'), '{"ok":true}')

    // 上游收到的请求必须原样保留 path 与方法；Host 头由传输层补齐
    assert.equal(fixture.requests.length, 1)
    assert.equal(fixture.requests[0].method, 'GET')
    assert.equal(fixture.requests[0].url, '/v1/ping')
    assert.equal(fixture.requests[0].headers.host, `${HOST}:${fixture.port}`)

    // 六段里这次真正跑过的三段都应有值（第一段 DNS 由注入解析器完成）
    await waitFor(() => res.timings.totalMs !== null, { timeoutMs: 1000, label: 'totalMs' })
    assert.ok(res.timings.dnsMs >= 0)
    assert.ok(res.timings.connectMs >= 0)
    assert.ok(res.timings.tlsMs >= 0)
    assert.ok(res.timings.firstByteMs >= 0)

    const st = t.stats()
    assert.equal(st.requests, 1)
    assert.equal(st.completed, 1)
    assert.equal(st.inFlight, 0)
    assert.equal(st.sockets.opened, 1)
    assert.equal(st.sockets.reused, 0)
  } finally {
    await t.close()
    await fixture.close()
  }
})

/* ============================================================
 * 2. 请求体
 * ============================================================ */

test('POST：Web ReadableStream 请求体原样送上游，方法自动大写', async () => {
  const fixture = await startHttpsUpstream({ status: 201, body: '{"created":true}' })
  const t = transportFor(fixture)
  try {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"a":1}'))
        controller.enqueue(new TextEncoder().encode('{"b":2}'))
        controller.close()
      },
    })
    const res = await t.send(
      { method: 'post', path: '/v1/items', headers: { 'content-type': 'application/json' }, body },
      upstreamFor(fixture.port, 'u-post'),
    )
    assert.equal(res.statusCode, 201)
    assert.equal((await readBody(res)).toString('utf8'), '{"created":true}')
    assert.equal(fixture.requests[0].method, 'POST', '方法应被规范成大写')
    assert.equal(fixture.requests[0].body, '{"a":1}{"b":2}')
  } finally {
    await t.close()
    await fixture.close()
  }
})

/* ============================================================
 * 3. 连接复用
 * ============================================================ */

test('连接复用：两次请求只开一条 socket，第二次跑在复用连接上', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'ok' })
  const t = transportFor(fixture)
  const up = upstreamFor(fixture.port, 'up-reuse')
  try {
    const first = await t.send({ method: 'GET', path: '/a' }, up)
    assert.equal(first.socketReused, false)
    await readBody(first)
    // 等 agent 把 socket 放回空闲池（res 'end' 之后才会 free）
    await waitFor(() => t.stats().pool.activeCount === 1, { timeoutMs: 1000, label: 'pool ready' })
    await sleep(20)

    const second = await t.send({ method: 'GET', path: '/b' }, up)
    assert.equal(second.socketReused, true, '第二次请求应复用连接')
    await readBody(second)

    const st = t.stats()
    assert.equal(st.sockets.opened, 1, '只应创建一条连接')
    assert.equal(st.sockets.reused, 1)
    assert.ok(st.sockets.reuseRate > 0.4, `复用率 ${st.sockets.reuseRate}`)
    assert.equal(st.upstreams.length, 1)
    assert.equal(st.upstreams[0].opened, 1)
    assert.equal(st.upstreams[0].reused, 1)
    // 复用连接上采不到建连/握手耗时 —— 置 null，不拿别的段顶替
    assert.equal(second.timings.connectMs, null)
    assert.equal(second.timings.tlsMs, null)
  } finally {
    await t.close()
    await fixture.close()
  }
})

/* ============================================================
 * 4. 并发上限
 * ============================================================ */

test('maxSockets 限并发：4 个并发请求最多 2 条连接', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'ok', delayFirstByteMs: 120 })
  const t = transportFor(fixture, { maxSockets: 2 })
  const up = upstreamFor(fixture.port, 'up-conc')

  let maxSeen = 0
  const timer = setInterval(() => {
    maxSeen = Math.max(maxSeen, fixture.connections())
  }, 5)

  try {
    const bodies = await Promise.all(
      [0, 1, 2, 3].map((i) => t.send({ method: 'GET', path: `/c${i}` }, up).then(readBody)),
    )
    assert.equal(bodies.length, 4)
    assert.equal(fixture.requests.length, 4, '四个请求都应真正发出')
    assert.equal(t.stats().sockets.opened, 2, '并发被限制时只应开 2 条连接')
    assert.ok(maxSeen <= 2, `上游观测到的并发连接数 ${maxSeen} 超过上限 2`)
  } finally {
    clearInterval(timer)
    await t.close()
    await fixture.close()
  }
})

/* ============================================================
 * 5. 六段超时
 * ============================================================ */

test('dnsMs：解析卡住 → UpstreamTimeout(phase=dns)', async () => {
  const t = createTransport({
    resolve: () => new Promise(() => {}), // 永不返回，模拟 getaddrinfo 卡死
    timeouts: { dnsMs: 60 },
    drainTimeoutMs: 200,
  })
  try {
    const err = await expectReject(
      t.send({ method: 'GET', path: '/' }, makeUpstream({ id: 'u-dns', hostname: 'slow.example', port: 443 })),
      UpstreamTimeout, 'dns',
    )
    assert.equal(err.details.limitMs, 60)
    const st = t.stats()
    assert.equal(st.timedOut, 1)
    assert.equal(st.inFlight, 0, '超时后必须归还池槽，否则 close 排不空')
  } finally {
    await t.close()
  }
})

test('connectMs：socket 建不起来 → UpstreamTimeout(phase=connect)', async () => {
  const t = createTransport({
    resolve: resolveLocal,
    // 永不回调：Agent 拿不到 socket，传输层只能等 connect 段到点
    createConnection: () => {},
    timeouts: { connectMs: 80, tlsMs: 2000, firstByteMs: 2000 },
    drainTimeoutMs: 200,
  })
  try {
    const err = await expectReject(
      t.send({ method: 'GET', path: '/' }, makeUpstream({ id: 'u-connect', hostname: HOST, port: 443 })),
      UpstreamTimeout, 'connect',
    )
    assert.equal(err.details.limitMs, 80)
    assert.equal(t.stats().timedOut, 1)
  } finally {
    await t.close()
  }
})

test('tlsMs：TCP 通了但握手不完成 → UpstreamTimeout(phase=tls)', async () => {
  // 只 accept、绝不说 TLS 的裸服务：握手永远等不到 ServerHello
  const silentSockets = new Set()
  const silent = net.createServer((s) => {
    silentSockets.add(s)
    s.on('error', () => {})
    s.on('close', () => silentSockets.delete(s))
  })
  await new Promise((r) => silent.listen(0, '127.0.0.1', r))
  const port = silent.address().port

  const t = transportFor(null, { timeouts: { connectMs: 2000, tlsMs: 100, firstByteMs: 2000 } })
  try {
    const err = await expectReject(
      t.send({ method: 'GET', path: '/' }, makeUpstream({ id: 'u-tls', hostname: HOST, port })),
      UpstreamTimeout, 'tls',
    )
    assert.equal(err.details.limitMs, 100)
  } finally {
    await t.close()
    for (const s of silentSockets) { try { s.destroy() } catch { /* ignore */ } }
    await new Promise((r) => silent.close(r))
  }
})

test('firstByteMs：上游迟迟不回响应头 → UpstreamTimeout(phase=first_byte)', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'late', delayFirstByteMs: 400 })
  const t = transportFor(fixture, { timeouts: { firstByteMs: 80 } })
  try {
    const err = await expectReject(
      t.send({ method: 'GET', path: '/slow' }, upstreamFor(fixture.port, 'u-fb')),
      UpstreamTimeout, 'first_byte',
    )
    assert.equal(err.details.limitMs, 80)
    // 传输层要真的把连接掐掉，不能只是「不等了」
    await waitFor(() => fixture.connections() === 0, { timeoutMs: 1000, label: 'socket closed' })
  } finally {
    await t.close()
    await fixture.close()
  }
})

test('streamIdleMs：流中途沉默 → body 流抛 UpstreamTimeout(phase=stream_idle)', async () => {
  // 第一块立刻发，之后沉默 400ms：首字节段已经过去，只有流空闲能抓住
  const fixture = await startHttpsUpstream({
    sse: true,
    sseEvents: ['data: {"delta":"a"}\n\n', 'data: [DONE]\n\n'],
    delayBodyMs: 400,
  })
  const t = transportFor(fixture, { timeouts: { streamIdleMs: 100 } })
  try {
    const res = await t.send({ method: 'GET', path: '/stream' }, upstreamFor(fixture.port, 'u-idle'))
    assert.equal(res.statusCode, 200)

    // send 已经在首字节处 resolve，流空闲只能体现在 body 上
    const err = await expectReject(readBody(res), UpstreamTimeout, 'stream_idle')
    assert.equal(err.details.limitMs, 100)
    assert.equal(t.stats().timedOut, 1)
  } finally {
    await t.close()
    await fixture.close()
  }
})

test('totalMs：整次请求上限 → UpstreamTimeout(phase=total)', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'slow', delayFirstByteMs: 400 })
  const t = transportFor(fixture, {
    timeouts: { totalMs: 80, firstByteMs: 2000, connectMs: 2000, streamIdleMs: 2000 },
  })
  try {
    const err = await expectReject(
      t.send({ method: 'GET', path: '/slow' }, upstreamFor(fixture.port, 'u-total')),
      UpstreamTimeout, 'total',
    )
    assert.equal(err.details.limitMs, 80)
  } finally {
    await t.close()
    await fixture.close()
  }
})

/* ============================================================
 * 6. 客户端取消
 * ============================================================ */

test('AbortSignal：首字节前取消 → ClientCancelled，且上游看到连接被断', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'never', delayFirstByteMs: 500 })
  const t = transportFor(fixture, { timeouts: { firstByteMs: 3000 } })
  const ac = new AbortController()
  try {
    const p = t.send({ method: 'GET', path: '/cancel', signal: ac.signal }, upstreamFor(fixture.port, 'u-cancel'))
    setTimeout(() => ac.abort(), 60)

    const err = await expectReject(p, ClientCancelled)
    assert.equal(err.code, 'client_cancelled')
    assert.equal(t.stats().cancelled, 1)
    assert.equal(t.stats().inFlight, 0)

    // 取消必须真的传播到 socket 层：上游会看到响应没写完连接就断了
    await waitFor(() => fixture.abortedCount() >= 1, {
      timeoutMs: 2000,
      label: 'upstream saw abort',
      describe: () => `aborted=${fixture.abortedCount()} completed=${fixture.completedCount()}`,
    })
  } finally {
    await t.close()
    await fixture.close()
  }
})

test('AbortSignal：body 传输中取消 → body 流抛 ClientCancelled', async () => {
  const fixture = await startHttpsUpstream({
    sse: true,
    sseEvents: ['data: 1\n\n', 'data: 2\n\n', 'data: 3\n\n'],
    delayBodyMs: 120,
  })
  const t = transportFor(fixture, { timeouts: { streamIdleMs: 3000 } })
  const ac = new AbortController()
  try {
    const res = await t.send({ method: 'GET', path: '/stream2', signal: ac.signal }, upstreamFor(fixture.port, 'u-cancel2'))
    assert.ok(res.body)
    const reader = res.body.getReader()
    const first = await reader.read() // 拿到第一块，确保已经在流里
    assert.ok(first.value.length > 0)
    ac.abort()

    // 同一个 reader 继续读：取消必须体现为流上的错误，而不是静默结束
    try {
      for (;;) {
        const { done } = await reader.read()
        if (done) break
      }
    } catch (err) {
      assert.ok(err instanceof ClientCancelled, `期望 ClientCancelled，实际 ${err?.name}：${err?.message}`)
      assert.equal(err.code, 'client_cancelled')
      return
    }
    assert.fail('取消之后 body 不应正常结束')
  } finally {
    await t.close()
    await fixture.close()
  }
})

/* ============================================================
 * 7. 停机
 * ============================================================ */

test('close() 幂等：并发与重复调用都不报错', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'ok' })
  const t = transportFor(fixture)
  try {
    const r1 = await t.send({ method: 'GET', path: '/' }, upstreamFor(fixture.port, 'u-close'))
    await readBody(r1)

    const [a, b, c] = await Promise.all([t.close(), t.close(), t.close()])
    assert.equal(a, undefined)
    assert.equal(b, undefined)
    assert.equal(c, undefined)
    await t.close() // 第三次再调也不能抛
    assert.equal(t.stats().closed, true)
    // 空闲连接应已关闭（服务端 socket 的 close 事件晚一个 tick）
    await waitFor(() => fixture.connections() === 0, {
      timeoutMs: 1000, label: 'idle sockets closed', describe: () => `open=${fixture.connections()}`,
    })
  } finally {
    await fixture.close()
  }
})

test('close() 之后新请求被拒（transport_closed）', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'ok' })
  const t = transportFor(fixture)
  try {
    await t.close()
    try {
      await t.send({ method: 'GET', path: '/' }, upstreamFor(fixture.port, 'u-after'))
      assert.fail('close 之后不应还能发请求')
    } catch (err) {
      assert.equal(err.code, 'transport_closed')
      assert.match(err.message, /已关闭/)
    }
    assert.equal(fixture.requests.length, 0, '被拒的请求不应到达上游')
  } finally {
    await fixture.close()
  }
})

test('close() 排空在途请求：轮到它跑完再关', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'drained', delayFirstByteMs: 120 })
  const t = transportFor(fixture, { drainTimeoutMs: 3000 })
  try {
    const p = t.send({ method: 'GET', path: '/drain' }, upstreamFor(fixture.port, 'u-drain'))
    // 等请求真的进了在途表再关，避免「还没开始就被拒」
    await waitFor(() => t.stats().inFlight === 1, { timeoutMs: 1000, label: 'in flight' })

    const res = await p
    assert.equal(res.statusCode, 200)
    const body = await readBody(res)
    assert.equal(body.toString('utf8'), 'drained')

    await t.close()
    assert.equal(t.stats().closed, true)
  } finally {
    await fixture.close()
  }
})

test('close() 到点仍未排空：在途请求被终止而不是永远挂着', async () => {
  const fixture = await startHttpsUpstream({ status: 200, body: 'never', delayFirstByteMs: 3000 })
  const t = transportFor(fixture, { drainTimeoutMs: 60 })
  try {
    const p = t.send({ method: 'GET', path: '/stuck' }, upstreamFor(fixture.port, 'u-stuck'))
    await waitFor(() => t.stats().inFlight === 1, { timeoutMs: 1000, label: 'in flight' })

    const started = Date.now()
    await t.close()
    assert.ok(Date.now() - started < 2000, 'close 不应真的等满 3s')

    const err = await expectReject(p, StreamFailure)
    assert.equal(err.details.reason, 'transport_closed')
    assert.equal(t.stats().inFlight, 0)
  } finally {
    await fixture.close()
  }
})

/* ============================================================
 * 8. 配置校验（构造期就炸，不要等到第一个请求）
 * ============================================================ */

test('非法超时值在构造期报错', () => {
  assert.throws(() => createTransport({ timeouts: { dnsMs: -1 } }), /dnsMs/)
  assert.throws(() => createTransport({ timeouts: { firstByteMs: 'soon' } }), /firstByteMs/)
  assert.throws(() => createTransport({ maxSockets: 0 }), /maxSockets/)
})

test('默认值：totalMs 默认关闭（SSE 不能被默认总时长掐死）', () => {
  assert.equal(DEFAULT_TIMEOUTS.totalMs, null)
  for (const field of ['dnsMs', 'connectMs', 'tlsMs', 'firstByteMs', 'streamIdleMs']) {
    assert.ok(DEFAULT_TIMEOUTS[field] > 0, `${field} 应有正数默认值`)
  }
})
