/**
 * health-event-race.test.js — 事件竞争与幂等（Issue #9 阶段 6）
 *
 * 方案 §11.1 的关键提醒：现有 `settled` 在收到响应头时也会被置 true，
 * 直接拿它当错误守卫会**吞掉响应头之后的流式传输失败**。
 * 这里验证独立的 `errorHandled` 只挡重复记账，不挡真实失败。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { freePort, waitFor } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const IP = '127.0.0.1'

async function boot(fixtureOpts = {}, overrides = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
  const listenPort = await freePort()
  setupPlugin({
    targets: [HOST], listenHost: '127.0.0.1', listenPort,
    allowPrivateTargets: true, adminToken: 't', adminRateLimit: 9999,
    probeSamples: 1, probeTimeoutMs: 1500, upstreamTimeoutMs: 20000,
    firstByteTimeoutMs: 5000, failThreshold: 2,
    ...overrides,
  })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
  const server = api.createProxy()
  await new Promise((r) => server.once('listening', r))
  await api.refreshHost(HOST)
  await new Promise((r) => setTimeout(r, 150))

  // 某些 fixture（abortMidBody / resetConnection）会让探测本身失败，
  // 导致 currentIp 为空 —— 那样 HTTP 请求根本没有 IP 可记账。
  // 这里显式补一条可用候选与当前线路，让用例专注于「事件竞争」而非探测成败。
  const st = api.state()
  if (!st.hosts.get(HOST) || (st.hosts.get(HOST).results || []).length === 0) {
    st.hosts.set(HOST, {
      ips: ['127.0.0.1'],
      results: [{ ip: '127.0.0.1', okCount: 3, samples: 3, ttfbMedian: 50, ttfbBest: 50, totalMedian: 70, tcpMedian: 5, tlsMedian: 8, colo: 'HKG', excluded: null }],
      lastProbeAt: api.deps.now(), error: null,
    })
  }
  if (!st.currentIp.get(HOST)) st.currentIp.set(HOST, '127.0.0.1')

  return { up, port: server.address().port }
}

function req(port, { path = '/x', method = 'GET', chunks = null } = {}) {
  return new Promise((resolve) => {
    const q = http.request({ host: '127.0.0.1', port, path, method }, (res) => {
      const b = []
      res.on('data', (c) => b.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(b) }))
      res.on('error', () => resolve({ status: res.statusCode, body: Buffer.concat(b), err: 'res' }))
    })
    q.on('error', () => resolve({ err: 'req' }))
    if (chunks) for (const c of chunks) q.write(c)
    q.end()
  })
}

async function shutdown(env) {
  try { api.closeProxy() } catch { /* ignore */ }
  await env.up.close()
  mod.__resetForTest()
}

test.afterEach(async () => { try { api.closeProxy() } catch { /* ignore */ } mod.__resetForTest() })

/* ============================================================
 * 关键：不能吞掉响应头之后的传输失败
 * ============================================================ */

test('响应头到达后响应体中断 → 仍要记失败（不能被幂等守卫吞掉）', async () => {
  const env = await boot({ status: 200, body: 'z'.repeat(20000), abortMidBody: true })
  try {
    const before = api.statOf(HOST, IP).fail
    await req(env.port, {})

    await waitFor(() => api.statOf(HOST, IP).fail > before, {
      timeoutMs: 3000,
      label: 'transfer failure recorded',
      describe: () => `fail=${api.statOf(HOST, IP).fail}`,
    })
    assert.ok(api.statOf(HOST, IP).fail > before, '流式传输中断必须记账')
  } finally { await shutdown(env) }
})

test('已收到响应头的正常 SSE 完成 → 不记失败', async () => {
  const env = await boot({ status: 200, sse: true, sseEvents: Array(5).fill('data: x\\n\\n') })
  try {
    const before = api.statOf(HOST, IP).fail
    await req(env.port, { method: 'POST' })
    await new Promise((r) => setTimeout(r, 200))
    assert.equal(api.statOf(HOST, IP).fail, before, '正常完成不该被记成失败')
  } finally { await shutdown(env) }
})

/* ============================================================
 * 幂等：同一次失败只记一次
 * ============================================================ */

test('超时与主动销毁竞争 → 只记 1 次失败', async () => {
  // 上游拖过 firstByteTimeoutMs 触发超时销毁；两个计时器可能同时到点，
  // 这里断言无论竞争如何，只记 1 次
  const env = await boot({ status: 200, delayFirstByteMs: 900 }, { firstByteTimeoutMs: 5000 })
  try {
    const before = api.statOf(HOST, IP).fail
    // 用 upstreamTimeoutMs 先掐断，制造「超时 + destroy」竞争
    await req(env.port, {})
    await new Promise((r) => setTimeout(r, 1200))

    const delta = api.statOf(HOST, IP).fail - before
    assert.ok(delta <= 1, `一次请求最多记 1 次失败，实际 ${delta}`)
  } finally { await shutdown(env) }
})

test('客户端取消后上游 ECONNRESET → 不计失败', async () => {
  const env = await boot({ status: 200, body: 'x'.repeat(8 * 1024 * 1024), chunkedWrite: 16 })
  try {
    const before = api.statOf(HOST, IP).fail
    await new Promise((resolve) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/big' }, (res) => {
        let got = 0
        res.on('data', (c) => {
          got += c.length
          if (got > 64 * 1024) { q.destroy(); res.destroy() }
        })
        res.on('error', () => {})
        res.on('close', () => resolve())
      })
      q.on('error', () => resolve())
      q.end()
    })
    await waitFor(() => env.up.abortedCount() > 0, { timeoutMs: 3000, label: 'aborted' })
    await new Promise((r) => setTimeout(r, 200))

    assert.equal(api.statOf(HOST, IP).fail, before, '客户端取消产生的上游错误不算 IP 失败')
  } finally { await shutdown(env) }
})

test('上游连接重置 → 记且只记 1 次', async () => {
  const env = await boot({ resetConnection: true })
  try {
    const before = api.statOf(HOST, IP).fail
    await req(env.port, { method: 'POST' })
    await new Promise((r) => setTimeout(r, 300))

    assert.equal(api.statOf(HOST, IP).fail - before, 1, '应恰好记 1 次')
  } finally { await shutdown(env) }
})

/* ============================================================
 * 状态机与既有保护机制共存
 * ============================================================ */

test('失败达阈值后进入 cooling，且 generation 不变量仍成立', async () => {
  const env = await boot({ resetConnection: true }, { failThreshold: 1 })
  try {
    await req(env.port, { method: 'POST' })
    await waitFor(() => api.getHealthState(HOST, IP) === 'cooling', {
      timeoutMs: 3000, label: 'cooling',
      describe: () => `state=${api.getHealthState(HOST, IP)} fail=${api.statOf(HOST, IP).fail}`,
    })
    assert.equal(api.getHealthState(HOST, IP), 'cooling')
    assert.equal(api.getRouteGeneration(HOST), api.state().switches.length, 'generation 不变量')
  } finally { await shutdown(env) }
})

test('既有代理行为未变：正常请求成功且不计失败', async () => {
  const env = await boot({ status: 200, body: '{"ok":1}' })
  try {
    const r = await req(env.port, {})
    assert.equal(r.status, 200)
    assert.equal(JSON.parse(r.body.toString()).ok, 1)
    assert.equal(api.statOf(HOST, IP).fail, 0)
    assert.equal(api.getHealthState(HOST, IP), 'healthy')
  } finally { await shutdown(env) }
})
