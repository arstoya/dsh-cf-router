/**
 * connection-pool-integration.test.js — 活动请求计数接入（Issue #12 阶段 2）
 *
 * 验证池计数在真实请求路径上正确增减，且**所有退出路径都归还**（不泄漏）。
 * 计数泄漏的后果：排空永远等不到归零，池只能被超时强杀。
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

async function boot(fixtureOpts = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
  const port = await freePort()
  setupPlugin({
    targets: [HOST], listenHost: '127.0.0.1', listenPort: port,
    allowPrivateTargets: true, adminToken: 't', adminRateLimit: 9999,
    probeSamples: 1, probeTimeoutMs: 1500, upstreamTimeoutMs: 20000,
    firstByteTimeoutMs: 5000, failThreshold: 2, discoverEnabled: false,
  })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (h, cb) => cb(null, [IP])
  const srv = api.createProxy()
  await new Promise((r) => srv.once('listening', r))
  await api.refreshHost(HOST)
  await new Promise((r) => setTimeout(r, 150))
  return { up, port }
}

function req(port, { path = '/x', method = 'GET', chunks = null } = {}) {
  return new Promise((resolve) => {
    const q = http.request({ host: '127.0.0.1', port, path, method }, (res) => {
      const b = []
      res.on('data', (c) => b.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(b) }))
      res.on('error', () => resolve({ status: res.statusCode, err: true }))
    })
    q.on('error', () => resolve({ err: true }))
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
 * 正常路径
 * ============================================================ */

test('请求期间占位，结束后归零', async () => {
  const env = await boot({ status: 200, body: '{"ok":1}' })
  try {
    const before = api.poolRegistry.stats().totalInFlight
    const p = req(env.port, {})

    // 请求在飞时应有占位（可能在极短时间内完成，所以只断言最终归零）
    await p
    await waitFor(() => api.poolRegistry.stats().totalInFlight === before, {
      timeoutMs: 2000, label: 'inFlight back to baseline',
      describe: () => `now=${api.poolRegistry.stats().totalInFlight} before=${before}`,
    })
    assert.equal(api.poolRegistry.stats().totalInFlight, before, '不应泄漏计数')
  } finally { await shutdown(env) }
})

test('多个请求结束后计数归零', async () => {
  const env = await boot({ status: 200, body: '{"ok":1}' })
  try {
    await Promise.all([
      req(env.port, {}), req(env.port, {}), req(env.port, {}),
    ])
    await waitFor(() => api.poolRegistry.stats().totalInFlight === 0, {
      timeoutMs: 2000, label: 'all released',
      describe: () => `inFlight=${api.poolRegistry.stats().totalInFlight}`,
    })
  } finally { await shutdown(env) }
})

/* ============================================================
 * 异常路径
 * ============================================================ */

test('上游连接重置后计数归零（error 路径）', async () => {
  const env = await boot({ resetConnection: true })
  try {
    await req(env.port, { method: 'POST' })
    await waitFor(() => api.poolRegistry.stats().totalInFlight === 0, {
      timeoutMs: 3000, label: 'released after error',
      describe: () => `inFlight=${api.poolRegistry.stats().totalInFlight}`,
    })
  } finally { await shutdown(env) }
})

test('客户端中途取消后计数归零（close 路径）', async () => {
  const env = await boot({ status: 200, body: 'x'.repeat(8 * 1024 * 1024), chunkedWrite: 16 })
  try {
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
    await waitFor(() => api.poolRegistry.stats().totalInFlight === 0, {
      timeoutMs: 3000, label: 'released after abort',
      describe: () => `inFlight=${api.poolRegistry.stats().totalInFlight}`,
    })
  } finally { await shutdown(env) }
})

test('上游响应体中断后计数归零', async () => {
  const env = await boot({ status: 200, body: 'z'.repeat(20000), abortMidBody: true })
  try {
    await req(env.port, {})
    await waitFor(() => api.poolRegistry.stats().totalInFlight === 0, {
      timeoutMs: 3000, label: 'released after response abort',
      describe: () => `inFlight=${api.poolRegistry.stats().totalInFlight}`,
    })
  } finally { await shutdown(env) }
})

test('首字节超时后计数归零', async () => {
  const env = await boot({ status: 200, delayFirstByteMs: 3000 })
  try {
    await req(env.port, {})
    await waitFor(() => api.poolRegistry.stats().totalInFlight === 0, {
      timeoutMs: 5000, label: 'released after timeout',
      describe: () => `inFlight=${api.poolRegistry.stats().totalInFlight}`,
    })
  } finally { await shutdown(env) }
})

/* ============================================================
 * SSE：响应体传输期间算活动
 * ============================================================ */

test('SSE 传输期间计数保持占位，结束后归零', async () => {
  const events = Array.from({ length: 5 }, (_, i) => `data: ${i}\n\n`)
  const env = await boot({ status: 200, sse: true, sseEvents: events, delayBodyMs: 300 })
  try {
    let sawInFlight = 0
    const done = new Promise((resolve) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/sse', method: 'POST' }, (res) => {
        res.on('data', () => {
          // 收到事件时检查计数：SSE 传输中应当仍占着槽位
          const n = api.poolRegistry.stats().totalInFlight
          if (n > sawInFlight) sawInFlight = n
        })
        res.on('end', resolve)
        res.on('error', resolve)
      })
      q.on('error', resolve)
      q.end('{}')
    })
    await done

    assert.ok(sawInFlight >= 1, `SSE 传输期间应占位，实测峰值 ${sawInFlight}`)

    await waitFor(() => api.poolRegistry.stats().totalInFlight === 0, {
      timeoutMs: 2000, label: 'sse released',
      describe: () => `inFlight=${api.poolRegistry.stats().totalInFlight}`,
    })
  } finally { await shutdown(env) }
})

/* ============================================================
 * 池登记
 * ============================================================ */

test('按 host|ip 登记池', async () => {
  const env = await boot({ status: 200 })
  try {
    await req(env.port, {})
    const s = api.poolRegistry.stats()
    assert.ok(s.activeCount >= 1, `应登记池，实际 ${JSON.stringify(s)}`)
    const key = `${HOST}|${IP}`
    const found = s.activePools.find((p) => p.key === key)
    assert.ok(found, `应存在 ${key}`)
  } finally { await shutdown(env) }
})

test('direct 模式登记为 host|direct', async () => {
  const env = await boot({ status: 200 })
  try {
    api.setRoutingMode('direct')
    await req(env.port, {})
    const s = api.poolRegistry.stats()
    const found = s.activePools.find((p) => p.key === `${HOST}|direct`)
    assert.ok(found, `direct 应登记为 host|direct，实际 ${JSON.stringify(s.activePools.map((x) => x.key))}`)
  } finally { await shutdown(env) }
})
