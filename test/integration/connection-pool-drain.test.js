/**
 * connection-pool-drain.test.js — 排空而非立即销毁（Issue #12 阶段 3）
 *
 * **本文件最重要的一条**：线路切换不能中断正在传输的 SSE。
 * 改造前 dropAgents() 直接 agent.destroy()，会把在飞的连接一起掐断。
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
  const port = await freePort()
  setupPlugin({
    targets: [HOST], listenHost: '127.0.0.1', listenPort: port,
    allowPrivateTargets: true, adminToken: 't', adminRateLimit: 9999,
    probeSamples: 1, probeTimeoutMs: 1500, upstreamTimeoutMs: 30000,
    firstByteTimeoutMs: 10000, failThreshold: 2, discoverEnabled: false,
    ...overrides,
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

async function shutdown(env) {
  try { api.closeProxy() } catch { /* ignore */ }
  await env.up.close()
  mod.__resetForTest()
}

test.afterEach(async () => { try { api.closeProxy() } catch { /* ignore */ } mod.__resetForTest() })

/* ============================================================
 * 核心断言：切换不中断 SSE
 * ============================================================ */

test('SSE 传输中切换线路 → SSE 继续跑完，不被掐断', async () => {
  const events = [
    ...Array.from({ length: 7 }, (_, i) => `data: ${i}\n\n`),
    'data: [DONE]\n\n',
  ]
  const env = await boot({ status: 200, sse: true, sseEvents: events, delayBodyMs: 250 })
  try {
    const received = []
    let switched = false

    const done = new Promise((resolve) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/sse', method: 'POST' }, (res) => {
        res.on('data', (c) => {
          received.push(c.toString())
          // 收到第 2 个事件时切换线路（模拟用户在流式过程中换 IP）
          if (!switched && received.length === 2) {
            switched = true
            api.dropAgents(HOST)
          }
        })
        res.on('end', resolve)
        res.on('error', () => resolve())
      })
      q.on('error', () => resolve())
      q.end('{}')
    })

    await done

    assert.equal(switched, true, '应已触发切换')
    assert.equal(received.length, 8, `SSE 应完整收到 8 个事件，实际 ${received.length}`)
    assert.match(received.join(''), /\[DONE\]/, '应收到结束标记')
  } finally { await shutdown(env) }
})

test('SSE 传输中池进入 draining，活动请求归零后才销毁', async () => {
  const env = await boot({ status: 200, sse: true, sseEvents: ['a\n\n', 'b\n\n', 'c\n\n'], delayBodyMs: 250 })
  try {
    let poolKey = null
    const done = new Promise((resolve) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/sse', method: 'POST' }, (res) => {
        if (!poolKey) poolKey = `${HOST}|${IP}`
        res.on('data', () => {
          if (!res.__drained) {
            res.__drained = true
            api.dropAgents(HOST)
            const s = api.poolRegistry.stats()
            assert.ok(s.drainingCount >= 1, `应进入 draining，实际 ${JSON.stringify(s)}`)
          }
        })
        res.on('end', resolve)
        res.on('error', () => resolve())
      })
      q.on('error', () => resolve())
      q.end('{}')
    })
    await done

    // 回收由 healthTick 周期驱动（生产环境按 probeIntervalMs 跑）。
    // 测试里显式触发一轮，验证「空闲池会被回收」这个契约本身。
    const r = api.poolRegistry.reclaim(api.getCfg().drainTimeoutMs)
    assert.ok(r.destroyed.length >= 1, '空闲的排空池应被回收')
    assert.equal(r.forced.length, 0, '不该需要强杀')
    assert.equal(api.poolRegistry.stats().drainingCount, 0)
    assert.ok(poolKey)
  } finally { await shutdown(env) }
})

/* ============================================================
 * 判死不再立即 destroy
 * ============================================================ */

test('IP 判死后池进入 draining 而非立即销毁', async () => {
  const env = await boot({ status: 200 }, { failThreshold: 1 })
  try {
    // 先制造一次请求，让池存在
    await new Promise((res) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/x' }, (x) => {
        x.resume(); x.on('end', res)
      })
      q.on('error', res); q.end()
    })

    // 判死该 IP
    const e = new Error('ECONNREFUSED'); e.code = 'ECONNREFUSED'
    api.recordRequestFailure(HOST, IP, { message: 'ECONNREFUSED', err: e }, api.getRouteGeneration(HOST))

    const s = api.poolRegistry.stats()
    assert.ok(s.drainingCount >= 1, `应进入 draining，实际 ${JSON.stringify(s)}`)
    assert.equal(api.getHealthState(HOST, IP), 'cooling')
  } finally { await shutdown(env) }
})

/* ============================================================
 * 回收
 * ============================================================ */

test('排空完成后 reclaim 会销毁池', async () => {
  const env = await boot({ status: 200 })
  try {
    await new Promise((res) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/x' }, (x) => {
        x.resume(); x.on('end', res)
      })
      q.on('error', res); q.end()
    })
    api.dropAgents(HOST)

    const r = api.poolRegistry.reclaim(api.getCfg().drainTimeoutMs)
    assert.ok(r.destroyed.length >= 1, '空闲的池应被回收')
    assert.equal(r.forced.length, 0, '不该需要强杀')
  } finally { await shutdown(env) }
})

test('drainTimeoutMs 默认 120 秒（适合长 SSE）', async () => {
  const env = await boot({ status: 200 })
  try {
    assert.equal(api.getCfg().drainTimeoutMs, 120000)
  } finally { await shutdown(env) }
})

/* ============================================================
 * 重复切换不泄漏
 * ============================================================ */

test('高频切换不会让 Agent 数量持续增长', async () => {
  const env = await boot({ status: 200 })
  try {
    for (let i = 0; i < 5; i += 1) {
      await new Promise((res) => {
        const q = http.request({ host: '127.0.0.1', port: env.port, path: '/x' }, (x) => {
          x.resume(); x.on('end', res)
        })
        q.on('error', res); q.end()
      })
      api.dropAgents(HOST)
      api.poolRegistry.reclaim(api.getCfg().drainTimeoutMs)
    }

    const s = api.poolRegistry.stats()
    assert.equal(s.drainingCount, 0, `排空池应全部回收，实际 ${s.drainingCount}`)
    assert.ok(s.activeCount <= 1, `active 池不该累积，实际 ${s.activeCount}`)
  } finally { await shutdown(env) }
})

test('切换后新请求走新池，不复用排空中的旧池', async () => {
  const env = await boot({ status: 200 })
  try {
    await new Promise((res) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/x' }, (x) => {
        x.resume(); x.on('end', res)
      })
      q.on('error', res); q.end()
    })

    const beforeId = api.poolRegistry.stats().activePools.find((p) => p.key === `${HOST}|${IP}`)?.id
    api.dropAgents(HOST)

    await new Promise((res) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/x' }, (x) => {
        x.resume(); x.on('end', res)
      })
      q.on('error', res); q.end()
    })

    const afterId = api.poolRegistry.stats().activePools.find((p) => p.key === `${HOST}|${IP}`)?.id
    assert.ok(afterId > beforeId, `新请求应拿到新一代池：${beforeId} → ${afterId}`)
  } finally { await shutdown(env) }
})

/* ============================================================
 * 阶段 4：状态接口与进程退出
 * ============================================================ */

test('statusSnapshot 暴露连接池状态与强制回收倒计时', async () => {
  const env = await boot({ status: 200 })
  try {
    await new Promise((res) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/x' }, (x) => {
        x.resume(); x.on('end', res)
      })
      q.on('error', res); q.end()
    })
    api.dropAgents(HOST)

    const cp = api.statusSnapshot().connectionPools
    assert.ok(cp.activeCount >= 0)
    assert.ok(cp.drainingCount >= 1)
    assert.equal(cp.drainTimeoutMs, 120000)
    const p = cp.drainingPools[0]
    assert.ok('forcedReclaimInMs' in p, '应给出还有多久强杀')
    assert.ok(p.forcedReclaimInMs > 0)
    assert.ok(p.forcedReclaimInMs <= cp.drainTimeoutMs)
  } finally { await shutdown(env) }
})

test('dispose 立即销毁所有池（退出不等排空）', async () => {
  const env = await boot({ status: 200 })
  try {
    await new Promise((res) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/x' }, (x) => {
        x.resume(); x.on('end', res)
      })
      q.on('error', res); q.end()
    })
    api.dropAgents(HOST)
    assert.ok(api.poolRegistry.stats().drainingCount >= 1)

    mod.dispose()
    // dispose 之后池登记表应清空
    const s = api.poolRegistry.stats()
    assert.equal(s.activeCount + s.drainingCount, 0, '退出时不该留任何池')
  } finally { await shutdown(env) }
})
