/**
 * concurrency.test.js — 并发与资源不泄漏（Issue #15 15-B）
 *
 * 15-B 原有的三条要求里，24 小时长稳需要实机观察，这里覆盖
 * 现在就能测的部分：
 *
 *   · 多 host 并发刷新互不干扰
 *   · 同一 host 并发刷新（probeGeneration 保护）
 *   · 候选池并发写入不丢数据
 *   · 高频切换后 Agent 数量不增长
 *   · Map 规模在多轮探测后稳定
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi

async function bootHosts(hostCount, overrides = {}) {
  const targets = Array.from({ length: hostCount }, (_, i) => `h${i}.test`)
  const up = await startHttpsUpstream({ status: 200 })
  const clock = {
    t: 1_000_000,
    now() { return this.t },
    advance(ms) { this.t += ms },
  }
  setupPlugin({
    targets,
    discoverEnabled: false,
    allowPrivateTargets: true,
    probeSamples: 1,
    probeTimeoutMs: 1500,
    ...overrides,
  }, { now: () => clock.now() })
  api.deps.upstreamPort = up.port
  // 多 host 测试用的是 h0.test / h1.test，而 fixture 证书的 SAN 只含 localhost。
  // 这里跳过主机名校验：本文件测的是并发逻辑，TLS 校验有专门的测试覆盖。
  api.deps.tlsOptions = { ca: up.cert, checkServerIdentity: () => undefined }
  api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
  return { up, clock, targets }
}

test.afterEach(async () => {
  try { api.closeProxy() } catch { /* ignore */ }
  teardownPlugin()
})

/* ============================================================
 * 多 host 并发
 * ============================================================ */

test('多 host 并发刷新互不干扰', async () => {
  const { up, targets } = await bootHosts(3)
  try {
    await Promise.all(targets.map((h) => api.refreshHost(h)))

    for (const h of targets) {
      const entry = api.state().hosts.get(h)
      assert.ok(entry, `${h} 应有探测结果`)
      assert.equal(entry.error, null, `${h} 不该有错误`)
      assert.ok(entry.results.length > 0, `${h} 应有候选`)
    }

    // 三个 host 各自独立选路
    const currents = targets.map((h) => api.state().currentIp.get(h))
    assert.equal(currents.filter(Boolean).length, 3, '三个 host 都应有当前线路')
  } finally { await up.close() }
})

test('多 host 的统计互不串味', async () => {
  const { up, targets } = await bootHosts(2)
  try {
    await Promise.all(targets.map((h) => api.refreshHost(h)))

    // 只给 h0 记失败
    const e = new Error('ECONNREFUSED'); e.code = 'ECONNREFUSED'
    api.recordRequestFailure(targets[0], '127.0.0.1', { message: 'x', err: e }, 0)

    assert.ok(api.statOf(targets[0], '127.0.0.1').fail > 0, 'h0 应有失败')
    assert.equal(api.statOf(targets[1], '127.0.0.1').fail, 0, 'h1 不该受影响')
  } finally { await up.close() }
})

/* ============================================================
 * 同一 host 并发刷新（generation 保护）
 * ============================================================ */

test('同一 host 并发刷新：旧轮次不覆盖新结果', async () => {
  const { up, targets } = await bootHosts(1)
  try {
    const host = targets[0]
    // 同时发起 5 轮，只有最后一轮的 generation 是有效的
    const rounds = Array.from({ length: 5 }, () => api.refreshHost(host))
    await Promise.all(rounds)

    const entry = api.state().hosts.get(host)
    assert.ok(entry, '应有一份结果')
    // generation 必须等于探测轮数（每轮 +1）
    assert.equal(api.getProbeGeneration(host), 5, 'generation 应等于发起轮数')
    assert.equal(entry.results.length, 1, '结果里不该出现重复候选')
  } finally { await up.close() }
})

test('并发刷新后 host 数不会膨胀', async () => {
  const { up, targets } = await bootHosts(1)
  try {
    for (let i = 0; i < 10; i += 1) {
      await api.refreshHost(targets[0])
    }
    assert.equal(api.state().hosts.size, 1, 'hosts 应仍是 1 个')
  } finally { await up.close() }
})

/* ============================================================
 * 候选池并发
 * ============================================================ */

test('候选池并发写入不丢数据', async () => {
  const { up, targets } = await bootHosts(1)
  try {
    const host = targets[0]
    const pool = api.getCandidatePool(host)
    const before = pool.candidates.size

    // 并发塞入 50 个不同 IP
    await Promise.all(Array.from({ length: 50 }, (_, i) => {
      api.mergeCandidates(pool, { discoveredIps: [`10.0.${i >> 8}.${i & 255}`] }, api.deps.now())
      return Promise.resolve()
    }))

    assert.equal(pool.candidates.size, before + 50, '50 个都应在池里')
    // 去重：Key 唯一
    const keys = [...pool.candidates.keys()]
    assert.equal(new Set(keys).size, keys.length)
  } finally { await up.close() }
})

test('并发探测同一 host 不让候选池计数错乱', async () => {
  const { up, targets } = await bootHosts(1)
  try {
    const host = targets[0]
    await api.refreshHost(host)
    const c = api.getCandidatePool(host).candidates.get('127.0.0.1')
    const n1 = c.probeCount

    await Promise.all([api.refreshHost(host), api.refreshHost(host)])
    const n2 = api.getCandidatePool(host).candidates.get('127.0.0.1').probeCount

    assert.ok(n2 >= n1, 'probeCount 只增不减')
    assert.ok(n2 - n1 <= 2, `两轮刷新最多 +2，实际 +${n2 - n1}`)
  } finally { await up.close() }
})

/* ============================================================
 * 切换与连接池
 * ============================================================ */

test('高频切换后 Agent 数量不增长', async () => {
  const { up, targets } = await bootHosts(1, { failThreshold: 1 })
  try {
    const host = targets[0]
    await api.refreshHost(host)

    for (let i = 0; i < 20; i += 1) {
      api.switchRoute(host, i % 2 === 0 ? '127.0.0.1' : null, `test${i}`)
      api.poolRegistry.reclaim(0)   // 立刻回收空闲池
    }

    const st = api.poolRegistry.stats()
    assert.ok(st.activeCount + st.drainingCount <= 2,
      `池数量应受控，实际 active=${st.activeCount} draining=${st.drainingCount}`)
  } finally { await up.close() }
})

test('多轮探测后各 Map 规模稳定', async () => {
  const { up, targets } = await bootHosts(2)
  try {
    for (let round = 0; round < 5; round += 1) {
      await Promise.all(targets.map((h) => api.refreshHost(h)))
    }

    const st = api.state()
    assert.equal(st.hosts.size, 2, 'hosts 稳定')
    assert.equal(st.currentIp.size, 2, 'currentIp 稳定')
    assert.ok(st.ipStats.size <= 8, `ipStats 应受控，实际 ${st.ipStats.size}`)
    assert.equal(api.candidatePools.size, 2, 'candidatePools 稳定')
  } finally { await up.close() }
})

/* ============================================================
 * 并发请求 + 并发切换
 * ============================================================ */

test('请求进行中并发切换不崩、不丢统计', async () => {
  const { up, targets } = await bootHosts(1)
  try {
    const host = targets[0]
    const port = await freePort()
    api.configure({ ...api.getCfg(), listenHost: '127.0.0.1', listenPort: port })
    const srv = api.createProxy()
    await new Promise((r) => srv.once('listening', r))
    await api.refreshHost(host)

    const before = api.statusSnapshot().stats.requests

    // 并发发请求 + 并发切换
    const reqs = Array.from({ length: 10 }, () => new Promise((res) => {
      const q = http.request({ host: '127.0.0.1', port, path: '/x', method: 'POST' }, (r) => {
        r.resume(); r.on('end', res)
      })
      q.on('error', res); q.end('{}')
    }))
    const sw = (async () => {
      for (let i = 0; i < 5; i += 1) {
        api.switchRoute(host, i % 2 ? null : '127.0.0.1', `race${i}`)
        await new Promise((r) => setTimeout(r, 5))
      }
    })()

    await Promise.all([...reqs, sw])

    const after = api.statusSnapshot().stats.requests
    assert.equal(after - before, 10, '10 个请求都该被计到')
    // 进程没崩就是最大的验收
    assert.ok(api.getRouteGeneration(host) >= 5, '切换都已记录')
  } finally { await up.close() }
})
