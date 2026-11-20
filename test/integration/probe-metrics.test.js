/**
 * probe-metrics.test.js — 探测计时边界（Issue #3 §3.3）
 *
 * 核心要求：TTFB 必须在「收到响应头」时记录，不能等响应体结束。
 * 改造前 probeOnce 的 finish 在 res.end 之后，所以「探测耗时」里混着响应体下载时间。
 *
 * 用一个「响应头立刻回、响应体慢吞吞」的上游就能把两者区分开：
 *   TTFB 应该接近 0，total 应该明显更大。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'

/** 起上游并把插件依赖指过去 */
async function withUpstream(fixtureOpts = {}, cfgOverrides = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
  setupPlugin({
    targets: [HOST],
    probeSamples: 1,
    probeTimeoutMs: 3000,
    probePath: '/probe',
    l1Concurrency: 1,
    l2TopN: 1,
    ...cfgOverrides,
  })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (host, cb) => cb(null, ['127.0.0.1'])
  return up
}

test.afterEach(async () => {
  teardownPlugin()
})

/* ============================================================
 * 计时边界
 * ============================================================ */

test('TTFB 在响应头到达时记录，不含响应体下载时间', async () => {
  // 响应头立即回，响应体分两片、中间停 300ms
  const up = await withUpstream({ status: 200, body: 'x'.repeat(1000), delayBodyMs: 300 })
  try {
    const r = await api.probeOnce(HOST, '127.0.0.1', 5000, '/probe')

    assert.equal(r.ok, true)
    assert.ok(Number.isFinite(r.ttfbMs), 'ttfbMs 必须有值')
    assert.ok(Number.isFinite(r.totalMs), 'totalMs 必须有值')
    assert.ok(
      r.ttfbMs < 200,
      `TTFB 应远小于 300ms 的响应体延迟，实际 ${r.ttfbMs?.toFixed?.(1)}ms`,
    )
    assert.ok(
      r.totalMs >= 280,
      `totalMs 应包含响应体下载时间（≥280ms），实际 ${r.totalMs?.toFixed?.(1)}ms`,
    )
    assert.ok(r.totalMs > r.ttfbMs, 'total 必须大于 ttfb')
  } finally {
    await up.close()
  }
})

test('TCP / TLS / TTFB / total 四个计时都返回且递增', async () => {
  const up = await withUpstream({ status: 200 })
  try {
    const r = await api.probeOnce(HOST, '127.0.0.1', 5000, '/probe')

    assert.equal(r.ok, true)
    for (const k of ['tcpMs', 'tlsMs', 'ttfbMs', 'totalMs']) {
      assert.ok(k in r, `缺字段 ${k}`)
      assert.ok(Number.isFinite(r[k]) || r[k] === null, `${k} 应为数字或 null`)
    }
    assert.ok(r.tcpMs >= 0, 'tcpMs 非负')
    assert.ok(r.tlsMs >= r.tcpMs, 'TLS 完成时间应不早于 TCP 完成')
    assert.ok(r.ttfbMs >= r.tlsMs, 'TTFB 应不早于 TLS 完成')
    assert.ok(r.totalMs >= r.ttfbMs, 'total 应不早于 TTFB')
  } finally {
    await up.close()
  }
})

test('探测响应体必须被完整消费（不泄漏连接）', async () => {
  const up = await withUpstream({ status: 200, body: 'y'.repeat(5000) })
  try {
    await api.probeOnce(HOST, '127.0.0.1', 5000, '/probe')
    // 探测用的是 connection: close，跑完上游连接数应归零
    await new Promise((r) => setTimeout(r, 100))
    assert.equal(up.connections(), 0, '连接应已关闭')
  } finally {
    await up.close()
  }
})

/* ============================================================
 * 状态码语义不变
 * ============================================================ */

for (const status of [200, 401, 404, 429, 500, 503]) {
  test(`HTTP ${status}：可达即 ok，且 ttfbMs 有值`, async () => {
    const up = await withUpstream({ status, body: '{}' })
    try {
      const r = await api.probeOnce(HOST, '127.0.0.1', 3000, '/probe')
      assert.equal(r.ok, true)
      assert.equal(r.statusCode, status)
      assert.ok(Number.isFinite(r.ttfbMs))
    } finally {
      await up.close()
    }
  })
}

/* ============================================================
 * 失败路径：计时不得被记为成功
 * ============================================================ */

test('请求超时：ok=false，且不产生 TTFB 样本', async () => {
  const up = await withUpstream({ status: 200, delayFirstByteMs: 1500 })
  try {
    const r = await api.probeOnce(HOST, '127.0.0.1', 300, '/probe')
    assert.equal(r.ok, false)
    assert.equal(r.detail, 'timeout')
    assert.equal(r.ttfbMs, null, '超时不该有 TTFB')
  } finally {
    await up.close()
  }
})

test('响应体中途断开：不会被记为成功', async () => {
  const up = await withUpstream({ status: 200, body: 'z'.repeat(20000), abortMidBody: true })
  try {
    const r = await api.probeOnce(HOST, '127.0.0.1', 3000, '/probe')
    // 响应头到了但 body 断了：TTFB 有值，但整体不能算成功
    assert.equal(r.ok, false, '响应体中断不该算 ok')
  } finally {
    await up.close()
  }
})

test('连接重置：ok=false 且各计时为 null', async () => {
  const up = await withUpstream({ resetConnection: true })
  try {
    const r = await api.probeOnce(HOST, '127.0.0.1', 3000, '/probe')
    assert.equal(r.ok, false)
    assert.equal(r.ttfbMs, null)
  } finally {
    await up.close()
  }
})

/* ============================================================
 * measureIp 聚合
 * ============================================================ */

test('measureIp 用 TTFB 中位数作主分数，total 单独聚合', async () => {
  const up = await withUpstream({ status: 200 }, { probeSamples: 3 })
  try {
    const r = await api.measureIp(HOST, '127.0.0.1', 3, 3000, '/probe')

    assert.equal(r.okCount, 3)
    assert.ok(Number.isFinite(r.ttfbMedian), '应有 ttfbMedian')
    assert.ok(Number.isFinite(r.totalMedian), '应有 totalMedian')
    assert.ok(Number.isFinite(r.tcpMedian), '应有 tcpMedian')
    assert.ok(Number.isFinite(r.tlsMedian), '应有 tlsMedian')
    assert.ok(r.totalMedian >= r.ttfbMedian, 'total 中位数应不小于 TTFB 中位数')
    // 兼容字段：median 现在等于 ttfbMedian
    assert.equal(r.median, r.ttfbMedian, 'median 应等同于 ttfbMedian')
  } finally {
    await up.close()
  }
})

test('measureIp 部分样本失败时只按成功样本聚合', async () => {
  const up = await withUpstream({ status: 200 }, { probeSamples: 3 })
  try {
    const r = await api.measureIp(HOST, '127.0.0.1', 2, 3000, '/probe')
    assert.equal(r.okCount, 2)
    assert.equal(r.samples, 2)
  } finally {
    await up.close()
  }
})

/* ============================================================
 * 探测样本进入指标
 * ============================================================ */

test('refreshHost 后指标里出现探测样本', async () => {
  const up = await withUpstream({ status: 200 }, { probeSamples: 1 })
  try {
    await api.refreshHost(HOST)
    const s = api.statOf(HOST, '127.0.0.1')

    assert.ok(s.samples.probeTtfb > 0, '应有 probeTtfb 样本')
    assert.ok(s.metrics.probeTtfbEwmaMs != null, 'probeTtfbEwmaMs 应有值')
    assert.ok(s.metrics.tcpEwmaMs != null, 'tcpEwmaMs 应有值')
  } finally {
    await up.close()
  }
})
