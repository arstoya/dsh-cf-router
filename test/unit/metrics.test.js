/**
 * metrics.test.js — 延迟指标拆分（Issue #3）
 *
 * 改造前的问题：
 *   1. probeOnce 的计时到 `res.end` 才结束，所以「探测中位数」实际混着响应体下载时间
 *   2. handleProxy 里 `recordRequestSuccess(host, ip, { ttfbMs: tlsMs ?? ttfb })`
 *      —— TLS 握手耗时和 HTTP 首字节混进同一个 EWMA
 *   3. 新连接与复用连接的 TTFB 不区分
 *   4. scoreOf 对不同量纲的两个数取 min，缺乏统计意义
 *
 * 本文件锁定拆分后的契约：
 *   - 每个指标只由一种事件产生，单位统一是毫秒，含义见下表
 *   - 无法可靠采集时明确为 null，绝不拿别的指标顶替
 *   - ewmaMaxMs 只作用于可能被上游 prefill 污染的 TTFB
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'
import { assertCloseTo } from '../helpers/assertions.mjs'

const api = mod.__testApi
const HOST = 'localhost'

function setup(overrides = {}) {
  const clock = createClock()
  setupPlugin({ ewmaAlpha: 0.5, ewmaMaxMs: 3000, ...overrides }, { now: clock.now })
  return clock
}

function seed(entries) {
  api.state().hosts.set(HOST, {
    ips: entries.map((e) => e.ip),
    results: entries.map((e) => ({
      ip: e.ip,
      okCount: e.okCount ?? 3,
      samples: 3,
      // 探测结果现在用 TTFB 中位数作为分数来源
      ttfbMedian: e.ttfb ?? 100,
      ttfbBest: e.ttfb ?? 100,
      totalMedian: e.total ?? (e.ttfb ?? 100) + 20,
      tcpMedian: e.tcp ?? 10,
      tlsMedian: e.tls ?? 20,
      colo: 'HKG',
      excluded: null,
    })),
    lastProbeAt: api.deps.now(),
    error: null,
  })
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * updateEwma 通用函数
 * ============================================================ */

test('updateEwma：首个样本直接成为起点', () => {
  assert.equal(api.updateEwma(null, 400, 0.5), 400)
})

test('updateEwma：第二个样本按 alpha 加权', () => {
  assertCloseTo(api.updateEwma(400, 600, 0.5), 500, { label: 'ewma' })
  assertCloseTo(api.updateEwma(400, 600, 0.25), 450, { label: 'ewma' })
})

test('updateEwma：脏样本一律不改动原值', () => {
  for (const bad of [NaN, Infinity, -Infinity, -1, 0, null, undefined, '100']) {
    assert.equal(api.updateEwma(300, bad, 0.5), 300, `脏样本 ${String(bad)} 不该改 EWMA`)
  }
})

test('updateEwma：alpha 越界被夹取', () => {
  // alpha 5 → 夹到 0.9：1000*0.1 + 2000*0.9 = 1900
  assertCloseTo(api.updateEwma(1000, 2000, 5), 1900, { label: 'alpha 上限' })
  // alpha -1 → 夹到 0.05：1000*0.95 + 2000*0.05 = 1050
  assertCloseTo(api.updateEwma(1000, 2000, -1), 1050, { label: 'alpha 下限' })
})

/* ============================================================
 * 指标结构：六个独立指标
 * ============================================================ */

test('statOf 初始结构含六个独立 EWMA 与六个采样计数', () => {
  setup()
  const s = api.statOf(HOST, '203.0.113.1')

  for (const k of ['tcpEwmaMs', 'tlsEwmaMs', 'probeTtfbEwmaMs', 'probeTotalEwmaMs', 'freshTtfbEwmaMs', 'reusedTtfbEwmaMs']) {
    assert.ok(k in s.metrics, `metrics 缺 ${k}`)
    assert.equal(s.metrics[k], null, `${k} 初始应为 null 而非 0`)
  }
  for (const k of ['tcp', 'tls', 'probeTtfb', 'probeTotal', 'freshTtfb', 'reusedTtfb']) {
    assert.equal(s.samples[k], 0, `${k} 初始计数应为 0`)
  }
})

test('每个指标只由对应事件更新，互不串味', () => {
  setup()
  const s = api.statOf(HOST, '203.0.113.1')

  api.recordProbeSample(HOST, '203.0.113.1', { tcpMs: 12, tlsMs: 34, ttfbMs: 56, totalMs: 78 })

  assertCloseTo(s.metrics.tcpEwmaMs, 12)
  assertCloseTo(s.metrics.tlsEwmaMs, 34)
  assertCloseTo(s.metrics.probeTtfbEwmaMs, 56)
  assertCloseTo(s.metrics.probeTotalEwmaMs, 78)
  // 真实请求指标不该被探测污染
  assert.equal(s.metrics.freshTtfbEwmaMs, null)
  assert.equal(s.metrics.reusedTtfbEwmaMs, null)
})

test('新连接与复用连接的 TTFB 走不同 EWMA', () => {
  setup()
  const s = api.statOf(HOST, '203.0.113.1')

  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 300, reused: false }, 0)
  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 100, reused: true }, 0)

  assertCloseTo(s.metrics.freshTtfbEwmaMs, 300, { label: '新连接' })
  assertCloseTo(s.metrics.reusedTtfbEwmaMs, 100, { label: '复用连接' })
  assert.equal(s.samples.freshTtfb, 1)
  assert.equal(s.samples.reusedTtfb, 1)
})

test('TLS 采样不进入 TTFB EWMA（改造前二者混在一起）', () => {
  setup()
  const s = api.statOf(HOST, '203.0.113.1')

  // 新连接：TLS 80ms，TTFB 500ms。改造前会把 80ms 当 TTFB 记进去
  api.recordRequestSuccess(HOST, '203.0.113.1', { tlsMs: 80, ttfbMs: 500, totalMs: 900, reused: false }, 0)

  assertCloseTo(s.metrics.tlsEwmaMs, 80, { label: 'TLS' })
  assertCloseTo(s.metrics.freshTtfbEwmaMs, 500, { label: 'TTFB' })
  // 关键：TTFB 的 EWMA 绝不能因为 TLS 快而变小
  assert.notEqual(s.metrics.freshTtfbEwmaMs, 80)
})

/* ============================================================
 * 模型延迟隔离（Issue #3 §3.8）
 * ============================================================ */

test('10 秒模型推理不会被当成 TLS 网络延迟', () => {
  setup({ ewmaMaxMs: 3000 })
  const s = api.statOf(HOST, '203.0.113.1')

  // IP-A：TLS 100ms，但模型想了 10 秒才吐首字节
  api.recordRequestSuccess(HOST, '203.0.113.1', { tlsMs: 100, ttfbMs: 10_100, reused: false }, 0)

  assertCloseTo(s.metrics.tlsEwmaMs, 100, { label: 'TLS 仍是 100ms' })
  // 关键：TLS 与 TTFB 是两个指标，不能互相顶替
  assert.notEqual(s.metrics.freshTtfbEwmaMs, 100, 'TTFB 不能取 TLS 的值')
  assert.equal(s.lastTtfbMs, 10_100, '原始 TTFB 必须留档')
})

test('超额 TTFB 样本仍进 EWMA，只额外标记 overCap（不丢原始观测）', () => {
  setup({ ewmaMaxMs: 3000 })
  const s = api.statOf(HOST, '203.0.113.1')

  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 10_100, reused: false }, 0)

  assert.equal(s.samples.freshTtfb, 1, '样本必须计入总数')
  assert.equal(s.samples.freshTtfbOverCap, 1, '同时标记为超额')
  assertCloseTo(s.metrics.freshTtfbEwmaMs, 10_100, { label: '原始值仍进 EWMA' })
  assert.equal(s.recentTtfbMs.length, 1, '原始环里应留一条')
  assert.equal(s.recentTtfbMs[0].ms, 10_100)
  assert.equal(s.recentTtfbMs[0].source, 'fresh')
})

test('TLS 快不能把 10 秒 TTFB 伪装成 100ms', () => {
  setup({ ewmaMaxMs: 3000 })
  const s = api.statOf(HOST, '203.0.113.1')

  api.recordRequestSuccess(HOST, '203.0.113.1', { tlsMs: 100, ttfbMs: 10_100, reused: false }, 0)
  // 评分绝不能拿 TLS 的值顶替 TTFB
  const score = api.scoreOf(HOST, '203.0.113.1', api.deps.now())
  assert.notEqual(score, 100, '评分不能等于 TLS 耗时')
})

test('ewmaMaxMs 只用于分级，不作用于 TCP/TLS，也不丢弃任何 TTFB', () => {
  setup({ ewmaMaxMs: 200 })
  const s = api.statOf(HOST, '203.0.113.1')

  // TLS 800ms 远超 ewmaMaxMs(200)，但它不是 prefill，必须照记
  api.recordRequestSuccess(HOST, '203.0.113.1', { tlsMs: 800, ttfbMs: 900, reused: false }, 0)

  assertCloseTo(s.metrics.tlsEwmaMs, 800, { label: 'TLS 不受阈值影响' })
  // TTFB 900 > 200：仍进 EWMA，只是被标记
  assertCloseTo(s.metrics.freshTtfbEwmaMs, 900, { label: 'TTFB 仍入库' })
  assert.equal(s.samples.freshTtfbOverCap, 1, '被标记为超额')
})

/* ============================================================
 * scoreOf：只用有明确来源的数据
 * ============================================================ */

test('scoreOf 以探测 TTFB 为主要依据', () => {
  setup()
  seed([{ ip: '203.0.113.1', ttfb: 120 }])

  assertCloseTo(api.scoreOf(HOST, '203.0.113.1', api.deps.now()), 120)
})

test('scoreOf 不再对 TLS 与完整往返取 min', () => {
  setup()
  seed([{ ip: '203.0.113.1', ttfb: 600, total: 900, tls: 80 }])
  const s = api.statOf(HOST, '203.0.113.1')

  // 即使真实请求的 TLS 只有 80ms，也不能把分数拉到 80
  api.recordRequestSuccess(HOST, '203.0.113.1', { tlsMs: 80, ttfbMs: 100, reused: false }, 0)

  const score = api.scoreOf(HOST, '203.0.113.1', api.deps.now())
  assert.ok(score >= 80, `评分不该低于 80，实际 ${score}`)
  assert.notEqual(score, 80, '不能用 TLS 值作为评分')
})

test('scoreOf 在没有任何探测数据时返回 Infinity', () => {
  setup()
  api.state().hosts.set(HOST, { ips: [], results: [], lastProbeAt: api.deps.now(), error: 'DNS 无 A 记录' })
  assert.equal(api.scoreOf(HOST, '203.0.113.1', api.deps.now()), Infinity)
})

test('scoreOf：单条超大样本不会把评分拉偏（用原始样本中位数，不用 EWMA）', () => {
  setup({ ewmaAlpha: 0.5, ewmaMaxMs: 300 })
  api.state().hosts.set(HOST, {
    ips: ['203.0.113.1'],
    results: [{ ip: '203.0.113.1', okCount: 0, samples: 6, ttfbMedian: Infinity, ttfbBest: Infinity, colo: 'HKG', excluded: null }],
    lastProbeAt: api.deps.now(),
    error: null,
  })
  // 5 条 120ms + 1 条 5000ms（模型 prefill）
  for (let i = 0; i < 5; i += 1) api.recordProbeSample(HOST, '203.0.113.1', { ttfbMs: 120 })
  api.recordProbeSample(HOST, '203.0.113.1', { ttfbMs: 5000 })

  const score = api.scoreOf(HOST, '203.0.113.1', api.deps.now())
  assertCloseTo(score, 120, { label: '评分应是干净样本的中位数' })
  // EWMA 确实被拉高了，但它不参与评分
  assert.ok(api.statOf(HOST, '203.0.113.1').metrics.probeTtfbEwmaMs > 500, 'EWMA 保留被污染的事实')
})

test('scoreOf：全部样本超额时判为不可评分', () => {
  setup({ ewmaMaxMs: 300 })
  api.state().hosts.set(HOST, {
    ips: ['203.0.113.1'],
    results: [{ ip: '203.0.113.1', okCount: 0, samples: 3, ttfbMedian: Infinity, ttfbBest: Infinity, colo: 'HKG', excluded: null }],
    lastProbeAt: api.deps.now(),
    error: null,
  })
  for (let i = 0; i < 3; i += 1) api.recordProbeSample(HOST, '203.0.113.1', { ttfbMs: 5000 })

  assert.equal(api.scoreOf(HOST, '203.0.113.1', api.deps.now()), Infinity, '没有干净样本时不可评分')
})

test('scoreOf 对冷却中的 IP 仍返回 Infinity', () => {
  const clock = setup()
  seed([{ ip: '203.0.113.1', ttfb: 100 }])
  api.statOf(HOST, '203.0.113.1').penaltyUntil = clock.now() + 5000

  assert.equal(api.scoreOf(HOST, '203.0.113.1', clock.now()), Infinity)
})

/* ============================================================
 * 状态接口
 * ============================================================ */

test('statusSnapshot 每个候选暴露六个独立指标与计数', () => {
  setup()
  seed([{ ip: '203.0.113.1', ttfb: 150 }])
  api.recordProbeSample(HOST, '203.0.113.1', { tcpMs: 10, tlsMs: 20, ttfbMs: 150, totalMs: 180 })
  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 200, reused: true }, 0)

  const cand = api.statusSnapshot().hosts[0].candidates[0]

  for (const k of ['tcpEwmaMs', 'tlsEwmaMs', 'probeTtfbEwmaMs', 'probeTotalEwmaMs', 'freshTtfbEwmaMs', 'reusedTtfbEwmaMs']) {
    assert.ok(k in cand.metrics, `候选缺 metrics.${k}`)
  }
  for (const k of ['tcp', 'tls', 'probeTtfb', 'probeTotal', 'freshTtfb', 'reusedTtfb', 'probeTtfbOverCap']) {
    assert.ok(k in cand.samples, `候选缺 samples.${k}`)
  }
  assert.ok(Array.isArray(cand.recentTtfbMs), '候选应暴露原始 TTFB 环')

  assertCloseTo(cand.metrics.tcpEwmaMs, 10)
  assertCloseTo(cand.metrics.probeTtfbEwmaMs, 150)
  assertCloseTo(cand.metrics.reusedTtfbEwmaMs, 200)
  assert.equal(cand.metrics.freshTtfbEwmaMs, null, '没有新连接样本时应为 null')
})

test('原始 TTFB 环：保留最近 20 条，区分 probe / fresh / reused', () => {
  setup()
  const s = api.statOf(HOST, '203.0.113.1')

  api.recordProbeSample(HOST, '203.0.113.1', { ttfbMs: 50 })
  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 60, reused: false }, 0)
  api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 40, reused: true }, 0)

  assert.deepEqual(s.recentTtfbMs.map((r) => r.source), ['probe', 'fresh', 'reused'])
  assert.deepEqual(s.recentTtfbMs.map((r) => r.ms), [50, 60, 40])

  // 灌满超过 20 条，只保留最后 20
  for (let i = 0; i < 30; i += 1) api.recordProbeSample(HOST, '203.0.113.1', { ttfbMs: 100 + i })
  assert.equal(s.recentTtfbMs.length, 20, '环容量应为 20')
  assert.equal(s.recentTtfbMs.at(-1).ms, 129)
})

test('statusSnapshot 无样本时全部为 null，不伪造默认值', () => {
  setup()
  seed([{ ip: '203.0.113.1', ttfb: 100 }])

  const cand = api.statusSnapshot().hosts[0].candidates[0]
  for (const k of ['tcpEwmaMs', 'tlsEwmaMs', 'freshTtfbEwmaMs', 'reusedTtfbEwmaMs']) {
    assert.equal(cand.metrics[k], null, `${k} 不该有值`)
  }
})

test('statusSnapshot 保留兼容字段 probeMs（语义改为 TTFB）', () => {
  setup()
  seed([{ ip: '203.0.113.1', ttfb: 123 }])
  const cand = api.statusSnapshot().hosts[0].candidates[0]

  assert.equal(cand.probeMs, 123, 'probeMs 现在表示探测 TTFB 中位数')
  assert.equal(cand.probeTtfbMs, 123)
  assert.equal(cand.probeTotalMs, 143, 'totalMedian = ttfb + 20')
})
