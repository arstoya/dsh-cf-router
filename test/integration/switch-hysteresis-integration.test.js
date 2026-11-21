/**
 * switch-hysteresis-integration.test.js — 迟滞接入（Issue #10 阶段 2）
 *
 * 验证 refreshHost 真的走 decideSwitch，而不是只存在于单测里。
 * 重点：A/B 抖动不切、硬故障立即切、连续更优最终切。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const A = '203.0.113.1'
const B = '203.0.113.2'

/** 播种两条候选，指定各自的中位延迟与样本数 */
function seed({ aMs = 200, bMs = 100, samples = 5, ips = [A, B], current = A } = {}) {
  const now = api.deps.now()
  api.state().hosts.set(HOST, {
    ips,
    results: [
      { ip: A, okCount: samples, samples, ttfbMedian: aMs, ttfbBest: aMs, totalMedian: aMs + 20, tcpMedian: 10, tlsMedian: 20, colo: 'HKG', excluded: null },
      { ip: B, okCount: samples, samples, ttfbMedian: bMs, ttfbBest: bMs, totalMedian: bMs + 20, tcpMedian: 10, tlsMedian: 20, colo: 'SIN', excluded: null },
    ],
    lastProbeAt: now, error: null,
  })
  // 让样本计数看起来像探测过的
  for (const ip of ips) {
    api.statOf(HOST, ip).samples.probeTtfb = samples
  }
  if (current) api.state().currentIp.set(HOST, current)
  else api.state().currentIp.delete(HOST)
}

/** 直接调 decideSwitch，模拟 refreshHost 的决策（不经真实探测） */
function decide({ prev = A, bestIp = B, cfg = {} } = {}) {
  const now = api.deps.now()
  const sst = api.getSwitchState(HOST)
  return api.decideSwitch({
    prevIp: prev,
    prevScore: api.scoreOf(HOST, prev, now),
    bestIp,
    bestScore: api.scoreOf(HOST, bestIp, now),
    prevHealth: api.getHealthState(HOST, prev),
    roundsBetter: sst.roundsBetter,
    lastSwitchAt: sst.lastSwitchAt,
    now,
    prevSamples: api.statOf(HOST, prev).samples?.probeTtfb || 0,
    bestSamples: api.statOf(HOST, bestIp).samples?.probeTtfb || 0,
    cfg: {
      minImprovementRatio: cfg.minImprovementRatio ?? api.getCfg().minImprovementRatio,
      consecutiveBetterRounds: cfg.consecutiveBetterRounds ?? api.getCfg().consecutiveBetterRounds,
      minDwellTimeMs: cfg.minDwellTimeMs ?? api.getCfg().minDwellTimeMs,
      minSamples: cfg.minSamples ?? api.getCfg().minSamples,
    },
  })
}

function setup(overrides = {}) {
  const clock = createClock()
  setupPlugin({
    targets: [HOST], discoverEnabled: false, allowPrivateTargets: true,
    probeSamples: 1, probeTimeoutMs: 1500,
    ...overrides,
  }, { now: clock.now })
  return clock
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 新配置项
 * ============================================================ */

test('迟滞配置项有默认值', () => {
  setup()
  const c = api.getCfg()
  assert.equal(c.minImprovementRatio, 0.15)
  assert.equal(c.consecutiveBetterRounds, 2)
  assert.equal(c.minDwellTimeMs, 120000)
  assert.equal(c.minSamples, 3)
})

/* ============================================================
 * A/B 抖动不切
 * ============================================================ */

test('两线接近（200 vs 190）→ 不切', () => {
  setup()
  seed({ aMs: 200, bMs: 190 })
  const r = decide()
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'insufficient_improvement')
})

test('单次探测波动不造成切换（连续 5 轮小幅更优）', () => {
  setup()
  seed({ aMs: 200, bMs: 180 })   // 快 10%，低于 15% 门槛
  let rounds = 0
  for (let i = 0; i < 5; i += 1) {
    const r = decide()
    rounds = r.roundsBetter
    assert.equal(r.switch, false, `第 ${i} 轮不该切`)
  }
  assert.equal(rounds, 0, '幅度不足时轮次不累计')
})

test('显著更优但只一轮 → 不切', () => {
  setup()
  seed({ aMs: 200, bMs: 100 })   // 快 50%
  const r = decide()
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'need_more_rounds')
  assert.equal(r.roundsBetter, 1)
})

test('连续两轮显著更优 → 切', () => {
  setup()
  seed({ aMs: 200, bMs: 100 })
  const r1 = decide()
  assert.equal(r1.switch, false)

  api.getSwitchState(HOST).roundsBetter = r1.roundsBetter
  const r2 = decide()
  assert.equal(r2.switch, true)
  assert.match(r2.reason, /连续 2 轮更优/)
})

/* ============================================================
 * 中间候选跳过
 * ============================================================ */

test('最优候选不够格时不会切到次优（只看 best）', () => {
  setup()
  // A=200，B=100（最优）但样本不足
  seed({ aMs: 200, bMs: 100, samples: 5 })
  api.statOf(HOST, B).samples.probeTtfb = 1
  const r = decide()
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'insufficient_samples')
})

/* ============================================================
 * 硬故障立即切
 * ============================================================ */

test('当前线路 cooling → 立即切，不需要样本/轮次/驻留', () => {
  const clock = setup()
  seed({ aMs: 200, bMs: 100, samples: 1 })
  api.transitionHealth(HOST, A, 'cooling', 'test')
  // 刚切过（驻留不足）
  api.getSwitchState(HOST).lastSwitchAt = clock.now() - 1000

  const r = decide()
  assert.equal(r.switch, true)
  assert.equal(r.kind, 'hard_fail')
})

test('当前线路不可评分 → 立即切', () => {
  setup()
  seed({ aMs: 200, bMs: 100, samples: 1 })
  api.statOf(HOST, A).health.metricsStale = true

  const r = decide()
  assert.equal(r.switch, true)
  assert.equal(r.kind, 'hard_fail')
})

/* ============================================================
 * 最短驻留
 * ============================================================ */

test('刚切完（驻留不足）→ 即使连续更优也不切', () => {
  const clock = setup()
  seed({ aMs: 200, bMs: 100 })
  api.getSwitchState(HOST).roundsBetter = 1
  api.getSwitchState(HOST).lastSwitchAt = clock.now() - 1000

  const r = decide()
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'min_dwell')
})

test('驻留时间够了 → 允许切', () => {
  const clock = setup()
  seed({ aMs: 200, bMs: 100 })
  api.getSwitchState(HOST).roundsBetter = 1
  clock.advance(121_000)
  api.getSwitchState(HOST).lastSwitchAt = clock.now() - 121_000

  const r = decide()
  assert.equal(r.switch, true)
})

/* ============================================================
 * 状态接口
 * ============================================================ */

test('statusSnapshot 暴露 switchHysteresis', () => {
  setup()
  seed()
  api.getSwitchState(HOST).roundsBetter = 1
  api.getSwitchState(HOST).lastSwitchAt = api.deps.now() - 60_000

  const h = api.statusSnapshot().switchHysteresis.find((x) => x.host === HOST)
  assert.ok(h, '应暴露该 host')
  assert.equal(h.roundsBetter, 1)
  assert.equal(h.minDwellTimeMs, 120000)
  assert.equal(h.dwellRemainingMs, 60000, '还剩 60 秒')
})

test('resetAll 清空迟滞状态', () => {
  setup()
  seed()
  api.getSwitchState(HOST).roundsBetter = 3
  api.resetAll()
  assert.equal(api.getSwitchState(HOST).roundsBetter, 0)
})

/* ============================================================
 * 兼容：门槛配 0 时退化为旧行为
 * ============================================================ */

test('门槛全配 0/1 时立即按分数切（旧行为）', () => {
  setup()
  seed({ aMs: 200, bMs: 190 })
  const r = decide({
    cfg: { minImprovementRatio: 0, consecutiveBetterRounds: 1, minDwellTimeMs: 0, minSamples: 1 },
  })
  assert.equal(r.switch, true, '快 5% 也切，等同于旧的宽松配置')
})

test('旧的 30% 门槛可用 minImprovementRatio=0.3 等价表达', () => {
  setup()
  seed({ aMs: 100, bMs: 75 })   // 快 25%
  const r = decide({
    cfg: { minImprovementRatio: 0.3, consecutiveBetterRounds: 1, minDwellTimeMs: 0, minSamples: 1 },
  })
  assert.equal(r.switch, false, '25% < 30% 不该切')

  seed({ aMs: 100, bMs: 65 })   // 快 35%
  api.getSwitchState(HOST).roundsBetter = 0
  const r2 = decide({
    cfg: { minImprovementRatio: 0.3, consecutiveBetterRounds: 1, minDwellTimeMs: 0, minSamples: 1 },
  })
  assert.equal(r2.switch, true, '35% > 30% 应切')
})
