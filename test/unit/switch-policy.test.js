/**
 * switch-policy.test.js — 切换迟滞策略（Issue #10 阶段 1）
 *
 * 三个独立闸门：样本量 → 改善幅度 → 连续更优轮次 → 最短驻留。
 * 外加一条铁律：**硬故障不受任何迟滞约束**。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  decideSwitch, hasEnoughSamples, SWITCH_HARD_FAIL, SWITCH_PERFORMANCE, SWITCH_NONE,
} from '../../lib/switch-policy.mjs'

const T = 1_700_000_000_000
const CFG = {
  minImprovementRatio: 0.15,
  consecutiveBetterRounds: 2,
  minDwellTimeMs: 120_000,
  minSamples: 3,
}

/** 构造一个「应该切」的基线输入 */
const base = (over = {}) => ({
  prevIp: 'a', prevScore: 200, bestIp: 'b', bestScore: 100,
  prevHealth: 'healthy', roundsBetter: 0, lastSwitchAt: T - 200_000,
  now: T, prevSamples: 5, bestSamples: 5, cfg: CFG, ...over,
})

/* ============================================================
 * 硬故障：不受任何迟滞约束
 * ============================================================ */

test('当前线路 cooling → 立即切，即使驻留时间是 0', () => {
  const r = decideSwitch(base({
    prevHealth: 'cooling', lastSwitchAt: T, roundsBetter: 0, prevSamples: 0, bestSamples: 0,
  }))
  assert.equal(r.switch, true)
  assert.equal(r.kind, SWITCH_HARD_FAIL)
})

test('当前线路 half_open → 立即切', () => {
  const r = decideSwitch(base({ prevHealth: 'half_open', lastSwitchAt: T }))
  assert.equal(r.switch, true)
  assert.equal(r.kind, SWITCH_HARD_FAIL)
})

test('当前线路不可评分（Infinity）→ 立即切', () => {
  const r = decideSwitch(base({ prevScore: Infinity, prevSamples: 0, bestSamples: 0 }))
  assert.equal(r.switch, true)
  assert.equal(r.kind, SWITCH_HARD_FAIL)
})

test('硬故障不被最短驻留时间阻止', () => {
  const r = decideSwitch(base({
    prevHealth: 'cooling', lastSwitchAt: T - 1000, cfg: { ...CFG, minDwellTimeMs: 600_000 },
  }))
  assert.equal(r.switch, true, '硬故障优先于驻留约束')
})

test('硬故障不被样本不足阻止', () => {
  const r = decideSwitch(base({
    prevHealth: 'cooling', prevSamples: 0, bestSamples: 0, cfg: { ...CFG, minSamples: 10 },
  }))
  assert.equal(r.switch, true)
})

/* ============================================================
 * 性能切换：四个闸门
 * ============================================================ */

test('样本不足 → 不切，且不累计轮次', () => {
  const r = decideSwitch(base({ prevSamples: 1, bestSamples: 1 }))
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'insufficient_samples')
  assert.equal(r.roundsBetter, 0, '样本不足不该计入连续更优')
})

test('改善幅度不足 → 不切', () => {
  // 200 → 190 只快了 5%，门槛 15%
  const r = decideSwitch(base({ bestScore: 190 }))
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'insufficient_improvement')
  assert.ok(r.improvementRatio < 0.15)
})

test('改善幅度刚好过线 → 进入轮次判定', () => {
  // 200 → 170 快 15%
  const r = decideSwitch(base({ bestScore: 170, roundsBetter: 1 }))
  assert.equal(r.switch, true, '已有 1 轮 + 本轮 = 2 轮，达门槛')
  assert.equal(r.kind, SWITCH_PERFORMANCE)
})

test('连续更优不足 → 不切，但累计轮次 +1', () => {
  const r = decideSwitch(base({ roundsBetter: 0 }))
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'need_more_rounds')
  assert.equal(r.roundsBetter, 1, '应记住这一轮')
})

test('连续更优达标 → 切，且轮次清零', () => {
  const r = decideSwitch(base({ roundsBetter: 1 }))
  assert.equal(r.switch, true)
  assert.equal(r.roundsBetter, 0, '切换后清零')
})

test('驻留时间不足 → 不切', () => {
  const r = decideSwitch(base({ roundsBetter: 1, lastSwitchAt: T - 1000 }))
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'min_dwell')
})

test('四个闸门的判定顺序：样本 → 幅度 → 轮次 → 驻留', () => {
  // 样本不足时不该报幅度问题
  assert.equal(decideSwitch(base({ prevSamples: 0 })).blockedBy, 'insufficient_samples')
  // 幅度不足时不该报轮次问题
  assert.equal(decideSwitch(base({ bestScore: 199 })).blockedBy, 'insufficient_improvement')
  // 轮次不足时不该报驻留问题
  assert.equal(
    decideSwitch(base({ roundsBetter: 0, lastSwitchAt: T })).blockedBy,
    'need_more_rounds',
  )
})

/* ============================================================
 * 边界
 * ============================================================ */

test('无候选 → 不切', () => {
  const r = decideSwitch(base({ bestIp: null, bestScore: Infinity }))
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'no_candidate')
})

test('当前已是最优 → 不切，且清零连续轮次', () => {
  const r = decideSwitch(base({ bestIp: 'a', roundsBetter: 1 }))
  assert.equal(r.switch, false)
  assert.equal(r.blockedBy, 'already_best')
  assert.equal(r.roundsBetter, 0, '已是最优应清零，避免陈旧计数')
})

test('没有当前线路 → 直接上', () => {
  const r = decideSwitch(base({ prevIp: null, prevScore: Infinity }))
  assert.equal(r.switch, true)
})

test('首次切换（lastSwitchAt=0）不受驻留约束', () => {
  const r = decideSwitch(base({ roundsBetter: 1, lastSwitchAt: 0 }))
  assert.equal(r.switch, true)
})

test('门槛都能配成 0：立即按分数切', () => {
  const r = decideSwitch(base({
    roundsBetter: 0, lastSwitchAt: T,
    cfg: { minImprovementRatio: 0, consecutiveBetterRounds: 1, minDwellTimeMs: 0, minSamples: 1 },
  }))
  assert.equal(r.switch, true)
})

test('A/B 接近时不会反复切换（连续抖动）', () => {
  // 200 vs 195：只快 2.5%，远低于门槛
  let rounds = 0
  for (let i = 0; i < 5; i += 1) {
    const r = decideSwitch(base({ bestScore: 195, roundsBetter: rounds }))
    rounds = r.roundsBetter
    assert.equal(r.switch, false, `第 ${i} 轮不该切`)
  }
  assert.equal(rounds, 0, '幅度不足时轮次不该累计')
})

test('持续明显更好的线路最终会被选中', () => {
  let rounds = 0
  let switched = false
  for (let i = 0; i < 3; i += 1) {
    const r = decideSwitch(base({ roundsBetter: rounds }))
    rounds = r.roundsBetter
    if (r.switch) { switched = true; break }
  }
  assert.equal(switched, true, '连续 2 轮更优后应切')
})

test('hasEnoughSamples 两侧取小', () => {
  assert.equal(hasEnoughSamples(5, 5, 3), true)
  assert.equal(hasEnoughSamples(1, 9, 3), false, '当前侧不足就不该比')
  assert.equal(hasEnoughSamples(9, 1, 3), false, '候选侧不足同样不该比')
})
