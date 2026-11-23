/**
 * watch-stability.test.js — 长稳判据（Issue #15 15-B）
 *
 * 这些判据本身要能被验证，否则「脚本说没泄漏」和「脚本坏了」分不清。
 *
 * 核心设计：LEAK? 必须同时满足「斜率超阈值」与「相邻增量够单调」。
 * 只用斜率会在短跨度上把噪声放大成假泄漏 —— 实测 18 秒涨 3 MB
 * 会外推成 +633 MB/h。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { slope, monotonicRatio, judgeTrend } from '../../scripts/watch-stability.mjs'

/* ============================================================
 * slope
 * ============================================================ */

test('slope：完全线性时斜率精确', () => {
  // x 毫秒，y 每 1000ms 涨 2
  const xs = [0, 1000, 2000, 3000]
  const ys = [10, 12, 14, 16]
  const s = slope(xs, ys)
  assert.ok(Math.abs(s - 0.002) < 1e-9, `实际 ${s}`)
})

test('slope：常数序列斜率为 0', () => {
  assert.equal(slope([0, 1000, 2000], [5, 5, 5]), 0)
})

test('slope：样本不足返回 0', () => {
  assert.equal(slope([], []), 0)
  assert.equal(slope([0], [1]), 0)
})

/* ============================================================
 * monotonicRatio
 * ============================================================ */

test('monotonicRatio：单调上升为 1', () => {
  assert.equal(monotonicRatio([1, 2, 3, 4]), 1)
})

test('monotonicRatio：单调下降为 1（方向无关，只看一致性）', () => {
  assert.equal(monotonicRatio([4, 3, 2, 1]), 1)
})

test('monotonicRatio：完全震荡为 0.5 左右', () => {
  const r = monotonicRatio([1, 3, 2, 4, 3])
  assert.ok(r <= 0.6, `实际 ${r}`)
})

test('monotonicRatio：持平序列返回 0（没有方向）', () => {
  assert.equal(monotonicRatio([5, 5, 5]), 0)
})

test('monotonicRatio：样本不足返回 0', () => {
  assert.equal(monotonicRatio([1, 2]), 0)
})

/* ============================================================
 * judgeTrend：核心判据
 * ============================================================ */

test('判定：无变化 → OK（哪怕跨度很短）', () => {
  const xs = [0, 1000, 2000]
  assert.equal(judgeTrend(xs, [100, 100, 100], 50, 2000), 'OK')
})

test('判定：短跨度上单调增长 → INSUFFICIENT，不报 LEAK', () => {
  // 这正是实测踩到的场景：18 秒涨 3MB，外推 633MB/h
  const xs = [0, 9000, 18000]
  const ys = [294.8, 296.4, 297.9]
  assert.equal(judgeTrend(xs, ys, 50, 18000), 'INSUFFICIENT',
    '跨度不足 10 分钟时不能下泄漏结论')
})

test('判定：跨度够 + 单调上升 + 超阈值 → LEAK?', () => {
  // 30 分钟内每小时涨 100MB
  const spanMs = 30 * 60 * 1000
  const xs = [0, spanMs / 2, spanMs]
  const ys = [100, 125, 150]      // 30 分钟涨 50 → 100/h
  assert.equal(judgeTrend(xs, ys, 50, spanMs), 'LEAK?')
})

test('判定：跨度够但震荡 → NOISY，不报 LEAK', () => {
  const spanMs = 30 * 60 * 1000
  const xs = [0, spanMs / 4, spanMs / 2, (spanMs * 3) / 4, spanMs]
  const ys = [100, 400, 90, 420, 95]   // 大幅震荡
  const v = judgeTrend(xs, ys, 50, spanMs)
  assert.notEqual(v, 'LEAK?', '震荡不能算泄漏')
  assert.ok(['NOISY', 'OK'].includes(v), `实际 ${v}`)
})

test('判定：下降趋势标 DECREASING 而不是 LEAK', () => {
  const spanMs = 30 * 60 * 1000
  const xs = [0, spanMs / 2, spanMs]
  const ys = [300, 250, 200]
  assert.equal(judgeTrend(xs, ys, 50, spanMs), 'DECREASING')
})

test('判定：含 null 的序列 → INSUFFICIENT（拿不到数据就别猜）', () => {
  const xs = [0, 1000, 2000]
  assert.equal(judgeTrend(xs, [100, null, 102], 50, 900000), 'INSUFFICIENT')
})

test('判定：样本不足 3 条 → INSUFFICIENT', () => {
  assert.equal(judgeTrend([0, 1], [1, 2], 50, 900000), 'INSUFFICIENT')
})

/* ============================================================
 * 关键回归：不许把短跨度噪声报成泄漏
 * ============================================================ */

test('回归：18 秒内的 RSS 波动不得判为 LEAK', () => {
  // 实测数据：4 条样本，18 秒，294.8 → 297.9
  const xs = [0, 6000, 12000, 18000]
  const ys = [294.8, 295.1, 297.9, 297.9]
  const v = judgeTrend(xs, ys, 50, 18000)
  assert.equal(v, 'INSUFFICIENT',
    '这是脚本第一版的误报场景：外推 633MB/h 但跨度只有 18 秒')
})

test('回归：池数量在稳定流量下不应判泄漏', () => {
  const spanMs = 60 * 60 * 1000
  const xs = [0, spanMs / 3, (spanMs * 2) / 3, spanMs]
  const ys = [1, 1, 1, 1]          // 一直是 1 个 active 池
  assert.equal(judgeTrend(xs, ys, 10, spanMs), 'OK')
})

test('回归：draining 池长期不归零才算问题', () => {
  const spanMs = 60 * 60 * 1000
  const xs = [0, spanMs / 3, (spanMs * 2) / 3, spanMs]
  // 每小时涨 12 个（阈值 10），单调 → 该报警
  const stuck = [0, 4, 8, 12]
  assert.equal(judgeTrend(xs, stuck, 10, spanMs), 'LEAK?')

  const healthy = [0, 1, 0, 0]     // 排空后归零
  assert.notEqual(judgeTrend(xs, healthy, 10, spanMs), 'LEAK?')
})
