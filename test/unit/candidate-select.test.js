/**
 * candidate-select.test.js — 候选保留策略（Issue #11 阶段 2）
 *
 * 核心不变量：当前线路与 DNS 兜底**无条件入选**，不受配额约束。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { makePool, mergeCandidates, markSuccess, markProbed, SOURCE_DNS } from '../../lib/candidate-pool.mjs'
import {
  computeQuotas, pickHistorical, selectCandidates,
} from '../../lib/candidate-select.mjs'

const T = 1_700_000_000_000
const RATIOS = { historical: 0.4, current: 0.2, dns: 0.2, exploration: 0.2 }

/* ============================================================
 * 配额计算
 * ============================================================ */

test('配额按比例分配', () => {
  const q = computeQuotas(10, RATIOS)
  assert.equal(q.historical, 4)
  assert.equal(q.current, 2)
  assert.equal(q.dns, 2)
  assert.equal(q.exploration, 2)
})

test('比例之和不为 1 时归一化，不产生不可预测分配', () => {
  const q = computeQuotas(10, { historical: 2, current: 1, dns: 1, exploration: 0 })
  assert.equal(q.historical + q.current + q.dns + q.exploration, 10)
  assert.equal(q.historical, 5, '2/4 应得 5')
})

test('取整丢失的配额补给 dns（兜底不该因取整变少）', () => {
  const q = computeQuotas(7, RATIOS)   // 7*0.4=2.8, 7*0.2=1.4
  const sum = q.historical + q.current + q.dns + q.exploration
  assert.equal(sum, 7, '总和应等于 requested total')
})

test('全 0 比例时全部给 dns（不产生空池）', () => {
  const q = computeQuotas(5, {})
  assert.equal(q.dns, 5)
  assert.equal(q.historical + q.current + q.exploration, 0)
})

test('负比例被夹到 0', () => {
  const q = computeQuotas(10, { historical: -1, current: 0.5, dns: 0.5, exploration: 0 })
  assert.ok(q.historical >= 0)
  assert.equal(q.current + q.dns, 10)
})

/* ============================================================
 * historical 排序
 * ============================================================ */

test('pickHistorical 优先有成功记录的', () => {
  const list = [
    { ip: 'a', lastSuccessAt: 0, probeCount: 10 },
    { ip: 'b', lastSuccessAt: T - 1000, probeCount: 1 },
  ]
  const picked = pickHistorical(list, 1, T)
  assert.equal(picked[0].ip, 'b', '有成功记录的优先')
})

test('pickHistorical 同条件下探测次数多的优先（样本更可信）', () => {
  const list = [
    { ip: 'a', lastSuccessAt: T - 1000, probeCount: 2 },
    { ip: 'b', lastSuccessAt: T - 1000, probeCount: 9 },
  ]
  assert.equal(pickHistorical(list, 1, T)[0].ip, 'b')
})

test('pickHistorical 配额为 0 时返回空', () => {
  assert.deepEqual(pickHistorical([{ ip: 'a', lastSuccessAt: T }], 0, T), [])
})

/* ============================================================
 * selectCandidates：核心不变量
 * ============================================================ */

function mkPool(dnsIps, discovered) {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps, discoveredIps: discovered }, T)
  return pool
}

test('当前 IP 无条件入选（即使比例是 0）', () => {
  const pool = mkPool(['1.1.1.1'], ['2.2.2.2'])
  const r = selectCandidates({
    pool, currentIp: '2.2.2.2', dnsIps: ['1.1.1.1'],
    ratios: { historical: 1, current: 0, dns: 0, exploration: 0 },
    total: 1, now: T,
  })
  assert.ok(r.selected.includes('2.2.2.2'), '当前线路必须保留，否则正常请求会突然断线')
})

test('DNS 候选无条件入选（即使比例是 0）', () => {
  const pool = mkPool(['1.1.1.1', '2.2.2.2'], ['3.3.3.3'])
  const r = selectCandidates({
    pool, currentIp: '3.3.3.3', dnsIps: ['1.1.1.1', '2.2.2.2'],
    ratios: { historical: 1, current: 0, dns: 0, exploration: 0 },
    total: 1, now: T,
  })
  assert.ok(r.selected.includes('1.1.1.1'))
  assert.ok(r.selected.includes('2.2.2.2'))
})

test('结果去重：同一 IP 不重复出现', () => {
  const pool = mkPool(['1.1.1.1'], ['1.1.1.1'])
  const r = selectCandidates({
    pool, currentIp: '1.1.1.1', dnsIps: ['1.1.1.1'],
    ratios: RATIOS, total: 8, now: T,
  })
  assert.equal(r.selected.filter((ip) => ip === '1.1.1.1').length, 1)
  assert.equal(new Set(r.selected).size, r.selected.length)
})

test('历史优秀 IP 在配额内被选中且跨轮稳定', () => {
  const pool = mkPool(['1.1.1.1'], ['2.2.2.2', '3.3.3.3', '4.4.4.4'])
  markSuccess(pool.candidates.get('2.2.2.2'), T - 1000, 'HKG')
  markProbed(pool.candidates.get('2.2.2.2'), T - 1000, 'HKG')
  markSuccess(pool.candidates.get('3.3.3.3'), T - 5000, 'HKG')

  const run = (now) => selectCandidates({
    pool, currentIp: '1.1.1.1', dnsIps: ['1.1.1.1'],
    ratios: { historical: 0.5, current: 0.1, dns: 0.2, exploration: 0.2 },
    total: 6, now,
  })

  const a = run(T)
  const b = run(T + 60_000)
  assert.ok(a.selected.includes('2.2.2.2'), '历史优秀 IP 应入选')
  assert.deepEqual(a.selected, b.selected, '相邻两轮结果应稳定')
})

test('健康过滤：cooling 的候选不入选', () => {
  const pool = mkPool(['1.1.1.1'], ['2.2.2.2', '3.3.3.3'])
  markSuccess(pool.candidates.get('2.2.2.2'), T - 1000)
  markSuccess(pool.candidates.get('3.3.3.3'), T - 1000)

  const r = selectCandidates({
    pool, currentIp: '1.1.1.1', dnsIps: ['1.1.1.1'],
    ratios: RATIOS, total: 8, now: T,
    isSelectable: (ip) => ip !== '2.2.2.2',   // 模拟 cooling
  })
  assert.equal(r.selected.includes('2.2.2.2'), false, 'cooling 不该入选')
  assert.ok(r.selected.includes('3.3.3.3'))
})

test('当前 IP 若处于 cooling 也不入选（健康优先于保留）', () => {
  const pool = mkPool(['1.1.1.1'], ['2.2.2.2'])
  const r = selectCandidates({
    pool, currentIp: '2.2.2.2', dnsIps: ['1.1.1.1'],
    ratios: RATIOS, total: 4, now: T,
    isSelectable: (ip) => ip !== '2.2.2.2',
  })
  assert.equal(r.selected.includes('2.2.2.2'), false)
})

test('breakdown 如实反映各类别入选数', () => {
  const pool = mkPool(['1.1.1.1'], ['2.2.2.2'])
  markSuccess(pool.candidates.get('2.2.2.2'), T - 1000)

  const r = selectCandidates({
    pool, currentIp: '1.1.1.1', dnsIps: ['1.1.1.1'],
    ratios: RATIOS, total: 4, now: T,
  })
  assert.equal(r.breakdown.current, 1)
  assert.equal(r.breakdown.dns, 1)
  assert.ok(r.breakdown.historical >= 1)
  assert.equal(typeof r.breakdown.quotas, 'object')
})

test('空池不报错', () => {
  const r = selectCandidates({ pool: new Map(), currentIp: null, dnsIps: [], ratios: RATIOS, total: 5, now: T })
  assert.deepEqual(r.selected, [])
})
