/**
 * candidate-explore.test.js — 有限探索（Issue #11 阶段 3）
 *
 * 核心：新 IP 仍有稳定进入机会，但每轮不会无条件重新生成完整候选集。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  makePool, mergeCandidates, upsertCandidate, SOURCE_DISCOVERED, SOURCE_DNS,
} from '../../lib/candidate-pool.mjs'
import { shouldExplore, pickExploration, applyExploration } from '../../lib/candidate-explore.mjs'

const T = 1_700_000_000_000

/* ============================================================
 * 刷新间隔
 * ============================================================ */

test('从未刷新过 → 应探索', () => {
  const pool = makePool(T)
  pool.lastRefreshAt = 0
  assert.equal(shouldExplore(pool, T, 300_000), true)
})

test('未到最小间隔 → 不探索（避免每轮都重抽）', () => {
  const pool = makePool(T)
  pool.lastRefreshAt = T
  assert.equal(shouldExplore(pool, T + 100_000, 300_000), false, '不到 5 分钟不该重抽')
})

test('超过间隔 → 允许探索', () => {
  const pool = makePool(T)
  pool.lastRefreshAt = T
  assert.equal(shouldExplore(pool, T + 300_001, 300_000), true)
})

test('间隔为 0 → 每次都可探索', () => {
  const pool = makePool(T)
  pool.lastRefreshAt = T
  assert.equal(shouldExplore(pool, T, 0), true)
})

/* ============================================================
 * 探索候选筛选
 * ============================================================ */

test('遵守配额上限', () => {
  const picked = pickExploration({
    existing: new Set(),
    sampled: ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'],
    quota: 2,
  })
  assert.equal(picked.length, 2)
})

test('配额为 0 时不做探索', () => {
  assert.deepEqual(pickExploration({ existing: new Set(), sampled: ['1.1.1.1'], quota: 0 }), [])
})

test('已有候选不当作探索（那是更新不是探索）', () => {
  const existing = new Set(['1.1.1.1'])
  const picked = pickExploration({ existing, sampled: ['1.1.1.1', '2.2.2.2'], quota: 5 })
  assert.deepEqual(picked, ['2.2.2.2'], '已有的应被排除')
})

test('采样结果内部去重', () => {
  const picked = pickExploration({
    existing: new Set(),
    sampled: ['1.1.1.1', '1.1.1.1', '2.2.2.2'],
    quota: 5,
  })
  assert.deepEqual(picked, ['1.1.1.1', '2.2.2.2'])
})

test('健康过滤生效：冷却中的 IP 不进入探索', () => {
  const picked = pickExploration({
    existing: new Set(),
    sampled: ['1.1.1.1', '2.2.2.2'],
    quota: 5,
    isSelectable: (ip) => ip !== '1.1.1.1',
  })
  assert.deepEqual(picked, ['2.2.2.2'])
})

test('非法条目被忽略', () => {
  const picked = pickExploration({
    existing: new Set(),
    sampled: [null, '', 42, '1.1.1.1'],
    quota: 5,
  })
  assert.deepEqual(picked, ['1.1.1.1'])
})

/* ============================================================
 * 应用到池
 * ============================================================ */

test('applyExploration 写入新候选并记录刷新时间', () => {
  const pool = makePool(T)
  const r = applyExploration(pool, ['1.1.1.1', '2.2.2.2'], T + 1000, {
    upsertCandidate, SOURCE_DISCOVERED,
  })

  assert.equal(r.added, 2)
  assert.equal(pool.candidates.size, 2)
  assert.equal(pool.lastRefreshAt, T + 1000)
  assert.equal(pool.candidates.get('1.1.1.1').source, SOURCE_DISCOVERED)
})

test('applyExploration 对已有候选只更新不重复添加', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps: ['1.1.1.1'] }, T)
  const r = applyExploration(pool, ['1.1.1.1'], T + 1000, { upsertCandidate, SOURCE_DISCOVERED })

  assert.equal(r.added, 0, '已存在的不算新增')
  assert.equal(pool.candidates.size, 1)
  assert.equal(pool.candidates.get('1.1.1.1').source, SOURCE_DNS, 'DNS 来源不被降级')
})

test('applyExploration 空输入也刷新时间戳', () => {
  const pool = makePool(T)
  applyExploration(pool, [], T + 5000, { upsertCandidate, SOURCE_DISCOVERED })
  assert.equal(pool.lastRefreshAt, T + 5000, '刷新时间应推进，避免立刻又抽一轮')
})

/* ============================================================
 * 端到端：连续刷新的探索节奏
 * ============================================================ */

test('连续刷新不会每轮都重抽（探索受间隔与去重双重约束）', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps: ['1.1.1.1'] }, T)
  // makePool 把 lastRefreshAt 设成了创建时刻，这里显式清零表示「从没探索过」
  pool.lastRefreshAt = 0
  const deps = { upsertCandidate, SOURCE_DISCOVERED }

  // 第 1 轮：允许探索
  assert.equal(shouldExplore(pool, T, 300_000), true)
  const first = pickExploration({ existing: pool.candidates, sampled: ['2.2.2.2'], quota: 3 })
  applyExploration(pool, first, T, deps)
  assert.equal(pool.candidates.size, 2)

  // 第 2 轮（1 分钟后）：不到间隔，不该探索
  const t2 = T + 60_000
  assert.equal(shouldExplore(pool, t2, 300_000), false)

  // 第 3 轮（6 分钟后）：允许探索，但同一 IP 已被排除
  const t3 = T + 360_000
  assert.equal(shouldExplore(pool, t3, 300_000), true)
  const again = pickExploration({ existing: pool.candidates, sampled: ['2.2.2.2'], quota: 3 })
  assert.deepEqual(again, [], '已有的不重复当探索')
})
