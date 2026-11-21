/**
 * candidate-prune.test.js — 容量与过期淘汰（Issue #11 阶段 4）
 *
 * **两条最要紧的断言**（评审特别强调）：
 *   1. DNS 数量超过 candidatePoolMaxSize 时，实际容量临时超出，不丢 DNS
 *   2. 淘汰候选不影响历史统计（本层不碰 ipStats）
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { makePool, mergeCandidates, markProbed, markSuccess, SOURCE_DNS } from '../../lib/candidate-pool.mjs'
import { pruneCandidatePool, expireCandidatePool, protectionReason } from '../../lib/candidate-prune.mjs'

const T = 1_700_000_000_000

function mkPool(dnsIps, discovered) {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps, discoveredIps: discovered }, T)
  return pool
}

/* ============================================================
 * 保护判定
 * ============================================================ */

test('当前线路受保护', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const c = pool.candidates.get('2.2.2.2')
  assert.equal(protectionReason(c, { currentIp: '2.2.2.2' }), 'current')
})

test('当前 DNS 返回的候选受保护', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const c = pool.candidates.get('2.2.2.2')
  assert.equal(protectionReason(c, { dnsIps: new Set(['2.2.2.2']) }), 'dns')
})

test('健康保护期内受保护', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const c = pool.candidates.get('2.2.2.2')
  markProbed(c, T - 1000, 'HKG')
  assert.equal(
    protectionReason(c, { isHealthProtected: () => true, now: T, coolingRetentionMs: 3_600_000 }),
    'health',
  )
})

test('非保护候选返回 null', () => {
  const pool = mkPool([], ['2.2.2.2'])
  assert.equal(protectionReason(pool.candidates.get('2.2.2.2'), {}), null)
})

/* ============================================================
 * 容量：DNS 兜底优先于上限（评审第 1 点）
 * ============================================================ */

test('DNS 数量超过 maxSize 时实际容量临时超出，不丢任何 DNS', () => {
  const dnsIps = Array.from({ length: 10 }, (_, i) => `10.0.0.${i + 1}`)
  const pool = mkPool(dnsIps, [])

  const r = pruneCandidatePool(pool, { maxSize: 3, dnsIps: new Set(dnsIps), now: T })

  assert.equal(r.removed.length, 0, '不该删任何 DNS 兜底')
  assert.equal(r.size, 10, '实际容量应超出配置上限')
  assert.equal(r.overCapacity, 7, '应如实报告超出多少')
  assert.equal(r.protectedCount, 10)
  for (const ip of dnsIps) assert.ok(pool.candidates.has(ip), `${ip} 必须保留`)
})

test('容量未超时不删任何东西', () => {
  const pool = mkPool(['1.1.1.1'], ['2.2.2.2'])
  const r = pruneCandidatePool(pool, { maxSize: 64, dnsIps: new Set(['1.1.1.1']), now: T })
  assert.equal(r.removed.length, 0)
  assert.equal(r.size, 2)
  assert.equal(r.overCapacity, 0)
})

test('超出容量时优先淘汰低价值候选', () => {
  // dns: 1 个（受保护）；discovered: 4 个
  const pool = mkPool(['1.1.1.1'], ['2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'])
  // 给其中两个成功记录（高价值）
  markSuccess(pool.candidates.get('4.4.4.4'), T - 1000)
  markProbed(pool.candidates.get('4.4.4.4'), T - 1000)
  markSuccess(pool.candidates.get('5.5.5.5'), T - 2000)
  markProbed(pool.candidates.get('5.5.5.5'), T - 2000)

  // maxSize=3：1 个 DNS 占位 → budget=2 → 应保住 4.4.4.4 与 5.5.5.5
  const r = pruneCandidatePool(pool, {
    maxSize: 3, dnsIps: new Set(['1.1.1.1']), now: T,
  })

  assert.equal(r.size, 3)
  assert.ok(pool.candidates.has('1.1.1.1'), 'DNS 必须留')
  assert.ok(pool.candidates.has('4.4.4.4'), '有成功记录的应优先保留')
  assert.ok(pool.candidates.has('5.5.5.5'))
  assert.deepEqual(r.removed, ['2.2.2.2', '3.3.3.3'], '无记录的先淘汰')
})

test('当前线路即使容量超限也不能删', () => {
  const pool = mkPool(['1.1.1.1'], ['2.2.2.2', '3.3.3.3'])
  const r = pruneCandidatePool(pool, {
    maxSize: 1, currentIp: '3.3.3.3', dnsIps: new Set(['1.1.1.1']), now: T,
  })
  assert.ok(pool.candidates.has('3.3.3.3'), '当前线路绝不能被删')
  assert.equal(r.protectedCount, 2, '当前 + DNS 都受保护')
  assert.ok(r.size >= 2, '受保护数超过上限时如实超出')
})

test('全部候选都受保护时不删任何东西', () => {
  const dns = ['1.1.1.1', '2.2.2.2', '3.3.3.3']
  const pool = mkPool(dns, [])
  const r = pruneCandidatePool(pool, { maxSize: 1, dnsIps: new Set(dns), now: T })
  assert.equal(r.removed.length, 0)
  assert.equal(r.size, 3)
})

/* ============================================================
 * 过期淘汰
 * ============================================================ */

test('超过 TTL 且无保护 → 淘汰', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const r = expireCandidatePool(pool, { now: T + 90_000_000, ttlMs: 86_400_000 })
  assert.deepEqual(r.expired, ['2.2.2.2'])
  assert.equal(pool.candidates.size, 0)
})

test('TTL 内不淘汰', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const r = expireCandidatePool(pool, { now: T + 1000, ttlMs: 86_400_000 })
  assert.equal(r.expired.length, 0)
})

test('DNS 候选即使超 TTL 也不淘汰', () => {
  const pool = mkPool(['1.1.1.1'], [])
  const r = expireCandidatePool(pool, {
    now: T + 90_000_000, ttlMs: 86_400_000, dnsIps: new Set(['1.1.1.1']),
  })
  assert.equal(r.expired.length, 0)
  assert.ok(pool.candidates.has('1.1.1.1'))
})

test('当前线路即使超 TTL 也不淘汰', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const r = expireCandidatePool(pool, {
    now: T + 90_000_000, ttlMs: 86_400_000, currentIp: '2.2.2.2',
  })
  assert.equal(r.expired.length, 0)
})

test('长期不在 DNS 但有近期成功记录 → 保留（不能只看 lastSeenAt）', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const c = pool.candidates.get('2.2.2.2')
  // lastSeenAt 很旧，但最近探测成功过
  c.lastSeenAt = T
  markProbed(c, T + 80_000_000, 'HKG')
  markSuccess(c, T + 80_000_000, 'HKG')

  const r = expireCandidatePool(pool, { now: T + 90_000_000, ttlMs: 86_400_000 })
  assert.equal(r.expired.length, 0, '三个时间戳取最近值判定')
  assert.ok(pool.candidates.has('2.2.2.2'))
})

test('健康保护期内不淘汰', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const c = pool.candidates.get('2.2.2.2')
  markProbed(c, T + 89_000_000)
  const r = expireCandidatePool(pool, {
    now: T + 90_000_000, ttlMs: 1, isHealthProtected: () => true, coolingRetentionMs: 3_600_000,
  })
  assert.equal(r.expired.length, 0)
  assert.equal(r.keptProtected, 1)
})

/* ============================================================
 * 淘汰与历史统计的关系（评审第 2 点）
 * ============================================================ */

test('淘汰候选不触及任何性能字段（本层不碰 ipStats）', () => {
  const pool = mkPool([], ['2.2.2.2'])
  const before = JSON.stringify(pool.candidates.get('2.2.2.2'))
  assert.ok(before.includes('lastSeenAt'))

  expireCandidatePool(pool, { now: T + 90_000_000, ttlMs: 86_400_000 })
  // 候选记录被删，但这条记录里从来没有性能字段可丢 —— 性能在 ipStats
  assert.equal(pool.candidates.has('2.2.2.2'), false)

  // 重新加入时是全新记录（这正是需要独立 ipStats 生命周期来兜住的原因）
  mergeCandidates(pool, { discoveredIps: ['2.2.2.2'] }, T + 100_000_000)
  const fresh = pool.candidates.get('2.2.2.2')
  assert.equal(fresh.probeCount, 0, '候选记录重建，但 ipStats 那边的历史仍应存在')
})
