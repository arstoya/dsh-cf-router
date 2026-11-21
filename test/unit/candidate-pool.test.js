/**
 * candidate-pool.test.js — 候选池数据结构（Issue #11 阶段 1）
 *
 * 本阶段只验证「合并与去重」，保留策略/探索/淘汰在后续阶段。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  makePool, makeCandidate, upsertCandidate, mergeCandidates,
  candidateIps, candidatesBySource, markProbed, markSuccess, markSelected,
  SOURCE_DNS, SOURCE_DISCOVERED, DEFAULT_TTL_MS,
} from '../../lib/candidate-pool.mjs'

const T = 1_700_000_000_000

test('新候选记录字段完整', () => {
  const c = makeCandidate('203.0.113.1', SOURCE_DNS, T)
  for (const k of ['ip', 'source', 'firstSeenAt', 'lastSeenAt', 'lastProbeAt',
    'lastSuccessAt', 'lastSelectedAt', 'lastColo', 'probeCount', 'expiresAt']) {
    assert.ok(k in c, `缺字段 ${k}`)
  }
  assert.equal(c.firstSeenAt, T)
  assert.equal(c.probeCount, 0)
  assert.equal(c.expiresAt, T + DEFAULT_TTL_MS)
})

test('合并 DNS 与 discovered，去重后数量正确', () => {
  const pool = makePool(T)
  const r = mergeCandidates(pool, {
    dnsIps: ['1.1.1.1', '2.2.2.2'],
    discoveredIps: ['3.3.3.3', '1.1.1.1'],   // 与 DNS 重复
  }, T)

  assert.equal(r.total, 3, '应去重为 3 个')
  assert.equal(r.added, 3)
  assert.deepEqual(candidateIps(pool), ['1.1.1.1', '2.2.2.2', '3.3.3.3'])
})

test('同一 IP 既是 DNS 又是 discovered → 标记为 dns（DNS 优先）', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps: ['1.1.1.1'], discoveredIps: ['1.1.1.1'] }, T)

  const c = pool.candidates.get('1.1.1.1')
  assert.equal(c.source, SOURCE_DNS, 'DNS 是兜底，不能被标成普通发现')
})

test('重复合并不重建记录（firstSeenAt 与 probeCount 保留）', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps: ['1.1.1.1'] }, T)
  const first = pool.candidates.get('1.1.1.1')
  markProbed(first, T + 1000, 'HKG')
  markSuccess(first, T + 1000, 'HKG')

  mergeCandidates(pool, { dnsIps: ['1.1.1.1'] }, T + 50_000)
  const again = pool.candidates.get('1.1.1.1')

  assert.equal(again.firstSeenAt, T, 'firstSeenAt 不该被重置')
  assert.equal(again.probeCount, 1, 'probeCount 不该被清零')
  assert.equal(again.lastSeenAt, T + 50_000, 'lastSeenAt 应更新')
  assert.equal(again.lastColo, 'HKG')
})

test('再次出现会续期 expiresAt', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps: ['1.1.1.1'] }, T)
  const before = pool.candidates.get('1.1.1.1').expiresAt

  mergeCandidates(pool, { dnsIps: ['1.1.1.1'] }, T + 3_600_000)
  assert.ok(pool.candidates.get('1.1.1.1').expiresAt > before, '续期应推后过期时间')
})

test('空输入与非法输入安全', () => {
  const pool = makePool(T)
  assert.equal(mergeCandidates(pool, {}, T).total, 0)
  assert.equal(mergeCandidates(pool, { dnsIps: [], discoveredIps: [] }, T).total, 0)
  mergeCandidates(pool, { dnsIps: [null, '', 42, '1.1.1.1'] }, T)
  assert.deepEqual(candidateIps(pool), ['1.1.1.1'], '非法条目应被忽略')
})

test('candidatesBySource 按来源筛选', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps: ['1.1.1.1'], discoveredIps: ['2.2.2.2', '3.3.3.3'] }, T)

  assert.deepEqual(candidatesBySource(pool, SOURCE_DNS).map((c) => c.ip), ['1.1.1.1'])
  assert.equal(candidatesBySource(pool, SOURCE_DISCOVERED).length, 2)
})

test('markProbed / markSuccess / markSelected 只更新生命周期字段', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps: ['1.1.1.1'] }, T)
  const c = pool.candidates.get('1.1.1.1')

  markProbed(c, T + 100, 'SIN')
  markSuccess(c, T + 200, 'SIN')
  markSelected(c, T + 300)

  assert.equal(c.lastProbeAt, T + 100)
  assert.equal(c.probeCount, 1)
  assert.equal(c.lastSuccessAt, T + 200)
  assert.equal(c.lastSelectedAt, T + 300)
  assert.equal(c.lastColo, 'SIN')
  // 不写性能数据 —— 那是 ipStats 的职责
  assert.equal('ewma' in c, false)
  assert.equal('failureScore' in c, false)
})

test('候选记录不含任何性能字段（职责分离）', () => {
  const c = makeCandidate('203.0.113.1', SOURCE_DISCOVERED, T)
  const forbidden = ['tcpEwmaMs', 'tlsEwmaMs', 'probeTtfbEwmaMs', 'metrics',
    'samples', 'failureScore', 'consecutiveFail', 'penaltyUntil', 'health']
  for (const k of forbidden) {
    assert.equal(k in c, false, `候选记录不该含 ${k}（那是 ipStats 的）`)
  }
})

test('自定义 TTL 生效', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { dnsIps: ['1.1.1.1'] }, T, { ttlMs: 60_000 })
  assert.equal(pool.candidates.get('1.1.1.1').expiresAt, T + 60_000)
})
