/**
 * candidate-pool-integration.test.js — 候选池接入（Issue #11 阶段 5）
 *
 * 验证候选池真的参与 refreshHost 的探测决策，而不是只存在于状态接口。
 * 重点：DNS 兜底不被容量上限丢弃；候选跨轮稳定。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'

const api = mod.__testApi
const HOST = 'localhost'

async function boot(overrides = {}) {
  const up = await startHttpsUpstream({ status: 200 })
  const clock = createClock()
  setupPlugin({
    targets: [HOST], discoverEnabled: false, allowPrivateTargets: true,
    probeSamples: 1, probeTimeoutMs: 1500, probePath: '/probe',
    ...overrides,
  }, { now: clock.now })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
  return { up, clock }
}

test.afterEach(async () => {
  try { api.closeProxy() } catch { /* ignore */ }
  teardownPlugin()
})

test('refreshHost 会建立候选池', async () => {
  const { up } = await boot()
  try {
    await api.refreshHost(HOST)
    const pool = api.getCandidatePool(HOST)
    assert.ok(pool, '应有候选池')
    assert.ok(pool.candidates.has('127.0.0.1'), 'DNS 候选应入池')
    assert.equal(pool.candidates.get('127.0.0.1').source, 'dns')
  } finally { await up.close() }
})

test('DNS 数量超过 maxSize 时池允许超出，不丢 DNS', async () => {
  const { up } = await boot({ candidatePoolMaxSize: 1 })
  try {
    // 让 DNS 返回 5 个地址（其中只有 127.0.0.1 真实可达，其余会探测失败但仍在池里）
    api.deps.resolve4 = (h, cb) => cb(null, [
      '127.0.0.1', '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4',
    ])
    await api.refreshHost(HOST)

    const pool = api.getCandidatePool(HOST)
    assert.equal(pool.candidates.size, 5, 'DNS 一个都不能丢')
    const summary = api.statusSnapshot().candidatePools.find((x) => x.host === HOST)
    assert.equal(summary.overCapacity, 4, '应如实报告超出 4 个')
  } finally { await up.close() }
})

test('连续刷新时候选池不丢失已有成员', async () => {
  const { up } = await boot()
  try {
    await api.refreshHost(HOST)
    const first = [...api.getCandidatePool(HOST).candidates.keys()].sort()

    await api.refreshHost(HOST)
    const second = [...api.getCandidatePool(HOST).candidates.keys()].sort()

    assert.deepEqual(second, first, '相邻两轮候选集合应稳定')
  } finally { await up.close() }
})

test('候选记录跨轮保留 probeCount（不重建）', async () => {
  const { up, clock } = await boot()
  try {
    await api.refreshHost(HOST)
    const c1 = api.getCandidatePool(HOST).candidates.get('127.0.0.1')
    const firstSeen = c1.firstSeenAt
    const probes = c1.probeCount

    clock.advance(10_000)
    await api.refreshHost(HOST)
    const c2 = api.getCandidatePool(HOST).candidates.get('127.0.0.1')

    assert.equal(c2.firstSeenAt, firstSeen, 'firstSeenAt 不该被重置')
    assert.ok(c2.probeCount >= probes, 'probeCount 应累加而非清零')
  } finally { await up.close() }
})

test('候选池状态可在 statusSnapshot 解释来源', async () => {
  const { up } = await boot()
  try {
    await api.refreshHost(HOST)
    const s = api.statusSnapshot().candidatePools.find((x) => x.host === HOST)
    assert.equal(s.dnsCount, 1)
    assert.equal(s.discoveredCount, 0)
    assert.equal(s.maxSize, 64)
    assert.ok(s.ratios, '应暴露归一化后的比例')
    assert.equal(typeof s.ratios.historical, 'number')
  } finally { await up.close() }
})

test('cooling 的候选不被选入本轮探测', async () => {
  const { up, clock } = await boot({ failThreshold: 1 })
  try {
    await api.refreshHost(HOST)
    // 把唯一候选打进 cooling
    api.transitionHealth(HOST, '127.0.0.1', 'cooling', 'test')
    assert.equal(api.isCandidateSelectable(HOST, '127.0.0.1'), false)

    const before = api.getCandidatePool(HOST).candidates.get('127.0.0.1').probeCount
    clock.advance(1000)
    await api.refreshHost(HOST)
    const after = api.getCandidatePool(HOST).candidates.get('127.0.0.1').probeCount
    assert.equal(after, before, 'cooling 期间不该再探测（除非 DNS 强制兜底路径）')
  } finally { await up.close() }
})

test('SSRF 拦截仍然优先于候选池', async () => {
  const { up } = await boot({ allowPrivateTargets: false })
  try {
    api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
    await api.refreshHost(HOST)
    const entry = api.state().hosts.get(HOST)
    assert.match(String(entry.error), /ssrf_blocked/, 'SSRF 优先，不建候选池')
  } finally { await up.close() }
})

test('比例归一化：配置和不等于 1 时不产生不可预测分配', async () => {
  const { up } = await boot({
    candidateHistoricalRatio: 2, candidateCurrentRatio: 1,
    candidateDnsRatio: 1, candidateExploreRatio: 0,
  })
  try {
    const r = api.getCfg()._candidateRatios
    const sum = r.historical + r.current + r.dns + r.exploration
    assert.ok(Math.abs(sum - 1) < 1e-6, `归一化后应等于 1，实际 ${sum}`)
    assert.equal(r.normalized, true)
  } finally { await up.close() }
})

test('四比例全 0 时退化为 DNS 兜底（不产生空池）', async () => {
  const { up } = await boot({
    candidateHistoricalRatio: 0, candidateCurrentRatio: 0,
    candidateDnsRatio: 0, candidateExploreRatio: 0,
  })
  try {
    const r = api.getCfg()._candidateRatios
    assert.equal(r.dns, 1, '全 0 时应全部给 dns')
    await api.refreshHost(HOST)
    assert.ok(api.getCandidatePool(HOST).candidates.size >= 1)
  } finally { await up.close() }
})

test('maxSize 非法值被归一化为默认 64', async () => {
  const { up } = await boot({ candidatePoolMaxSize: 0 })
  try {
    assert.equal(api.getCfg().candidatePoolMaxSize, 64)
  } finally { await up.close() }
})

test('TTL 与刷新间隔有下限，避免频繁刷新或立即淘汰', async () => {
  const { up } = await boot({
    candidatePoolTtlMs: 1,
    candidateRefreshMinIntervalMs: 1,
  })
  try {
    assert.ok(api.getCfg().candidatePoolTtlMs >= 60_000)
    assert.ok(api.getCfg().candidateRefreshMinIntervalMs >= 1_000)
  } finally { await up.close() }
})
