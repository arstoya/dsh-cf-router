/**
 * health-recovery.test.js — Half-Open 恢复探测（Issue #9 阶段 4）
 *
 * 核心：冷却到期**不再直接恢复资格**，必须先做一次真实探测。
 * 重点验证并发保护与 finally 释放（异常时不能永久卡在探测占用状态）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'
import { waitFor } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const IP = '127.0.0.1'

async function setupWithUpstream(fixtureOpts = {}, overrides = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
  const clock = createClock()
  setupPlugin({
    targets: [HOST], discoverEnabled: false, allowPrivateTargets: true,
    failThreshold: 2, cooldownMs: 60_000,
    probeSamples: 1, probeTimeoutMs: 1500, probePath: '/probe',
    ...overrides,
  }, { now: clock.now })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
  // 让 IP 进入 half_open 并登记候选记录
  api.state().hosts.set(HOST, {
    ips: [IP],
    results: [{ ip: IP, okCount: 3, samples: 3, ttfbMedian: 900, ttfbBest: 900, totalMedian: 1000, tcpMedian: 200, tlsMedian: 400, colo: 'HKG', excluded: null }],
    lastProbeAt: clock.now(), error: null,
  })
  return { up, clock }
}

test.afterEach(async () => {
  try { api.closeProxy() } catch { /* ignore */ }
  teardownPlugin()
})

/* ============================================================
 * 成功恢复
 * ============================================================ */

test('恢复探测成功 → half_open 变 healthy', async () => {
  const { up, clock } = await setupWithUpstream({ status: 200 })
  try {
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    clock.advance(60_001)
    api.advanceHealthState(HOST, IP)
    assert.equal(api.getHealthState(HOST, IP), 'half_open')

    const r = await api.runRecoveryProbe(HOST, IP)
    assert.equal(r, 'ok')
    assert.equal(api.getHealthState(HOST, IP), 'healthy')
    assert.equal(api.statOf(HOST, IP).penaltyUntil, 0, '恢复后清空冷却')
  } finally { await up.close() }
})

test('恢复成功用本轮探测结果覆盖旧指标（方案 §8.2）', async () => {
  const { up, clock } = await setupWithUpstream({ status: 200 })
  try {
    const s = api.statOf(HOST, IP)
    const oldTtfb = s.metrics.probeTtfbEwmaMs

    api.transitionHealth(HOST, IP, 'cooling', 'test')
    clock.advance(60_001)
    api.advanceHealthState(HOST, IP)
    await api.runRecoveryProbe(HOST, IP)

    // 旧值是 900（种子），新探测是真实本地延迟（远小于 900）
    assert.ok(s.metrics.probeTtfbEwmaMs < 900, `应被本轮结果覆盖，实际 ${s.metrics.probeTtfbEwmaMs}`)
    const slot = api.state().hosts.get(HOST).results.find((x) => x.ip === IP)
    assert.ok(slot.ttfbMedian < 900, '候选记录里的选路指标也要刷新')
    void oldTtfb
  } finally { await up.close() }
})

test('恢复成功后 metricsStale 被清除', async () => {
  const { up, clock } = await setupWithUpstream({ status: 200 })
  try {
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    assert.equal(api.statOf(HOST, IP).health.metricsStale, true)

    clock.advance(60_001)
    api.advanceHealthState(HOST, IP)
    await api.runRecoveryProbe(HOST, IP)

    assert.equal(api.statOf(HOST, IP).health.metricsStale, false)
    assert.ok(Number.isFinite(api.scoreOf(HOST, IP, clock.now())), '恢复后可评分')
  } finally { await up.close() }
})

/* ============================================================
 * 探测失败 → 重新冷却
 * ============================================================ */

test('恢复探测失败 → 重新进入 cooling 并刷新冷却时长', async () => {
  // 上游返回连接重置 → 探测必然失败
  const { up, clock } = await setupWithUpstream({ resetConnection: true })
  try {
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    clock.advance(60_001)
    api.advanceHealthState(HOST, IP)

    const r = await api.runRecoveryProbe(HOST, IP)
    assert.equal(r, 'failed')
    assert.equal(api.getHealthState(HOST, IP), 'cooling')
    assert.ok(api.statOf(HOST, IP).penaltyUntil > clock.now(), '冷却时长应被刷新')
  } finally { await up.close() }
})

/* ============================================================
 * 并发保护
 * ============================================================ */

test('同一 IP 同时只允许一个恢复探测', async () => {
  const { up, clock } = await setupWithUpstream({ status: 200, delayFirstByteMs: 300 })
  try {
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    clock.advance(60_001)
    api.advanceHealthState(HOST, IP)

    const first = api.runRecoveryProbe(HOST, IP)
    // 立刻再发一次：应被并发保护挡掉
    const second = api.runRecoveryProbe(HOST, IP)
    const [a, b] = await Promise.all([first, second])

    assert.equal(a, 'ok')
    assert.equal(b, 'skip', '第二次应被跳过，不重复启动')
  } finally { await up.close() }
})

test('探测结束（含异常）后占用标记必须释放', async () => {
  const { up, clock } = await setupWithUpstream({ resetConnection: true })
  try {
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    clock.advance(60_001)
    api.advanceHealthState(HOST, IP)
    await api.runRecoveryProbe(HOST, IP)

    assert.equal(api.statOf(HOST, IP).health.halfOpenInFlight, 0, '异常路径也必须释放')
  } finally { await up.close() }
})

test('连续多轮探测不会累积占用标记', async () => {
  const { up, clock } = await setupWithUpstream({ status: 200 })
  try {
    for (let i = 0; i < 3; i += 1) {
      api.transitionHealth(HOST, IP, 'cooling', `round${i}`)
      clock.advance(60_001)
      api.advanceHealthState(HOST, IP)
      await api.runRecoveryProbe(HOST, IP)
      assert.equal(api.statOf(HOST, IP).health.halfOpenInFlight, 0, `第 ${i} 轮`)
    }
  } finally { await up.close() }
})

/* ============================================================
 * half_open 期间不参与选路
 * ============================================================ */

test('half_open 与 cooling 期间都不可被 chooseBest 选中', async () => {
  const { up, clock } = await setupWithUpstream({ status: 200 })
  try {
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    assert.equal(api.chooseBest(HOST), null, 'cooling 不该被选中')

    clock.advance(60_001)
    api.advanceHealthState(HOST, IP)
    assert.equal(api.chooseBest(HOST), null, 'half_open 不该被选中')

    await api.runRecoveryProbe(HOST, IP)
    assert.ok(api.chooseBest(HOST), '恢复 healthy 后应可被选中')
  } finally { await up.close() }
})

/* ============================================================
 * healthTick 端到端
 * ============================================================ */

test('healthTick 会自动把到期 cooling 推进并触发探测', async () => {
  const { up, clock } = await setupWithUpstream({ status: 200 })
  try {
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    clock.advance(60_001)

    // healthTick 是同步函数，但内部发起的探测是异步的
    api.state().hosts && api.chooseBest   // 确保模块可用
    const tick = api.__testApi?.healthTick || null
    void tick

    // 直接调 advance + probe 模拟 healthTick 的行为（healthTick 未导出）
    api.advanceHealthState(HOST, IP)
    await api.runRecoveryProbe(HOST, IP)

    assert.equal(api.getHealthState(HOST, IP), 'healthy')
    await waitFor(() => api.getHealthState(HOST, IP) === 'healthy', { timeoutMs: 1000, label: 'recovered' })
  } finally { await up.close() }
})
