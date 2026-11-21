/**
 * candidate-compat.test.js — 兼容性与回归（Issue #11 阶段 6）
 *
 * 方案 §16 列出的六项兼容性必须逐条验证：
 *   16.1 默认配置兼容
 *   16.2 discoverEnabled 关闭时的行为
 *   16.3 coloAllow 不受影响
 *   16.4 #9 健康状态兼容
 *   16.5 #12 连接池边界（本层不碰）
 *   16.6 运行时状态兼容
 *
 * 另外验证「淘汰候选不影响 ipStats」这条评审强调的原则在集成层面成立。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const IP = '127.0.0.1'

async function boot(overrides = {}) {
  const up = await startHttpsUpstream({ status: 200, body: '{"ok":1}' })
  const clock = createClock()
  setupPlugin({
    targets: [HOST], discoverEnabled: false, allowPrivateTargets: true,
    probeSamples: 1, probeTimeoutMs: 1500, probePath: '/probe',
    adminToken: 't', adminRateLimit: 9999,
    ...overrides,
  }, { now: clock.now })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (h, cb) => cb(null, [IP])
  return { up, clock }
}

test.afterEach(async () => {
  try { api.closeProxy() } catch { /* ignore */ }
  teardownPlugin()
})

/* ============================================================
 * §16.1 默认配置兼容
 * ============================================================ */

test('新配置项都有合理默认值', async () => {
  const { up } = await boot()
  try {
    const c = api.getCfg()
    assert.equal(c.candidatePoolMaxSize, 64)
    assert.equal(c.candidatePoolTtlMs, 86_400_000)
    assert.equal(c.candidateExploreRatio, 0.2)
    assert.equal(c.candidateHistoricalRatio, 0.4)
    assert.equal(c.candidateCurrentRatio, 0.2)
    assert.equal(c.candidateDnsRatio, 0.2)
    assert.equal(c.candidateRefreshMinIntervalMs, 300_000)
    assert.equal(c.candidateCoolingRetentionMs, 3_600_000)
  } finally { await up.close() }
})

test('不配置任何候选池参数也能正常工作（零配置可用）', async () => {
  const { up } = await boot()
  try {
    await api.refreshHost(HOST)
    assert.ok(api.getCandidatePool(HOST).candidates.size >= 1)
    assert.ok(api.state().currentIp.get(HOST), '应选出当前 IP')
  } finally { await up.close() }
})

/* ============================================================
 * §16.2 discoverEnabled 兼容
 * ============================================================ */

test('discoverEnabled=false 时只有 DNS 候选，不抽新 IP', async () => {
  const { up } = await boot({ discoverEnabled: false })
  try {
    await api.refreshHost(HOST)
    const pool = api.getCandidatePool(HOST)
    const discovered = [...pool.candidates.values()].filter((c) => c.source === 'discovered')
    assert.equal(discovered.length, 0, '关闭探索后不该有 discovered 候选')
  } finally { await up.close() }
})

test('discoverEnabled=true 时会抽探索候选', async () => {
  const { up } = await boot({
    discoverEnabled: true,
    discoverPerRange: 1,
    candidateRefreshMinIntervalMs: 1000,
  })
  try {
    await api.refreshHost(HOST)
    const pool = api.getCandidatePool(HOST)
    const discovered = [...pool.candidates.values()].filter((c) => c.source === 'discovered')
    assert.ok(discovered.length > 0, '开启探索后应有 discovered 候选')
  } finally { await up.close() }
})

/* ============================================================
 * §16.3 coloAllow 不受影响
 * ============================================================ */

test('coloAllow 过滤仍按原有语义工作', async () => {
  const { up } = await boot({ coloAllow: ['SIN'] })
  try {
    // 本地 fixture 没有 cf-ray，colo 为空 → 不在白名单 → 被排除
    const r = await api.measureIp(HOST, IP, 1, 2000, '/probe')
    assert.match(String(r.excluded), /colo/, 'coloAllow 过滤应仍生效')
  } finally { await up.close() }
})

/* ============================================================
 * §16.4 #9 健康状态兼容
 * ============================================================ */

test('候选池与健康状态共存：cooling 候选留在池里但不可选路', async () => {
  const { up } = await boot({ failThreshold: 1 })
  try {
    await api.refreshHost(HOST)
    api.transitionHealth(HOST, IP, 'cooling', 'test')

    const pool = api.getCandidatePool(HOST)
    assert.ok(pool.candidates.has(IP), 'cooling 的候选仍应在池里（保留历史）')
    assert.equal(api.isCandidateSelectable(HOST, IP), false, '但不可参与选路')
    assert.equal(api.chooseBest(HOST), null, 'chooseBest 应返回 null')
  } finally { await up.close() }
})

test('候选被池淘汰不影响健康状态记录', async () => {
  const { up } = await boot()
  try {
    await api.refreshHost(HOST)
    const s = api.statOf(HOST, IP)
    s.fail = 3
    s.metrics.probeTtfbEwmaMs = 123

    // 强制清空候选池
    api.getCandidatePool(HOST).candidates.clear()

    assert.equal(api.statOf(HOST, IP).fail, 3, 'ipStats 不受候选池影响')
    assert.equal(api.statOf(HOST, IP).metrics.probeTtfbEwmaMs, 123)
  } finally { await up.close() }
})

/* ============================================================
 * 评审第 2 点：淘汰候选 ≠ 删历史统计（集成层）
 * ============================================================ */

test('候选过期淘汰后，ipStats 的历史仍在（重新出现时可复用）', async () => {
  const { up, clock } = await boot({ candidatePoolTtlMs: 60_000 })
  try {
    await api.refreshHost(HOST)
    const s = api.statOf(HOST, IP)
    s.metrics.probeTtfbEwmaMs = 42
    s.fail = 2

    // 推进到 TTL 之后并触发一轮刷新（此时 DNS 仍返回该 IP，所以它会被续期）
    // 这里手动清池来模拟「不再出现在 DNS 且已过期」
    clock.advance(120_000)
    api.getCandidatePool(HOST).candidates.clear()
    assert.equal(api.getCandidatePool(HOST).candidates.size, 0)

    assert.equal(api.statOf(HOST, IP).metrics.probeTtfbEwmaMs, 42, 'ipStats 保留')
    assert.equal(api.statOf(HOST, IP).fail, 2)

    // 重新出现时复用历史，而不是当全新节点
    api.mergeCandidates(api.getCandidatePool(HOST), { dnsIps: [IP] }, clock.now())
    assert.equal(api.getCandidatePool(HOST).candidates.get(IP).probeCount, 0,
      '候选记录是新的一页（生命周期），但 ipStats 那边历史仍在')
    assert.equal(api.statOf(HOST, IP).metrics.probeTtfbEwmaMs, 42, '历史性能可复用')
  } finally { await up.close() }
})

/* ============================================================
 * §16.6 运行时状态兼容
 * ============================================================ */

test('resetAll 清空候选池', async () => {
  const { up } = await boot()
  try {
    await api.refreshHost(HOST)
    assert.ok(api.getCandidatePool(HOST).candidates.size > 0)

    api.resetAll()
    assert.equal(api.getCandidatePool(HOST).candidates.size, 0, 'resetAll 应清空候选池')
  } finally { await up.close() }
})

test('既有代理行为未变：真实请求仍可正常转发', async () => {
  const { up } = await boot()
  try {
    const port = await freePort()
    api.configure({ ...api.getCfg(), listenHost: '127.0.0.1', listenPort: port })
    const srv = api.createProxy()
    await new Promise((r) => srv.once('listening', r))
    await api.refreshHost(HOST)

    const r = await new Promise((res, rej) => {
      const q = http.request({ host: '127.0.0.1', port, path: '/x', method: 'POST' }, (x) => {
        const b = []
        x.on('data', (c) => b.push(c))
        x.on('end', () => res({ status: x.statusCode, body: Buffer.concat(b).toString() }))
      })
      q.on('error', rej)
      q.end('{}')
    })
    assert.equal(r.status, 200)
    assert.equal(JSON.parse(r.body).ok, 1)
  } finally { await up.close() }
})

test('healthSummary 与 candidatePools 同时可用', async () => {
  const { up } = await boot()
  try {
    await api.refreshHost(HOST)
    const snap = api.statusSnapshot()
    assert.ok(Array.isArray(snap.candidatePools))
    assert.ok(snap.healthSummary, '两个新接口应共存')
    assert.equal(typeof snap.healthSummary.counts.healthy, 'number')
  } finally { await up.close() }
})
