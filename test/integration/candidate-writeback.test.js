/**
 * candidate-writeback.test.js — 探测/选中结果回写候选池（Issue #11 补漏）
 *
 * 背景：六阶段实施完成后发现 markProbed / markSuccess / markSelected
 * 三个函数写好了、测试也覆盖了，但**没有接上真实路径** ——
 * 候选记录里的 probeCount / lastSuccessAt / lastSelectedAt 永远不更新。
 *
 * 后果：pickHistorical 与 valueRank 只能退化成看 lastSeenAt 单一判据，
 * 「历史优秀 IP」这个核心卖点在实机上不成立。
 *
 * 本文件验证三个回写点真的被触达。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const IP = '127.0.0.1'

async function boot(fixtureOpts = {}, overrides = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
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
 * markProbed / markSuccess
 * ============================================================ */

test('探测成功后候选的 probeCount 与 lastSuccessAt 被更新', async () => {
  const { up, clock } = await boot({ status: 200 })
  try {
    await api.refreshHost(HOST)
    const c = api.getCandidatePool(HOST).candidates.get(IP)

    assert.ok(c.probeCount >= 1, `probeCount 应 >0，实际 ${c.probeCount}`)
    assert.ok(c.lastProbeAt > 0, 'lastProbeAt 应被记录')
    assert.ok(c.lastSuccessAt > 0, 'lastSuccessAt 应被记录（探测成功）')
    assert.equal(c.lastColo, '', '本地 fixture 无 cf-ray，colo 为空')
    assert.ok(c.lastProbeAt <= clock.now())
  } finally { await up.close() }
})

test('探测失败时 probeCount 仍累加，但 lastSuccessAt 不更新', async () => {
  // 连接重置 → 探测必然失败，但仍是「探测过一次」
  const { up } = await boot({ resetConnection: true })
  try {
    await api.refreshHost(HOST)
    const c = api.getCandidatePool(HOST).candidates.get(IP)

    assert.ok(c.probeCount >= 1, '失败也是一次探测，probeCount 要加')
    assert.ok(c.lastProbeAt > 0, 'lastProbeAt 要记')
    assert.equal(c.lastSuccessAt, 0, '失败不该设 lastSuccessAt')
  } finally { await up.close() }
})

test('多轮刷新时 probeCount 持续累加（不重置）', async () => {
  const { up, clock } = await boot({ status: 200 })
  try {
    await api.refreshHost(HOST)
    const n1 = api.getCandidatePool(HOST).candidates.get(IP).probeCount

    clock.advance(10_000)
    await api.refreshHost(HOST)
    const n2 = api.getCandidatePool(HOST).candidates.get(IP).probeCount

    assert.ok(n2 > n1, `第二轮的 probeCount 应更大：${n1} → ${n2}`)
  } finally { await up.close() }
})

test('lastSuccessAt 随成功探测推进', async () => {
  const { up, clock } = await boot({ status: 200 })
  try {
    await api.refreshHost(HOST)
    const t1 = api.getCandidatePool(HOST).candidates.get(IP).lastSuccessAt

    clock.advance(30_000)
    await api.refreshHost(HOST)
    const t2 = api.getCandidatePool(HOST).candidates.get(IP).lastSuccessAt

    assert.ok(t2 > t1, `lastSuccessAt 应推进：${t1} → ${t2}`)
  } finally { await up.close() }
})

/* ============================================================
 * markSelected
 * ============================================================ */

test('被选为当前线路时 lastSelectedAt 被更新', async () => {
  const { up, clock } = await boot({ status: 200 })
  try {
    await api.refreshHost(HOST)
    const c = api.getCandidatePool(HOST).candidates.get(IP)

    assert.equal(api.state().currentIp.get(HOST), IP, '应被选为当前线路')
    assert.ok(c.lastSelectedAt > 0, 'lastSelectedAt 必须被记录')
    assert.ok(c.lastSelectedAt <= clock.now())
  } finally { await up.close() }
})

test('switchRoute 切到某 IP 时也回写 lastSelectedAt', async () => {
  const { up, clock } = await boot({ status: 200 })
  try {
    await api.refreshHost(HOST)
    const pool = api.getCandidatePool(HOST)
    // 加一个第二候选，手工切换过去
    api.mergeCandidates(pool, { discoveredIps: ['203.0.113.9'] }, clock.now())
    const before = pool.candidates.get('203.0.113.9').lastSelectedAt
    assert.equal(before, 0, '初始为 0')

    api.switchRoute(HOST, '203.0.113.9', 'test')
    assert.ok(pool.candidates.get('203.0.113.9').lastSelectedAt > 0, '切换后应被记录')
  } finally { await up.close() }
})

/* ============================================================
 * 回写让 pickHistorical / valueRank 真正有用
 * ============================================================ */

test('回写后历史优秀候选能被 pickHistorical 识别', async () => {
  const { up, clock } = await boot({ status: 200 })
  try {
    await api.refreshHost(HOST)
    const pool = api.getCandidatePool(HOST)
    // 再加两个从未探测过的候选
    api.mergeCandidates(pool, { discoveredIps: ['203.0.113.8', '203.0.113.9'] }, clock.now())

    const withHistory = [...pool.candidates.values()].filter((c) => c.lastSuccessAt > 0)
    const withoutHistory = [...pool.candidates.values()].filter((c) => c.lastSuccessAt === 0)

    assert.equal(withHistory.length, 1, '真实探测过的那个应有成功记录')
    assert.equal(withHistory[0].ip, IP)
    assert.equal(withoutHistory.length, 2, '未探测的没有成功记录')

    // 容量紧张时优先保住有历史的
    const r = api.pruneCandidatePool(pool, {
      maxSize: 2, now: clock.now(), currentIp: IP, dnsIps: new Set([IP]),
    })
    assert.ok(pool.candidates.has(IP), '有历史的必须留')
    assert.equal(r.size, 2)
  } finally { await up.close() }
})

/* ============================================================
 * DNS 兜底不能凌驾于健康状态（回写时发现的缺陷）
 * ============================================================ */

test('cooling 的候选即使在 DNS 里也不被重复探测', async () => {
  const { up, clock } = await boot({ status: 200, failThreshold: 1 })
  try {
    await api.refreshHost(HOST)
    const c = api.getCandidatePool(HOST).candidates.get(IP)
    const n1 = c.probeCount

    api.transitionHealth(HOST, IP, 'cooling', 'test')
    clock.advance(1000)
    await api.refreshHost(HOST)

    assert.equal(c.probeCount, n1, 'cooling 期间不该再探测（DNS 兜底不凌驾健康状态）')
  } finally { await up.close() }
})

test('换算力：cooling 候选不出现在本轮探测集合里，但仍留在候选池', async () => {
  const { up } = await boot({ status: 200, failThreshold: 1 })
  try {
    await api.refreshHost(HOST)
    api.transitionHealth(HOST, IP, 'cooling', 'test')

    // 淘汰逻辑仍把 DNS 当受保护（不删），但探测选择把它排除
    const pool = api.getCandidatePool(HOST)
    assert.ok(pool.candidates.has(IP), '候选仍留在池里')
    assert.equal(api.isCandidateSelectable(HOST, IP), false, '但不可被探测/选路')

    // 淘汰时不会删（DNS 保护）
    const r = api.pruneCandidatePool(pool, {
      maxSize: 0, now: api.deps.now(), dnsIps: new Set([IP]),
    })
    assert.ok(pool.candidates.has(IP), '淘汰逻辑里 DNS 仍受保护')
    assert.equal(r.removed.length, 0)
  } finally { await up.close() }
})
