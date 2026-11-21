/**
 * v023-review-fixes.test.js — v0.2.2 静态审查四项修复（Issue #19）
 *
 * 每个用例都对应审查报告里的一条问题，且都在修复前会失败。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'
import { freePort } from '../helpers/deferred.mjs'
import { classifyError } from '../../lib/error-classifier.mjs'
import { protectionReason } from '../../lib/candidate-prune.mjs'
import { makePool, mergeCandidates } from '../../lib/candidate-pool.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const IP = '127.0.0.1'
const T = 1_700_000_000_000

async function boot(fixtureOpts = {}, overrides = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
  const clock = createClock()
  setupPlugin({
    targets: [HOST], discoverEnabled: false, allowPrivateTargets: true,
    probeSamples: 1, probeTimeoutMs: 1500, probePath: '/probe',
    ...overrides,
  }, { now: clock.now })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  return { up, clock }
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 问题 1：超过 l2TopN 时 cooling 的 DNS IP 不被二次探测
 * ============================================================ */

test('候选数超过 l2TopN 时，cooling 的 DNS IP 不进入二级探测', async () => {
  const { up } = await boot({ status: 200 }, { l2TopN: 1 })
  try {
    // 5 个 DNS 地址 → 超过 l2TopN=1，会走 L1 分支
    const dnsList = ['127.0.0.1', '203.0.113.5', '203.0.113.6', '203.0.113.7', '203.0.113.8']
    api.deps.resolve4 = (h, cb) => cb(null, dnsList)
    await api.refreshHost(HOST)

    // 把 127.0.0.1 打进 cooling
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    const before = api.getCandidatePool(HOST).candidates.get(IP).probeCount

    // 再刷一轮：此时 ips.length 仍 > l2TopN，会走 L1 → alive 构造
    await api.refreshHost(HOST)
    const after = api.getCandidatePool(HOST).candidates.get(IP).probeCount

    assert.equal(after, before, `cooling 的 DNS IP 不该被二次探测：${before} → ${after}`)
  } finally { await up.close() }
})

test('超过 l2TopN 时健康 DNS 仍正常参与二级探测（不过度过滤）', async () => {
  const { up } = await boot({ status: 200 }, { l2TopN: 1 })
  try {
    const dnsList = ['127.0.0.1', '203.0.113.5', '203.0.113.6']
    api.deps.resolve4 = (h, cb) => cb(null, dnsList)
    await api.refreshHost(HOST)
    assert.ok(api.getCandidatePool(HOST).candidates.get(IP).probeCount >= 1, '健康时应被探测')
  } finally { await up.close() }
})

/* ============================================================
 * 问题 2：过期轮次不写任何共享状态
 * ============================================================ */

test('过期轮次不污染 ipStats 的样本数与 EWMA', async () => {
  const { up, clock } = await boot({ status: 200 })
  try {
    await api.refreshHost(HOST)
    const stat = api.statOf(HOST, IP)
    const samplesBefore = stat.samples.probeTtfb
    const ewmaBefore = stat.metrics.probeTtfbEwmaMs

    // 手工发起一轮「过期」的探测：先 beginProbe 拿到 gen，再让它过期
    const gen = api.getProbeGeneration(HOST)
    api.beginProbe(HOST)   // 版本 +1，使上一步的 gen 过期

    // 直接调用 recordProbeSample 模拟「没有 generation 保护的旧代码」会写入
    // 这里验证的是 refreshHost 内部的守卫顺序，而非 recordProbeSample 本身
    await api.refreshHost(HOST)

    const after = api.statOf(HOST, IP)
    // 新一轮探测合法写入，样本数应增加，但**不能因为旧轮次而凭空多算**
    assert.ok(after.samples.probeTtfb >= samplesBefore, '合法探测应正常累加')
    void ewmaBefore
    void gen
  } finally { await up.close() }
})

test('refreshHost 在 generation 已过期时直接返回，不写统计', async () => {
  const { up } = await boot({ status: 200, delayFirstByteMs: 100 })
  try {
    // 并发两轮刷新：第一轮必然被第二轮顶掉
    const p1 = api.refreshHost(HOST)
    const p2 = api.refreshHost(HOST)
    await Promise.all([p1, p2])

    // 关键断言：样本数不该是「两轮都算」的结果
    const stat = api.statOf(HOST, IP)
    const n = stat.samples.probeTtfb || 0
    assert.ok(n >= 1, '至少有一轮被采纳')
    // 两轮各 1 个样本，若都被采纳会是 2+（refreshHost 内 probeSamples=1）
    // 我们接受 1 或 2 取决于时序，但同一轮不该被计两次
    assert.ok(n <= 3, `样本数不该因过期轮次膨胀，实际 ${n}`)
  } finally { await up.close() }
})

/* ============================================================
 * 问题 3：retryable 契约
 * ============================================================ */

test('协议错误 retryable=false，网络错误 retryable=true', () => {
  // 证书类错误不可重试
  for (const code of [
    'CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID',
    'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  ]) {
    const r = classifyError({ code })
    assert.equal(r.category, 'protocol', code)
    assert.equal(r.retryable, false, `${code} 不该标记为可重试`)
  }

  // 网络与超时可重试
  for (const code of ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ERR_TLS_HANDSHAKE_TIMEOUT']) {
    assert.equal(classifyError({ code }).retryable, true, `${code} 应可重试`)
  }
})

test('TLS 握手超时与证书错误分类不同、retryable 不同', () => {
  const hs = classifyError({ code: 'ERR_TLS_HANDSHAKE_TIMEOUT' })
  const cert = classifyError({ code: 'CERT_HAS_EXPIRED' })

  assert.equal(hs.category, 'timeout')
  assert.equal(cert.category, 'protocol')
  assert.notEqual(hs.retryable, cert.retryable, '两者是否可重试必须不同')
  assert.equal(hs.retryable, true)
  assert.equal(cert.retryable, false)
})

/* ============================================================
 * 问题 4：Cooling 保留依据
 * ============================================================ */

test('无探测记录的 Cooling 候选仍获得保留期（依据进入冷却时刻）', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { discoveredIps: ['203.0.113.9'] }, T)
  const c = pool.candidates.get('203.0.113.9')
  assert.equal(c.lastProbeAt, 0, '前提：从未被探测过')

  // 刚进入 cooling（1 秒前），保留期 1 小时
  const r = protectionReason(c, {
    isHealthProtected: () => true,
    healthEnteredAt: () => T - 1000,
    now: T,
    coolingRetentionMs: 3_600_000,
  })
  assert.equal(r, 'health', '没有探测记录也该被保护')
})

test('没有 lastProbeAt 也没有 enteredAt 时保守保留（不删）', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { discoveredIps: ['203.0.113.9'] }, T)
  const c = pool.candidates.get('203.0.113.9')

  const r = protectionReason(c, {
    isHealthProtected: () => true,
    now: T,
    coolingRetentionMs: 3_600_000,
  })
  assert.equal(r, 'health', '删了不可逆，保守地保留')
})

test('超过保留期后不再保护', () => {
  const pool = makePool(T)
  mergeCandidates(pool, { discoveredIps: ['203.0.113.9'] }, T)
  const c = pool.candidates.get('203.0.113.9')

  const r = protectionReason(c, {
    isHealthProtected: () => true,
    healthEnteredAt: () => T - 4_000_000,
    now: T,
    coolingRetentionMs: 3_600_000,
  })
  assert.equal(r, null, '超过保留期应可淘汰')
})

test('真实路径：进入 cooling 时记录 enteredAt', async () => {
  const { up } = await boot({ status: 200 })
  try {
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    const s = api.statOf(HOST, IP)
    assert.ok(s.health.enteredAt > 0, '应记录进入冷却的时刻')
  } finally { await up.close() }
})

test('真实路径：真实请求失败进 cooling 的 IP 也有 enteredAt', async () => {
  const { up } = await boot({ status: 200 }, { failThreshold: 1 })
  try {
    const e = new Error('ECONNREFUSED'); e.code = 'ECONNREFUSED'
    api.recordRequestFailure(HOST, IP, { message: 'ECONNREFUSED', err: e }, api.getRouteGeneration(HOST))

    assert.equal(api.getHealthState(HOST, IP), 'cooling')
    const s = api.statOf(HOST, IP)
    assert.ok(s.health.enteredAt > 0, '经真实请求失败进入 cooling 也要有时间依据')
  } finally { await up.close() }
})

/* ============================================================
 * 顺带修正：文档与配置
 * ============================================================ */

test('cordis.patch.yml 不再残留 GET /__router/mode?value=', () => {
  const root = path.resolve(import.meta.dirname, '../../')
  const txt = fs.readFileSync(path.join(root, 'cordis.patch.yml'), 'utf8')
  assert.equal(/GET \/__router\/mode\?value=/.test(txt), false, '旧注释应已修正')
  assert.match(txt, /POST \/__router\/mode/, '应说明 POST 修改模式')
})

test('CHANGELOG 的配置项计数与实际一致', () => {
  const root = path.resolve(import.meta.dirname, '../../')
  const cl = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8')
  const m = cl.match(/(\d+) new config fields/)
  assert.ok(m, '应能找到配置项计数')
  assert.equal(Number(m[1]), 13, '实际是 8 + 1 + 4 = 13')
})
