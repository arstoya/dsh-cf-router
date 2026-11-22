/**
 * state-restore.test.js — 业务状态恢复（Issue #22 阶段 2）
 *
 * 用两个独立的 plugin 实例模拟「重启」：实例 A 制造状态并写盘，
 * 实例 B 从同一个 stateFile 加载，验证恢复真的生效。
 *
 * 最要紧的一条：**恢复必须在 refreshAll() 之前发生**，
 * 否则第一轮探测会用空池覆盖掉恢复的候选池。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'
import { STATE_SCHEMA_VERSION } from '../../lib/state-store.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const IP = '127.0.0.1'

function tmpState(tag) {
  return path.join(os.tmpdir(), `cfr-restore-${tag}-${process.pid}-${Date.now()}.json`)
}

/** 起一个实例（不监听端口，只装配状态） */
function bootA(stateFile, overrides = {}) {
  const clock = createClock()
  setupPlugin({
    targets: [HOST], discoverEnabled: false, allowPrivateTargets: true,
    stateFile, ...overrides,
  }, { now: clock.now })
  return clock
}

/** 拆掉当前实例，再起一个新实例读同一个文件（模拟重启） */
function reboot(stateFile, overrides = {}) {
  teardownPlugin()
  const clock = createClock()
  setupPlugin({
    targets: [HOST], discoverEnabled: false, allowPrivateTargets: true,
    stateFile, ...overrides,
  }, { now: clock.now })
  return clock
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 候选池恢复
 * ============================================================ */

test('候选池跨重启保留（含 probeCount）', () => {
  const f = tmpState('cand')
  try {
    const c1 = bootA(f)
    // 制造候选：直接往池里塞，再写盘
    const pool = api.getCandidatePool(HOST)
    pool.candidates.set('203.0.113.7', {
      ip: '203.0.113.7', source: 'discovered',
      firstSeenAt: c1.now() - 100_000, lastSeenAt: c1.now(),
      lastProbeAt: c1.now() - 5000, lastSuccessAt: c1.now() - 5000,
      lastSelectedAt: c1.now() - 3000, lastColo: 'HKG',
      probeCount: 17, expiresAt: c1.now() + 86_400_000,
    })
    assert.equal(api.saveState(), true, '写盘应成功')

    reboot(f)
    const restored = api.getCandidatePool(HOST).candidates.get('203.0.113.7')
    assert.ok(restored, '重启后候选应恢复')
    assert.equal(restored.probeCount, 17, 'probeCount 不该归零')
    assert.equal(restored.source, 'discovered')
    assert.ok(restored.lastSuccessAt > 0, 'lastSuccessAt 应保留')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('恢复的候选池不需要等一轮探测就能参与评分', () => {
  const f = tmpState('score')
  try {
    bootA(f)
    const s = api.statOf(HOST, IP)
    s.metrics.probeTtfbEwmaMs = 250
    s.samples.probeTtfb = 30
    const pool = api.getCandidatePool(HOST)
    pool.candidates.set(IP, {
      ip: IP, source: 'dns', firstSeenAt: 1, lastSeenAt: api.deps.now(),
      lastProbeAt: 2, lastSuccessAt: 3, lastSelectedAt: 0, lastColo: 'HKG',
      probeCount: 30, expiresAt: api.deps.now() + 86_400_000,
    })
    api.saveState()

    reboot(f)
    const restored = api.statOf(HOST, IP)
    assert.equal(restored.metrics.probeTtfbEwmaMs, 250, 'EWMA 应恢复')
    assert.equal(restored.samples.probeTtfb, 30, '样本数应恢复（#10 minSamples 依赖它）')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 切换迟滞恢复
 * ============================================================ */

test('lastSwitchAt 跨重启保留，不会立刻触发性能切换', () => {
  const f = tmpState('hyst')
  try {
    const c1 = bootA(f)
    const st = api.getSwitchState(HOST)
    st.roundsBetter = 1
    st.lastSwitchAt = c1.now() - 1000     // 刚切过 1 秒
    api.saveState()

    const c2 = reboot(f)
    const back = api.getSwitchState(HOST)
    assert.equal(back.roundsBetter, 1, '连续更优轮次应恢复')
    assert.equal(back.lastSwitchAt, c1.now() - 1000, '上次切换时刻应恢复')
    assert.ok(c2.now() - back.lastSwitchAt < 120_000, '仍在驻留期内')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('从未切换过时不写入迟滞条目', () => {
  const f = tmpState('hyst2')
  try {
    bootA(f)
    // 显式清空：setupPlugin 内部可能已经触发过 switchRoute，
    // 那会把 lastSwitchAt 置成有效值，此时写入是正确的（不是垃圾）。
    // 这条用例要验证的是「真的从未切换」时不该产生条目。
    api.switchState.clear()
    api.saveState()
    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    const entry = raw.hosts[HOST]
    assert.equal(entry && entry.hysteresis, undefined,
      '从未切换时不该有 hysteresis 条目')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 健康状态：保守恢复（安全关键）
 * ============================================================ */

test('冷却已过期的 IP 重启后是 half_open，不是 healthy', () => {
  const f = tmpState('cool')
  try {
    const c1 = bootA(f)
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    // 把冷却截止时间改到过去（模拟关机很久后重启）
    api.statOf(HOST, IP).penaltyUntil = c1.now() - 60_000
    api.saveState()

    reboot(f)
    assert.equal(api.getHealthState(HOST, IP), 'half_open',
      '重启后必须经恢复探测才能回 healthy，不能直接放行')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('冷却未过期的 IP 重启后仍是 cooling', () => {
  const f = tmpState('cool2')
  try {
    bootA(f)
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    api.saveState()

    reboot(f)
    assert.equal(api.getHealthState(HOST, IP), 'cooling')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('恢复出的 half_open 标记 metricsStale，不参与评分', () => {
  const f = tmpState('stale')
  try {
    const c1 = bootA(f)
    api.transitionHealth(HOST, IP, 'cooling', 'test')
    api.statOf(HOST, IP).penaltyUntil = c1.now() - 60_000
    api.saveState()

    const c2 = reboot(f)
    const s = api.statOf(HOST, IP)
    assert.equal(s.health.metricsStale, true)
    assert.equal(api.scoreOf(HOST, IP, c2.now()), Infinity,
      'half_open + metricsStale 不可评分')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('healthy 的 IP 重启后仍可正常评分', () => {
  const f = tmpState('healthy')
  try {
    bootA(f)
    const s = api.statOf(HOST, IP)
    s.metrics.probeTtfbEwmaMs = 180
    s.samples.probeTtfb = 10
    api.saveState()

    const c2 = reboot(f)
    assert.equal(api.getHealthState(HOST, IP), 'healthy')
    const sc = api.scoreOf(HOST, IP, c2.now())
    assert.ok(Number.isFinite(sc), `healthy 应可评分，实际 ${sc}`)
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 与既有行为的一致性
 * ============================================================ */

test('routingMode 恢复行为未变（与 v1 一样）', () => {
  const f = tmpState('mode')
  try {
    bootA(f)
    api.setRoutingMode('direct')
    reboot(f)
    assert.equal(api.currentMode(), 'direct')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('状态文件带 schema v2 与 hosts 结构', () => {
  const f = tmpState('shape')
  try {
    bootA(f)
    api.statOf(HOST, IP).samples.probeTtfb = 5
    api.statOf(HOST, IP).metrics.probeTtfbEwmaMs = 300
    api.saveState()

    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    assert.equal(raw.version, STATE_SCHEMA_VERSION)
    assert.ok(raw.hosts && typeof raw.hosts === 'object', '应含 hosts')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('损坏的状态文件不阻止启动，也不被改写', () => {
  const f = tmpState('corrupt')
  fs.writeFileSync(f, '{ broken', 'utf8')
  try {
    bootA(f, { routingMode: 'direct' })
    assert.equal(api.currentMode(), 'direct')
    assert.equal(fs.readFileSync(f, 'utf8'), '{ broken', '读失败不该覆盖原文件')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('v1 旧文件升级后不丢 routingMode 且能正常工作', () => {
  const f = tmpState('v1')
  fs.writeFileSync(f, JSON.stringify({
    version: 1, routingMode: 'direct', updatedAt: 1_700_000_000_000,
  }), 'utf8')
  try {
    bootA(f)
    assert.equal(api.currentMode(), 'direct')
    assert.equal(api.getCandidatePool(HOST).candidates.size, 0, '旧文件没有候选，等同旧行为')
    assert.equal(api.saveState(), true, '能正常写回 v2')
    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    assert.equal(raw.version, 2)
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('statusSnapshot 暴露 restore 摘要', () => {
  const f = tmpState('summary')
  try {
    bootA(f)
    api.statOf(HOST, IP).samples.probeTtfb = 3
    api.saveState()
    reboot(f)
    const r = api.statusSnapshot().restore
    assert.ok(r, '应暴露 restore 摘要')
    assert.equal(typeof r.stats, 'number')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})
