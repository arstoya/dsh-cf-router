/**
 * health-state.test.js — 健康状态机（Issue #9 阶段 3）
 *
 * 三个实际状态：healthy / cooling / half_open（degraded 方案明确暂不实现）。
 * 关键约束：penaltyUntil 与 health.state 只能通过 transitionHealth 同步更新。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const IP = '203.0.113.1'

function setup(overrides = {}) {
  const clock = createClock()
  setupPlugin({ failThreshold: 2, cooldownMs: 60_000, ...overrides }, { now: clock.now })
  api.state().hosts.set(HOST, {
    ips: [IP],
    results: [{ ip: IP, okCount: 3, samples: 3, ttfbMedian: 100, ttfbBest: 100, totalMedian: 120, tcpMedian: 10, tlsMedian: 20, colo: 'HKG', excluded: null }],
    lastProbeAt: api.deps.now(), error: null,
  })
  return clock
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 初始状态与结构
 * ============================================================ */

test('新 IP 初始为 healthy，penaltyUntil 为 0', () => {
  setup()
  assert.equal(api.getHealthState(HOST, IP), 'healthy')
  assert.equal(api.statOf(HOST, IP).penaltyUntil, 0)
})

test('只有三个合法状态，degraded 不在其中', () => {
  assert.deepEqual([...api.HEALTH_STATES], ['healthy', 'cooling', 'half_open'])
})

/* ============================================================
 * 合法与非法转换
 * ============================================================ */

test('healthy → cooling 合法，且同步设置 penaltyUntil', () => {
  const clock = setup()
  const r = api.transitionHealth(HOST, IP, 'cooling', 'test')

  assert.equal(r.ok, true)
  assert.equal(r.from, 'healthy')
  assert.equal(r.to, 'cooling')
  assert.equal(api.getHealthState(HOST, IP), 'cooling')
  assert.ok(api.statOf(HOST, IP).penaltyUntil > clock.now(), 'penaltyUntil 必须同步')
})

test('healthy 不能直接跳 half_open', () => {
  setup()
  const r = api.transitionHealth(HOST, IP, 'half_open', 'illegal')
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'illegal_transition')
  assert.equal(api.getHealthState(HOST, IP), 'healthy', '状态不该变')
})

test('cooling 不能直接回 healthy', () => {
  setup()
  api.transitionHealth(HOST, IP, 'cooling', 'test')
  const r = api.transitionHealth(HOST, IP, 'healthy', 'skip-half-open')

  assert.equal(r.ok, false)
  assert.equal(api.getHealthState(HOST, IP), 'cooling')
})

test('cooling → half_open 合法，penaltyUntil 保持不动', () => {
  const clock = setup()
  api.transitionHealth(HOST, IP, 'cooling', 'test')
  const before = api.statOf(HOST, IP).penaltyUntil
  clock.advance(61_000)

  const r = api.transitionHealth(HOST, IP, 'half_open', 'expired')
  assert.equal(r.ok, true)
  assert.equal(api.getHealthState(HOST, IP), 'half_open')
  assert.equal(api.statOf(HOST, IP).penaltyUntil, before, '冷却时间戳不该被改写')
})

test('half_open → healthy 合法，清空 penaltyUntil', () => {
  setup()
  api.transitionHealth(HOST, IP, 'cooling', 'test')
  api.transitionHealth(HOST, IP, 'half_open', 'expired')
  const r = api.transitionHealth(HOST, IP, 'healthy', 'probe-ok')

  assert.equal(r.ok, true)
  assert.equal(api.getHealthState(HOST, IP), 'healthy')
  assert.equal(api.statOf(HOST, IP).penaltyUntil, 0)
  assert.ok(api.statOf(HOST, IP).health.lastRecoveryAt > 0, '应记录恢复时间')
})

test('half_open → cooling 合法（恢复探测失败）', () => {
  setup()
  api.transitionHealth(HOST, IP, 'cooling', 'test')
  api.transitionHealth(HOST, IP, 'half_open', 'expired')
  const r = api.transitionHealth(HOST, IP, 'cooling', 'probe-failed')

  assert.equal(r.ok, true)
  assert.equal(api.getHealthState(HOST, IP), 'cooling')
})

test('非法状态名被拒绝', () => {
  setup()
  for (const bad of ['degraded', 'dead', '', null]) {
    const r = api.transitionHealth(HOST, IP, bad, 'test')
    assert.equal(r.ok, false)
    assert.equal(r.reason, 'invalid_state')
  }
})

test('重复转换到同一状态是 noop', () => {
  setup()
  const r = api.transitionHealth(HOST, IP, 'healthy', 'noop')
  assert.equal(r.ok, true)
  assert.equal(r.reason, 'noop')
})

/* ============================================================
 * 时间推进
 * ============================================================ */

test('cooling 未到期 → advance 不动', () => {
  setup()
  api.transitionHealth(HOST, IP, 'cooling', 'test')
  const r = api.advanceHealthState(HOST, IP)
  assert.equal(r.to, 'cooling')
  assert.equal(api.getHealthState(HOST, IP), 'cooling')
})

test('cooling 到期 → advance 推进到 half_open', () => {
  const clock = setup()
  api.transitionHealth(HOST, IP, 'cooling', 'test')
  clock.advance(60_001)

  const r = api.advanceHealthState(HOST, IP)
  assert.equal(r.ok, true)
  assert.equal(r.to, 'half_open')
  assert.equal(api.getHealthState(HOST, IP), 'half_open')
})

/* ============================================================
 * 选路过滤
 * ============================================================ */

test('cooling 与 half_open 都不参与普通选路', () => {
  const clock = setup()
  assert.ok(Number.isFinite(api.scoreOf(HOST, IP, clock.now())), 'healthy 可评分')

  api.transitionHealth(HOST, IP, 'cooling', 'test')
  assert.equal(api.scoreOf(HOST, IP, clock.now()), Infinity, 'cooling 不可评分')

  clock.advance(60_001)
  api.advanceHealthState(HOST, IP)
  assert.equal(api.getHealthState(HOST, IP), 'half_open')
  assert.equal(api.scoreOf(HOST, IP, clock.now()), Infinity, 'half_open 不可评分')
})

test('metricsStale 时不可评分（恢复后待刷新）', () => {
  const clock = setup()
  api.statOf(HOST, IP).health.metricsStale = true
  assert.equal(api.scoreOf(HOST, IP, clock.now()), Infinity)
})

/* ============================================================
 * 失败路径接入状态机
 * ============================================================ */

test('达到阈值判死时经 transitionHealth 进入 cooling', () => {
  const clock = setup({ failThreshold: 2 })
  const netFail = () => {
    const e = new Error('ECONNREFUSED')
    e.code = 'ECONNREFUSED'
    api.recordRequestFailure(HOST, IP, { message: 'ECONNREFUSED', err: e }, 0)
  }
  netFail(); netFail()

  assert.equal(api.getHealthState(HOST, IP), 'cooling')
  assert.ok(api.statOf(HOST, IP).penaltyUntil > clock.now())
})

test('已是 cooling 时再次判死不触发非法转换', () => {
  setup({ failThreshold: 1 })
  const netFail = () => {
    const e = new Error('ECONNREFUSED')
    e.code = 'ECONNREFUSED'
    api.recordRequestFailure(HOST, IP, { message: 'x', err: e }, 0)
  }
  netFail()
  assert.equal(api.getHealthState(HOST, IP), 'cooling')
  netFail()   // 冷却中再失败
  assert.equal(api.getHealthState(HOST, IP), 'cooling', '不该抛错或跳变')
})

/* ============================================================
 * 状态接口与不变量
 * ============================================================ */

test('statusSnapshot 暴露 health 且保留旧字段', () => {
  const clock = setup()
  api.transitionHealth(HOST, IP, 'cooling', 'test')

  const c = api.statusSnapshot().hosts[0].candidates[0]
  assert.equal(c.health.state, 'cooling')
  assert.equal(typeof c.health.failureScore, 'number')
  assert.equal(c.health.metricsStale, true)
  // 旧字段仍在
  assert.ok(c.cooldownMsLeft > 0)
  assert.equal(typeof c.consecutiveFail, 'number')
})

test('健康状态变化不污染路由切换记录（generation 不变量）', () => {
  setup()
  const before = api.state().switches.length
  api.transitionHealth(HOST, IP, 'cooling', 'test')
  api.transitionHealth(HOST, IP, 'half_open', 'expired')
  api.transitionHealth(HOST, IP, 'healthy', 'ok')

  assert.equal(api.state().switches.length, before, '健康变化不该进 routes switches')
  assert.equal(api.getRouteGeneration(HOST), api.state().switches.length, 'generation 不变量仍成立')
})
