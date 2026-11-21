/**
 * health-weighted-failure.test.js — 加权失败统计（Issue #9 阶段 2）
 *
 * 方案 §13.3 给出的五个场景必须成立。注意本阶段**阈值判定仍以 consecutiveFail
 * 为准**（保持既有熔断行为），failureScore 是新增的观测量：
 *   · 它能区分「4 次首字节超时」与「4 次建连失败」
 *   · 阶段 4/5 引入状态机后才用它做更细的判断
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'

const api = mod.__testApi
const HOST = 'localhost'

function setup(overrides = {}) {
  const clock = createClock()
  setupPlugin({ failThreshold: 2, cooldownMs: 60_000, ...overrides }, { now: clock.now })
  return clock
}

const seed = () => api.state().hosts.set(HOST, {
  ips: ['203.0.113.1'],
  results: [{ ip: '203.0.113.1', okCount: 3, samples: 3, ttfbMedian: 100, ttfbBest: 100, totalMedian: 120, tcpMedian: 10, tlsMedian: 20, colo: 'HKG', excluded: null }],
  lastProbeAt: api.deps.now(), error: null,
})

/** 模拟一次上游网络错误 */
const netFail = (code = 'ECONNREFUSED') => {
  const e = new Error(code)
  e.code = code
  api.recordRequestFailure(HOST, '203.0.113.1', { message: code, err: e }, 0)
}
const firstByteFail = () => api.recordRequestFailure(HOST, '203.0.113.1', { message: 'first_byte_timeout' }, 0)
const okRequest = () => api.recordRequestSuccess(HOST, '203.0.113.1', { ttfbMs: 100, reused: false }, 0)

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 方案 §13.3 的五个场景
 * ============================================================ */

test('两次建连失败 → 进入 Cooling（权重各 1）', () => {
  const clock = setup({ failThreshold: 2 })
  seed()
  netFail(); netFail()

  const s = api.statOf(HOST, '203.0.113.1')
  assert.ok(s.penaltyUntil > clock.now(), '应已冷却')
  assert.equal(s.failureScore, 0, '判死后分数清零')
})

test('四次首字节超时 → 加权分数到 2（0.5×4）', () => {
  setup({ failThreshold: 99 })   // 抬高阈值，只看分数累积
  seed()
  for (let i = 0; i < 4; i += 1) firstByteFail()

  const s = api.statOf(HOST, '203.0.113.1')
  assert.equal(s.failureScore, 2, '0.5 × 4 = 2')
  assert.equal(s.consecutiveFail, 4, '未加权连败也记 4 次')
})

test('一次建连失败 + 两次首字节超时 → 分数 2（1 + 0.5×2）', () => {
  setup({ failThreshold: 99 })
  seed()
  netFail()
  firstByteFail(); firstByteFail()

  assert.equal(api.statOf(HOST, '203.0.113.1').failureScore, 2)
})

test('一次建连失败 + 一次成功 → 分数归零，不冷却', () => {
  const clock = setup({ failThreshold: 2 })
  seed()
  netFail()
  okRequest()

  const s = api.statOf(HOST, '203.0.113.1')
  assert.equal(s.failureScore, 0, '成功清零加权分数')
  assert.equal(s.consecutiveFail, 0)
  assert.equal(s.penaltyUntil <= clock.now(), true, '不该冷却')
})

test('一次客户端取消 + 一次建连失败 → 分数 1，不冷却', () => {
  const clock = setup({ failThreshold: 2 })
  seed()
  // 客户端取消：即使带 ECONNRESET 也不计惩罚
  const e = new Error('ECONNRESET')
  e.code = 'ECONNRESET'
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'ECONNRESET', err: e, clientAborted: true }, 0)
  netFail()

  const s = api.statOf(HOST, '203.0.113.1')
  assert.equal(s.failureScore, 1, '取消权重 0，只有建连失败计 1')
  assert.equal(s.consecutiveFail, 1)
  assert.equal(s.penaltyUntil <= clock.now(), true, '未达阈值不该冷却')
})

/* ============================================================
 * 不计惩罚的错误不污染统计
 * ============================================================ */

test('HTTP 401 不增加 fail / failureScore / consecutiveFail', () => {
  setup({ failThreshold: 2 })
  seed()
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'http_401', statusCode: 401 }, 0)

  const s = api.statOf(HOST, '203.0.113.1')
  assert.equal(s.fail, 0)
  assert.equal(s.consecutiveFail, 0)
  assert.equal(s.failureScore, 0)
})

test('HTTP 429 / 500 同样不惩罚 IP', () => {
  setup({ failThreshold: 2 })
  seed()
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'http_429', statusCode: 429 }, 0)
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'http_500', statusCode: 500 }, 0)

  assert.equal(api.statOf(HOST, '203.0.113.1').fail, 0)
})

test('不计惩罚的错误仍计入分类计数与 stats.errors', () => {
  setup({ failThreshold: 2 })
  seed()
  const before = api.statusSnapshot().stats.errors
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'http_403', statusCode: 403 }, 0)

  const st = api.statusSnapshot().stats
  assert.equal(st.errors, before + 1, '全局错误总数仍要反映事实')
  assert.ok(st.byCategory.auth >= 1, '应按分类累计')
})

/* ============================================================
 * 分类计数可观测
 * ============================================================ */

test('byCategory 按类别分别累计', () => {
  setup({ failThreshold: 99 })
  seed()
  netFail('ECONNREFUSED')
  netFail('ECONNRESET')
  firstByteFail()
  api.recordRequestFailure(HOST, '203.0.113.1', { message: 'http_429', statusCode: 429 }, 0)

  const c = api.statusSnapshot().stats.byCategory
  assert.ok(c.network >= 2, `network 计数，实际 ${JSON.stringify(c)}`)
  assert.ok(c.timeout >= 1)
  assert.ok(c.rate_limit >= 1)
})

/* ============================================================
 * 兼容性：现有字段语义未变
 * ============================================================ */

test('consecutiveFail 的语义与改造前一致（阈值判断仍按它）', () => {
  const clock = setup({ failThreshold: 2 })
  seed()
  // 4 次首字节超时：加权到 2，但 consecutiveFail=4 也过阈值
  for (let i = 0; i < 4; i += 1) {
    if (api.statOf(HOST, '203.0.113.1').penaltyUntil > clock.now()) break
    firstByteFail()
  }
  // 第 2 次就该判死了（阈值按 consecutiveFail）
  assert.ok(api.statOf(HOST, '203.0.113.1').penaltyUntil > clock.now(), '阈值行为未变')
})

test('statusSnapshot 保留原有候选字段', () => {
  setup()
  seed()
  const cand = api.statusSnapshot().hosts[0].candidates[0]
  for (const k of ['ok', 'fail', 'consecutiveFail', 'cooldownMsLeft', 'score']) {
    assert.ok(k in cand, `缺字段 ${k}`)
  }
})
