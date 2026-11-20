/**
 * router.test.js — 路由选择与故障切换（Issue #1 基准行为）
 *
 * 这一层直接驱动 __testApi，不启代理、不发网络请求：
 * 路由决策是纯计算，用假时钟 + 直接写 hosts/ipStats 就能完整覆盖。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { createClock } from '../helpers/fake-clock.mjs'

const api = mod.__testApi
const HOST = 'api.test'

/** 装一份最小配置 + 假时钟，并清空状态 */
function setup(overrides = {}) {
  api.reset()
  const clock = createClock()
  api.deps.now = clock.now
  api.configure({
    targets: [HOST],
    discoverEnabled: false,
    failThreshold: 2,
    cooldownMs: 60_000,
    ewmaAlpha: 0.5,
    ewmaMaxMs: 3000,
    ...overrides,
  })
  return clock
}

/** 直接造一份探测结果：ip -> 中位延迟 */
function seedCandidates(host, entries) {
  api.state().hosts.set(host, {
    ips: entries.map((e) => e.ip),
    results: entries.map((e) => ({
      ip: e.ip,
      okCount: e.okCount ?? 3,
      samples: 3,
      // Issue #3 起评分读 ttfbMedian；median 保留为兼容别名，指向同一 TTFB 值
      ttfbMedian: e.median,
      ttfbBest: e.median,
      totalMedian: (e.median ?? 0) + 20,
      tcpMedian: 10,
      tlsMedian: 20,
      median: e.median,
      best: e.median,
      colo: e.colo ?? 'HKG',
      excluded: null,
    })),
    lastProbeAt: api.deps.now(),
    error: null,
  })
}

test.afterEach(() => {
  mod.__resetForTest()
})

test('首次选择：chooseBest 返回延迟最低的 IP', () => {
  setup()
  seedCandidates(HOST, [
    { ip: '203.0.113.1', median: 180 },
    { ip: '203.0.113.2', median: 90 },
    { ip: '203.0.113.3', median: 140 },
  ])
  const best = api.chooseBest(HOST)
  assert.equal(best.ip, '203.0.113.2')
  assert.equal(best.score, 90)
})

test('无候选时 chooseBest 返回 null', () => {
  setup()
  assert.equal(api.chooseBest('nothing.test'), null)
})

test('全部候选处于冷却时 chooseBest 返回 null', () => {
  const clock = setup()
  seedCandidates(HOST, [{ ip: '203.0.113.1', median: 100 }])
  const s = api.statOf(HOST, '203.0.113.1')
  s.penaltyUntil = clock.now() + 30_000
  assert.equal(api.chooseBest(HOST), null)
})

test('冷却到期后重新可选', () => {
  const clock = setup()
  seedCandidates(HOST, [{ ip: '203.0.113.1', median: 100 }])
  const s = api.statOf(HOST, '203.0.113.1')
  s.penaltyUntil = clock.now() + 30_000
  assert.equal(api.chooseBest(HOST), null)
  clock.advance(30_001)
  assert.equal(api.chooseBest(HOST).ip, '203.0.113.1')
})

test('noteSuccess 更新成功计数并清零连败', () => {
  setup()
  seedCandidates(HOST, [{ ip: '203.0.113.1', median: 100 }])
  api.state().currentIp.set(HOST, '203.0.113.1')
  const s = api.statOf(HOST, '203.0.113.1')
  s.consecutiveFail = 1

  api.noteSuccess(HOST, '203.0.113.1', 120)

  assert.equal(s.ok, 1)
  assert.equal(s.consecutiveFail, 0)
})

test('noteFailure 未达阈值只计数，不切换', () => {
  setup({ failThreshold: 3 })
  seedCandidates(HOST, [
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 300 },
  ])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteFailure(HOST, '203.0.113.1', 'boom', 'error')

  const s = api.statOf(HOST, '203.0.113.1')
  assert.equal(s.fail, 1)
  assert.equal(s.consecutiveFail, 1)
  assert.equal(api.state().currentIp.get(HOST), '203.0.113.1')
})

test('noteFailure 达到阈值：判死 + 冷却 + 切到次优', () => {
  const clock = setup({ failThreshold: 2, cooldownMs: 60_000 })
  seedCandidates(HOST, [
    { ip: '203.0.113.1', median: 100 },
    { ip: '203.0.113.2', median: 300 },
  ])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteFailure(HOST, '203.0.113.1', 'boom', 'error')
  api.noteFailure(HOST, '203.0.113.1', 'boom', 'error')

  const s = api.statOf(HOST, '203.0.113.1')
  assert.ok(s.penaltyUntil > clock.now(), '被判死的 IP 应进入冷却')
  assert.equal(api.state().currentIp.get(HOST), '203.0.113.2', '应切到下一个候选')
  assert.equal(api.state().switches.length, 1)
  assert.equal(api.state().switches[0].to, '203.0.113.2')
})

test('失败次数累加会统计 timeout 分类', () => {
  setup({ failThreshold: 5 })
  seedCandidates(HOST, [{ ip: '203.0.113.1', median: 100 }])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteFailure(HOST, '203.0.113.1', 'no first byte', 'timeout')

  assert.equal(api.state().stats.timeouts, 1)
  assert.equal(api.state().stats.errors, 1)
})

test('direct 模式不钉 IP：statusSnapshot 报告 direct', () => {
  setup()
  seedCandidates(HOST, [{ ip: '203.0.113.1', median: 100 }])
  const r = api.setRoutingMode('direct')
  assert.equal(r.ok, true)
  assert.equal(api.currentMode(), 'direct')
  assert.equal(api.statusSnapshot().routingMode, 'direct')
})

test('setRoutingMode 拒绝非法模式', () => {
  setup()
  const r = api.setRoutingMode('turbo')
  assert.equal(r.ok, false)
  assert.equal(r.error, 'invalid_mode')
  assert.deepEqual(r.allowed, ['auto', 'direct'])
})

test('强制切换路径：recordSwitch 累加统计', () => {
  setup()
  const before = api.state().stats.switches
  api.recordSwitch(HOST, '203.0.113.1', '203.0.113.2', 'test')
  assert.equal(api.state().stats.switches, before + 1)
  assert.equal(api.state().switches.at(-1).reason, 'test')
})

test('resetAll 清空统计、冷却与切换记录', () => {
  setup()
  seedCandidates(HOST, [{ ip: '203.0.113.1', median: 100 }])
  api.state().currentIp.set(HOST, '203.0.113.1')
  api.noteFailure(HOST, '203.0.113.1', 'x', 'error')
  api.recordSwitch(HOST, 'a', 'b', 'r')

  api.resetAll()

  const st = api.state()
  assert.equal(st.switches.length, 0)
  assert.equal(st.stats.requests, 0)
  assert.equal(st.currentIp.size, 0)
  assert.equal(st.ipStats.size, 0)
})
