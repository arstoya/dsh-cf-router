/**
 * metrics.test.js — EWMA 与评分（Issue #1 基准行为）
 *
 * 这里锁定的是**改造前**的语义，作为 Issue #3 重构的对照基线：
 *   - noteSuccess 的 EWMA 会被 ewmaMaxMs 截断（prefill 污染防护）
 *   - scoreOf 当前取 min(ewma, probeMedian)
 * 到 Issue #3 时这些断言会有意调整，届时同步改本文件。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { createClock } from '../helpers/fake-clock.mjs'
import { assertCloseTo } from '../helpers/assertions.mjs'

const api = mod.__testApi
const HOST = 'api.test'

function setup(overrides = {}) {
  api.reset()
  const clock = createClock()
  api.deps.now = clock.now
  api.configure({
    targets: [HOST],
    discoverEnabled: false,
    ewmaAlpha: 0.5,
    ewmaMaxMs: 3000,
    ...overrides,
  })
  return clock
}

function seed(entries) {
  api.state().hosts.set(HOST, {
    ips: entries.map((e) => e.ip),
    results: entries.map((e) => ({
      ip: e.ip, okCount: 3, samples: 3, median: e.median, best: e.median, colo: 'HKG', excluded: null,
    })),
    lastProbeAt: api.deps.now(),
    error: null,
  })
}

test.afterEach(() => mod.__resetForTest())

test('首个样本直接成为 EWMA 起点', () => {
  setup({ ewmaAlpha: 0.5 })
  seed([{ ip: '203.0.113.1', median: 200 }])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteSuccess(HOST, '203.0.113.1', 400)

  assert.equal(api.statOf(HOST, '203.0.113.1').ewmaMs, 400)
})

test('alpha=0.5 时第二个样本取中值', () => {
  setup({ ewmaAlpha: 0.5 })
  seed([{ ip: '203.0.113.1', median: 200 }])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteSuccess(HOST, '203.0.113.1', 400)
  api.noteSuccess(HOST, '203.0.113.1', 600)

  // 400*0.5 + 600*0.5 = 500
  assertCloseTo(api.statOf(HOST, '203.0.113.1').ewmaMs, 500, { label: 'ewma' })
})

test('超过 ewmaMaxMs 的样本被丢弃（大 prompt prefill 不污染线路评分）', () => {
  setup({ ewmaAlpha: 0.5, ewmaMaxMs: 3000 })
  seed([{ ip: '203.0.113.1', median: 200 }])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteSuccess(HOST, '203.0.113.1', 400)
  api.noteSuccess(HOST, '203.0.113.1', 12_000)   // 模型推理 12 秒，不是网络问题

  assertCloseTo(api.statOf(HOST, '203.0.113.1').ewmaMs, 400, { label: 'ewma 应保持 400' })
  assert.equal(api.statOf(HOST, '203.0.113.1').ok, 2, '样本仍要计入成功次数')
})

test('非有限值、零、负数样本不进入 EWMA', () => {
  setup({ ewmaAlpha: 0.5 })
  seed([{ ip: '203.0.113.1', median: 200 }])
  api.state().currentIp.set(HOST, '203.0.113.1')

  for (const bad of [NaN, Infinity, -1, 0, null, undefined]) {
    api.noteSuccess(HOST, '203.0.113.1', bad)
  }

  assert.equal(api.statOf(HOST, '203.0.113.1').ewmaMs, null, '脏样本不该产生 EWMA')
})

test('ewmaAlpha 被夹在 [0.05, 0.9]', () => {
  setup({ ewmaAlpha: 5 })
  seed([{ ip: '203.0.113.1', median: 200 }])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteSuccess(HOST, '203.0.113.1', 1000)
  api.noteSuccess(HOST, '203.0.113.1', 2000)

  // alpha 被夹到 0.9：1000*0.1 + 2000*0.9 = 1900
  assertCloseTo(api.statOf(HOST, '203.0.113.1').ewmaMs, 1900, { label: 'alpha 夹取' })
})

test('scoreOf 取 min(ewma, probeMedian)：任一指标快就不判它慢', () => {
  setup({ ewmaAlpha: 0.5 })
  seed([{ ip: '203.0.113.1', median: 600 }])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteSuccess(HOST, '203.0.113.1', 200)   // EWMA=200，比探测 600 快

  assert.equal(api.scoreOf(HOST, '203.0.113.1', api.deps.now()), 200)
})

test('scoreOf：EWMA 超出 probeMedian×4 时视为被污染，回退到探测值', () => {
  setup({ ewmaAlpha: 0.5, ewmaMaxMs: 100_000 })
  seed([{ ip: '203.0.113.1', median: 100 }])
  api.state().currentIp.set(HOST, '203.0.113.1')

  api.noteSuccess(HOST, '203.0.113.1', 900)   // 900 > 100*4，应被丢弃

  assert.equal(api.scoreOf(HOST, '203.0.113.1', api.deps.now()), 100)
})

test('scoreOf 对冷却中的 IP 返回 Infinity', () => {
  const clock = setup()
  seed([{ ip: '203.0.113.1', median: 100 }])
  const s = api.statOf(HOST, '203.0.113.1')
  s.penaltyUntil = clock.now() + 1000

  assert.equal(api.scoreOf(HOST, '203.0.113.1', clock.now()), Infinity)
})

test('scoreOf 对完全没有数据的 IP 返回 Infinity', () => {
  setup()
  seed([{ ip: '203.0.113.9', median: Infinity }])
  const entry = api.state().hosts.get(HOST)
  entry.results[0].okCount = 0
  entry.results[0].median = Infinity

  assert.equal(api.scoreOf(HOST, '203.0.113.9', api.deps.now()), Infinity)
})

test('statusSnapshot 里的候选字段在无样本时是 null 而不是 0', () => {
  setup()
  seed([{ ip: '203.0.113.1', median: 120 }])

  const snap = api.statusSnapshot()
  const cand = snap.hosts[0].candidates[0]

  assert.equal(cand.ewmaMs, null, '没有真实请求样本时 ewmaMs 必须是 null')
  assert.equal(cand.ok, 0)
  assert.equal(cand.fail, 0)
  assert.equal(cand.probeMs, 120)
})

test('TCP/TLS 计时工具函数：ipToInt / intToIp 往返一致', () => {
  for (const ip of ['0.0.0.0', '127.0.0.1', '203.0.113.7', '255.255.255.255']) {
    assert.equal(api.intToIp(api.ipToInt(ip)), ip)
  }
  assert.ok(Number.isNaN(api.ipToInt('300.1.1.1')))
  assert.ok(Number.isNaN(api.ipToInt('1.2.3')))
})

test('样本生成：sampleFromRanges 落在给定网段内且不重复超出配额', () => {
  setup()
  const ips = api.sampleFromRanges(['203.0.113.0/24'], 3)
  assert.equal(ips.length, 3)
  for (const ip of ips) assert.match(ip, /^203\.0\.113\.\d+$/)
})

test('randInCidr 对非法输入返回 null', () => {
  setup()
  for (const bad of ['', 'x/24', '1.2.3.4', '1.2.3.4/33', '1.2.3.4/4']) {
    assert.equal(api.randInCidr(bad), null, `应为 null: ${bad}`)
  }
})
