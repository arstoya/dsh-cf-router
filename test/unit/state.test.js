/**
 * state.test.js — 状态快照、配置默认值一致性、测试隔离
 *
 * 这一组里有两条是「防止测试自己骗自己」的：
 *   1. DEFAULTS 与 Config 的 .default() 必须逐字段相同 ——
 *      __testApi.configure 用 DEFAULTS 装配配置，两边漂移就等于测试跑在另一套默认值上。
 *   2. __resetForTest 必须真的清空状态，否则测试之间会互相污染，
 *      单跑通过、连跑失败。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { createClock } from '../helpers/fake-clock.mjs'
import { assertStatusShape } from '../helpers/assertions.mjs'

const api = mod.__testApi
const HOST = 'api.test'

function setup(overrides = {}) {
  api.reset()
  const clock = createClock()
  api.deps.now = clock.now
  api.configure({ targets: [HOST], discoverEnabled: false, ...overrides })
  return clock
}

test.afterEach(() => mod.__resetForTest())

test('DEFAULTS 与 Config 默认值逐字段一致', () => {
  // Config 用 stub 的 .default() 真值构造一次空输入，拿到「全默认」对象
  const built = mod.Config({})
  const diffs = []
  for (const [key, def] of Object.entries(mod.DEFAULTS)) {
    if (!(key in built)) { diffs.push(`${key}: DEFAULTS 有但 Config 没有`); continue }
    const a = JSON.stringify(def)
    const b = JSON.stringify(built[key])
    if (a !== b) diffs.push(`${key}: DEFAULTS=${a} Config=${b}`)
  }
  for (const key of Object.keys(built)) {
    if (!(key in mod.DEFAULTS)) diffs.push(`${key}: Config 有但 DEFAULTS 没有`)
  }
  assert.deepEqual(diffs, [], 'DEFAULTS 与 Config 不一致，改一边必须改另一边')
})

test('statusSnapshot 基本形状', () => {
  setup()
  const snap = api.statusSnapshot()
  assertStatusShape(snap)
  assert.equal(snap.ok, true)
  assert.match(snap.listen, /^http:\/\/127\.0\.0\.1:\d+$/)
  assert.equal(snap.routingMode, 'auto')
  assert.deepEqual(snap.hosts, [])
})

test('statusSnapshot 列出 host 与候选的完整字段', () => {
  setup()
  api.state().hosts.set(HOST, {
    ips: ['203.0.113.1'],
    results: [{ ip: '203.0.113.1', okCount: 3, samples: 3, median: 88, best: 80, colo: 'HKG', excluded: null }],
    lastProbeAt: api.deps.now(),
    error: null,
  })
  api.state().currentIp.set(HOST, '203.0.113.1')

  const h = api.statusSnapshot().hosts[0]
  assert.equal(h.host, HOST)
  assert.equal(h.current, '203.0.113.1')
  assert.equal(h.candidates.length, 1)
  for (const key of ['ip', 'colo', 'probeMs', 'probeBestMs', 'probeOk', 'ewmaMs', 'ok', 'fail', 'consecutiveFail', 'cooldownMsLeft', 'score']) {
    assert.ok(key in h.candidates[0], `候选缺字段 ${key}`)
  }
})

test('statusSnapshot 的统计字段完整', () => {
  setup()
  const st = api.statusSnapshot().stats
  for (const key of ['requests', 'errors', 'switches', 'timeouts', 'directFallback', 'bytesIn', 'bytesOut']) {
    assert.equal(typeof st[key], 'number', `stats.${key} 应为数字`)
  }
})

test('__resetForTest 清空所有模块级状态', () => {
  setup()
  api.state().hosts.set(HOST, { ips: [], results: [], lastProbeAt: 1, error: null })
  api.state().currentIp.set(HOST, '203.0.113.1')
  api.statOf(HOST, '203.0.113.1').ok = 5
  api.recordSwitch(HOST, 'a', 'b', 'x')
  api.deps.upstreamPort = 12345
  api.deps.tlsOptions = { ca: 'x' }

  mod.__resetForTest()

  const st = api.state()
  assert.equal(st.hosts.size, 0)
  assert.equal(st.currentIp.size, 0)
  assert.equal(st.ipStats.size, 0)
  assert.equal(st.switches.length, 0)
  assert.equal(st.stats.requests, 0)
  assert.equal(api.deps.upstreamPort, 443, '依赖必须复位')
  assert.deepEqual(api.deps.tlsOptions, {}, 'TLS 选项必须复位')
  assert.equal(api.getCfg(), null, '配置必须复位')
})

test('测试隔离：连续两次 setup 拿到互不可见的状态', () => {
  setup()
  api.state().hosts.set(HOST, { ips: ['1.1.1.1'], results: [], lastProbeAt: 1, error: null })
  assert.equal(api.state().hosts.size, 1)

  setup()   // 内部会 reset
  assert.equal(api.state().hosts.size, 0, '第二次 setup 应看不到上一次的 host')
})

test('currentMode：配置里的 routingMode 在启动时不会直接生效（已知问题，见 baseline）', () => {
  // 记录实际行为而不是理想行为：apply() 先把 cfg.routingMode 记成 lastCfgMode 基准，
  // 于是首次 currentMode() 认为「设置页没动过」，沿用 loadState() 的默认 auto。
  // 结果是「在 patch 里写 routingMode: direct」启动后并不生效，必须运行时调 setRoutingMode。
  // 这不是本轮要修的（不在 Issue #1–#3 范围），先钉住行为防止无意中改掉。
  setup({ routingMode: 'direct' })
  assert.equal(api.currentMode(), 'auto')
})

test('setRoutingMode 运行时生效并持久化到 stateFile（用临时路径，不碰 DSH_HOME）', async () => {
  const os = await import('node:os')
  const fs = await import('node:fs')
  const path = await import('node:path')
  const tmp = path.join(os.tmpdir(), `cfr-state-test-${process.pid}-${Date.now()}.json`)
  try { fs.unlinkSync(tmp) } catch { /* ignore */ }

  setup({ stateFile: tmp })
  const r = api.setRoutingMode('direct')

  assert.equal(r.ok, true)
  assert.equal(r.persisted, true)
  assert.equal(api.currentMode(), 'direct')
  const written = JSON.parse(fs.readFileSync(tmp, 'utf8'))
  assert.equal(written.routingMode, 'direct')

  fs.unlinkSync(tmp)
})

test('工具注册：apply 会注册四个工具且名称稳定', () => {
  api.reset()
  const registered = []
  const ctx = { tools: { register: (t) => registered.push(t) } }
  mod.apply(ctx, mod.Config({ targets: [], listenHost: '127.0.0.1', listenPort: 0, discoverEnabled: false }))

  const names = registered.map((t) => t.name).sort()
  assert.deepEqual(names, ['cf_router_mode', 'cf_router_probe', 'cf_router_reset', 'cf_router_status'])

  mod.dispose()
  mod.__resetForTest()
})
