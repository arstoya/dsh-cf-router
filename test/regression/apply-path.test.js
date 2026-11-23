/**
 * apply-path.test.js — 生产装配路径（Issue #6 回归）
 *
 * 背景：这是一个真实缺陷的防回归测试。
 *
 * `apply()` 与 `__testApi.configure()` 是两条装配路径：
 *   · 测试全走 configure() → 内部调 withDefaults() → _allowedHosts 正常
 *   · 生产走 apply()       → 曾经是 `cfg = config` → _allowedHosts 从未生成
 *
 * 后果：targetOf 对任何目标都返回 target_not_allowed，生产环境全部 403。
 * 因为 547 项测试全都用 configure，这个缺陷长期没被发现。
 *
 * 本文件的所有用例都必须走 apply()，不能走 configure()。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import * as mod from '../../lib/index.js'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'

/** 只走 apply()，模拟 DSH Loader 的真实装配 */
function bootViaApply(overrides = {}) {
  const listened = []
  const ctx = {
    tools: { register: (t) => listened.push(t.name) },
    on() {}, get() {}, effect() {},
    logger: { info() {}, warn() {}, error() {} },
  }
  const server = mod.apply(ctx, mod.Config({
    targets: [HOST],
    listenHost: '127.0.0.1',
    listenPort: 0,
    allowPrivateTargets: true,
    discoverEnabled: false,
    stateFile: globalThis.__CFR_TEST_STATE_FILE__,
    probeIntervalMs: 9_999_999,
    healthCheckMs: 9_999_999,
    verbose: false,
    ...overrides,
  }))
  return { listened, server }
}

test.afterEach(() => {
  try { mod.dispose() } catch { /* ignore */ }
  mod.__resetForTest()
})

/* ============================================================
 * 核心：apply 必须初始化派生字段
 * ============================================================ */

test('apply() 之后 _allowedHosts 必须存在且非空', () => {
  bootViaApply()

  const snap = api.statusSnapshot()
  assert.deepEqual(snap.allowedTargets, [HOST],
    'apply 路径必须生成白名单，否则生产环境全部 403')
})

test('apply() 之后 _candidateRatios 已归一化', () => {
  bootViaApply()
  const cfg = api.getCfg()
  assert.ok(cfg._candidateRatios, '_candidateRatios 应由 applyTargetGuard 生成')
  const r = cfg._candidateRatios
  const sum = r.historical + r.current + r.dns + r.exploration
  assert.ok(Math.abs(sum - 1) < 1e-6, `比例应归一化，实际和 ${sum}`)
})

test('apply() 也能剔除非法 targets 并记录原因', () => {
  bootViaApply({ targets: ['good.example.com', '127.0.0.1', 'bad host'] })
  const snap = api.statusSnapshot()
  assert.deepEqual(snap.allowedTargets, ['good.example.com'])
  assert.equal(snap.rejectedTargets.length, 2)
})

/* ============================================================
 * 端到端：apply 装配的实例能真正转发
 * ============================================================ */

test('apply() 装配后，白名单内的目标能被正常路由（不再 403）', async () => {
  const port = await freePort()
  bootViaApply({ listenPort: port, allowPrivateTargets: true })

  // 等监听
  await new Promise((r) => setTimeout(r, 150))

  const r = await new Promise((resolve, reject) => {
    const q = http.request({ host: '127.0.0.1', port, path: '/provider/v1/models', method: 'GET' }, (res) => {
      const b = []
      res.on('data', (c) => b.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(b).toString() }))
    })
    q.on('error', reject)
    q.end()
  })

  // 不能是 403 target_not_allowed —— 那正是这个缺陷的症状
  assert.notEqual(r.status, 403, `不该被白名单拒绝，实际 ${r.status}: ${r.body.slice(0, 120)}`)
  // 具体状态取决于上游是否可达，但不能是「目标不在白名单」
  assert.equal(r.body.includes('target_not_allowed'), false,
    '不允许出现 target_not_allowed')
})

test('apply() 之后白名单外目标仍然是 403（防护没被放松）', async () => {
  const port = await freePort()
  bootViaApply({ listenPort: port })
  await new Promise((r) => setTimeout(r, 150))

  const r = await new Promise((resolve, reject) => {
    const q = http.request({
      host: '127.0.0.1', port, path: '/x', method: 'GET',
      headers: { 'x-cf-target': 'evil.example.com' },
    }, (res) => {
      const b = []
      res.on('data', (c) => b.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(b).toString() }))
    })
    q.on('error', reject)
    q.end()
  })

  assert.equal(r.status, 403, '白名单外仍应拒绝')
  assert.match(r.body, /target_not_allowed/)
})

/* ============================================================
 * 两条路径一致性
 * ============================================================ */

test('apply() 与 configure() 得到相同的派生字段', () => {
  const userCfg = {
    targets: ['a.example.com', 'b.example.com'],
    allowPrivateTargets: true,
    discoverEnabled: false,
  }

  // 路径 A：apply
  bootViaApply(userCfg)
  const viaApply = {
    allowed: api.statusSnapshot().allowedTargets.slice().sort(),
    ratios: api.getCfg()._candidateRatios,
  }
  mod.dispose()
  mod.__resetForTest()

  // 路径 B：configure
  api.reset()
  api.configure(userCfg)
  const viaConfigure = {
    allowed: api.statusSnapshot().allowedTargets.slice().sort(),
    ratios: api.getCfg()._candidateRatios,
  }

  assert.deepEqual(viaApply.allowed, viaConfigure.allowed,
    '两条装配路径必须得到同一份白名单')
  assert.deepEqual(viaApply.ratios, viaConfigure.ratios,
    '两条装配路径必须得到同一份归一化比例')
})
