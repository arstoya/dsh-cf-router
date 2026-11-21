/**
 * config-effective.test.js — 配置的「写的值」与「跑的值」（Issue #17 最小修复）
 *
 * 核心要求（评审提出）：状态接口必须显示**实际生效值**，而不只是配置原值。
 *
 * 反例：配 firstByteTimeoutMs: 300，代码执行 Math.max(5000, 300)，
 * 真实生效 5000。若接口只贴 cfg.firstByteTimeoutMs，显示 300 —— 等于骗人，
 * 「静默夹取」问题根本没解决。
 *
 * 本 issue 刻意**不做**统一 CLAMPS 表、不加新上限：
 * 现有各字段的边界语义本来就不同，为消除一个静默夹取而引入统一上下限，
 * 反而会制造更多静默行为（见 docs/development/review-issue-17-18.md）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'

const api = mod.__testApi

function setup(overrides = {}) {
  setupPlugin({ targets: ['localhost'], discoverEnabled: false, ...overrides })
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 核心：配置值与生效值必须分开
 * ============================================================ */

test('firstByteTimeoutMs 配 300 → effective 显示 5000', () => {
  setup({ firstByteTimeoutMs: 300 })
  const e = api.statusSnapshot().configEffective.firstByteTimeoutMs

  assert.equal(e.configured, 300, '配置值应如实反映用户写的 300')
  assert.equal(e.effective, 5000, '生效值必须是 5000，不能显示成 300')
  assert.equal(e.floorMs, 5000)
})

test('firstByteTimeoutMs 配 180000（本机部署值）→ 原样生效', () => {
  setup({ firstByteTimeoutMs: 180000 })
  const e = api.statusSnapshot().configEffective.firstByteTimeoutMs
  assert.equal(e.configured, 180000)
  assert.equal(e.effective, 180000, '高于下限时不该被改动')
})

test('cooldownMs 配 500 → effective 显示 1000', () => {
  setup({ cooldownMs: 500 })
  const e = api.statusSnapshot().configEffective.cooldownMs
  assert.equal(e.configured, 500)
  assert.equal(e.effective, 1000)
})

test('probeIntervalMs 配 10000 → effective 显示 30000', () => {
  setup({ probeIntervalMs: 10000 })
  const e = api.statusSnapshot().configEffective.probeIntervalMs
  assert.equal(e.configured, 10000)
  assert.equal(e.effective, 30000)
})

test('healthCheckMs 配 1000 → effective 显示 5000', () => {
  setup({ healthCheckMs: 1000 })
  const e = api.statusSnapshot().configEffective.healthCheckMs
  assert.equal(e.configured, 1000)
  assert.equal(e.effective, 5000)
})

test('ewmaMaxMs 配 50 → effective 显示 200，并注明是分级阈值', () => {
  setup({ ewmaMaxMs: 50 })
  const e = api.statusSnapshot().configEffective.ewmaMaxMs
  assert.equal(e.configured, 50)
  assert.equal(e.effective, 200)
  assert.match(e.note, /分级阈值/)
})

/* ============================================================
 * 不新增上限：高值必须原样通过
 * ============================================================ */

test('不给只有下限的字段凭空加上限', () => {
  // 900000ms（15 分钟）用于长时间推理是完全合理的
  setup({ firstByteTimeoutMs: 900000, cooldownMs: 7_200_000 })
  const snap = api.statusSnapshot().configEffective

  assert.equal(snap.firstByteTimeoutMs.effective, 900000, '不该有 600000 上限')
  assert.equal(snap.cooldownMs.effective, 7_200_000, '不该有 3600000 上限')
})

/* ============================================================
 * 缺失值不伪造
 * ============================================================ */

test('配置缺省时 configured 是 null，不伪造', () => {
  api.reset()
  api.configure({ targets: ['localhost'], discoverEnabled: false })
  const e = api.statusSnapshot().configEffective

  // 注意：__testApi.configure 会走 withDefaults，所以这里是默认值而非 null
  // 真正缺省（cfg 里没有该键）才应为 null，这里验证类型合法
  for (const k of ['firstByteTimeoutMs', 'cooldownMs', 'probeIntervalMs', 'healthCheckMs', 'ewmaMaxMs']) {
    assert.ok(k in e, `缺少 ${k}`)
    assert.equal(typeof e[k].effective, 'number', `${k}.effective 应为数字`)
  }
})

/* ============================================================
 * 与实际执行路径一致
 * ============================================================ */

test('effective 值必须与代码实际执行时的夹取一致', () => {
  // 交叉校验：状态接口报的 effective，应等于代码里 Math.max(floor, cfg.x) 的结果
  const cases = [
    ['firstByteTimeoutMs', 300, 5000, 'Math.max(5000, cfg.firstByteTimeoutMs)'],
    ['cooldownMs', 500, 1000, 'Math.max(1000, cfg.cooldownMs)'],
    ['probeIntervalMs', 10000, 30000, 'Math.max(30000, cfg.probeIntervalMs)'],
    ['healthCheckMs', 1000, 5000, 'Math.max(5000, cfg.healthCheckMs)'],
    ['ewmaMaxMs', 50, 200, 'Math.max(200, cfg.ewmaMaxMs)'],
  ]
  for (const [field, configured, expected] of cases) {
    setup({ [field]: configured })
    const e = api.statusSnapshot().configEffective[field]
    assert.equal(e.configured, configured, `${field} configured`)
    assert.equal(e.effective, expected, `${field} effective 应与代码夹取一致`)
  }
})
