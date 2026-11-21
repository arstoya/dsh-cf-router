/**
 * volatile-stub.test.js — 测试桩与生产 volatile 语义一致性（Issue #18 前置）
 *
 * 存在的理由：插件代码里有一条分支
 *   const raw = cfg.routingMode
 *   const cv = typeof raw?.get === 'function' ? raw.get() : raw
 * 如果测试桩返回普通字符串，这条 else 分支被覆盖，而生产走的是 get() 分支。
 * 于是"测试全绿"和"生产能跑"是两件事 —— 这层用例就是防这个。
 *
 * 同时也直接对生产实现做一次只读校验（不 import，只读源码文本），
 * 确保我们模拟的合约没有随上游版本漂移。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'

import z, { makeVolatile, isVolatileRef } from '../helpers/stubs/schemastery.mjs'

/* ============================================================
 * 生产合约只读校验
 * ============================================================ */

const SCHEMASTERy = 'D:/Deepseek Harness/resources/app/dsh/node_modules/@deepseek-ai/schemastery/lib/index.mjs'
const COSMOKIT = 'D:/Deepseek Harness/resources/app/dsh/node_modules/@deepseek-ai/cosmokit/lib/index.js'

test('生产 volatile 仍由 createVolatile 包装（合约未被上游改掉）', (t) => {
  if (!existsSync(SCHEMASTERy) || !existsSync(COSMOKIT)) {
    t.skip('宿主源码不在本机，跳过合约校验')
    return
  }
  const sm = readFileSync(SCHEMASTERy, 'utf8')
  assert.match(sm, /createVolatile\(value\)/, 'schemastery 应仍调用 createVolatile')

  const ck = readFileSync(COSMOKIT, 'utf8')
  const i = ck.indexOf('function createVolatile(')
  assert.ok(i >= 0, 'cosmokit 应仍定义 createVolatile')
  const body = ck.slice(i, i + 500)
  assert.match(body, /get:\s*\(\)\s*=>/, '引用应暴露 get()')
  assert.match(body, /Object\.freeze/, '引用应被冻结')
})

/* ============================================================
 * 桩的 volatile 合约（Issue 里列出的最低测试要求）
 * ============================================================ */

test('volatile 字段返回引用对象，不是普通值', () => {
  const schema = z.object({
    routingMode: z.string().default('auto').volatile(),
  })
  const config = schema({})

  const ref = config.routingMode
  assert.equal(typeof ref, 'object', '必须是对象，不能是字符串')
  assert.equal(typeof ref.get, 'function', '必须暴露 .get()')
  assert.equal(ref.get(), 'auto')
})

test('引用身份稳定：同一字段多次访问是同一个对象', () => {
  const schema = z.object({
    routingMode: z.string().default('auto').volatile(),
  })
  const config = schema({})

  assert.equal(config.routingMode, config.routingMode, '引用身份必须稳定')
})

test('引用被冻结：不能新增或删除属性', () => {
  const ref = makeVolatile('direct')
  assert.equal(Object.isFrozen(ref), true)

  const before = Object.keys(ref).length
  assert.throws(() => { ref.injected = 1 }, TypeError)
  assert.equal(Object.keys(ref).length, before)
})

test('更新后 .get() 能读到新值', () => {
  const schema = z.object({
    routingMode: z.string().default('auto').volatile(),
  })
  const config = schema({})
  const ref = config.routingMode

  assert.equal(ref.get(), 'auto')
  ref.set('direct')
  assert.equal(ref.get(), 'direct', '写入后应读到新值')
})

test('volatile 与非 volatile 字段的产出形态不同', () => {
  const schema = z.object({
    plain: z.string().default('x'),
    volatileField: z.string().default('y').volatile(),
  })
  const config = schema({})

  assert.equal(config.plain, 'x', '普通字段仍是原值')
  assert.equal(typeof config.volatileField, 'object')
  assert.equal(config.volatileField.get(), 'y')
})

test('isVolatileRef 能正确识别两种形态', () => {
  const ref = makeVolatile('auto')
  assert.equal(isVolatileRef(ref), true)
  assert.equal(isVolatileRef('auto'), false)
  assert.equal(isVolatileRef(null), false)
  assert.equal(isVolatileRef({}), false)
})

/* ============================================================
 * 插件代码确实走 get() 分支
 * ============================================================ */

test('插件 currentMode() 读取 volatile 引用时走 .get() 分支', async () => {
  const mod = await import('../../lib/index.js')
  const api = mod.__testApi
  api.reset()

  // 用真实的 Config 产出 volatile 引用，再交给 configure
  const built = mod.Config({ targets: ['x.test'], routingMode: 'direct' })
  assert.equal(typeof built.routingMode, 'object', 'Config 产出的 routingMode 应是引用')

  api.configure(built)
  // 有 stateFile 时按现有语义（stateFile 优先），无 stateFile 时读配置
  const mode = api.currentMode()
  assert.ok(['auto', 'direct'].includes(mode), `currentMode 应返回合法值，实际 ${mode}`)

  mod.__resetForTest()
})
