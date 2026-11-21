/**
 * state-store.test.js — 版本化状态持久化（Issue #13 阶段 1）
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  migrateState, buildState, defaultState, isValidMode, STATE_SCHEMA_VERSION,
} from '../../lib/state-store.mjs'

const T = 1_700_000_000_000

/* ============================================================
 * v0 → v1 迁移
 * ============================================================ */

test('v0（无 version）→ v1，routingMode 保留', () => {
  const raw = { routingMode: 'direct', updatedAt: '2026-11-21T10:00:00.000Z' }
  const r = migrateState(raw)

  assert.equal(r.ok, true)
  assert.equal(r.fromVersion, 0)
  assert.equal(r.migrated, true)
  assert.equal(r.state.version, 1)
  assert.equal(r.state.routingMode, 'direct')
  assert.ok(r.state.updatedAt > 0, 'ISO 字符串应转成毫秒')
})

test('v0 的非法 routingMode 被清成 null（不编造）', () => {
  for (const bad of ['turbo', 1, null, undefined, {}]) {
    const r = migrateState({ routingMode: bad })
    assert.equal(r.state.routingMode, null, `${JSON.stringify(bad)} 应被清空`)
  }
})

test('v0 的 updatedAt 无法解析时留 0', () => {
  const r = migrateState({ routingMode: 'auto', updatedAt: 'not-a-date' })
  assert.equal(r.state.updatedAt, 0)
})

test('迁移保留用户手写的未知字段', () => {
  const r = migrateState({ routingMode: 'auto', myCustomNote: 'hello', updatedAt: 0 })
  assert.equal(r.state.myCustomNote, 'hello', '不该吃掉用户字段')
})

test('已是当前版本 → 不标记 migrated', () => {
  const r = migrateState({ version: 1, routingMode: 'auto', updatedAt: T })
  assert.equal(r.ok, true)
  assert.equal(r.fromVersion, 1)
  assert.equal(r.migrated, false)
  assert.equal(r.state.routingMode, 'auto')
  assert.equal(r.state.updatedAt, T)
})

/* ============================================================
 * 边界与安全降级
 * ============================================================ */

test('未来版本 → 不迁移、不覆盖，按默认启动', () => {
  const r = migrateState({ version: 99, routingMode: 'direct', someNewField: 1 })
  assert.equal(r.ok, false)
  assert.equal(r.blockedBy, 'future_version')
  assert.equal(r.state.version, STATE_SCHEMA_VERSION)
  assert.equal(r.state.routingMode, null, '保守默认，不猜')
})

test('非对象 → invalid_shape', () => {
  for (const bad of [null, undefined, 42, 'str', [], true]) {
    const r = migrateState(bad)
    assert.equal(r.ok, false)
    assert.equal(r.blockedBy, 'invalid_shape', `${JSON.stringify(bad)}`)
  }
})

test('空对象视为 v0 且可用', () => {
  const r = migrateState({})
  assert.equal(r.ok, true)
  assert.equal(r.state.routingMode, null)
})

test('版本号是非整数时按 v0 处理', () => {
  for (const v of [1.5, '1', -1, null]) {
    const r = migrateState({ version: v, routingMode: 'auto' })
    assert.equal(r.fromVersion, 0, `version=${JSON.stringify(v)} 应按 v0`)
    assert.equal(r.ok, true)
  }
})

/* ============================================================
 * buildState
 * ============================================================ */

test('buildState 写入当前版本与时间戳', () => {
  const s = buildState({ routingMode: 'direct' }, T)
  assert.equal(s.version, STATE_SCHEMA_VERSION)
  assert.equal(s.routingMode, 'direct')
  assert.equal(s.updatedAt, T)
})

test('buildState 对非法 mode 写 null', () => {
  assert.equal(buildState({ routingMode: 'turbo' }, T).routingMode, null)
  assert.equal(buildState({}, T).routingMode, null)
})

test('buildState 保留 extra 里的未知字段，但不许覆盖受控字段', () => {
  const s = buildState({
    routingMode: 'auto',
    extra: { myNote: 'x', version: 99, routingMode: 'direct', updatedAt: 0 },
  }, T)
  assert.equal(s.myNote, 'x')
  assert.equal(s.version, STATE_SCHEMA_VERSION, 'extra 不能改版本')
  assert.equal(s.routingMode, 'auto', 'extra 不能改模式')
  assert.equal(s.updatedAt, T)
})

test('buildState → migrateState 往返一致', () => {
  const built = buildState({ routingMode: 'direct' }, T)
  const back = migrateState(JSON.parse(JSON.stringify(built)))
  assert.equal(back.migrated, false)
  assert.equal(back.state.routingMode, 'direct')
  assert.equal(back.state.updatedAt, T)
})

/* ============================================================
 * 工具
 * ============================================================ */

test('isValidMode 只认 auto 与 direct', () => {
  assert.equal(isValidMode('auto'), true)
  assert.equal(isValidMode('direct'), true)
  for (const bad of ['AUTO', 'Direct', '', null, 1, {}]) {
    assert.equal(isValidMode(bad), false)
  }
})

test('defaultState 是当前版本且无模式', () => {
  const d = defaultState()
  assert.equal(d.version, STATE_SCHEMA_VERSION)
  assert.equal(d.routingMode, null)
})
