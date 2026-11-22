/**
 * state-migration.test.js — 版本化状态持久化接入（Issue #13 阶段 2）
 *
 * 验证真实 stateFile 路径上的行为：
 *   · v0 旧文件能读、能迁移
 *   · 写入带 version
 *   · 原子写不留半截文件
 *   · 未来版本不被覆盖
 *   · 未知字段不丢
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { STATE_SCHEMA_VERSION } from '../../lib/state-store.mjs'

const api = mod.__testApi
const HOST = 'localhost'

function tmpPath(tag) {
  return path.join(os.tmpdir(), `cfr-state-${tag}-${process.pid}-${Date.now()}.json`)
}

function boot(stateFile, overrides = {}) {
  setupPlugin({ targets: [HOST], discoverEnabled: false, allowPrivateTargets: true, stateFile, ...overrides })
  return stateFile
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * v0 兼容
 * ============================================================ */

test('v0 旧文件（无 version）能被读取并识别模式', () => {
  const f = tmpPath('v0')
  fs.writeFileSync(f, JSON.stringify({ routingMode: 'direct', updatedAt: '2026-11-21T10:00:00.000Z' }), 'utf8')
  try {
    boot(f)
    assert.equal(api.currentMode(), 'direct')
    assert.equal(api.statusSnapshot().stateSchema.loadedFrom, STATE_SCHEMA_VERSION, '应报告迁移后的版本')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('写入后文件带当前 schema 版本', () => {
  const f = tmpPath('ver')
  try {
    boot(f)
    api.setRoutingMode('direct')
    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    assert.equal(raw.version, STATE_SCHEMA_VERSION)
    assert.equal(raw.routingMode, 'direct')
    assert.equal(typeof raw.updatedAt, 'number', 'v1 起 updatedAt 是毫秒数')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('v0 文件被设置模式后升级到当前版本', () => {
  const f = tmpPath('upgrade')
  fs.writeFileSync(f, JSON.stringify({ routingMode: 'auto', updatedAt: '2026-11-21T10:00:00.000Z' }), 'utf8')
  try {
    boot(f)
    api.setRoutingMode('direct')
    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    assert.equal(raw.version, STATE_SCHEMA_VERSION)
    assert.equal(raw.routingMode, 'direct')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 原子写
 * ============================================================ */

test('写入不留下临时文件', () => {
  const f = tmpPath('atomic')
  try {
    boot(f)
    api.setRoutingMode('direct')
    api.setRoutingMode('auto')

    const dir = path.dirname(f)
    const base = path.basename(f)
    const leftovers = fs.readdirSync(dir).filter((n) => n.startsWith(`${base}.tmp`))
    assert.deepEqual(leftovers, [], `不该残留临时文件，实际 ${JSON.stringify(leftovers)}`)
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('写入是完整 JSON（可被反复解析）', () => {
  const f = tmpPath('parse')
  try {
    boot(f)
    for (const m of ['direct', 'auto', 'direct']) {
      api.setRoutingMode(m)
      const txt = fs.readFileSync(f, 'utf8')
      assert.doesNotThrow(() => JSON.parse(txt), `写完 ${m} 后应是完整 JSON`)
    }
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 损坏与未来版本
 * ============================================================ */

test('损坏文件不阻止启动，退回配置值', () => {
  const f = tmpPath('corrupt')
  fs.writeFileSync(f, '{ this is not json', 'utf8')
  try {
    boot(f, { routingMode: 'direct' })
    assert.equal(api.currentMode(), 'direct', '应用配置值')
    // 关键：不该静默破坏用户的文件
    assert.equal(fs.readFileSync(f, 'utf8'), '{ this is not json', '读失败不该改写原文件')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('未来 schema 版本 → 不被覆盖，按配置启动', () => {
  const f = tmpPath('future')
  const future = JSON.stringify({ version: 99, routingMode: 'direct', futureField: 'keep-me' })
  fs.writeFileSync(f, future, 'utf8')
  try {
    boot(f, { routingMode: 'auto' })
    assert.equal(api.currentMode(), 'auto', '不采信未来版本的模式')
    assert.equal(fs.readFileSync(f, 'utf8'), future, '绝不能覆盖未来版本的文件')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 未知字段保留
 * ============================================================ */

test('用户手写的未知字段在写入后仍保留', () => {
  const f = tmpPath('extra')
  fs.writeFileSync(f, JSON.stringify({
    version: 1, routingMode: 'auto', updatedAt: 0, myNote: '请勿删除', another: 42,
  }), 'utf8')
  try {
    boot(f)
    api.setRoutingMode('direct')
    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    assert.equal(raw.myNote, '请勿删除', '不该吃掉用户字段')
    assert.equal(raw.another, 42)
    assert.equal(raw.routingMode, 'direct')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * resetRoutingMode 走同一条路径
 * ============================================================ */

test('reset-mode 只删 routingMode，写回仍是当前版本', () => {
  const f = tmpPath('reset')
  fs.writeFileSync(f, JSON.stringify({
    version: 1, routingMode: 'direct', updatedAt: 0, keepMe: 'x',
  }), 'utf8')
  try {
    boot(f, { routingMode: 'auto' })
    const r = api.resetRoutingMode()
    assert.equal(r.ok, true)

    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    assert.equal('routingMode' in raw, false, 'routingMode 应被删除')
    assert.equal(raw.version, STATE_SCHEMA_VERSION, '应写回当前版本')
    assert.equal(raw.keepMe, 'x', '其它字段保留')
    assert.ok(raw.routingModeResetAt > 0, '记录重置时刻')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('reset-mode 对 v0 文件也能工作（先迁移再删键）', () => {
  const f = tmpPath('reset-v0')
  fs.writeFileSync(f, JSON.stringify({ routingMode: 'direct', updatedAt: '2026-11-21T10:00:00.000Z' }), 'utf8')
  try {
    boot(f, { routingMode: 'auto' })
    const r = api.resetRoutingMode()
    assert.equal(r.ok, true)

    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    assert.equal('routingMode' in raw, false)
    assert.equal(raw.version, STATE_SCHEMA_VERSION, 'v0 文件重置后应升级到当前版本')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 状态接口
 * ============================================================ */

test('statusSnapshot 暴露 stateSchema', () => {
  const f = tmpPath('snap')
  try {
    boot(f)
    api.setRoutingMode('direct')
    const s = api.statusSnapshot().stateSchema
    assert.equal(s.version, STATE_SCHEMA_VERSION)
    assert.equal(s.loadedFrom, STATE_SCHEMA_VERSION)
    assert.equal(s.path, f)
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('无状态文件时 stateSchema.loadedFrom 为 null', () => {
  const f = tmpPath('none')
  try {
    boot(f)   // 文件不存在
    assert.equal(api.statusSnapshot().stateSchema.loadedFrom, null)
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})
