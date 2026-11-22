/**
 * state-throttle.test.js — 写盘节流（Issue #22 阶段 3）
 *
 * 状态变化会标脏，但只有超过最小间隔才真写盘；退出时强制写。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { createClock } from '../helpers/fake-clock.mjs'

const api = mod.__testApi
const HOST = 'localhost'

function tmpState(tag) {
  return path.join(os.tmpdir(), `cfr-throttle-${tag}-${process.pid}-${Date.now()}.json`)
}

function boot(stateFile, overrides = {}) {
  const clock = createClock()
  setupPlugin({
    targets: [HOST], discoverEnabled: false, allowPrivateTargets: true,
    stateFile, ...overrides,
  }, { now: clock.now })
  return clock
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 基本节流行为
 * ============================================================ */

test('未标脏时不写盘', () => {
  const f = tmpState('clean')
  try {
    boot(f)
    assert.equal(api.flushState(), false, '没变化就不该写')
    assert.equal(fs.existsSync(f), false)
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('标脏后首次 flush 会写盘', () => {
  const f = tmpState('first')
  try {
    boot(f)
    api.markStateDirty()
    assert.equal(api.flushState(), true, '首次应写盘')
    assert.equal(fs.existsSync(f), true)
    assert.equal(api.statusSnapshot().statePersistence.dirty, false, '写成功后清脏')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('间隔内再次 flush 被跳过且保持脏', () => {
  const f = tmpState('skip')
  try {
    const clock = boot(f, { stateFlushMinIntervalMs: 60_000 })
    api.markStateDirty()
    assert.equal(api.flushState(), true)

    clock.advance(1000)          // 只过 1 秒
    api.markStateDirty()
    assert.equal(api.flushState(), false, '不足间隔应跳过')
    assert.equal(api.statusSnapshot().statePersistence.dirty, true, '仍应保持脏')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('超过间隔后 flush 生效', () => {
  const f = tmpState('after')
  try {
    const clock = boot(f, { stateFlushMinIntervalMs: 60_000 })
    api.markStateDirty()
    api.flushState()

    clock.advance(61_000)
    api.markStateDirty()
    assert.equal(api.flushState(), true, '过间隔应写')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('force 忽略间隔', () => {
  const f = tmpState('force')
  try {
    boot(f, { stateFlushMinIntervalMs: 600_000 })
    api.markStateDirty()
    api.flushState()

    api.markStateDirty()
    assert.equal(api.flushState(false), false, '未 force 应跳过')
    assert.equal(api.flushState(true), true, 'force 应写')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('状态变化会标脏（switchRoute / recordRequestSuccess）', () => {
  const f = tmpState('dirty')
  try {
    boot(f)
    api.flushState(true)                        // 清干净
    assert.equal(api.statusSnapshot().statePersistence.dirty, false)

    api.recordRequestSuccess(HOST, '127.0.0.1', { ttfbMs: 100 }, null)
    assert.equal(api.statusSnapshot().statePersistence.dirty, true, '成功应标脏')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 写入内容正确性
 * ============================================================ */

test('节流写入的内容包含最新状态（不是旧快照）', () => {
  const f = tmpState('content')
  try {
    const clock = boot(f, { stateFlushMinIntervalMs: 60_000 })
    api.markStateDirty()
    api.flushState()

    // 再制造变化，等过间隔后写
    const s = api.statOf(HOST, '203.0.113.5')
    s.metrics.probeTtfbEwmaMs = 777
    s.samples.probeTtfb = 9
    api.markStateDirty()
    clock.advance(61_000)
    api.flushState()

    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    const stored = raw.hosts[HOST].stats['203.0.113.5']
    assert.equal(stored.metrics.probeTtfbEwmaMs, 777)
    assert.equal(stored.samples.probeTtfb, 9)
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

/* ============================================================
 * 失败容忍
 * ============================================================ */

test('写盘失败不抛错，且保持脏以便重试', () => {
  // 指向一个必然写不进去的路径（把文件当目录用）
  const bad = path.join(os.tmpdir(), `cfr-bad-${process.pid}-${Date.now()}`)
  fs.writeFileSync(bad, 'x', 'utf8')
  try {
    boot(path.join(bad, 'sub', 'state.json'))
    api.markStateDirty()
    const r = api.flushState(true)
    assert.equal(r, false, '写失败应返回 false')
    assert.equal(api.statusSnapshot().statePersistence.dirty, true, '失败后仍保持脏')
  } finally { try { fs.unlinkSync(bad) } catch { /* ignore */ } }
})

test('dispose 时强制写盘，不受节流限制', () => {
  const f = tmpState('dispose')
  try {
    boot(f, { stateFlushMinIntervalMs: 600_000 })
    api.markStateDirty()
    api.flushState()                    // 建立 lastFlushAt

    const s = api.statOf(HOST, '203.0.113.9')
    s.metrics.probeTtfbEwmaMs = 555
    s.samples.probeTtfb = 4
    api.markStateDirty()
    assert.equal(api.flushState(false), false, '节流应拦住')

    mod.dispose()                       // 内部 flushState(true)

    const raw = JSON.parse(fs.readFileSync(f, 'utf8'))
    const stored = raw.hosts[HOST].stats['203.0.113.9']
    assert.equal(stored.metrics.probeTtfbEwmaMs, 555, 'dispose 必须真写')
  } finally {
    mod.__resetForTest()
    try { fs.unlinkSync(f) } catch { /* ignore */ }
  }
})

/* ============================================================
 * 配置
 * ============================================================ */

test('stateFlushMinIntervalMs 默认 60 秒', () => {
  const f = tmpState('cfg')
  try {
    boot(f)
    assert.equal(api.getCfg().stateFlushMinIntervalMs, 60000)
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})

test('间隔配 0 时每次标脏都立刻写', () => {
  const f = tmpState('zero')
  try {
    boot(f, { stateFlushMinIntervalMs: 0 })
    api.markStateDirty()
    assert.equal(api.flushState(), true)
    api.markStateDirty()
    assert.equal(api.flushState(), true, '间隔 0 不该拦')
  } finally { try { fs.unlinkSync(f) } catch { /* ignore */ } }
})
