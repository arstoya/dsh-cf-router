/**
 * connection-pool.test.js — 连接池生命周期（Issue #12 阶段 1）
 *
 * 纯逻辑测试：不建真实 socket，用假 agent 对象验证状态机与计数。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  createPoolRegistry, POOL_ACTIVE, POOL_DRAINING, POOL_DESTROYED, DEFAULT_DRAIN_TIMEOUT_MS,
} from '../../lib/connection-pool.mjs'

function mkAgent() {
  return { destroyed: false, destroy() { this.destroyed = true } }
}

function mkRegistry() {
  let t = 1_000_000
  const clock = { advance: (ms) => { t += ms }, now: () => t }
  const reg = createPoolRegistry({ now: clock.now })
  return { reg, clock }
}

/* ============================================================
 * 基本生命周期
 * ============================================================ */

test('get 创建 active 池，重复调用复用同一个', () => {
  const { reg } = mkRegistry()
  const a1 = reg.get('h|1.1.1.1', mkAgent)
  const a2 = reg.get('h|1.1.1.1', mkAgent)

  assert.equal(a1.id, a2.id, '同 key 应复用')
  assert.equal(a1.state, POOL_ACTIVE)
  assert.equal(a1.inFlight, 0)
})

test('acquire / release 正确增减活动计数', () => {
  const { reg } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)

  reg.acquire(pool.agent)
  reg.acquire(pool.agent)
  assert.equal(pool.inFlight, 2)
  assert.equal(pool.peakInFlight, 2)

  reg.release(pool.agent)
  assert.equal(pool.inFlight, 1)
})

test('release 幂等：多路径归还不让计数变负', () => {
  const { reg } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)

  reg.acquire(pool.agent)
  reg.release(pool.agent)
  reg.release(pool.agent)
  reg.release(pool.agent)

  assert.equal(pool.inFlight, 0, '不能变负，否则池永远排不空')
})

test('peakInFlight 记录峰值用于观测', () => {
  const { reg } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  reg.acquire(pool.agent); reg.acquire(pool.agent); reg.acquire(pool.agent)
  reg.release(pool.agent); reg.release(pool.agent); reg.release(pool.agent)
  reg.acquire(pool.agent)

  assert.equal(pool.inFlight, 1)
  assert.equal(pool.peakInFlight, 3, '峰值应保留')
})

/* ============================================================
 * Draining
 * ============================================================ */

test('drain 后不再被 get 复用（同 key 会新建 active 池）', () => {
  const { reg } = mkRegistry()
  const old = reg.get('h|1.1.1.1', mkAgent)
  const drained = reg.drain('h|1.1.1.1')

  assert.equal(drained.id, old.id)
  assert.equal(drained.state, POOL_DRAINING)
  assert.equal(reg.has('h|1.1.1.1'), false, 'draining 不算 active')

  const fresh = reg.get('h|1.1.1.1', mkAgent)
  assert.notEqual(fresh.id, old.id, '应新建一代，而不是复用排空中的')
  assert.equal(fresh.state, POOL_ACTIVE)
})

test('draining 中的池仍可 release（已有请求跑完）', () => {
  const { reg } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  reg.acquire(pool.agent)
  reg.acquire(pool.agent)
  reg.drain('h|1.1.1.1')

  assert.equal(pool.inFlight, 2)
  reg.release(pool.agent)
  assert.equal(pool.inFlight, 1, '排空过程中计数正常减少')
})

test('drain 不存在的 key 返回 null', () => {
  const { reg } = mkRegistry()
  assert.equal(reg.drain('nonexistent'), null)
})

test('drainAll 支持按前缀筛选', () => {
  const { reg } = mkRegistry()
  reg.get('a.com|1.1.1.1', mkAgent)
  reg.get('a.com|2.2.2.2', mkAgent)
  reg.get('b.com|1.1.1.1', mkAgent)

  const out = reg.drainAll((key) => key.startsWith('a.com|'))
  assert.equal(out.length, 2)
  assert.equal(reg.has('b.com|1.1.1.1'), true, '其他 host 不受影响')
})

/* ============================================================
 * 回收：idle 与超时
 * ============================================================ */

test('活动请求归零 → 可回收', () => {
  const { reg } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  reg.drain('h|1.1.1.1')

  assert.equal(pool.inFlight, 0)
  const list = reg.drainable()
  assert.equal(list.length, 1)
  assert.equal(list[0].reason, 'idle')
})

test('仍有活动请求且未超时 → 不可回收（这是保护活动请求的核心）', () => {
  const { reg } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  reg.acquire(pool.agent)
  reg.drain('h|1.1.1.1')

  assert.equal(reg.drainable(DEFAULT_DRAIN_TIMEOUT_MS).length, 0, '不能回收还在跑的请求')
})

test('超过排空超时 → 强制回收（超时保护，非默认行为）', () => {
  const { reg, clock } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  reg.acquire(pool.agent)
  reg.drain('h|1.1.1.1')

  clock.advance(DEFAULT_DRAIN_TIMEOUT_MS + 1)
  const list = reg.drainable(DEFAULT_DRAIN_TIMEOUT_MS)
  assert.equal(list.length, 1)
  assert.equal(list[0].reason, 'timeout')
})

test('reclaim 销毁并返回分类结果', () => {
  const { reg, clock } = mkRegistry()
  const a = reg.get('h|1.1.1.1', mkAgent)
  const b = reg.get('h|2.2.2.2', mkAgent)
  reg.acquire(b.agent)

  reg.drain('h|1.1.1.1')
  reg.drain('h|2.2.2.2')
  clock.advance(DEFAULT_DRAIN_TIMEOUT_MS + 1)

  const r = reg.reclaim(DEFAULT_DRAIN_TIMEOUT_MS)
  assert.deepEqual(r.destroyed.sort(), ['h|1.1.1.1', 'h|2.2.2.2'])
  // a 没有活动请求 → idle；b 有活动请求且超时 → forced（真正的强制回收）
  assert.deepEqual(r.forced, ['h|2.2.2.2'], '只有被超时强杀的才算 forced')
  assert.equal(a.agent.destroyed, true)
  assert.equal(b.agent.destroyed, true)
})

test('destroy 幂等', () => {
  const { reg } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  reg.drain('h|1.1.1.1')

  assert.equal(reg.destroy(pool), true)
  assert.equal(reg.destroy(pool), false, '第二次应返回 false')
  assert.equal(pool.state, POOL_DESTROYED)
})

/* ============================================================
 * 故障隔离 vs 正常淘汰
 * ============================================================ */

test('destroyNow 跳过排空直接销毁（故障隔离用）', () => {
  const { reg } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  reg.acquire(pool.agent)

  assert.equal(reg.destroyNow('h|1.1.1.1'), true)
  assert.equal(pool.agent.destroyed, true, '强制销毁不看活动请求')
  assert.equal(reg.has('h|1.1.1.1'), false)
})

test('destroyAll 清空所有池（进程退出用）', () => {
  const { reg } = mkRegistry()
  const a = reg.get('h|1.1.1.1', mkAgent)
  const b = reg.get('h|2.2.2.2', mkAgent)
  reg.drain('h|2.2.2.2')

  const out = reg.destroyAll()
  assert.equal(out.length, 2)
  assert.equal(a.agent.destroyed, true)
  assert.equal(b.agent.destroyed, true)
  assert.equal(reg.stats().activeCount, 0)
  assert.equal(reg.stats().drainingCount, 0)
})

/* ============================================================
 * 观测
 * ============================================================ */

test('stats 如实反映活动与排空', () => {
  const { reg } = mkRegistry()
  const a = reg.get('h|1.1.1.1', mkAgent)
  reg.get('h|2.2.2.2', mkAgent)
  reg.acquire(a.agent)
  reg.drain('h|1.1.1.1')

  const s = reg.stats()
  assert.equal(s.activeCount, 1)
  assert.equal(s.drainingCount, 1)
  assert.equal(s.totalInFlight, 1)
  assert.equal(s.drainingPools[0].key, 'h|1.1.1.1')
})

/* ============================================================
 * SSE 长请求场景
 * ============================================================ */

test('SSE 长时间不结束：通知期内不会被销毁', () => {
  const { reg, clock } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  // SSE 开始，占住一个活动槽
  reg.acquire(pool.agent)
  reg.drain('h|1.1.1.1')

  // 模拟线路切换后，SSE 又跑了 60 秒
  for (let i = 0; i < 6; i += 1) {
    clock.advance(10_000)
    assert.equal(reg.drainable(DEFAULT_DRAIN_TIMEOUT_MS).length, 0, `第 ${i} 次检查不该被回收`)
  }
  assert.equal(pool.agent.destroyed, false, 'SSE 仍在传输，不能被销毁')

  // SSE 自然结束
  reg.release(pool.agent)
  assert.equal(reg.drainable().length, 1, '结束后才可回收')
})

test('SSE 永不结束：最终由超时兜底', () => {
  const { reg, clock } = mkRegistry()
  const pool = reg.get('h|1.1.1.1', mkAgent)
  reg.acquire(pool.agent)
  reg.drain('h|1.1.1.1')

  clock.advance(DEFAULT_DRAIN_TIMEOUT_MS)
  const r = reg.reclaim(DEFAULT_DRAIN_TIMEOUT_MS)
  assert.deepEqual(r.forced, ['h|1.1.1.1'])
  assert.equal(pool.agent.destroyed, true)
})
