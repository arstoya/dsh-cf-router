/**
 * connection-pool.mjs — 连接池生命周期（Issue #12 阶段 1）
 *
 * 解决的问题：现在切换线路或判定 IP 故障时直接 `agent.destroy()`，
 * 会立即销毁该 Agent 上**所有** socket —— 包括正在传输的请求。
 * SSE 一旦被这样掐断，用户看到的是"生成中途卡死"。
 *
 * 三态生命周期（方案 §6.2）：
 *
 *   active ──切换/淘汰──► draining ──活动请求归零或超时──► destroyed
 *
 *   active    接受新请求
 *   draining  不再分配新请求，但允许已有请求跑完
 *   destroyed  已销毁
 *
 * 关键设计：**按 host|ip 分池，且允许同 key 存在多代**。
 * A 池排空中又要切回 A 时，新请求必须拿到一个全新的 active 池，
 * 而不是复用那个正在排空的。旧池自己排完再销毁。
 */

export const POOL_ACTIVE = 'active'
export const POOL_DRAINING = 'draining'
export const POOL_DESTROYED = 'destroyed'

/** 默认排空超时：超过这个时间还没排空就强制销毁（方案 §6.3-D） */
export const DEFAULT_DRAIN_TIMEOUT_MS = 120_000

/**
 * 创建一个连接池登记表。
 *
 * @param {object} [opts]
 * @param {() => number} [opts.now]
 * @param {(msg: string) => void} [opts.log]
 */
export function createPoolRegistry(opts = {}) {
  const now = opts.now || (() => Date.now())
  const log = opts.log || (() => {})

  /** key -> PoolRecord（只存 active 的，draining 的挪到下面） */
  const active = new Map()
  /** 排空中的池：Set<PoolRecord> */
  const draining = new Set()
  /** agent 对象 -> PoolRecord，用于请求结束时按 agent 找回归还 */
  const byAgent = new WeakMap()

  let seq = 0

  function makeRecord(key, agent) {
    seq += 1
    return {
      id: seq,
      key,
      agent,
      state: POOL_ACTIVE,
      inFlight: 0,
      createdAt: now(),
      drainingSince: 0,
      destroyedAt: 0,
      peakInFlight: 0,
    }
  }

  return {
    /**
     * 取（或登记）某个 key 的 active 池。
     * 已存在且仍是 active 就返回它；已被 drain 的不会在这里出现。
     */
    get(key, factory) {
      const cur = active.get(key)
      if (cur && cur.state === POOL_ACTIVE) return cur
      if (typeof factory !== 'function') return null
      const rec = makeRecord(key, factory())
      active.set(key, rec)
      byAgent.set(rec.agent, rec)
      return rec
    },

    /** 某个 key 当前是否已有 active 池 */
    has(key) {
      const cur = active.get(key)
      return Boolean(cur && cur.state === POOL_ACTIVE)
    },

    /** 通过 agent 对象反查池记录（请求结束时用） */
    recordOf(agent) {
      return byAgent.get(agent) || null
    },

    /**
     * 请求开始：活动计数 +1。返回池记录（可能为 null，表示不是我们管的对象）。
     */
    acquire(agent) {
      const rec = byAgent.get(agent)
      if (!rec || rec.state === POOL_DESTROYED) return null
      rec.inFlight += 1
      if (rec.inFlight > rec.peakInFlight) rec.peakInFlight = rec.inFlight
      return rec
    },

    /**
     * 请求结束：活动计数 -1。**必须幂等** —— 请求可能同时走 success、error、
     * close 多条路径，重复归还会让计数变成负数，池就永远排不空。
     */
    release(agent) {
      const rec = byAgent.get(agent)
      if (!rec || rec.state === POOL_DESTROYED) return null
      rec.inFlight = Math.max(0, rec.inFlight - 1)
      return rec
    },

    /**
     * 让某个 key 的 active 池进入 draining。
     * 不会被分配新请求，但已有请求继续跑。
     *
     * @returns {object|null} 被 drain 的池记录
     */
    drain(key) {
      const rec = active.get(key)
      if (!rec || rec.state !== POOL_ACTIVE) return null
      rec.state = POOL_DRAINING
      rec.drainingSince = now()
      active.delete(key)
      draining.add(rec)
      log(`pool drain ${key} (inFlight=${rec.inFlight})`)
      return rec
    },

    /** 让所有 active 池进入 draining（dropAgents 用） */
    drainAll(predicate) {
      const out = []
      for (const [key, rec] of [...active.entries()]) {
        if (typeof predicate === 'function' && !predicate(key, rec)) continue
        const d = this.drain(key)
        if (d) out.push(d)
      }
      return out
    },

    /**
     * 找出可以销毁的池：
     *   · 活动请求已归零，或
     *   · 排空时间超过 timeoutMs（**强制回收是超时保护，不是默认行为**）
     */
    drainable(timeoutMs = DEFAULT_DRAIN_TIMEOUT_MS) {
      const t = now()
      const out = []
      for (const rec of draining) {
        if (rec.inFlight === 0) { out.push({ rec, reason: 'idle' }); continue }
        if (t - rec.drainingSince >= timeoutMs) { out.push({ rec, reason: 'timeout' }); continue }
      }
      return out
    },

    /** 真正销毁一个池。幂等。 */
    destroy(rec) {
      if (!rec || rec.state === POOL_DESTROYED) return false
      rec.state = POOL_DESTROYED
      rec.destroyedAt = now()
      draining.delete(rec)
      try {
        rec.agent.destroy()
      } catch { /* ignore */ }
      log(`pool destroy ${rec.key} (peak=${rec.peakInFlight})`)
      return true
    },

    /**
     * 执行一轮回收：把 idle 或超时的 draining 池销毁。
     * @returns {{destroyed: string[], forced: string[]}}
     */
    reclaim(timeoutMs = DEFAULT_DRAIN_TIMEOUT_MS) {
      const destroyed = []
      const forced = []
      for (const { rec, reason } of this.drainable(timeoutMs)) {
        if (this.destroy(rec)) {
          destroyed.push(rec.key)
          if (reason === 'timeout') forced.push(rec.key)
        }
      }
      return { destroyed, forced }
    },

    /** 立即强制销毁某个 key 的 active 池（故障隔离用，跳过排空） */
    destroyNow(key) {
      const rec = active.get(key)
      if (!rec) return false
      active.delete(key)
      return this.destroy(rec)
    },

    /** 全部销毁（进程退出用） */
    destroyAll() {
      const out = []
      for (const [key, rec] of [...active.entries()]) {
        active.delete(key)
        if (this.destroy(rec)) out.push(key)
      }
      for (const rec of [...draining]) {
        if (this.destroy(rec)) out.push(rec.key)
      }
      return out
    },

    /** 观测 */
    stats() {
      const drainingList = [...draining].map((r) => ({
        id: r.id,
        key: r.key,
        inFlight: r.inFlight,
        drainingForMs: r.drainingSince ? now() - r.drainingSince : 0,
      }))
      return {
        activeCount: active.size,
        drainingCount: draining.size,
        totalInFlight: [...active.values()].reduce((a, r) => a + r.inFlight, 0)
          + [...draining].reduce((a, r) => a + r.inFlight, 0),
        activePools: [...active.values()].map((r) => ({
          id: r.id, key: r.key, inFlight: r.inFlight, peakInFlight: r.peakInFlight,
        })),
        drainingPools: drainingList,
      }
    },

    /** 仅供测试 */
    _raw() {
      return { active, draining, byAgent }
    },
  }
}
