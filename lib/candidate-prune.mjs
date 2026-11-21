/**
 * candidate-prune.mjs — 容量与过期淘汰（Issue #11 阶段 4）
 *
 * **第一原则（评审特别强调）：容量上限不能压过 DNS 兜底。**
 * 如果 DNS 返回数量已超过 candidatePoolMaxSize，实际容量必须临时超出配置值 ——
 * 不能为了满足上限丢弃 DNS 地址。同理，当前线路也绝不能被容量逻辑删掉。
 *
 * **第二原则：淘汰候选 ≠ 删历史统计。**
 * ipStats 的清理有独立生命周期（本阶段只做候选侧；统计侧留给后续，
 * Agent 回收是 #12），避免「刚淘汰又被抽中，只能当全新节点」。
 */

/**
 * 判断一条候选是否受保护（不能被容量/过期淘汰）。
 *
 * @param {object} c 候选记录
 * @param {object} ctx { currentIp, dnsIps:Set, isHealthProtected, now, coolingRetentionMs }
 * @returns {string|null} 保护原因，null 表示可淘汰
 */
export function protectionReason(c, ctx) {
  const {
    currentIp, dnsIps, isHealthProtected, healthEnteredAt, now, coolingRetentionMs = 0,
  } = ctx || {}
  if (!c) return 'invalid'

  // 1. 当前线路：绝不能删，否则正常请求会突然失去线路
  if (currentIp && c.ip === currentIp) return 'current'

  // 2. 当前 DNS 返回的基础候选：兜底，删了等于自断退路
  if (dnsIps && typeof dnsIps.has === 'function' && dnsIps.has(c.ip)) return 'dns'

  // 3. 健康状态保护（cooling / half_open 在保留期内）
  if (typeof isHealthProtected === 'function' && isHealthProtected(c.ip)) {
    if (coolingRetentionMs <= 0) return 'health'
    // 保留期内不淘汰；超期后由过期逻辑处理。
    //
    // **依据是「进入冷却的时刻」，不是 lastProbeAt**（v0.2.2 静态审查发现）：
    // 某个 IP 可能通过真实请求失败进入 cooling，从未被探测过，
    // lastProbeAt 为 0 → 条件短路 → 拿不到应有的额外保留期。
    // 调用方通过 healthEnteredAt(ip) 提供该时刻；拿不到则退化为 lastProbeAt，
    // 再拿不到就按「没有时间依据」处理 —— 保守地视为仍在保留期内。
    const enteredAt = typeof healthEnteredAt === 'function' ? Number(healthEnteredAt(c.ip)) || 0 : 0
    const since = enteredAt > 0 ? enteredAt : Number(c.lastProbeAt) || 0
    if (since > 0) {
      if (now - since < coolingRetentionMs) return 'health'
    } else {
      // 完全没有任何时间依据：宁可不淘汰（保留了才有意义，删了不可逆）
      return 'health'
    }
  }

  return null
}

/**
 * 按「价值从低到高」排序，用于淘汰时优先丢弃低价值的。
 *
 * 价值判据（都不是性能数值，避免越界到 #10）：
 *   有成功记录 > 无成功记录
 *   探测次数多 > 少
 *   最近成功近 > 远
 *   最近出现近 > 远
 */
export function valueRank(c) {
  const hasSuccess = c.lastSuccessAt > 0 ? 1 : 0
  return {
    hasSuccess,
    probeCount: c.probeCount || 0,
    lastSuccessAt: c.lastSuccessAt || 0,
    lastSeenAt: c.lastSeenAt || 0,
  }
}

function compareByValueAsc(a, b) {
  const va = valueRank(a)
  const vb = valueRank(b)
  if (va.hasSuccess !== vb.hasSuccess) return va.hasSuccess - vb.hasSuccess     // 无成功的先淘汰
  if (va.probeCount !== vb.probeCount) return va.probeCount - vb.probeCount     // 探测少的先
  if (va.lastSuccessAt !== vb.lastSuccessAt) return va.lastSuccessAt - vb.lastSuccessAt
  return va.lastSeenAt - vb.lastSeenAt
}

/**
 * 容量整理。
 *
 * **允许实际容量超过上限**：当受保护对象数量本身已超过 maxSize 时，
 * 结果会大于 maxSize。这是刻意行为，不是 bug —— 见文件头第一原则。
 *
 * @param {object} pool
 * @param {object} ctx
 * @returns {{removed: string[], size: number, overCapacity: number, protectedCount: number}}
 */
export function pruneCandidatePool(pool, ctx) {
  const { maxSize = 64 } = ctx || {}
  if (!pool || !(pool.candidates instanceof Map)) {
    return { removed: [], size: 0, overCapacity: 0, protectedCount: 0 }
  }

  const all = [...pool.candidates.values()]
  const protectedList = []
  const evictable = []
  const reasonOf = new Map()

  for (const c of all) {
    const why = protectionReason(c, ctx)
    if (why) {
      protectedList.push(c)
      reasonOf.set(c.ip, why)
    } else {
      evictable.push(c)
    }
  }

  // 受保护对象先全部保留，再看剩余名额
  const budget = Math.max(0, maxSize - protectedList.length)
  const kept = evictable.slice().sort(compareByValueAsc)
  const removed = []

  // budget 之内的保留（从高价值那头取），其余淘汰
  // evictable 已按「低价值在前」排序，所以超出的尾部是高价值
  const keepCount = Math.min(budget, evictable.length)
  const toRemove = kept.length - keepCount
  for (let i = 0; i < toRemove; i += 1) {
    const c = kept[i]
    removed.push(c.ip)
    pool.candidates.delete(c.ip)
  }

  const size = pool.candidates.size
  return {
    removed: removed.sort(),
    size,
    // 受保护对象本身超过上限时如实报告超出多少
    overCapacity: Math.max(0, size - maxSize),
    protectedCount: protectedList.length,
  }
}

/**
 * 过期淘汰。
 *
 * 同时看 lastSeenAt / lastProbeAt / lastSuccessAt —— **不能只看 lastSeenAt**。
 * 历史优秀 IP 可能长期不在 DNS 返回中，但依然值得保留。
 *
 * @param {object} pool
 * @param {object} ctx { now, ttlMs, currentIp, dnsIps, isHealthProtected, coolingRetentionMs }
 * @returns {{expired: string[], keptProtected: number}}
 */
export function expireCandidatePool(pool, ctx) {
  const { now = 0, ttlMs = 86_400_000 } = ctx || {}
  if (!pool || !(pool.candidates instanceof Map)) {
    return { expired: [], keptProtected: 0 }
  }

  const expired = []
  let keptProtected = 0

  for (const [ip, c] of [...pool.candidates.entries()]) {
    const why = protectionReason(c, ctx)
    if (why) { keptProtected += 1; continue }

    // 三个时间戳取「最近一次有意义的接触」
    const lastTouch = Math.max(
      Number(c.lastSeenAt || 0),
      Number(c.lastProbeAt || 0),
      Number(c.lastSuccessAt || 0),
    )
    if (now - lastTouch > ttlMs) {
      pool.candidates.delete(ip)
      expired.push(ip)
    }
  }

  return { expired: expired.sort(), keptProtected }
}
