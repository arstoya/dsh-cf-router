/**
 * candidate-explore.mjs — 有限探索（Issue #11 阶段 3）
 *
 * 目的：避免长期困在局部最优 —— 历史优秀 IP 不能完全占满候选池，
 * 但也不能每轮无条件重新生成整个候选集（那正是当前实现的毛病）。
 *
 * 三条约束：
 *   1. 探索有配额（比例来自配置，默认 20%）
 *   2. 探索有最小间隔（默认 5 分钟）—— 两次刷新之间不重复抽
 *   3. 已存在的候选、冷却中的 IP 不参与探索
 */

/**
 * 判断本轮是否该做探索。
 *
 * @param {object} pool 候选池容器
 * @param {number} now
 * @param {number} minIntervalMs 最小刷新间隔
 * @returns {boolean}
 */
export function shouldExplore(pool, now, minIntervalMs) {
  const interval = Math.max(0, Number(minIntervalMs) || 0)
  if (!pool) return true
  const last = Number(pool.lastRefreshAt || 0)
  if (!last) return true
  return now - last >= interval
}

/**
 * 生成探索候选。
 *
 * @param {object} input
 * @param {Set<string>|Map} input.existing  已有候选（Map 或 Set）
 * @param {string[]} input.sampled          本轮从 CF 网段抽到的原始 IP
 * @param {number} input.quota              探索配额
 * @param {(ip:string)=>boolean} [input.isSelectable] 健康过滤
 * @returns {string[]} 实际采用的探索 IP（去重、排除已有、遵守配额）
 */
export function pickExploration(input) {
  const { existing, sampled = [], quota = 0, isSelectable = () => true } = input
  if (quota <= 0) return []

  const has = (ip) => {
    if (!existing) return false
    if (typeof existing.has === 'function') return existing.has(ip)
    return false
  }

  const out = []
  const seen = new Set()
  for (const ip of sampled) {
    if (out.length >= quota) break
    if (typeof ip !== 'string' || !ip) continue
    if (seen.has(ip)) continue
    seen.add(ip)
    // 已有候选不再当探索（那是「更新」不是「探索」）
    if (has(ip)) continue
    if (!isSelectable(ip)) continue
    out.push(ip)
  }
  return out
}

/**
 * 合并一次探索结果到池中，并记录刷新时间。
 *
 * @param {object} pool
 * @param {string[]} ips
 * @param {number} now
 * @param {object} deps 依赖注入：{ upsertCandidate, SOURCE_DISCOVERED }
 */
export function applyExploration(pool, ips, now, deps) {
  const { upsertCandidate, SOURCE_DISCOVERED } = deps || {}
  if (!pool || !Array.isArray(ips) || !ips.length) {
    if (pool) pool.lastRefreshAt = now
    return { added: 0 }
  }
  let added = 0
  for (const ip of ips) {
    if (typeof ip !== 'string' || !ip) continue
    const isNew = !pool.candidates.has(ip)
    upsertCandidate(pool, ip, SOURCE_DISCOVERED, now)
    if (isNew) added += 1
  }
  pool.lastRefreshAt = now
  return { added }
}
