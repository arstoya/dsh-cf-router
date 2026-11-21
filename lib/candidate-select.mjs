/**
 * candidate-select.mjs — 候选选择与保留策略（Issue #11 阶段 2）
 *
 * 回答「本轮该探测哪些 IP」。四类来源按比例分配配额：
 *   current      当前正在用的 IP（必须保留，否则正常请求会突然失去线路）
 *   historical   历史表现优秀的（跨轮稳定，避免优质节点被随机抽样冲掉）
 *   dns          DNS 返回的基础兜底（必须保留）
 *   exploration  新 IP 探索（避免长期困在局部最优）
 *
 * 本阶段实现配额分配与去重；探索生成与容量淘汰分别在阶段 3、4。
 */

export const CATEGORY_CURRENT = 'current'
export const CATEGORY_HISTORICAL = 'historical'
export const CATEGORY_DNS = 'dns'
export const CATEGORY_EXPLORATION = 'exploration'

/**
 * 计算各类别的配额。
 *
 * 比例为 0 时该类别不参与（除非它是不可牺牲的兜底）。
 * 若比例之和不为 1，按总和归一化 —— 配置校验阶段就该拦住，
 * 这里是防御性处理，不静默产生不可预测的分配。
 *
 * @param {number} total 本轮要选多少个
 * @param {{historical:number, current:number, dns:number, exploration:number}} ratios
 */
export function computeQuotas(total, ratios) {
  const r = {
    historical: Math.max(0, Number(ratios?.historical) || 0),
    current: Math.max(0, Number(ratios?.current) || 0),
    dns: Math.max(0, Number(ratios?.dns) || 0),
    exploration: Math.max(0, Number(ratios?.exploration) || 0),
  }
  const sum = r.historical + r.current + r.dns + r.exploration
  if (sum <= 0) {
    // 全 0 时全部给 dns（兜底优先，不产生空池）
    return { current: 0, historical: 0, dns: total, exploration: 0 }
  }
  const n = (x) => Math.floor((x / sum) * total)
  const out = {
    current: n(r.current),
    historical: n(r.historical),
    dns: n(r.dns),
    exploration: n(r.exploration),
  }
  // 取整会丢配额，补给 dns（兜底不该因为取整而少）
  const assigned = out.current + out.historical + out.dns + out.exploration
  out.dns += Math.max(0, total - assigned)
  return out
}

/**
 * 按历史表现排序候选，取前 n 个。
 *
 * 判据优先级（都不是性能数值本身，避免与 #10 的评分职责重叠）：
 *   1. 近期有成功记录
 *   2. 探测次数多（样本可信）
 *   3. lastSuccessAt 更新
 *
 * **不比较 EWMA** —— 那是 ipStats 的事，候选池不该读它。
 *
 * @param {Array} list 候选记录数组
 * @param {number} n
 * @param {number} now
 */
export function pickHistorical(list, n, now) {
  if (n <= 0) return []
  const scored = list.map((c) => {
    const hasSuccess = c.lastSuccessAt > 0
    const recency = c.lastSuccessAt || 0
    return { c, hasSuccess, probeCount: c.probeCount || 0, recency }
  })
  scored.sort((a, b) => {
    if (a.hasSuccess !== b.hasSuccess) return a.hasSuccess ? -1 : 1
    if (a.probeCount !== b.probeCount) return b.probeCount - a.probeCount
    return b.recency - a.recency
  })
  void now
  return scored.slice(0, n).map((x) => x.c)
}

/**
 * 选出本轮的探测目标。
 *
 * 关键不变量：
 *   · **当前 IP 一定入选**（即使配额为 0）—— 否则正常请求会突然没有线路
 *   · **DNS 候选一定入选**（即使配额为 0）—— 它们是兜底
 *   · 结果去重（一个 IP 只出现一次）
 *
 * @param {object} input
 * @param {Map} input.pool        候选池 Map<ip, candidate>
 * @param {string|null} input.currentIp
 * @param {string[]} input.dnsIps 本轮 DNS 返回
 * @param {Array} input.explorationIps 阶段 3 提供；本阶段可传空
 * @param {object} input.ratios
 * @param {number} input.total    本轮目标数量
 * @param {number} input.now
 * @param {(ip:string)=>boolean} [input.isSelectable] 健康过滤（cooling/half_open 返回 false）
 * @returns {{selected: string[], breakdown: object}}
 */
export function selectCandidates(input) {
  const {
    pool = new Map(),
    currentIp = null,
    dnsIps = [],
    explorationIps = [],
    ratios = {},
    total = 0,
    now = 0,
    isSelectable = () => true,
  } = input

  // 兼容两种入参形态：候选池对象 { candidates: Map } 或裸 Map。
  // 实测踩过：测试传的是池对象，而实现按 Map 直接用，直接 TypeError。
  const map = pool && typeof pool.values === 'function'
    ? pool
    : (pool && pool.candidates instanceof Map ? pool.candidates : new Map())
  const all = [...map.values()]
  const byIp = new Map(all.map((c) => [c.ip, c]))
  const chosen = new Set()

  const selectable = (ip) => byIp.has(ip) && isSelectable(ip)

  // ---- 1. 不可牺牲的两类：当前线路 + DNS 兜底 ----
  // 不受配额约束，先无条件放进来
  if (currentIp && selectable(currentIp)) chosen.add(currentIp)
  const dnsAlive = (Array.isArray(dnsIps) ? dnsIps : []).filter(selectable)
  for (const ip of dnsAlive) chosen.add(ip)

  const protectedCount = chosen.size
  const quotas = computeQuotas(Math.max(0, total - protectedCount), ratios)

  // ---- 2. historical 配额 ----
  const historicalPool = all.filter((c) => (
    c.ip !== currentIp
    && c.source !== 'dns'
    && !chosen.has(c.ip)
    && c.lastSuccessAt > 0
    && isSelectable(c.ip)
  ))
  let takenHistorical = 0
  for (const c of pickHistorical(historicalPool, quotas.historical, now)) {
    chosen.add(c.ip)
    takenHistorical += 1
  }

  // ---- 3. exploration 配额（阶段 3 才真正生成新 IP；本阶段只消费传入的） ----
  let takenExploration = 0
  for (const ip of (Array.isArray(explorationIps) ? explorationIps : [])) {
    if (takenExploration >= quotas.exploration) break
    if (chosen.has(ip)) continue
    if (!selectable(ip)) continue
    chosen.add(ip)
    takenExploration += 1
  }

  return {
    selected: [...chosen].sort(),
    breakdown: {
      current: currentIp && chosen.has(currentIp) ? 1 : 0,
      dns: dnsAlive.length,
      historical: takenHistorical,
      exploration: takenExploration,
      protectedCount,
      quotas,
    },
  }
}
