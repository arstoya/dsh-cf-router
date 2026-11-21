/**
 * candidate-pool.mjs — 候选池生命周期（Issue #11 阶段 1）
 *
 * 职责边界（方案 §2.3）：
 *   候选池   回答「哪些 IP 值得保留 / 值得探测 / 可以淘汰」
 *   健康状态 回答「某个 IP 当前是否允许参与线路选择」（#9 已有）
 *   线路评分 回答「可用候选里哪个更适合当前请求」（#10 负责）
 *
 * **刻意不保存性能数据。** ipStats 仍是 EWMA / 失败次数 / 健康状态的
 * 唯一事实来源；这里只记生命周期元信息，两者通过 host + ip 关联。
 * 复制一份性能数据会立刻变成两套互相冲突的真相。
 */

/** IP 来源。dns = DNS 解析得到的基础兜底；discovered = 主动抽样发现 */
export const SOURCE_DNS = 'dns'
export const SOURCE_DISCOVERED = 'discovered'

/** 候选记录的默认 TTL（24 小时） */
export const DEFAULT_TTL_MS = 86_400_000

/**
 * 构造一条候选记录。
 * @param {string} ip
 * @param {string} source
 * @param {number} now
 */
export function makeCandidate(ip, source, now) {
  return {
    ip,
    source,
    firstSeenAt: now,
    lastSeenAt: now,
    lastProbeAt: 0,
    lastSuccessAt: 0,
    lastSelectedAt: 0,
    lastColo: '',
    probeCount: 0,
    expiresAt: now + DEFAULT_TTL_MS,
  }
}

/**
 * 新建一个 host 的候选池容器。
 */
export function makePool(now) {
  return { candidates: new Map(), lastRefreshAt: now }
}

/**
 * 插入或更新一条候选。
 *
 * 关键规则（方案 §5.1）：
 *   · 已存在的 IP 只更新 lastSeenAt / source，**不重建记录** ——
 *     否则 firstSeenAt、probeCount 全丢，等于每轮都当新节点
 *   · DNS 来源优先于 discovered：同一 IP 既是 DNS 又是抽样结果时，
 *     标记为 dns（它是兜底，不该被普通淘汰策略删掉）
 */
export function upsertCandidate(pool, ip, source, now, opts = {}) {
  const ttl = Number.isFinite(opts.ttlMs) ? opts.ttlMs : DEFAULT_TTL_MS
  const existing = pool.candidates.get(ip)

  if (existing) {
    existing.lastSeenAt = now
    // DNS 覆盖 discovered（单向：dns 更「硬」，不反向降级）
    if (source === SOURCE_DNS) existing.source = SOURCE_DNS
    // 续期：只要还被看见，过期时间就往后推
    existing.expiresAt = now + ttl
    return existing
  }

  const c = makeCandidate(ip, source, now)
  c.expiresAt = now + ttl
  pool.candidates.set(ip, c)
  return c
}

/**
 * 合并一批候选。
 *
 * @param {object} pool
 * @param {{dnsIps?: string[], discoveredIps?: string[]}} input
 * @param {number} now
 * @param {object} [opts] { ttlMs }
 * @returns {{added: number, updated: number, total: number}}
 */
export function mergeCandidates(pool, input, now, opts = {}) {
  const before = new Set(pool.candidates.keys())
  const dnsIps = Array.isArray(input.dnsIps) ? input.dnsIps : []
  const discoveredIps = Array.isArray(input.discoveredIps) ? input.discoveredIps : []

  // DNS 先写，保证同 IP 最终标记为 dns
  for (const ip of dnsIps) {
    if (typeof ip !== 'string' || !ip) continue
    upsertCandidate(pool, ip, SOURCE_DNS, now, opts)
  }
  for (const ip of discoveredIps) {
    if (typeof ip !== 'string' || !ip) continue
    upsertCandidate(pool, ip, SOURCE_DISCOVERED, now, opts)
  }

  let added = 0
  for (const ip of pool.candidates.keys()) if (!before.has(ip)) added += 1

  return {
    added,
    updated: pool.candidates.size - added,
    total: pool.candidates.size,
  }
}

/** 取候选 IP 列表（按 ip 排序，输出稳定便于测试比对） */
export function candidateIps(pool) {
  return [...pool.candidates.keys()].sort()
}

/** 取指定来源的候选 */
export function candidatesBySource(pool, source) {
  return [...pool.candidates.values()].filter((c) => c.source === source)
}

/** 记录一次探测（不写性能数据，只更新生命周期） */
export function markProbed(candidate, now, colo) {
  if (!candidate) return
  candidate.lastProbeAt = now
  candidate.probeCount += 1
  if (colo) candidate.lastColo = colo
}

/** 记录一次成功 */
export function markSuccess(candidate, now, colo) {
  if (!candidate) return
  candidate.lastSuccessAt = now
  if (colo) candidate.lastColo = colo
}

/** 记录一次被选为当前线路 */
export function markSelected(candidate, now) {
  if (!candidate) return
  candidate.lastSelectedAt = now
}
