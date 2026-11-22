/**
 * state-store.mjs — 版本化状态持久化
 *
 * v1（Issue #13）：只存 routingMode + updatedAt，建立 schema 版本、原子写、迁移链。
 * v2（Issue #22）：扩展业务状态 —— 候选池、探测指标、切换迟滞、健康状态。
 *
 * 设计原则：
 *   · schema 版本与包版本解耦 —— 只有文件结构变化才升 version
 *   · 迁移是**纯函数**，读时做，不改写原文件
 *   · 遇到比自己新的版本：**不覆盖**，按保守默认启动并记录原因
 *   · 所有写入走同一条原子路径
 *   · **只持久化重启后能安全恢复的数据**（见下面 §持久化范围）
 *
 * ## 持久化范围（v2）
 *
 * 存：
 *   · 候选池：source / firstSeenAt / lastProbeAt / lastSuccessAt /
 *     lastSelectedAt / probeCount —— 不存则重启后池为空，「历史优秀 IP」归零
 *   · 探测指标：probeTtfbEwmaMs / probeTotalEwmaMs / samples.probeTtfb /
 *     samples.probeTotal —— #10 的 minSamples 门槛依赖它
 *   · 切换迟滞：roundsBetter / lastSwitchAt —— 不存则重启后可瞬间绕过 minDwellTimeMs
 *   · 健康状态摘要：state / penaltyUntil / enteredAt
 *
 * 不存（刻意）：
 *   · recentTtfbMs 原始观测环 —— 诊断数据，占体积约 60%，scoreOf 主路径不用它
 *   · freshTtfbEwmaMs / reusedTtfbEwmaMs —— 真实请求指标，重启后本就该重新积累
 *   · 连接池、halfOpenInFlight、限流器桶、stats —— 进程级瞬态
 */

/** 当前 schema 版本。加字段不用升，改结构才升。 */
export const STATE_SCHEMA_VERSION = 2

/** 健康状态只接受这三个值（degraded 未实现） */
const HEALTH_STATES = ['healthy', 'cooling', 'half_open']

/** 默认状态（无文件时使用） */
export function defaultState() {
  return { version: STATE_SCHEMA_VERSION, routingMode: null, updatedAt: 0, hosts: {} }
}

/**
 * 迁移链：版本 N → N+1。
 * 每个迁移函数接收「该版本的对象」，返回「下一版本的对象」。
 * **纯函数**：不改入参、不读写磁盘。
 */
const MIGRATIONS = {
  /**
   * v0（无 version 字段）→ v1
   *
   * v0 只有 { routingMode, updatedAt }，updatedAt 是 ISO 字符串。
   * v1 起 updatedAt 统一为毫秒时间戳，版本号显式写入。
   */
  0: (raw) => {
    const out = { version: 1, routingMode: null, updatedAt: 0 }
    if (raw && typeof raw === 'object') {
      out.routingMode = isValidMode(raw.routingMode) ? raw.routingMode : null
      // ISO 字符串 → 毫秒；解析不了就留 0（不编造时间）
      const u = raw.updatedAt
      if (typeof u === 'number' && Number.isFinite(u)) out.updatedAt = u
      else if (typeof u === 'string' && u) {
        const t = Date.parse(u)
        out.updatedAt = Number.isFinite(t) ? t : 0
      }
      // 保留未知字段：用户可能手写过别的键，迁移不该吃掉它们
      for (const [k, v] of Object.entries(raw)) {
        if (k in out) continue
        if (k === 'routingMode' || k === 'updatedAt' || k === 'version') continue
        out[k] = v
      }
    }
    return out
  },

  /**
   * v1 → v2（Issue #22）
   *
   * v1 只有 routingMode + updatedAt。v2 增加 hosts 业务状态。
   * **旧文件天然兼容**：迁移就是补一个空 hosts，用户升级后第一次启动
   * 只是没有历史候选（等同于旧行为），不会有任何数据丢失。
   */
  1: (raw) => {
    const out = { ...(raw && typeof raw === 'object' ? raw : {}) }
    out.version = 2
    if (!isPlainObject(out.hosts)) out.hosts = {}
    return out
  },
}

export function isValidMode(m) {
  return m === 'auto' || m === 'direct'
}

function isPlainObject(v) {
  return v != null && typeof v === 'object' && !Array.isArray(v)
}

/** 收口成有限数值；无效一律给 fallback（不编造） */
function num(v, fallback = 0) {
  const n = Number(v)
  return Number.isFinite(n) ? n : fallback
}

/** 收口成可空有限数值 */
function numOrNull(v) {
  if (v === null || v === undefined) return null
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

/**
 * 把任意读到的对象迁移到当前版本。
 *
 * @param {any} raw 解析后的内容
 * @param {number} now 当前时间（迁移需要打时间戳时用）
 * @returns {{ ok: boolean, state: object, fromVersion: number, migrated: boolean,
 *            blockedBy: string|null, note: string|null }}
 */
export function migrateState(raw, now = 0) {
  if (!isPlainObject(raw)) {
    return {
      ok: false, state: defaultState(), fromVersion: -1, migrated: false,
      blockedBy: 'invalid_shape', note: '状态文件不是对象',
    }
  }

  // 无 version 字段 = v0
  const fromVersion = Number.isInteger(raw.version) && raw.version >= 0 ? raw.version : 0

  // 比自己新：不迁移、不覆盖，按默认启动（保守）
  if (fromVersion > STATE_SCHEMA_VERSION) {
    return {
      ok: false, state: defaultState(), fromVersion, migrated: false,
      blockedBy: 'future_version',
      note: `文件版本 ${fromVersion} 高于本程序支持的 ${STATE_SCHEMA_VERSION}`,
    }
  }

  let cur = raw
  let v = fromVersion
  while (v < STATE_SCHEMA_VERSION) {
    const step = MIGRATIONS[v]
    if (!step) {
      return {
        ok: false, state: defaultState(), fromVersion, migrated: false,
        blockedBy: 'no_migration_path',
        note: `缺少 v${v} → v${v + 1} 的迁移`,
      }
    }
    cur = step(cur, now)
    v += 1
  }

  // 归一：version 强制写成当前值，字段类型收口
  const state = {
    ...cur,
    version: STATE_SCHEMA_VERSION,
    routingMode: isValidMode(cur.routingMode) ? cur.routingMode : null,
    updatedAt: Number.isFinite(Number(cur.updatedAt)) ? Number(cur.updatedAt) : 0,
    hosts: isPlainObject(cur.hosts) ? cur.hosts : {},
  }

  return {
    ok: true, state, fromVersion, migrated: fromVersion !== STATE_SCHEMA_VERSION,
    blockedBy: null,
    note: fromVersion === STATE_SCHEMA_VERSION ? null : `已从 v${fromVersion} 迁移到 v${STATE_SCHEMA_VERSION}`,
  }
}

/**
 * 构造要写入的状态对象。
 * @param {object} input { routingMode, hosts, extra }
 * @param {number} now
 */
export function buildState(input = {}, now = 0) {
  const mode = isValidMode(input.routingMode) ? input.routingMode : null
  const out = {
    version: STATE_SCHEMA_VERSION,
    routingMode: mode,
    updatedAt: now,
    hosts: isPlainObject(input.hosts) ? input.hosts : {},
  }
  // extra 里的未知字段保留（与迁移的"不吃掉用户字段"保持一致）
  for (const [k, v] of Object.entries(input.extra || {})) {
    if (k === 'version' || k === 'routingMode' || k === 'updatedAt' || k === 'hosts') continue
    out[k] = v
  }
  return out
}

/* ============================================================================
 * 序列化：运行态 → 可 JSON 化的对象
 * ========================================================================== */

/**
 * 把候选池、ipStats、切换迟滞压成 v2 的 hosts 结构。
 *
 * @param {object} input
 * @param {Map} input.candidatePools  host -> { candidates: Map<ip, cand>, ... }
 * @param {Map} input.ipStats         `${host}|${ip}` -> stat
 * @param {Map} input.switchState     host -> { roundsBetter, lastSwitchAt }
 * @returns {object} hosts
 */
export function serializeHosts(input = {}) {
  const { candidatePools, ipStats, switchState } = input
  const hosts = {}

  const ensure = (host) => {
    if (!hosts[host]) hosts[host] = { candidates: {}, stats: {}, hysteresis: null }
    return hosts[host]
  }

  // ---- 候选池 ----
  if (candidatePools && typeof candidatePools.forEach === 'function') {
    candidatePools.forEach((pool, host) => {
      const list = pool && pool.candidates
      if (!list || typeof list.forEach !== 'function') return
      list.forEach((c, ip) => {
        if (typeof ip !== 'string' || !ip) return
        ensure(host).candidates[ip] = {
          source: c.source === 'dns' ? 'dns' : 'discovered',
          firstSeenAt: num(c.firstSeenAt),
          lastProbeAt: num(c.lastProbeAt),
          lastSuccessAt: num(c.lastSuccessAt),
          lastSelectedAt: num(c.lastSelectedAt),
          probeCount: num(c.probeCount),
        }
      })
    })
  }

  // ---- ipStats：只取探测类指标 + 健康摘要 ----
  if (ipStats && typeof ipStats.forEach === 'function') {
    ipStats.forEach((s, key) => {
      if (typeof key !== 'string') return
      const idx = key.indexOf('|')
      if (idx <= 0) return
      const host = key.slice(0, idx)
      const ip = key.slice(idx + 1)
      if (!ip) return

      // 完全不值得存的记录（从没探测、也没健康信息）直接跳过，省体积
      const hasProbe = s.samples && num(s.samples.probeTtfb) > 0
      const state = s.health && s.health.state
      const interesting = hasProbe || state === 'cooling' || state === 'half_open'
      if (!interesting) return

      ensure(host).stats[ip] = {
        health: {
          state: HEALTH_STATES.includes(state) ? state : 'healthy',
          penaltyUntil: num(s.penaltyUntil),
          enteredAt: num(s.health && s.health.enteredAt),
          lastRecoveryAt: num(s.health && s.health.lastRecoveryAt),
        },
        metrics: {
          probeTtfbEwmaMs: numOrNull(s.metrics && s.metrics.probeTtfbEwmaMs),
          probeTotalEwmaMs: numOrNull(s.metrics && s.metrics.probeTotalEwmaMs),
        },
        samples: {
          probeTtfb: num(s.samples && s.samples.probeTtfb),
          probeTotal: num(s.samples && s.samples.probeTotal),
        },
      }
    })
  }

  // ---- 切换迟滞 ----
  if (switchState && typeof switchState.forEach === 'function') {
    switchState.forEach((st, host) => {
      if (!st) return
      const rb = num(st.roundsBetter)
      const ls = num(st.lastSwitchAt)
      if (rb === 0 && ls === 0) return
      ensure(host).hysteresis = { roundsBetter: rb, lastSwitchAt: ls }
    })
  }

  // 丢掉完全空白的 host 条目
  for (const [h, v] of Object.entries(hosts)) {
    const empty = Object.keys(v.candidates).length === 0
      && Object.keys(v.stats).length === 0
      && !v.hysteresis
    if (empty) delete hosts[h]
  }
  return hosts
}

/* ============================================================================
 * 反序列化：文件内容 → 可灌回运行态的对象（含保守健康化）
 * ========================================================================== */

/**
 * 校验并转换 hosts 结构。
 *
 * **健康状态保守化**（安全关键）：重启后不能把上次冷却中的 IP 直接当健康节点。
 *   cooling + 已过期  → half_open（必须经过恢复探测才能回 healthy）
 *   cooling + 未过期  → 保持 cooling
 *   half_open        → 保持 half_open
 *
 * @param {object} rawHosts 文件里的 hosts
 * @param {number} now
 * @returns {{ candidates: Map<string, Map<string, object>>,
 *             stats: Map<string, object>,
 *             hysteresis: Map<string, object>,
 *             summary: object }}
 */
export function parseHosts(rawHosts, now = 0) {
  const candidates = new Map()
  const stats = new Map()
  const hysteresis = new Map()
  const summary = { hosts: 0, candidates: 0, stats: 0, demoted: 0, dropped: 0 }

  if (!isPlainObject(rawHosts)) return { candidates, stats, hysteresis, summary }

  for (const [host, entry] of Object.entries(rawHosts)) {
    if (typeof host !== 'string' || !host || !isPlainObject(entry)) continue
    summary.hosts += 1

    // ---- 候选 ----
    const cmap = new Map()
    if (isPlainObject(entry.candidates)) {
      for (const [ip, c] of Object.entries(entry.candidates)) {
        if (typeof ip !== 'string' || !ip || !isPlainObject(c)) { summary.dropped += 1; continue }
        cmap.set(ip, {
          ip,
          source: c.source === 'dns' ? 'dns' : 'discovered',
          firstSeenAt: num(c.firstSeenAt),
          lastSeenAt: num(c.firstSeenAt),      // 文件里不存 lastSeenAt，用 firstSeenAt 兜底
          lastProbeAt: num(c.lastProbeAt),
          lastSuccessAt: num(c.lastSuccessAt),
          lastSelectedAt: num(c.lastSelectedAt),
          lastColo: '',
          probeCount: num(c.probeCount),
          expiresAt: num(c.firstSeenAt) + 86_400_000,
        })
        summary.candidates += 1
      }
    }
    if (cmap.size) candidates.set(host, cmap)

    // ---- 统计 ----
    if (isPlainObject(entry.stats)) {
      for (const [ip, s] of Object.entries(entry.stats)) {
        if (typeof ip !== 'string' || !ip || !isPlainObject(s)) { summary.dropped += 1; continue }
        const h = isPlainObject(s.health) ? s.health : {}
        let state = HEALTH_STATES.includes(h.state) ? h.state : 'healthy'
        const penaltyUntil = num(h.penaltyUntil)

        // 保守化：冷却到期的不能直接回 healthy
        if (state === 'cooling' && penaltyUntil <= now) {
          state = 'half_open'
          summary.demoted += 1
        }

        stats.set(`${host}|${ip}`, {
          health: {
            state,
            penaltyUntil,
            enteredAt: num(h.enteredAt),
            lastRecoveryAt: num(h.lastRecoveryAt),
            halfOpenInFlight: 0,        // 瞬态，永远从 0 开始
            recoveryProbeSuccesses: 0,
            // 恢复期必须重新验证指标，不能让陈旧 EWMA 直接参与选路
            metricsStale: state === 'half_open' || state === 'cooling',
          },
          metrics: {
            probeTtfbEwmaMs: numOrNull(s.metrics && s.metrics.probeTtfbEwmaMs),
            probeTotalEwmaMs: numOrNull(s.metrics && s.metrics.probeTotalEwmaMs),
          },
          samples: {
            probeTtfb: num(s.samples && s.samples.probeTtfb),
            probeTotal: num(s.samples && s.samples.probeTotal),
          },
        })
        summary.stats += 1
      }
    }

    // ---- 迟滞 ----
    if (isPlainObject(entry.hysteresis)) {
      const rb = num(entry.hysteresis.roundsBetter)
      const ls = num(entry.hysteresis.lastSwitchAt)
      if (rb > 0 || ls > 0) {
        hysteresis.set(host, { roundsBetter: rb, lastSwitchAt: ls })
      }
    }
  }

  return { candidates, stats, hysteresis, summary }
}
