/**
 * state-store.mjs — 版本化状态持久化（Issue #13 阶段 1）
 *
 * 现状三个问题：
 *   1. **无版本号**。文件里只有 `{ routingMode, updatedAt }`。
 *      将来加字段时，旧代码读到新文件会静默忽略，新代码读到旧文件
 *      也只能靠"字段不存在"猜，没法做真正的迁移。
 *   2. **非原子写**。`saveState` 直接 writeFileSync，进程在写一半崩掉
 *      会留下半截 JSON —— 下次启动解析失败，用户的路由模式就丢了。
 *      （`resetRoutingMode` 里已用临时文件+rename，两处不一致。）
 *   3. **写入范围不一致**。saveState 整份覆写，resetRoutingMode 只删
 *      routingMode 键保留其它字段 —— 两者对"文件里该有什么"理解不同。
 *
 * 设计原则：
 *   · schema 版本与包版本解耦 —— 只有文件结构变化才升 version
 *   · 迁移是**纯函数**，读时做，不改写原文件
 *   · 遇到比自己新的版本：**不覆盖**，按保守默认启动并记录原因
 *   · 所有写入走同一条原子路径
 */

/** 当前 schema 版本。加字段不用升，改结构才升。 */
export const STATE_SCHEMA_VERSION = 1

/** 默认状态（无文件时使用） */
export function defaultState() {
  return { version: STATE_SCHEMA_VERSION, routingMode: null, updatedAt: 0 }
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
}

export function isValidMode(m) {
  return m === 'auto' || m === 'direct'
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
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) {
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
  }

  return {
    ok: true, state, fromVersion, migrated: fromVersion !== STATE_SCHEMA_VERSION,
    blockedBy: null,
    note: fromVersion === STATE_SCHEMA_VERSION ? null : `已从 v${fromVersion} 迁移到 v${STATE_SCHEMA_VERSION}`,
  }
}

/**
 * 构造要写入的状态对象。
 * @param {object} input { routingMode, extra }
 * @param {number} now
 */
export function buildState(input = {}, now = 0) {
  const mode = isValidMode(input.routingMode) ? input.routingMode : null
  const out = { version: STATE_SCHEMA_VERSION, routingMode: mode, updatedAt: now }
  // extra 里的未知字段保留（与迁移的"不吃掉用户字段"保持一致）
  for (const [k, v] of Object.entries(input.extra || {})) {
    if (k === 'version' || k === 'routingMode' || k === 'updatedAt') continue
    out[k] = v
  }
  return out
}
