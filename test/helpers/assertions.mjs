/**
 * assertions.mjs — 项目特定断言
 *
 * 通用断言用 node:assert/strict。这里只放「这个项目独有的契约」。
 */

/**
 * 断言两个延迟值接近（用于 EWMA 这类浮点计算）。
 * 绝对误差与相对误差任一满足即可 —— 小数在 0 附近时相对误差没意义。
 */
export function assertCloseTo(actual, expected, { epsilon = 1e-6, rel = 1e-3, label = '' } = {}) {
  const diff = Math.abs(actual - expected)
  const relativeOk = expected !== 0 && diff / Math.abs(expected) <= rel
  if (diff > epsilon && !relativeOk) {
    throw new Error(`${label || '值'} 不接近：实际 ${actual}，期望 ${expected}（差 ${diff}）`)
  }
}

/** 断言一个值在合理延迟范围内（毫秒） */
export function assertLatency(value, { min = 0, max = 60_000, label = 'latency' } = {}) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label} 不是有限数字：${value}`)
  }
  if (value < min || value > max) {
    throw new Error(`${label} 超出范围 [${min}, ${max}]：${value}`)
  }
}

/** 断言状态快照里某个 host 的字段结构完整 */
export function assertStatusShape(snap, { hosts = ['host', 'current', 'candidates'] } = {}) {
  if (!snap || typeof snap !== 'object') throw new Error('status 不是对象')
  for (const key of ['ok', 'listen', 'routingMode', 'stats']) {
    if (!(key in snap)) throw new Error(`status 缺少字段 ${key}`)
  }
  if (!Array.isArray(snap.hosts)) throw new Error('status.hosts 不是数组')
  for (const h of snap.hosts) {
    for (const key of hosts) {
      if (!(key in h)) throw new Error(`host 条目缺少字段 ${key}`)
    }
  }
}
