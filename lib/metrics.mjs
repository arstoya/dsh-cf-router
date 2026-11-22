/**
 * metrics.mjs — 指标结构与 EWMA 原语（Issue #14 拆分批次 1）
 *
 * 从 index.js 逐字搬出。**没有改任何逻辑**。
 * 这一组是纯函数/纯工厂：不持有状态，只操作传入的对象。
 *
 * 注意边界：本模块只管「怎么算」，不管「数据存在哪」。
 * `ipStats` 这个 Map 仍由 index.js 持有 —— 那属于状态层，不在本次拆分范围。
 */

/** 六个独立延迟指标的空结构（Issue #3） */
export function emptyMetrics() {
  return {
    tcpEwmaMs: null,
    tlsEwmaMs: null,
    probeTtfbEwmaMs: null,
    probeTotalEwmaMs: null,
    freshTtfbEwmaMs: null,
    reusedTtfbEwmaMs: null,
  }
}

/** 样本计数器的空结构 */
export function emptySamples() {
  return {
    tcp: 0,
    tls: 0,
    probeTtfb: 0,
    probeTotal: 0,
    freshTtfb: 0,
    reusedTtfb: 0,
    // 超过 ewmaMaxMs 的样本不再被丢弃，而是单独计数。
    // 它们仍进 EWMA（原始观测一律保留），只是评分可以据此判断「这轮数据被 prefill 污染了」。
    freshTtfbOverCap: 0,
    reusedTtfbOverCap: 0,
    probeTtfbOverCap: 0,
  }
}

/**
 * 通用 EWMA。脏样本（非有限、≤0、非数字）一律不改变原值。
 *
 * **刻意不做隐式类型转换**：把 '100' 悄悄当 100 用，会掩盖上游传错类型的 bug，
 * 而指标一旦被脏数据污染就查不出来了。
 */
export function updateEwma(previous, sample, alpha) {
  // 只接受真正的数字。刻意不做隐式转换：把 '100' 悄悄当 100 用，
  // 会掩盖上游传错类型的 bug，而指标一旦被脏数据污染就查不出来了。
  if (typeof sample !== 'number' || !Number.isFinite(sample) || sample <= 0) return previous
  const a = Math.min(0.9, Math.max(0.05, Number(alpha)))
  if (previous == null) return sample
  return previous * (1 - a) + sample * a
}

/** 给样本计数器 +1；key 不在结构里就静默忽略（防御未知指标名） */
export function bumpSample(s, key) {
  if (key in s.samples) s.samples[key] += 1
}

/** 有限数才 round，否则 null —— 绝不把 NaN 变成 0 */
export function round(n) {
  return Number.isFinite(n) ? Math.round(n) : null
}

/** 收口成可空有限数值 */
export function numOrNull(v) {
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}
