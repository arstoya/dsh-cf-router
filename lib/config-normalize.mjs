/**
 * config-normalize.mjs — 配置默认值与归一化（Issue #14 拆分批次 2）
 *
 * 从 index.js 逐字搬出。**没有改任何逻辑**。
 *
 * 这一组是纯函数：只操作传入的 cfgObj，不读模块级状态。
 * 唯一的外部依赖是 ssrf-guard 的 normalizeAllowlist（本身就是纯函数）。
 *
 * 注意：DEFAULTS 必须与 index.js 里的 Config schema 逐字段一致，
 * 有测试（state.test.js）专门钉住这一点 —— 两边漂移等于测试跑在另一套默认值上。
 */

import { normalizeAllowlist } from './ssrf-guard.mjs'

export const DEFAULTS = {
  targets: [],
  listenHost: '127.0.0.1',
  listenPort: 8787,
  probePath: '/',
  probeSamples: 3,
  probeTimeoutMs: 6000,
  probeIntervalMs: 300000,
  discoverEnabled: true,
  discoverPerRange: 2,
  candidatePoolMaxSize: 64,
  candidatePoolTtlMs: 86400000,
  candidateExploreRatio: 0.2,
  candidateHistoricalRatio: 0.4,
  candidateCurrentRatio: 0.2,
  candidateDnsRatio: 0.2,
  candidateRefreshMinIntervalMs: 300000,
  candidateCoolingRetentionMs: 3600000,
  stateFlushMinIntervalMs: 60000,
  minImprovementRatio: 0.15,
  consecutiveBetterRounds: 2,
  minDwellTimeMs: 120000,
  minSamples: 3,
  drainTimeoutMs: 120000,
  discoverRanges: [
    '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '162.158.0.0/15',
    '198.41.128.0/17', '141.101.64.0/18', '108.162.192.0/18', '173.245.48.0/20',
    '188.114.96.0/20', '190.93.240.0/20', '197.234.240.0/22', '103.21.244.0/22',
    '103.22.200.0/22', '103.31.4.0/22', '131.0.72.0/22',
  ],
  coloAllow: [],
  l1Concurrency: 20,
  l1TimeoutMs: 1200,
  l2TopN: 10,
  idleSkipMs: 1800000,
  healthCheckMs: 30000,
  maxSockets: 16,
  keepAlive: true,
  failThreshold: 2,
  cooldownMs: 60000,
  ewmaAlpha: 0.3,
  ewmaMaxMs: 3000,
  firstByteTimeoutMs: 60000,
  upstreamTimeoutMs: 600000,
  allowDirectFallback: true,
  allowPrivateTargets: false,
  corsAllowOrigin: '',
  adminToken: '',
  adminTokenFile: '',
  adminProtectStatus: false,
  adminAllowedOrigins: [],
  adminRateLimit: 30,
  adminRateWindowMs: 60000,
  allowUnauthenticatedLocalAdmin: false,
  routingMode: 'auto',
  stateFile: '',
  verbose: false,
}

export function withDefaults(userConfig) {
  const out = { ...DEFAULTS }
  for (const [k, v] of Object.entries(userConfig || {})) {
    if (v === undefined || v === null) continue
    out[k] = v
  }
  return applyTargetGuard(out)
}

/**
 * 候选池配置归一化（Issue #11 方案 §4 约束）：
 *   · 四个比例必须 ≥0；全为 0 时退化为「DNS 兜底」而不是空池
 *   · 比例之和不为 1 时按总和归一化（selectCandidates 内部也做，这里统一一次便于观测）
 *   · maxSize 必须是正整数，且不低于 1
 *   · TTL / 刷新间隔 / 保留期有下限，避免错误配置导致频繁刷新或立即淘汰
 */
export function normalizeCandidateConfig(cfgObj) {
  const posInt = (v, d) => {
    const n = Math.floor(Number(v))
    return Number.isFinite(n) && n >= 1 ? n : d
  }
  cfgObj.candidatePoolMaxSize = posInt(cfgObj.candidatePoolMaxSize, 64)
  cfgObj.candidatePoolTtlMs = Math.max(60_000, Number(cfgObj.candidatePoolTtlMs) || 86_400_000)
  cfgObj.candidateRefreshMinIntervalMs = Math.max(1_000, Number(cfgObj.candidateRefreshMinIntervalMs) || 300_000)
  cfgObj.candidateCoolingRetentionMs = Math.max(0, Number(cfgObj.candidateCoolingRetentionMs) || 0)

  const clamp01 = (v) => Math.min(1, Math.max(0, Number(v) || 0))
  const ratios = {
    historical: clamp01(cfgObj.candidateHistoricalRatio),
    current: clamp01(cfgObj.candidateCurrentRatio),
    dns: clamp01(cfgObj.candidateDnsRatio),
    exploration: clamp01(cfgObj.candidateExploreRatio),
  }
  const sum = ratios.historical + ratios.current + ratios.dns + ratios.exploration
  cfgObj._candidateRatios = sum > 0
    ? {
      historical: ratios.historical / sum,
      current: ratios.current / sum,
      dns: ratios.dns / sum,
      exploration: ratios.exploration / sum,
      normalized: Math.abs(sum - 1) > 1e-9,
    }
    : { historical: 0, current: 0, dns: 1, exploration: 0, normalized: true, degenerate: true }
  return cfgObj
}

export function applyTargetGuard(cfgObj) {
  const { allowed, rejected } = normalizeAllowlist(cfgObj.targets)
  cfgObj._allowedHosts = allowed
  cfgObj._allowedRejected = rejected
  normalizeCandidateConfig(cfgObj)
  return cfgObj
}

/** 是否为修改型路由（POST）—— 管理接口鉴权用它区分读写 */
export function isMutatingRoute(route, method) {
  return method === 'POST'
}
