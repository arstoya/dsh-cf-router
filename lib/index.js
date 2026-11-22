/**
 * dsh-cf-router — 上游连接自动优选（常驻测速 + 自动切换）
 *
 * 解决的问题（针对 Cloudflare 前置的 API 上游）：
 *   1. DNS 同时返回 A / AAAA，Windows 默认 IPv6 优先，
 *      而 IPv6 出口常绕道海外边缘（实测落 LAX），TLS 0.9–2.7s；
 *      同一域名走 IPv4 则落最近边缘（HKG），TLS 0.6s。
 *   2. 同一域名的多个边缘 IP 质量不一致，偶发 2s+ 的握手尖刺。
 *   3. 每次请求重新握手，白白多付一个 TLS RTT。
 *
 * 三层机制：
 *   [测速] probeTimer 每 probeIntervalMs 对每个 IPv4 做真请求取样，
 *          得中位数作为初始分；真实转发又按 TTFB 反馈 EWMA，
 *          探测分只在"没有真实数据"时兜底。
 *   [切换] 单个 IP 连续失败 failThreshold 次 → 进入冷却（cooldownMs），
 *          currentIp 立刻改判到次优 IP，不等下一轮探测；
 *          healthTimer 每 healthCheckMs 巡检一次，发现当前 IP 被罚或消失就切。
 *   [兜底] 所有候选都在冷却时走 allowDirectFallback 的直接 DNS 连接，
 *          宁可慢也不 503。
 *
 * 接法：把 provider 的 baseURL 指到 http://127.0.0.1:8787
 *       （路径原样透传，例如 /v1/chat/completions）。
 */

import dns from 'node:dns'
import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'

import { defineTool } from '@deepseek-ai/dsh-tools'
import z from '@deepseek-ai/schemastery'

import { normalizeAuthority, normalizeAllowlist, filterResolvedIps } from './ssrf-guard.mjs'
import {
  authorize, resolveAdminToken, createRateLimiter, hostnameOf, isLoopbackHost,
} from './admin-auth.mjs'
import { filterRequestHeaders, filterResponseHeaders, isEventStream } from './headers.mjs'
import { classifyError } from './error-classifier.mjs'
import {
  ipToInt, intToIp, randInCidr, sampleFromRanges, pinLookup,
} from './net-util.mjs'
import {
  emptyMetrics, emptySamples, updateEwma, bumpSample, round, numOrNull,
} from './metrics.mjs'
import {
  makePool, upsertCandidate, mergeCandidates, candidateIps,
  markProbed, markSuccess, markSelected,
  SOURCE_DNS, SOURCE_DISCOVERED,
} from './candidate-pool.mjs'
import { selectCandidates } from './candidate-select.mjs'
import { shouldExplore, pickExploration, applyExploration } from './candidate-explore.mjs'
import { pruneCandidatePool, expireCandidatePool } from './candidate-prune.mjs'
import {
  createPoolRegistry, DEFAULT_DRAIN_TIMEOUT_MS,
} from './connection-pool.mjs'
import { decideSwitch, SWITCH_HARD_FAIL, SWITCH_PERFORMANCE } from './switch-policy.mjs'
import {
  migrateState, buildState, defaultState, isValidMode as isValidModeState,
  serializeHosts, parseHosts, STATE_SCHEMA_VERSION,
} from './state-store.mjs'

export const name = 'dsh-cf-router'

export const inject = ['tools']

export const Config = z.object({
  targets: z.array(z.string()).description('要优选的上游域名列表（必须自己填，留空则代理不做任何优选）').default([]),
  listenHost: z.string().description('本地代理监听地址').default('127.0.0.1'),
  listenPort: z.number().description('本地代理监听端口').default(8787),
  probePath: z.string().description('探测用的请求路径（任何返回响应的路径都算通）').default('/'),
  probeSamples: z.number().description('每个 IP 探测次数（取中位数）').default(3),
  probeTimeoutMs: z.number().description('单次探测超时').default(6000),
  probeIntervalMs: z.number().description('常驻测速间隔（毫秒，最小 30s）').default(300000),
  discoverEnabled: z.boolean().description('除 DNS 返回的 IP 外，再从 Cloudflare 公开网段抽样扩充候选池').default(true),
  discoverPerRange: z.number().description('每个 CF 网段抽几个 IP').default(2),
  candidatePoolMaxSize: z.number().description(
    '候选池最大容量。**DNS 数量超过它时实际容量会临时超出**——不会为了上限丢弃 DNS 兜底。',
  ).default(64),
  candidatePoolTtlMs: z.number().description('普通候选记录的过期时间（毫秒）').default(86400000),
  candidateExploreRatio: z.number().description('新 IP 探索比例（0~1）').default(0.2),
  candidateHistoricalRatio: z.number().description('历史优秀 IP 保留比例（0~1）').default(0.4),
  candidateCurrentRatio: z.number().description('当前线路保留比例（0~1）').default(0.2),
  candidateDnsRatio: z.number().description('DNS 候选预留比例（0~1）').default(0.2),
  candidateRefreshMinIntervalMs: z.number().description('常规探索的最小刷新间隔（毫秒）').default(300000),
  candidateCoolingRetentionMs: z.number().description('Cooling 候选的额外保留时间（毫秒）').default(3600000),
  stateFlushMinIntervalMs: z.number().description(
    '状态写盘的最小间隔（毫秒）。状态变化会标脏，但只有超过这个间隔才真正写盘，' +
    '避免按请求量放大 IO。进程退出时强制写入，不受此限制。',
  ).default(60000),
  minImprovementRatio: z.number().description(
    '性能切换要求的最小改善比例（0.15 = 15%）。低于它不切，避免 A/B 抖动。',
  ).default(0.15),
  consecutiveBetterRounds: z.number().description(
    '连续多少轮探测更优才允许性能切换。1 = 一次更优就切（不建议）。',
  ).default(2),
  minDwellTimeMs: z.number().description(
    '切换后最短驻留时间（毫秒）。硬故障切换不受此限制。',
  ).default(120000),
  minSamples: z.number().description(
    '参与性能比较所需的最小探测样本数（两侧都要满足）。',
  ).default(3),
  drainTimeoutMs: z.number().description(
    '连接池排空超时（毫秒）。切换线路后旧池会等已有请求跑完再销毁；' +
    '超过这个时间仍未排空则强制销毁。默认 120000（适合长 SSE）。',
  ).default(120000),
  discoverRanges: z.array(z.string()).description('用于抽样的 Cloudflare IPv4 网段').default([
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '162.158.0.0/15',
    '198.41.128.0/17',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '173.245.48.0/20',
    '188.114.96.0/20',
    '190.93.240.0/20',
    '197.234.240.0/22',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '131.0.72.0/22',
  ]),
  coloAllow: z.array(z.string()).description('只保留落在这些 Cloudflare 边缘节点的 IP（如 ["HKG"]），留空表示不限制').default([]),
  l1Concurrency: z.number().description('一级 TCP 探测并发数（太高会被 CF 当成扫描）').default(20),
  l1TimeoutMs: z.number().description('一级 TCP 探测超时（毫秒）').default(1200),
  l2TopN: z.number().description('二级 HTTP 实测的候选数量（取一级延迟最低的 N 个）').default(10),
  idleSkipMs: z.number().description('超过这么久没有真实请求就跳过本轮探测（毫秒，0=不跳过）').default(1800000),
  healthCheckMs: z.number().description('健康巡检间隔（毫秒，最小 5s）').default(30000),
  maxSockets: z.number().description('每主机最大并发连接').default(16),
  keepAlive: z.boolean().description('启用长连接复用').default(true),
  failThreshold: z.number().description('单个 IP 连续失败几次后判死').default(2),
  cooldownMs: z.number().description('判死后的冷却时长（毫秒），冷却期内不参与优选').default(60000),
  ewmaAlpha: z.number().description('真实 TTFB 的 EWMA 权重（越大越看重最近一次）').default(0.3),
  ewmaMaxMs: z.number().description('TTFB 超过这个值就不计入 EWMA（大 prompt 的 prefill 不是网络质量）').default(3000),
  firstByteTimeoutMs: z.number().description('上游首字节超时，超时即判死换 IP（长推理需放宽）').default(60000),
  upstreamTimeoutMs: z.number().description('上游整体无响应超时').default(600000),
  allowDirectFallback: z.boolean().description('所有候选都在冷却时退回系统 DNS 直连').default(true),
  adminToken: z.string().description(
    '管理接口的 Bearer Token。留空则从 adminTokenFile 读取；两者都空时修改型操作被禁用。' +
    '不要把这个值提交进版本库 —— 用 adminTokenFile 指向未跟踪的文件。',
  ).default(''),
  adminTokenFile: z.string().description(
    '存放管理 Token 的文件路径（首行、支持 # 注释）。推荐用它而不是直接写 adminToken。',
  ).default(''),
  adminProtectStatus: z.boolean().description(
    '是否也保护只读的 status 接口。默认 false：状态不含凭据，且 DSH 工具/监控需要读它。',
  ).default(false),
  adminAllowedOrigins: z.array(z.string()).description(
    '允许跨源调用管理接口的 Origin 列表。留空 = 拒绝任何带 Origin 的跨源请求（默认）。' +
    '不带 Origin 的客户端（curl / DSH / 服务端脚本）不受此限制。',
  ).default([]),
  adminRateLimit: z.number().description('管理接口每个窗口允许的请求数（按来源+读写分类）').default(30),
  adminRateWindowMs: z.number().description('管理接口限流窗口长度（毫秒）').default(60000),
  allowUnauthenticatedLocalAdmin: z.boolean().description(
    '逃生舱：未配置 Token 时仍允许**回环来源**修改状态。默认 false（安全默认）。' +
    '仅在完全受信的开发机上临时开启。',
  ).default(false),
  corsAllowOrigin: z.string().description(
    '管理接口允许的跨源来源（如 https://example.com）。默认空 = 不发 CORS 头，' +
    '浏览器同源策略会拦住跨源调用；命令行/curl 不受影响。',
  ).default(''),
  allowPrivateTargets: z.boolean().description(
    '允许目标解析到私网/回环/链路本地地址（Issue #6 第三层）。' +
    '默认 false：SSRF 防护会拒绝这类目标。仅在本地开发或受信内网部署时开启。',
  ).default(false),
  routingMode: z.string().description("路由模式：auto=优选 IPv4 并自动切换；direct=不优选，按系统 DNS 直连（仍经过本地代理）").default('auto').volatile(),
  stateFile: z.string().description('运行时选择的持久化文件（留空则用 DSH_HOME/cf-router-state.json）').default(''),
  verbose: z.boolean().description('把每次转发与切换写进内存日志').default(false),
})

// ---------------------------------------------------------------------------
// 配置默认值（纯数据副本，供 __testApi.configure 使用）
// ---------------------------------------------------------------------------

/**
 * 与 Config 里各字段的 .default() 保持一致。改 Config 的默认值时必须同步这里，
 * 否则测试跑的就是另一套默认值。下面 generate 时有用例比对二者一致性。
 */
export function withDefaults(userConfig) {
  const out = { ...DEFAULTS }
  for (const [k, v] of Object.entries(userConfig || {})) {
    if (v === undefined || v === null) continue
    out[k] = v
  }
  return applyTargetGuard(out)
}

/**
 * 把 `targets` 规范化成白名单集合 `_allowedHosts`（Issue #6 第二层）。
 *
 * 放在装载期做一次，而不是每次请求都规范化：
 *   · 请求路径上只做 O(1) Set 查询
 *   · 非法条目在装载期就被剔除并记录，不会留在白名单里
 *
 * 拒绝的条目写进 `_allowedRejected`，由 statusSnapshot() 暴露，
 * 避免「写了 target 但悄悄不生效」。
 */
/**
 * 候选池配置归一化（Issue #11 方案 §4 约束）：
 *   · 四个比例必须 ≥0；全为 0 时退化为「DNS 兜底」而不是空池
 *   · 比例之和不为 1 时按总和归一化（selectCandidates 内部也做，这里统一一次便于观测）
 *   · maxSize 必须是正整数，且不低于 1
 *   · TTL / 刷新间隔 / 保留期有下限，避免错误配置导致频繁刷新或立即淘汰
 */
function normalizeCandidateConfig(cfgObj) {
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

function applyTargetGuard(cfgObj) {
  const { allowed, rejected } = normalizeAllowlist(cfgObj.targets)
  cfgObj._allowedHosts = allowed
  cfgObj._allowedRejected = rejected
  normalizeCandidateConfig(cfgObj)
  return cfgObj
}

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

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 依赖注入（仅为可测试性）
// ---------------------------------------------------------------------------

/**
 * 可替换的运行时依赖。**生产环境下全部是默认值，行为与改造前完全一致。**
 *
 * 抽出这三样的唯一目的：自动化测试要能在本地起 HTTP/HTTPS 服务、
 * 控制时钟推进、伪造 DNS 结果，而不碰真实 Cloudflare 节点、真实 DNS、
 * 真实 API Key。测试通过 __testApi.deps 替换，用完 __resetForTest() 复位。
 */
const deps = {
  /** DNS A 记录解析。签名与 node:dns 的 resolve4(host, cb) 一致 */
  resolve4: (host, cb) => dns.resolve4(host, cb),
  /** 当前时间（毫秒）。测试注入假时钟即可精确控制冷却与驻留时间 */
  now: () => Date.now(), /* 默认实现，勿改 */
  /** 上游端口。生产固定 443；测试指向本地临时端口 */
  upstreamPort: 443,
  /** 额外 TLS 选项（测试用自签证书时需要传 ca） */
  tlsOptions: {},
}

let cfg = null
let proxyServer = null
let probeTimer = null
let healthTimer = null
/** 最近一次真实转发的时间；用来在长时间空闲时跳过探测，避免白跑请求 */
let lastRequestAt = 0
/** 因为空闲而跳过的轮次数（只做观测，不落盘） */
let idleSkips = 0
/** 'auto' | 'direct' —— 运行时可变，持久化在 statePath */
let routingMode = 'auto'
/**
 * 三个来源各自的模式，用于状态接口与冲突告警（Issue #18）：
 *   configMode  配置里写的值（读 volatile 引用）
 *   stateFileMode 上次 setRoutingMode 落盘的值；null = 状态文件不存在/无有效值
 *   effectiveMode 最终生效值（= routingMode）
 *
 * 优先级（评审确认）：stateFile 有效时优先，否则用配置，都没有则默认 auto。
 * 配置热更新是否覆盖 stateFile 走现有运行时机制（setRoutingMode），
 * 不靠初始化哨兵值间接决定。
 */
let configMode = 'auto'
let stateFileMode = null
/** 从状态文件读到的 schema 版本（Issue #13）；null = 没读到或不可用 */
let stateFileSchema = null
/** 最近一次启动恢复的统计（Issue #22），供状态接口展示 */
let lastRestoreSummary = null

/* ---------------------------------------------------------------------------
 * 状态写盘节流（Issue #22 阶段 3）
 *
 * 为什么需要：v2 起状态包含候选池与指标，而它们在每轮探测、
 * 每次真实请求里都会变。若每次变化都整份写盘，IO 量会随请求量线性增长。
 *
 * 策略：**标记 dirty + 在低频时机统一 flush**，不做 debounce 定时器
 * （定时器会让 dispose 必须同步清理，平添一个泄漏点）。
 *
 *   markStateDirty()     任何状态变化点调用，只置标记
 *   flushState(force)    探测完成 / dispose 时调用
 *     · force=true  忽略节流间隔（退出时必须真写）
 *     · force=false 距上次写入不足 minInterval 则跳过，保持 dirty
 * ------------------------------------------------------------------------- */

let stateDirty = false
let lastStateFlushAt = 0

function markStateDirty() {
  stateDirty = true
}

/**
 * @param {boolean} force 忽略节流间隔
 * @returns {boolean} 是否真的写了盘
 */
function flushState(force = false) {
  if (!stateDirty) return false
  const now = deps.now()
  const minInterval = Math.max(0, Number(cfg.stateFlushMinIntervalMs) || 0)
  if (!force && lastStateFlushAt > 0 && now - lastStateFlushAt < minInterval) {
    return false     // 保持 dirty，下次再试
  }
  const ok = saveState()
  if (ok) {
    stateDirty = false
    lastStateFlushAt = now
  }
  return ok
}
/** 上一次从设置页（volatile 字段）读到的值 */
let lastCfgMode = ''
/**
 * 生效的路由模式。设置页的 volatile 字段是主入口：它一变就把运行时值同步过去，
 * 这样 curl / 工具设的 override 只在设置页没动过时有效，不会互相打架。
 */
function currentMode() {
  const raw = cfg.routingMode
  const cv = String((raw && typeof raw.get === 'function' ? raw.get() : raw) || 'auto')
  if (cv !== lastCfgMode) {
    lastCfgMode = cv
    if (isValidMode(cv)) routingMode = cv
  }
  return isValidMode(routingMode) ? routingMode : 'auto'
}
/** 启动期捕获到的错误（fiber failed 时可从这里读到真因） */
let bootError = ''
function errText(e) {
  if (e == null) return 'unknown'
  const msg = (e && e.message) ? String(e.message) : String(e)
  const st = (e && e.stack) ? String(e.stack).split(String.fromCharCode(10)).slice(1, 3).join(' | ') : ''
  return st ? msg + ' @ ' + st : msg
}
/** 运行时选择的落盘路径 */
let statePath = ''

/** host -> { ips, results, lastProbeAt, error } */
const hosts = new Map()
/** `${host}|${ip}` -> https.Agent */
const agents = new Map()
/** `${host}|${ip}` -> { ok, fail, consecutiveFail, ewmaMs, penaltyUntil, lastFailAt } */
const ipStats = new Map()
/** host -> 当前在用的 IP */
const currentIp = new Map()
/**
 * 连接池生命周期登记表（Issue #12）。
 * key = `host|ip`（direct 模式用 `host|direct`）。
 * 只记状态与活动计数，agent 对象本身仍由 agents / directAgents 持有。
 */
/**
 * host -> 切换迟滞状态（Issue #10）
 *   roundsBetter  连续更优轮次
 *   lastSwitchAt  上次切换时刻
 */
const switchState = new Map()
function getSwitchState(host) {
  let st = switchState.get(host)
  if (!st) {
    st = { roundsBetter: 0, lastSwitchAt: 0 }
    switchState.set(host, st)
  }
  return st
}

const poolRegistry = createPoolRegistry({
  now: () => deps.now(),
  log: (m) => log(m),
})
/**
 * host -> 候选池容器（Issue #11）。
 * { candidates: Map<ip, candidate>, lastRefreshAt }
 * 只记生命周期元信息，性能数据仍在 ipStats。
 */
const candidatePools = new Map()

function getCandidatePool(host) {
  let pool = candidatePools.get(host)
  if (!pool) {
    // lastRefreshAt 置 0：新建池还没探索过，首轮应允许探索。
    // 若用 makePool(now())，shouldExplore 会认为「刚刷过」而跳过首轮
    //（实测踩到：discoverEnabled=true 时一个 discovered 候选都没抽到）。
    pool = makePool(0)
    candidatePools.set(host, pool)
  }
  return pool
}

/** 健康过滤：cooling / half_open / metricsStale 的候选不参与本轮探测 */
function isCandidateSelectable(host, ip) {
  const st = getHealthState(host, ip)
  if (st === 'cooling' || st === 'half_open') return false
  const s = statOf(host, ip)
  return !(s.health && s.health.metricsStale)
}
/**
 * host -> 路由版本号。**只在真正发生切换时递增**（含初选、切到 null）。
 * 用途：请求开始时快照这个值，回调时用它判断「我出发时的那条线路还是不是现在这条」。
 * 没有它，旧请求的迟到成功回调会把已经切走的线路改回来（Issue #2）。
 */
const routeGenerations = new Map()
/**
 * host -> 探测版本号。每发起一轮完整探测就递增，**与路由版本是两回事**：
 *   routeGeneration 回答「路由有没有变」
 *   probeGeneration 回答「我是不是最新一轮探测」
 * 混用会让「路由没变但探测换了」或反之的情况判断错误。
 */
const probeGenerations = new Map()
/** 不 pin IP 的兜底 agent（host -> agent） */
const directAgents = new Map()
/** 最近的切换事件 */
const switches = []
/** 最近的转发记录（verbose 时保留） */
const recent = []
let stats = {
  requests: 0,
  errors: 0,
  switches: 0,
  timeouts: 0,
  /** auto 模式下因没有可用 IP 而回退的请求数（保持原语义） */
  directFallback: 0,
  /** 主动处于 direct 模式的请求数（Issue #18：与兜底分开，否则 direct 下所有请求都算兜底） */
  directRequests: 0,
  /** 按错误分类累计（Issue #9）：便于观测「哪类错误在涨」 */
  byCategory: {},
  bytesIn: 0,
  bytesOut: 0,
}

// ---------------------------------------------------------------------------
// 运行时选择持久化
// ---------------------------------------------------------------------------

function resolveStatePath() {
  const configured = String(cfg.stateFile || '').trim()
  if (configured) return configured
  // 测试环境兜底：任何测试忘了注入 stateFile 时，绝不能落到真实的 $DSH_HOME，
  // 否则一次 setRoutingMode 就改掉了线上运行插件的状态文件（实测踩过）。
  if (process.env.CFR_TEST_MODE === '1') {
    return path.join(os.tmpdir(), `cfr-test-fallback-${process.pid}.json`)
  }
  const home = String(process.env.DSH_HOME || '').trim()
  return path.join(home || process.cwd(), 'cf-router-state.json')
}

function isValidMode(value) {
  return value === 'auto' || value === 'direct'
}

/**
 * 读取持久化的路由模式。
 *
 * 返回「真的读到了有效值吗」，而不是靠事后用路由值反推 ——
 * 这是 Issue #18 的核心：**必须能区分「stateFile 里保存了模式」与
 * 「程序只是在用默认值」**。先前版本靠 lastCfgMode 用配置值初始化，
 * 等于告诉 currentMode()「设置页已是这个值、跳过同步」，
 * 于是配置永远不生效，且没有任何提示。
 *
 * @returns {{found: boolean, mode: string|null}}
 */
/**
 * 原子写状态文件（Issue #13）。
 *
 * 先写 `.tmp` 再 rename —— rename 在同一文件系统内是原子的，
 * 所以读到的要么是旧完整文件，要么是新完整文件，不存在半截 JSON。
 * 改造前 `saveState` 直接 writeFileSync，进程在写一半崩掉会留下损坏文件，
 * 下次启动解析失败，用户的路由模式就丢了。
 *
 * @returns {{ok: boolean, error?: string}}
 */
function writeStateAtomic(obj) {
  const tmp = `${statePath}.tmp.${process.pid}`
  try {
    fs.mkdirSync(path.dirname(statePath), { recursive: true })
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8')
    fs.renameSync(tmp, statePath)
    return { ok: true }
  } catch (err) {
    // 清理临时文件，别在用户目录里留垃圾
    try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp) } catch { /* ignore */ }
    return { ok: false, error: String(err?.message || err) }
  }
}

/**
 * 读状态并迁移到当前 schema 版本（Issue #13）。
 *
 * 迁移是纯函数、读时做，**不回写原文件** —— 用户可能降级回旧版本，
 * 我们不该在他没要求的情况下把文件升级掉。真正写回要等下一次
 * 有意的状态变更（setRoutingMode / resetRoutingMode）。
 */
function loadState() {
  statePath = resolveStatePath()
  try {
    if (!fs.existsSync(statePath)) return { found: false, mode: null, schema: null }
    const rawText = fs.readFileSync(statePath, 'utf8')
    let raw
    try {
      raw = JSON.parse(rawText)
    } catch (e) {
      // 损坏文件：不复用、不静默覆盖 —— 记清楚原因，按无文件启动
      log(`loadState: ${statePath} 不是合法 JSON（${String(e?.message || e)}），按无状态启动`)
      // found 的语义是「读到了有效 routingMode」——损坏文件不算
      return { found: false, mode: null, schema: null, exists: true, corrupt: true }
    }

    const m = migrateState(raw, deps.now())
    if (!m.ok) {
      log(`loadState: 拒绝使用 ${statePath} — ${m.blockedBy}: ${m.note}`)
      return { found: false, mode: null, schema: m.fromVersion, exists: true, blockedBy: m.blockedBy }
    }
    if (m.migrated) log(`loadState: ${m.note}`)
    stateFileSchema = m.state.version
    if (isValidMode(m.state.routingMode)) {
      log(`loaded routingMode=${m.state.routingMode} from ${statePath} (schema v${m.state.version})`)
      return { found: true, mode: m.state.routingMode, schema: m.state.version, exists: true, state: m.state }
    }
    log(`loadState: ${statePath} 存在但没有有效 routingMode (schema v${m.state.version})`)
    return { found: false, mode: null, schema: m.state.version, exists: true, state: m.state }
  } catch (err) {
    log(`loadState failed: ${String(err?.message || err)}`)
    return { found: false, mode: null, schema: null }
  }
}

/** 从配置里读当前的 routingMode（volatile 字段是引用对象） */
function readConfigMode(source) {
  const raw = source ? source.routingMode : null
  const value = raw && typeof raw.get === 'function' ? raw.get() : raw
  return isValidMode(value) ? value : 'auto'
}

/**
 * 按优先级决定初始路由模式并刷新三个来源的缓存。
 *
 * 优先级（评审确认，与既有行为一致）：
 *   stateFile 有效 → 用它
 *   否则 → 配置值
 *   都无效 → auto
 */
function resolveInitialMode(source) {
  configMode = readConfigMode(source)
  const persisted = loadState()
  stateFileMode = persisted.found ? persisted.mode : null

  // 恢复业务状态（Issue #22）。放在这里是因为它必须在后续 refreshAll() 之前，
  // 而 resolveInitialMode 是 apply() 里最早被调用、且已经拿到状态文件内容的地方。
  lastRestoreSummary = restoreRuntimeState(persisted.state, deps.now())

  routingMode = persisted.found ? persisted.mode : configMode
  // 基准与「运行时当前值」保持一致，避免 currentMode() 首次调用把 stateFile 值盖掉
  lastCfgMode = configMode
  return { configMode, stateFileMode, effectiveMode: routingMode }
}

function saveState() {
  // 保留文件里已有的未知字段（用户手写或未来版本留下的），只改受控字段
  let extra = {}
  try {
    if (fs.existsSync(statePath)) {
      const raw = JSON.parse(fs.readFileSync(statePath, 'utf8'))
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
        const m = migrateState(raw, deps.now())
        extra = m.ok ? { ...m.state } : {}
        delete extra.version
        delete extra.routingMode
        delete extra.updatedAt
        delete extra.hosts       // hosts 由下面重新生成，不沿用旧的
      }
    }
  } catch { /* 读不到就只写受控字段 */ }

  // 业务状态（Issue #22）：候选池 + 探测指标 + 切换迟滞
  const hosts = serializeHosts({ candidatePools, ipStats, switchState })
  const payload = buildState({ routingMode, hosts, extra }, deps.now())
  const r = writeStateAtomic(payload)
  if (!r.ok) {
    log(`saveState failed: ${r.error}`)
    return false
  }
  // 写成功后本地 schema 状态就是当前版本（Issue #13）
  stateFileSchema = STATE_SCHEMA_VERSION
  return true
}

function setRoutingMode(value) {
  if (!isValidMode(value)) return { ok: false, error: 'invalid_mode', allowed: ['auto', 'direct'] }
  const previous = routingMode
  routingMode = value
  // 落盘成功才算 stateFile 里有值（Issue #18：三个来源要能随时说清）
  stateFileMode = value
  if (value === 'direct') {
    // 直连模式不再 pin IP，清掉现有连接池让下一次请求按系统 DNS 重新解析。
    // 路由一律走 switchRoute，保证 generation 与实际路由同步（Issue #2）。
    for (const host of hosts.keys()) {
      dropAgents(host)
      switchRoute(host, null, 'mode:direct')
    }
  } else {
    for (const host of hosts.keys()) {
      const next = chooseBest(host)
      if (next) switchRoute(host, next.ip, 'mode:auto')
    }
  }
  const persisted = saveState()
  return { ok: true, previous, routingMode, persisted, statePath }
}

/**
 * 把状态文件里的业务状态灌回运行态（Issue #22 阶段 2）。
 *
 * **必须在 refreshAll() 之前调用** —— 否则第一轮探测会覆盖掉恢复的候选池。
 *
 * 两个必须做对的点：
 *
 * 1. **用 statOf 补全默认结构再覆盖**。`parseHosts` 只还原持久化的字段
 *    （探测指标 + 健康摘要），而 `statOf` 期望完整记录（ok/fail/metrics 全字段…），
 *    直接赋值会让 scoreOf / chooseBest 读到 undefined。
 *
 * 2. **不信任文件里的健康状态**。`parseHosts` 已做保守化（冷却过期 → half_open），
 *    这里不要再动它 —— 尤其是**不要**因为「有成功样本」就升回 healthy。
 *
 * @returns {{hosts:number, candidates:number, stats:number, demoted:number, dropped:number}}
 */
function restoreRuntimeState(state, now) {
  const empty = { hosts: 0, candidates: 0, stats: 0, demoted: 0, dropped: 0 }
  if (!state || !state.hosts) return empty

  const parsed = parseHosts(state.hosts, now)

  // ---- 候选池 ----
  for (const [host, cmap] of parsed.candidates) {
    const pool = getCandidatePool(host)
    for (const [ip, cand] of cmap) pool.candidates.set(ip, cand)
  }

  // ---- hosts[].results 骨架 ----
  //
  // **这一步不能省**：scoreOf 的主路径读的是 hosts[].results[].ttfbMedian，
  // 而不是 ipStats 的 EWMA。只恢复 ipStats 而不重建 results，
  // 结果是「指标都在，但 scoreOf 一律返回 Infinity」—— 实测踩到。
  //
  // 用持久化的 probeTtfbEwmaMs 作为 ttfbMedian 的近似值，并标 restored=true，
  // 让调用方知道这是恢复值而非本轮实测。没有 EWMA 的 IP 不造记录。
  for (const [key, saved] of parsed.stats) {
    const idx0 = key.indexOf('|')
    if (idx0 <= 0) continue
    const host0 = key.slice(0, idx0)
    const ip0 = key.slice(idx0 + 1)
    const ewma = saved.metrics.probeTtfbEwmaMs
    if (!Number.isFinite(ewma)) continue

    let entry = hosts.get(host0)
    if (!entry) {
      entry = { ips: [], results: [], lastProbeAt: 0, error: null }
      hosts.set(host0, entry)
    }
    if (!Array.isArray(entry.results)) entry.results = []

    const exist = entry.results.find((r) => r.ip === ip0)
    if (!exist) {
      entry.results.push({
        ip: ip0,
        okCount: saved.samples.probeTtfb,
        samples: saved.samples.probeTtfb,
        ttfbMedian: ewma,
        ttfbBest: ewma,
        // 恢复时没有真实的 total/tcp/tls 数据，给 null 而不是编造
        totalMedian: null,
        tcpMedian: null,
        tlsMedian: null,
        colo: null,
        excluded: null,
        restored: true,
      })
      if (!entry.ips.includes(ip0)) entry.ips.push(ip0)
    }
  }

  // ---- ipStats：先拿完整默认结构，再覆盖持久化字段 ----
  for (const [key, saved] of parsed.stats) {
    const idx = key.indexOf('|')
    if (idx <= 0) continue
    const host = key.slice(0, idx)
    const ip = key.slice(idx + 1)

    const s = statOf(host, ip)          // 完整默认结构
    s.health = {
      ...s.health,
      state: saved.health.state,
      penaltyUntil: saved.health.penaltyUntil,
      enteredAt: saved.health.enteredAt,
      lastRecoveryAt: saved.health.lastRecoveryAt,
      // 瞬态字段保持默认 0（parseHosts 已归零，这里再显式一次）
      halfOpenInFlight: 0,
      recoveryProbeSuccesses: 0,
      metricsStale: saved.health.metricsStale,
    }
    // penaltyUntil 与 health.state 必须一致，否则 scoreOf 与 getHealthState 会打架
    if (saved.health.state === 'healthy') s.penaltyUntil = 0
    else s.penaltyUntil = saved.health.penaltyUntil

    s.metrics.probeTtfbEwmaMs = saved.metrics.probeTtfbEwmaMs
    s.metrics.probeTotalEwmaMs = saved.metrics.probeTotalEwmaMs
    s.samples.probeTtfb = saved.samples.probeTtfb
    s.samples.probeTotal = saved.samples.probeTotal
  }

  // ---- 切换迟滞 ----
  for (const [host, st] of parsed.hysteresis) {
    const cur = getSwitchState(host)
    cur.roundsBetter = st.roundsBetter
    cur.lastSwitchAt = st.lastSwitchAt
  }

  if (parsed.summary.candidates || parsed.summary.stats) {
    log(`restore: ${parsed.summary.hosts} host / ${parsed.summary.candidates} 候选 / ` +
        `${parsed.summary.stats} 指标` +
        (parsed.summary.demoted ? ` / ${parsed.summary.demoted} 个冷却已过期降级为 half_open` : '') +
        (parsed.summary.dropped ? ` / 丢弃 ${parsed.summary.dropped} 条非法记录` : ''))
  }
  return parsed.summary
}

/**
 * 只清除**持久化的 routingMode**，保留状态文件里的其它内容（Issue #18 评审意见）。
 *
 * 为什么不建议直接删 `stateFile`：该文件未来可能保存候选池、历史性能等数据，
 * 整文件删除会连带丢别的状态。这里只移除 routingMode 一个键，
 * 之后配置值重新生效。
 */
function resetRoutingMode() {
  const resolved = resolveStatePath()
  statePath = resolved
  let removed = false
  let kept = null

  try {
    if (fs.existsSync(resolved)) {
      const raw = JSON.parse(fs.readFileSync(resolved, 'utf8'))
      if (raw && typeof raw === 'object' && 'routingMode' in raw) {
        // 先迁移再删键：保证写回的是当前 schema 版本（Issue #13）
        const m = migrateState(raw, deps.now())
        const base = m.ok ? m.state : defaultState()
        const next = { ...base }
        delete next.routingMode
        next.routingModeResetAt = deps.now()
        kept = Object.keys(next)
        statePath = resolved
        const w = writeStateAtomic(next)
        if (!w.ok) throw new Error(w.error)
        removed = true
      }
    }
  } catch (err) {
    return { ok: false, error: String(err?.message || err), statePath: resolved }
  }

  // 清除后回到配置值（没有配置就用默认 auto）
  stateFileMode = null
  routingMode = configMode
  lastCfgMode = configMode
  if (routingMode === 'direct') {
    for (const host of hosts.keys()) {
      dropAgents(host)
      switchRoute(host, null, 'mode:direct')
    }
  } else {
    for (const host of hosts.keys()) {
      const next = chooseBest(host)
      if (next) switchRoute(host, next.ip, 'mode:auto')
    }
  }

  return {
    ok: true,
    removed,
    keptKeys: kept,
    routingMode,
    configMode,
    stateFileMode,
    statePath: resolved,
  }
}


const SERVER_KEY = Symbol.for('dsh-cf-router.server')

function log(line) {
  if (!cfg?.verbose) return
  recent.push({ at: deps.now(), line: String(line).slice(0, 300) })
  if (recent.length > 200) recent.shift()
}

function recordSwitch(host, from, to, reason) {
  stats.switches += 1
  switches.push({ at: deps.now(), host, from: from || null, to: to || null, reason })
  if (switches.length > 20) switches.shift()
  log(`switch ${host} ${from || '-'} → ${to || '-'} (${reason})`)
}

// ---------------------------------------------------------------------------
// 路由版本与统一切换入口（Issue #2）
// ---------------------------------------------------------------------------

/** 当前路由版本；未登记的 host 视为 0 */
function getRouteGeneration(host) {
  return routeGenerations.get(host) || 0
}

/** 当前探测版本；未登记视为 0 */
function getProbeGeneration(host) {
  return probeGenerations.get(host) || 0
}

/** 开始一轮新探测：递增版本，返回本轮应携带的版本号 */
function beginProbe(host) {
  const next = getProbeGeneration(host) + 1
  probeGenerations.set(host, next)
  return next
}

/**
 * 提交探测结果。**过期探测的结果必须丢弃**，否则「先发起的慢探测」回来时
 * 会把「后发起的快探测」刚写好的结果覆盖掉。
 * @returns {boolean} 是否被采纳
 */
function commitProbeResult(host, generation, entry) {
  if (generation !== getProbeGeneration(host)) {
    log(`probe ${host}: 丢弃过期结果 gen=${generation} 当前=${getProbeGeneration(host)}`)
    return false
  }
  hosts.set(host, entry)
  return true
}

/**
 * **修改当前路由的唯一入口。**
 *
 * 契约：
 *   - 目标 IP 与当前相同 → 什么都不做（不递增、不记切换）
 *   - 真的变了（含变 null）→ 递增 routeGeneration + 记一条 switch
 *
 * 所有原本直接 `currentIp.set(...)` 的地方都必须改走这里，
 * 否则版本号会与实际路由脱节，旧请求的判定就失效了。
 */
function switchRoute(host, ip, reason) {
  const prev = currentIp.get(host) || null
  const next = ip || null
  if (prev === next) return { ok: true, changed: false, generation: getRouteGeneration(host), from: prev, to: next }

  if (next === null) currentIp.delete(host)
  else currentIp.set(host, next)

  // 回写候选池的 lastSelectedAt（Issue #11 补漏）：这是「被选为当前线路」
  // 的唯一真实时刻。缺了它，候选池无法区分「探测过」与「真被用过」。
  if (next) {
    const pool = candidatePools.get(host)
    const cand = pool && pool.candidates.get(next)
    if (cand) markSelected(cand, deps.now())
  }

  const generation = getRouteGeneration(host) + 1
  routeGenerations.set(host, generation)
  recordSwitch(host, prev, next, reason)
  // 切换会改 lastSwitchAt，属于要持久化的状态（Issue #22）
  markStateDirty()
  return { ok: true, changed: true, generation, from: prev, to: next }
}

/**
 * 记录一次请求成功。
 *
 * **只更新统计与 EWMA，永远不碰路由。** 这条是 Issue #2 的核心：
 * 路由决策统一由 switchRoute 负责，请求回调无权改线路。
 * generation 参数保留用于观测与后续扩展，当前不参与判定 ——
 * 因为「成功」在任何情况下都不该触发线路变更。
 */
function recordRequestSuccess(host, ip, metrics = {}, generation = null) {
  markStateDirty()
  const s = statOf(host, ip)
  s.ok += 1
  s.consecutiveFail = 0
  s.failureScore = 0

  const a = cfg.ewmaAlpha

  // TLS 只在新建连接时采得到；复用连接没有这个阶段，就不该产生样本
  if (Number.isFinite(metrics.tlsMs) && metrics.tlsMs > 0) {
    s.metrics.tlsEwmaMs = updateEwma(s.metrics.tlsEwmaMs, metrics.tlsMs, a)
    bumpSample(s, 'tls')
  }
  if (Number.isFinite(metrics.tcpMs) && metrics.tcpMs > 0) {
    s.metrics.tcpEwmaMs = updateEwma(s.metrics.tcpEwmaMs, metrics.tcpMs, a)
    bumpSample(s, 'tcp')
  }

  // 真实请求 TTFB：新连接与复用连接分开统计。
  // **超额样本一律保留**，只是额外打一个 overCap 标记；
  // 是否「因为被 prefill 污染而降低权重」交给评分层判断，采集层不做丢弃决定。
  const ttfbMs = metrics.ttfbMs
  if (Number.isFinite(ttfbMs) && ttfbMs > 0) {
    s.lastTtfbMs = ttfbMs
    s.lastReused = Boolean(metrics.reused)
    pushRecentTtfb(s, ttfbMs, metrics.reused ? 'reused' : 'fresh')

    const overCap = ttfbOverCap(ttfbMs)
    if (metrics.reused) {
      s.metrics.reusedTtfbEwmaMs = updateEwma(s.metrics.reusedTtfbEwmaMs, ttfbMs, a)
      bumpSample(s, 'reusedTtfb')
      if (overCap) s.samples.reusedTtfbOverCap += 1
    } else {
      s.metrics.freshTtfbEwmaMs = updateEwma(s.metrics.freshTtfbEwmaMs, ttfbMs, a)
      bumpSample(s, 'freshTtfb')
      if (overCap) s.samples.freshTtfbOverCap += 1
    }
  }

  void generation
}

/**
 * 记录一次探测样本（由 measureIp / refreshHost 调用）。
 * 四个计时各自独立入库，互不串味。
 */
function recordProbeSample(host, ip, sample = {}) {
  const s = statOf(host, ip)
  const a = cfg.ewmaAlpha

  if (Number.isFinite(sample.tcpMs) && sample.tcpMs > 0) {
    s.metrics.tcpEwmaMs = updateEwma(s.metrics.tcpEwmaMs, sample.tcpMs, a)
    bumpSample(s, 'tcp')
  }
  if (Number.isFinite(sample.tlsMs) && sample.tlsMs > 0) {
    s.metrics.tlsEwmaMs = updateEwma(s.metrics.tlsEwmaMs, sample.tlsMs, a)
    bumpSample(s, 'tls')
  }
  // 探测 TTFB 同样可能被 prefill 污染，但样本一律保留，只做分级统计
  if (Number.isFinite(sample.ttfbMs) && sample.ttfbMs > 0) {
    s.metrics.probeTtfbEwmaMs = updateEwma(s.metrics.probeTtfbEwmaMs, sample.ttfbMs, a)
    bumpSample(s, 'probeTtfb')
    if (ttfbOverCap(sample.ttfbMs)) s.samples.probeTtfbOverCap += 1
    pushRecentTtfb(s, sample.ttfbMs, 'probe')
  }
  // total 含响应体下载，与 prefill 无关，不做阈值过滤
  if (Number.isFinite(sample.totalMs) && sample.totalMs > 0) {
    s.metrics.probeTotalEwmaMs = updateEwma(s.metrics.probeTotalEwmaMs, sample.totalMs, a)
    bumpSample(s, 'probeTotal')
  }
}

/**
 * 记录一次请求失败。
 *
 * 失败统计照记（旧请求的健康数据不能丢），但**是否切换要考虑版本**：
 *   - 该 IP 仍是当前线路 → 可以判死并切走
 *   - 该 IP 已不是当前线路（期间已经被切走）→ 只记统计，不许把它设回当前
 *
 * @param {string} host
 * @param {string} ip
 * @param {{message?: string, kind?: string}} error
 * @param {number|null} generation 请求出发时的路由版本；null 表示调用方不关心
 */
function recordRequestFailure(host, ip, error = {}, generation = null) {
  const message = error.message || 'unknown'
  const kind = error.kind || 'error'

  // 统一错误分类（Issue #9 阶段 2）：分类器只给语义，不改任何统计
  const cls = classifyError(error.err || { message, code: error.code }, {
    clientAborted: Boolean(error.clientAborted),
    statusCode: error.statusCode ?? null,
  })

  stats.errors += 1
  if (kind === 'timeout' || cls.category === 'timeout') stats.timeouts += 1
  /** 按分类累计，便于观测「哪类错误在涨」而不只是一个总数 */
  stats.byCategory = stats.byCategory || {}
  stats.byCategory[cls.category] = (stats.byCategory[cls.category] || 0) + 1

  markStateDirty()
  const s = statOf(host, ip)
  s.lastFailAt = deps.now()

  // 不计惩罚的错误（客户端取消、鉴权、限流、上游业务错误）到此为止：
  // 只记分类计数，不动 consecutiveFail / failureScore，也不影响熔断。
  if (!cls.penalizeIp) {
    log(`fail ${host} ${ip} [${cls.category}/${cls.phase}] 不计惩罚: ${message}`)
    return
  }

  s.fail += 1
  s.consecutiveFail += 1
  s.failureScore += cls.failureWeight
  log(`fail ${host} ${ip} [${cls.category}/${cls.phase}] ` +
      `(连败 ${s.consecutiveFail}/${cfg.failThreshold}, 加权 ${s.failureScore.toFixed(2)}) ${message}`)

  if (s.consecutiveFail < cfg.failThreshold) return

  // 判死：进冷却。这一步与版本无关 —— 这个 IP 确实失败够了，统计必须反映事实
  s.consecutiveFail = 0
  s.failureScore = 0
  // Agent 不立即销毁，改为进入排空（Issue #12）：该 IP 上可能还有正在
  // 传输的请求（尤其 SSE），直接 destroy 会掐断它们。
  // 排空后由 healthTick 的回收周期统一销毁，超时则强制回收。
  drainPoolFor(host, ip)
  // 状态变更统一走 transitionHealth，它会同步维护 penaltyUntil。
  if (getHealthState(host, ip) === 'healthy') {
    transitionHealth(host, ip, 'cooling', `fail×${cfg.failThreshold}`)
  } else {
    // 已是 cooling/half_open：刷新冷却，不触发非法转换
    s.penaltyUntil = deps.now() + Math.max(1000, cfg.cooldownMs)
    s.health.state = 'cooling'
  }

  // 到这里已经记录完失败统计与冷却。下面决定「要不要因此切换线路」，
  // 有两道保护，顺序不能反：
  //
  //   第一道（结构性）：请求回调本来就没有写 currentIp 的权限，
  //                     所有切换都必须经 switchRoute 显式发起。
  //   第二道（版本）：   请求出发时快照的 routeGeneration 若已过期，
  //                     说明它在飞行期间线路被别的决策改过 —— 它只能更新统计，
  //                     无权驱动切换。典型场景 A→B→A：IP 比对看起来「还是当前」，
  //                     但这个请求代表的是更早那一轮的观测，不该用来否决新决策。
  const currentGeneration = getRouteGeneration(host)
  const staleGeneration = generation != null && generation !== currentGeneration
  const isCurrent = currentIp.get(host) === ip

  if (!isCurrent) {
    log(`fail ${host} ${ip}: 已不是当前线路，只记统计不切换 (req gen=${generation} 当前 gen=${currentGeneration})`)
    return
  }
  if (staleGeneration) {
    log(`fail ${host} ${ip}: 请求版本已过期，只记统计不切换 (req gen=${generation} 当前 gen=${currentGeneration})`)
    return
  }

  const next = chooseBest(host)
  if (next) {
    switchRoute(host, next.ip, `fail×${cfg.failThreshold} ${message}`)
  } else {
    switchRoute(host, null, `fail×${cfg.failThreshold} 无可用候选`)
    // 没有候选了，触发一次重探测（可能 DNS 也变了）
    setTimeout(() => {
      refreshHost(host).catch(() => {})
    }, 200)
  }
}

// ---------------------------------------------------------------------------
// 每 IP 的运行指标
// ---------------------------------------------------------------------------

/**
 * 每个指标只由一种事件产生，含义与计时边界如下（Issue #3）：
 *
 *   tcpEwmaMs          socket 创建 → connect           探测
 *   tlsEwmaMs          TCP connect  → secureConnect    探测
 *   probeTtfbEwmaMs    请求发出      → 收到响应头        探测
 *   probeTotalEwmaMs   请求发出      → 响应体结束        探测
 *   freshTtfbEwmaMs    请求发出      → 收到响应头        真实请求（新连接）
 *   reusedTtfbEwmaMs   请求发出      → 收到响应头        真实请求（复用连接）
 *
 * 为什么新连接/复用要分开：新连接的 TTFB 里含着建连成本，和复用连接的
 * 纯往返不是一个量纲，混在一个 EWMA 里会让「刚建连的慢」污染「复用很快」这个事实。
 *
 * 为什么 ewmaMaxMs 只作用于 TTFB：只有 TTFB 会被上游 prefill 污染
 * （大 prompt 常常 10s+ 才吐首字节），TCP/TLS 是纯网络指标，不该被这个阈值过滤。
 */
function statOf(host, ip) {
  const key = `${host}|${ip}`
  let s = ipStats.get(key)
  if (!s) {
    s = {
      ok: 0,
      fail: 0,
      consecutiveFail: 0,
      /**
       * 加权失败分数（Issue #9 阶段 2）。
       * 与 consecutiveFail 并存而不是取代它：
       *   consecutiveFail  未加权连败次数，现有阈值判断仍用它（保持兼容）
       *   failureScore     加权累加，用于区分「4 次首字节超时」与「4 次建连失败」
       * 阈值判定**仍以 consecutiveFail 为准** —— 本阶段只增加观测量，
       * 不改变既有熔断行为（方案 §14 要求逐阶段验证）。
       */
      failureScore: 0,
      penaltyUntil: 0,
      lastFailAt: 0,
      /**
       * 健康状态（Issue #9 阶段 3）。
       *
       * 与 penaltyUntil 的关系：**penaltyUntil 必须保留**（现有代码与测试依赖），
       * 两者只能通过 transitionHealth() 同步更新，不允许不同模块各写一个。
       *
       * 本阶段只引入数据结构与转换函数，**实际状态推进在阶段 4** 才接上 ——
       * 目前 state 恒为 healthy、cooling，与 penaltyUntil 保持等价语义。
       */
      health: {
        state: 'healthy',        // healthy | cooling | half_open
        halfOpenInFlight: 0,     // 当前在飞的恢复探测数（阶段 4 才有非零值）
        recoveryProbeSuccesses: 0,
        lastRecoveryAt: 0,
        metricsStale: false,     // 恢复后旧 EWMA 是否待刷新（阶段 4）
        enteredAt: 0,            // 进入当前状态的时刻（v0.2.3）
      },
      metrics: emptyMetrics(),
      samples: emptySamples(),
      /** 最近一次真实请求的原始 TTFB */
      lastTtfbMs: null,
      /** 最近一次真实请求是否复用了连接 */
      lastReused: null,
      /**
       * 最近 N 个原始 TTFB 观测（含探测与真实请求），**不做任何过滤**。
       * 保留原始序列是为了事后判断「这条线到底是稳的慢，还是偶尔被大 prompt 拖了一下」——
       * 只留一个 EWMA 就再也回看不出分布形状了。
       */
      recentTtfbMs: [],
    }
    ipStats.set(key, s)
  }
  return s
}

// ---------------------------------------------------------------------------
// 健康状态机（Issue #9 阶段 3）
// ---------------------------------------------------------------------------

/** 合法状态；degraded 方案已明确暂不实现 */
const HEALTH_STATES = Object.freeze(['healthy', 'cooling', 'half_open'])

/**
 * 允许的转换。刻意的限制：
 *   · healthy 不能直接跳 half_open（必须经过 cooling）
 *   · cooling 只能到 half_open，不能直接回 healthy
 *   · half_open 未通过探测不能恢复 healthy
 */
const HEALTH_TRANSITIONS = Object.freeze({
  healthy: ['cooling'],
  cooling: ['half_open'],
  half_open: ['healthy', 'cooling'],
})

/** 读取当前健康状态（总是返回合法值） */
function getHealthState(host, ip) {
  const s = statOf(host, ip)
  const st = s.health && s.health.state
  return HEALTH_STATES.includes(st) ? st : 'healthy'
}

/**
 * **唯一的状态变更入口。**
 *
 * 同步维护 `penaltyUntil`，避免两个字段各自漂移：
 *   → cooling   设置 penaltyUntil = now + cooldownMs
 *   → half_open 保持 penaltyUntil 不变（冷却已到期，但还不能参与选路）
 *   → healthy   清空 penaltyUntil
 *
 * @returns {{ok: boolean, from: string, to: string, reason: string}}
 */
function transitionHealth(host, ip, nextState, reason, opts = {}) {
  const s = statOf(host, ip)
  s.health = s.health || {}
  const from = getHealthState(host, ip)

  if (!HEALTH_STATES.includes(nextState)) {
    log(`health: 非法状态 ${nextState}（${reason}）`)
    return { ok: false, from, to: from, reason: 'invalid_state' }
  }
  if (from === nextState) {
    return { ok: true, from, to: from, reason: 'noop' }
  }
  const allowed = HEALTH_TRANSITIONS[from] || []
  if (!allowed.includes(nextState)) {
    log(`health: 非法转换 ${from} → ${nextState}（${reason}）`)
    return { ok: false, from, to: from, reason: 'illegal_transition' }
  }

  s.health.state = nextState
  const now = deps.now()
  // 记录「进入当前状态的时刻」——#v0.2.3：Cooling 保留期要按它算，
  // 不能按 lastProbeAt（真实请求失败进入 cooling 的 IP 从未被探测过）
  s.health.enteredAt = now

  if (nextState === 'cooling') {
    const cooldown = opts.cooldownMs ?? Math.max(1000, cfg.cooldownMs)
    s.penaltyUntil = now + cooldown
    s.health.metricsStale = true
  } else if (nextState === 'half_open') {
    // 冷却已到期，但仍不参与普通选路
    s.health.metricsStale = true
    s.health.halfOpenInFlight = 0
    s.health.recoveryProbeSuccesses = 0
  } else if (nextState === 'healthy') {
    s.penaltyUntil = 0
    s.health.lastRecoveryAt = now
    s.health.metricsStale = false
    s.health.halfOpenInFlight = 0
  }

  markStateDirty()
  // 健康状态变化**不进 switches 数组** —— 那是路由切换记录，两者是不同维度。
  // 混进去会让「generation 等于 switches.length」这条不变量失效（实测踩到）。
  // 健康变化走独立日志与 statusSnapshot 的 health 字段。
  log(`health ${host} ${ip}: ${from} → ${nextState} (${reason})`)
  return { ok: true, from, to: nextState, reason }
}

/**
 * 按时间推进状态。阶段 4 会在 healthTick 里调用它触发恢复探测；
 * 本阶段只负责「cooling 到期 → half_open」这一步推进。
 */
function advanceHealthState(host, ip) {
  const s = statOf(host, ip)
  const now = deps.now()
  const cur = getHealthState(host, ip)

  if (cur === 'cooling' && s.penaltyUntil <= now) {
    return transitionHealth(host, ip, 'half_open', 'cooldown_expired')
  }
  return { ok: true, from: cur, to: cur, reason: 'noop' }
}

/**
 * Half-Open 恢复探测（Issue #9 阶段 4）。
 *
 * 冷却到期**不再直接恢复资格**，而是先做一次真实探测：
 *   · 成功 → healthy，并用本轮结果覆盖选路用的探测指标（方案 §8）
 *   · 失败 → 重新 cooling（刷新冷却时长）
 *
 * 并发保护：同一 IP 同时最多一个探测。占用标记必须在 finally 释放，
 * 否则异常会让 IP 永久卡在「正在探测」状态。
 *
 * @returns {Promise<'skip'|'ok'|'failed'>}
 */
async function runRecoveryProbe(host, ip) {
  const s = statOf(host, ip)
  s.health = s.health || {}

  // 已在探测中 → 跳过，不重复启动
  if (s.health.halfOpenInFlight > 0) return 'skip'
  s.health.halfOpenInFlight += 1

  try {
    const path = cfg.probePath
    const timeoutMs = cfg.probeTimeoutMs
    const r = await measureIp(host, ip, 1, timeoutMs, path)

    if (r && r.okCount > 0 && Number.isFinite(r.ttfbMedian)) {
      // 用本轮真实探测结果**覆盖**选路指标，而不是在旧 EWMA 上再滚一次
      // （方案 §8.2：仅 updateEwma 会让旧数据继续影响评分）
      const entry = hosts.get(host)
      if (entry && Array.isArray(entry.results)) {
        const slot = entry.results.find((x) => x.ip === ip)
        if (slot) {
          slot.ttfbMedian = r.ttfbMedian
          slot.ttfbBest = r.ttfbBest
          slot.totalMedian = r.totalMedian
          slot.tcpMedian = r.tcpMedian
          slot.tlsMedian = r.tlsMedian
          slot.okCount = r.okCount
          slot.samples = r.samples
        }
      }
      // 用本轮样本重置探测类 EWMA（历史 ok/fail 与原始 TTFB 环保留 —— 方案 §8.2）
      s.metrics.probeTtfbEwmaMs = r.ttfbMedian
      s.metrics.probeTotalEwmaMs = Number.isFinite(r.totalMedian) ? r.totalMedian : null
      s.metrics.tcpEwmaMs = Number.isFinite(r.tcpMedian) ? r.tcpMedian : s.metrics.tcpEwmaMs
      s.metrics.tlsEwmaMs = Number.isFinite(r.tlsMedian) ? r.tlsMedian : s.metrics.tlsEwmaMs

      s.health.recoveryProbeSuccesses += 1
      transitionHealth(host, ip, 'healthy', 'recovery_probe_ok')
      return 'ok'
    }

    // 探测失败 → 重新冷却（transitionHealth 会刷新 penaltyUntil）
    transitionHealth(host, ip, 'cooling', 'recovery_probe_failed')
    return 'failed'
  } catch (e) {
    log(`health ${host} ${ip}: 恢复探测异常 ${String(e?.message || e)}`)
    transitionHealth(host, ip, 'cooling', 'recovery_probe_error')
    return 'failed'
  } finally {
    // 必须释放，否则异常时 IP 永久卡在探测占用状态（方案 §7.3）
    s.health.halfOpenInFlight = Math.max(0, s.health.halfOpenInFlight - 1)
  }
}

/**
 * 通用 EWMA。脏样本（非有限、≤0、非数字）一律不改变原值。
 * alpha 夹在 [0.05, 0.9]：太小学不动，太大会被单次尖刺带偏。
 */
/** 采样计数 +1（只有真正采纳的样本才计） */

/** 最近原始观测的保留条数 */
const RECENT_TTFB_LIMIT = 20

/** 是否超出 prefill 污染阈值。**只用于分级统计，不再用于丢弃样本。** */
function ttfbOverCap(ms) {
  const maxSample = Math.max(200, Number(cfg.ewmaMaxMs) || 3000)
  return Number.isFinite(ms) && ms > maxSample
}

/** 记录一条原始 TTFB 观测（环形，超出容量丢最旧的） */
function pushRecentTtfb(s, ms, source) {
  if (!Number.isFinite(ms) || ms <= 0) return
  s.recentTtfbMs.push({ ms: Math.round(ms * 100) / 100, source, at: deps.now() })
  if (s.recentTtfbMs.length > RECENT_TTFB_LIMIT) s.recentTtfbMs.shift()
}

/** 分数越小越好；Infinity 表示不可用 */
/**
 * 线路评分。
 *
 * **只用探测 TTFB**（`r.ttfbMedian`），理由：
 *   - 它是唯一「同一种事件、同一量纲」在全候选上都有样本的指标；
 *   - TCP/TLS 是建连成本，与「复用连接时快不快」不是一回事；
 *   - 真实请求 TTFB 会被模型 prefill 污染且样本分布不均，本轮只保留为观察值，
 *     不参与排序（Issue #3 §3.6：融合方式未定前，先用探测 TTFB）。
 *
 * 改造前是 `min(ewmaMs, probeMedian)` —— 把一个 TLS 采样的 EWMA
 * 和一个完整 HTTP 往返取较小值，两者量纲不同，缺乏统计意义。
 */
function scoreOf(host, ip, now) {
  const s = statOf(host, ip)
  // 阶段 3 起按健康状态过滤，与 penaltyUntil 等价；阶段 4 会让 half_open
  // 与 metricsStale 真正生效（它们此刻恒为 healthy / false）。
  const state = getHealthState(host, ip)
  if (state === 'cooling' || state === 'half_open') return Infinity
  if (s.health && s.health.metricsStale) return Infinity
  if (s.penaltyUntil > now) return Infinity

  const entry = hosts.get(host)
  const r = entry?.results?.find((x) => x.ip === ip)
  if (!r) return Infinity

  const ttfb = Number.isFinite(r.ttfbMedian)
    ? r.ttfbMedian
    : (r.okCount > 0 && Number.isFinite(r.ttfbBest) ? r.ttfbBest : null)
  if (ttfb != null) return ttfb

  // 没有探测中位数时，从**原始观测环**里算一个稳健值，而不是直接用 EWMA。
  //
  // 理由：EWMA 对单条尖刺很敏感（alpha=0.5 时一条 5000ms 能把 125ms 的均值拉到 2500ms），
  // 而模型 prefill 恰好就是这种尖刺。采集层已经保留了全部原始样本并单独计数，
  // 所以「要不要相信这个均值」的判断应该在这里做，而不是在采集时把样本丢掉。
  const recent = s.recentTtfbMs || []
  const inCap = recent
    .filter((r) => r.source === 'probe' && !ttfbOverCap(r.ms))
    .map((r) => r.ms)
    .sort((a, b) => a - b)

  if (inCap.length) return inCap[Math.floor(inCap.length / 2)]  // 中位数，抗尖刺

  // 环里一条干净样本都没有，且确实存在超额样本 → 数据被污染，不可评分
  const total = s.samples.probeTtfb || 0
  const over = s.samples.probeTtfbOverCap || 0
  if (total > 0 && over === total) return Infinity

  // 完全没有样本时才退到 EWMA（此时它等于单条样本，没有污染问题）
  return s.metrics.probeTtfbEwmaMs != null ? s.metrics.probeTtfbEwmaMs : Infinity
}

/** 在候选里挑当前最优；返回 { ip, score } 或 null */
function chooseBest(host, excludeIp) {
  const entry = hosts.get(host)
  if (!entry || !entry.results?.length) return null
  const now = deps.now()
  let best = null
  let bestScore = Infinity
  for (const r of entry.results) {
    if (excludeIp && r.ip === excludeIp) continue
    if (r.excluded) continue
    const sc = scoreOf(host, r.ip, now)
    if (sc < bestScore) {
      bestScore = sc
      best = r
    }
  }
  if (!best || !Number.isFinite(bestScore)) return null
  return { ip: best.ip, score: bestScore }
}

// ---------------------------------------------------------------------------
// 探测
// ---------------------------------------------------------------------------

/**
 * 解析主机的 A 记录。**第三层防护：地址分类**（Issue #6）。
 *
 * 关键：DNS 结果不是「挑一个安全的用」，而是**任何一条命中黑名单就整体拒绝**。
 * 混合的公网/私网结果本身就是解析被污染的信号，那不是能用「过滤一下」解决的。
 *
 * 返回 `{ ips, blocked }`：blocked 非空时调用方必须放弃该 host，
 * 不能因为 ips 里还有公网地址就继续。
 */
function resolveIps(host) {
  return new Promise((resolve) => {
    deps.resolve4(host, (err, addrs) => {
      const list = err || !addrs ? [] : [...new Set(addrs)]
      if (!list.length) return resolve({ ips: [], blocked: [] })
      // 显式放开时（本地开发/受信内网）才允许私网地址。
      // 注意：放开的是**地址分类层**，第一层格式校验与第二层白名单仍然生效 ——
      // 也就是说只有 targets 里显式列出的域名才能走到这里。
      if (cfg && cfg.allowPrivateTargets) return resolve({ ips: list, blocked: [] })
      const verdict = filterResolvedIps(list)
      if (!verdict.ok) {
        log(`ssrf-guard: ${host} 解析到受保护地址 ${verdict.hit}，拒绝连接`)
        return resolve({ ips: [], blocked: verdict.hit ? verdict.hit.split(',') : [verdict.reason] })
      }
      resolve({ ips: list, blocked: [] })
    })
  })
}

/** 在 CIDR 里随机取一个 IPv4；非法输入返回 null */
/**
 * 候选池：DNS 返回的 IP 一定保留（保底），再从 CF 公开网段抽样补充。
 * 只靠 DNS 的话永远只有 3 个候选，挑不出真正更快的。
 */
async function discoverIps(host) {
  const { ips: dnsIps, blocked } = await resolveIps(host)
  // 第三层防护命中：不补充任何抽样候选，直接放弃这个 host
  if (blocked.length) return { ips: [], blocked }
  if (!cfg.discoverEnabled) return { ips: dnsIps, blocked: [] }
  const sampled = sampleFromRanges(cfg.discoverRanges, cfg.discoverPerRange)
  return { ips: [...new Set([...dnsIps, ...sampled])], blocked: [] }
}

/** 一级探测：只建 TCP，快、便宜，用来筛掉连不上的候选 */
function tcpProbe(ip, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint()
    const sock = net.connect({ host: ip, port: deps.upstreamPort })
    let settled = false
    const done = (ok) => {
      if (settled) return
      settled = true
      try { sock.destroy() } catch {}
      resolve({ ip, ok, ms: Number(process.hrtime.bigint() - t0) / 1e6 })
    }
    sock.setTimeout(timeoutMs, () => done(false))
    sock.once('connect', () => done(true))
    sock.once('error', () => done(false))
  })
}

/** 并发受限地跑一批 TCP 探测 */
async function tcpProbeAll(ips, concurrency, timeoutMs) {
  const limit = Math.max(1, Math.min(64, Number(concurrency) || 20))
  const out = []
  let cursor = 0
  const workers = Array.from({ length: Math.min(limit, ips.length) }, async () => {
    for (;;) {
      const idx = cursor
      cursor += 1
      if (idx >= ips.length) return
      out.push(await tcpProbe(ips[idx], timeoutMs))
    }
  })
  await Promise.all(workers)
  return out
}

/**
 * 单次探测。**四段计时各有明确的起止点**（Issue #3 §3.3）：
 *
 *   tcpMs    socket 创建 → connect           （仅新建连接）
 *   tlsMs    TCP connect → secureConnect     （仅新建连接）
 *   ttfbMs   请求发出    → 收到响应头         ← 改造前这里错记成「响应体结束」
 *   totalMs  请求发出    → 响应体结束
 *
 * 改造前 `finish()` 在 `res.end` 之后才收尾，导致「探测中位数」里混着响应体下载时间，
 * 不是纯粹的首字节时间。现在 TTFB 在 `response` 事件里就记录，total 单独在 `end` 记。
 *
 * 任何一段采不到就置 null，绝不拿别的段顶替。
 */
function probeOnce(host, ip, timeoutMs, path) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint()
    const elapsed = () => Number(process.hrtime.bigint() - t0) / 1e6

    let settled = false
    let colo = ''
    let tcpMs = null
    let tlsMs = null
    let ttfbMs = null
    let statusCode = null

    /** 统一的收尾。timings 里缺的段保持 null，不用别的值填充 */
    const finish = (ok, detail) => {
      if (settled) return
      settled = true
      resolve({
        ok,
        detail,
        colo,
        tcpMs,
        tlsMs,
        ttfbMs,
        totalMs: ok ? elapsed() : null,
        statusCode,
        // 兼容字段：改造前叫 ms（语义=含响应体的完整耗时）
        ms: ok ? elapsed() : null,
      })
    }

    let req
    try {
      req = https.request({
        host,
        port: deps.upstreamPort,
        path,
        method: 'GET',
        servername: host,
        lookup: pinLookup(ip),
        headers: {
          host,
          'user-agent': 'dsh-cf-router/probe',
          'accept-encoding': 'gzip',
          connection: 'close',
        },
        timeout: timeoutMs,
        ...deps.tlsOptions,
      })
    } catch (err) {
      finish(false, String(err?.message || err))
      return
    }

    // 建连与握手：只有新建连接才有这两个阶段
    let tcpDone = false
    req.on('socket', (sock) => {
      if (!sock) return
      if (sock.connecting) {
        sock.once('connect', () => {
          if (tcpDone) return
          tcpDone = true
          tcpMs = elapsed()
        })
        sock.once('secureConnect', () => {
          tlsMs = elapsed()
        })
      }
    })

    req.on('response', (res) => {
      // 首字节在**收到响应头**的这一刻就记录，不等 body
      ttfbMs = elapsed()
      statusCode = res.statusCode
      // cf-ray 形如 "8c8f...-HKG"，后半段是这个 IP 实际落到的边缘节点
      colo = String(res.headers['cf-ray'] || '').split('-')[1] || ''
      res.resume()
      res.on('end', () => finish(true, `http ${res.statusCode}`))
      res.on('error', (err) => finish(false, String(err?.message || err)))
      res.on('aborted', () => finish(false, 'aborted'))
    })
    req.on('error', (err) => finish(false, String(err?.message || err)))
    req.on('timeout', () => {
      req.destroy()
      finish(false, 'timeout')
    })
    req.end()
  })
}

/**
 * 对单个 IP 取样并聚合。**每个指标单独取中位数**，不混：
 *   ttfbMedian   → 评分主依据
 *   totalMedian  → 观察值（含响应体下载）
 *   tcpMedian / tlsMedian → 建连成本观察值
 *
 * 兼容字段 median 保留，语义改为 ttfbMedian（改造前它混着响应体时间）。
 */
async function measureIp(host, ip, samples, timeoutMs, path) {
  const runs = []
  for (let i = 0; i < samples; i += 1) {
    runs.push(await probeOnce(host, ip, timeoutMs, path))
  }
  const okRuns = runs.filter((r) => r.ok)

  const medianOf = (key) => {
    const vals = okRuns
      .map((r) => r[key])
      .filter((v) => Number.isFinite(v))
      .sort((a, b) => a - b)
    if (!vals.length) return Infinity
    return vals[Math.floor(vals.length / 2)]
  }

  const ttfbMedian = medianOf('ttfbMs')
  const totalMedian = medianOf('totalMs')
  const tcpMedian = medianOf('tcpMs')
  const tlsMedian = medianOf('tlsMs')

  const ttfbVals = okRuns.map((r) => r.ttfbMs).filter((v) => Number.isFinite(v)).sort((a, b) => a - b)
  const ttfbBest = ttfbVals.length ? ttfbVals[0] : Infinity

  const colo = okRuns.map((r) => r.colo).find(Boolean) || ''
  const coloOk = !cfg.coloAllow || !cfg.coloAllow.length || (colo && cfg.coloAllow.includes(colo))

  return {
    ip,
    okCount: okRuns.length,
    samples,
    // 主字段
    ttfbMedian,
    ttfbBest,
    totalMedian,
    tcpMedian,
    tlsMedian,
    // 兼容字段
    median: ttfbMedian,
    best: ttfbBest,
    // 元信息
    colo,
    excluded: coloOk ? null : `colo ${colo || 'unknown'}`,
  }
}

async function refreshHost(host, opts = {}) {
  // 每发起一轮完整探测就递增版本。晚于新探测完成的旧探测，
  // 其结果必须被丢弃，否则会把新结果覆盖掉（Issue #2 场景 C）。
  const generation = beginProbe(host)
  const path = opts.path || cfg.probePath
  const samples = Math.max(1, Math.min(5, opts.samples || cfg.probeSamples))
  const timeoutMs = opts.timeoutMs || cfg.probeTimeoutMs

  const resolved = await resolveIps(host)
  // 第三层防护命中：该域名解析到了受保护地址，整轮探测直接作废
  if (resolved.blocked.length) {
    const entryBlocked = {
      ips: [],
      results: [],
      lastProbeAt: deps.now(),
      error: `ssrf_blocked: ${resolved.blocked.join(',')}`,
      blocked: resolved.blocked,
    }
    commitProbeResult(host, generation, entryBlocked)
    return hosts.get(host)
  }
  const dnsIps = resolved.ips
  const now = deps.now()

  // ---- 候选池合并（Issue #11 阶段 5）----
  const pool = getCandidatePool(host)
  // DNS 无条件并入（它是兜底，不受容量约束）
  mergeCandidates(pool, { dnsIps }, now, { ttlMs: cfg.candidatePoolTtlMs })

  // 有限探索：只有到最小间隔才抽新的，避免每轮重抽
  let explored = []
  if (cfg.discoverEnabled && shouldExplore(pool, now, cfg.candidateRefreshMinIntervalMs)) {
    // 探索配额按「池容量 × 探索比例」算，至少 1 个（否则关掉探索等于没探索）
    const ratioTotal = Math.max(1, Number(cfg.candidatePoolMaxSize) || 64)
    const exploreRatio = cfg._candidateRatios
      ? cfg._candidateRatios.exploration
      : (Number(cfg.candidateExploreRatio) || 0.2)
    const quota = Math.max(1, Math.floor(ratioTotal * exploreRatio))
    const sampled = sampleFromRanges(cfg.discoverRanges, cfg.discoverPerRange)
    explored = pickExploration({
      existing: pool.candidates,
      sampled,
      quota,
      isSelectable: (ip) => isCandidateSelectable(host, ip),
    })
    applyExploration(pool, explored, now, { upsertCandidate, SOURCE_DISCOVERED })
  }

  // ---- 过期与容量整理 ----
  const dnsSet = new Set(dnsIps)
  expireCandidatePool(pool, {
    now,
    ttlMs: cfg.candidatePoolTtlMs,
    currentIp: currentIp.get(host) || null,
    dnsIps: dnsSet,
    isHealthProtected: (ip) => {
      const st = getHealthState(host, ip)
      return st === 'cooling' || st === 'half_open'
    },
    // 保留期依据：进入冷却的时刻，而非最近探测时刻（v0.2.3）
    healthEnteredAt: (ip) => statOf(host, ip).health?.enteredAt || 0,
    coolingRetentionMs: cfg.candidateCoolingRetentionMs,
  })
  pruneCandidatePool(pool, {
    maxSize: cfg.candidatePoolMaxSize,
    now,
    currentIp: currentIp.get(host) || null,
    dnsIps: dnsSet,
    isHealthProtected: (ip) => {
      const st = getHealthState(host, ip)
      return st === 'cooling' || st === 'half_open'
    },
    // 保留期依据：进入冷却的时刻，而非最近探测时刻（v0.2.3）
    healthEnteredAt: (ip) => statOf(host, ip).health?.enteredAt || 0,
    coolingRetentionMs: cfg.candidateCoolingRetentionMs,
  })

  // ---- 从池里选本轮探测对象（当前线路与 DNS 无条件入选）----
  const picked = selectCandidates({
    pool,
    currentIp: currentIp.get(host) || null,
    dnsIps,
    explorationIps: explored,
    ratios: cfg._candidateRatios || {
      historical: cfg.candidateHistoricalRatio,
      current: cfg.candidateCurrentRatio,
      dns: cfg.candidateDnsRatio,
      exploration: cfg.candidateExploreRatio,
    },
    total: Math.max(dnsIps.length, Number(cfg.candidatePoolMaxSize) || 64),
    now,
    isSelectable: (ip) => isCandidateSelectable(host, ip),
  })

  // 候选取并集：池里选出的 + DNS 兜底（SSRF 与 probeGeneration 保护保持不变）
  // 候选并集：池里选出的 + DNS 兜底。
  //
  // **但 DNS 兜底不能凌驾于健康状态**（Issue #11 回写时发现的缺陷）：
  // 原来无条件并入 dnsIps，导致 cooling 中的 IP 每次刷新都被重新探测 ——
  // 既浪费请求，又与「冷却期间不参与正常选路」相矛盾。
  // 现在 DNS 候选同样过 isCandidateSelectable，只保留健康的那些。
  // 注意：这不影响「DNS 兜底优先于容量」——那是淘汰逻辑，与探测选择是两件事。
  const healthyDns = dnsIps.filter((ip) => isCandidateSelectable(host, ip))
  const ips = [...new Set([...picked.selected, ...healthyDns])]
  if (!ips.length) {
    const empty = { ips: [], results: [], lastProbeAt: deps.now(), error: 'DNS 无 A 记录' }
    if (!commitProbeResult(host, generation, empty)) return hosts.get(host)
    return hosts.get(host)
  }

  // 一级：候选多的时候先用 TCP 快速筛，避免对几十个 IP 各发 3 次完整 HTTP
  let alive = ips
  const topN = Math.max(1, Math.min(50, Number(cfg.l2TopN) || 10))
  if (ips.length > topN) {
    const l1 = await tcpProbeAll(ips, cfg.l1Concurrency, cfg.l1TimeoutMs)
    const ok = l1.filter((r) => r.ok).sort((a, b) => a.ms - b.ms).map((r) => r.ip)
    // DNS 返回的 IP 是保底，即使 TCP 超时也进二级（可能是握手慢而非不通）。
    //
    // **但保底必须用健康过滤后的 healthyDns，不能用原始 dnsIps**
    // （v0.2.2 静态审查发现）：上面 1697 行已经过滤过一次，这里若用原始
    // dnsIps 就把 cooling 中的 IP 又放回二级 HTTP 探测，绕过了 #9/#11
    // 的约束。只在候选数 > l2TopN 时触发，所以既有 fixture 测试撞不到。
    alive = [...new Set([...ok.slice(0, topN), ...healthyDns])]
    if (!alive.length) alive = ips.slice(0, Math.min(3, ips.length))
  }

  const results = await Promise.all(alive.map((ip) => measureIp(host, ip, samples, timeoutMs, path)))

  /**
   * **generation 校验必须在任何共享状态写入之前**（v0.2.2 静态审查发现）。
   *
   * 改造前顺序是：measureIp → markProbed/markSuccess → recordProbeSample
   * → 最后才 commitProbeResult 做版本校验。也就是说旧轮次即使最终被丢弃，
   * 前面这些写入已经发生了：
   *
   *   · 旧探测污染新一轮的 EWMA
   *   · 候选池 lastSuccessAt / probeCount 被旧结果改写
   *   · 迟到样本抬高 samples.probeTtfb，进而让 #10 的 minSamples 门槛
   *     提前满足 —— **这条最要紧，样本门槛是迟滞策略的基础**
   *
   * 提前到这里的额外好处：省掉一次无用的 commitProbeResult。
   * 注意不能只看「有没有更新的探测开始过」就跳过 —— 还要保留原来的
   * commitProbeResult 语义（它会比较版本并决定是否覆盖 hosts）。
   */
  const generationStale = getProbeGeneration(host) !== generation
  if (generationStale) {
    log(`probe ${host}: 本轮结果已过期（gen ${generation} ≠ ${getProbeGeneration(host)}），丢弃且不写任何统计`)
    return hosts.get(host)
  }

  // 探测样本入指标（Issue #3）：四个计时分别入库，互不串味
  // 同时把结果回写到候选池（Issue #11 补漏）：
  //   probeCount / lastProbeAt / lastSuccessAt / lastColo 必须随探测更新，
  //   否则 pickHistorical 与 valueRank 只能退化成看 lastSeenAt 单一判据，
  //   「历史优秀 IP」这个核心卖点在实机上就不成立。
  for (const r of results) {
    const cand = pool.candidates.get(r.ip)
    if (cand) {
      // 无论成功与否都算一次探测 —— 失败也是有价值的生命周期信息
      markProbed(cand, now, r.colo)
      if (r.okCount > 0) markSuccess(cand, now, r.colo)
    }
    if (r.okCount <= 0) continue
    recordProbeSample(host, r.ip, {
      tcpMs: r.tcpMedian,
      tlsMs: r.tlsMedian,
      ttfbMs: r.ttfbMedian,
      totalMs: r.totalMedian,
    })
  }

  const usable = results.filter((r) => !r.excluded)
  const entry = {
    ips,
    results: results.sort((a, b) => {
      if (a.excluded && !b.excluded) return 1
      if (!a.excluded && b.excluded) return -1
      return a.median - b.median
    }),
    lastProbeAt: deps.now(),
    error: usable.some((r) => r.okCount > 0) ? null : '所有 IP 探测失败',
  }
  // 版本校验在这里统一做：过期结果直接丢弃，不改 hosts、不碰路由
  if (!commitProbeResult(host, generation, entry)) return hosts.get(host)

  // 探测刷新后重新判定当前 IP：如果它已经不在最优位（且差距明显）就切
  const prev = currentIp.get(host) || null
  const best = chooseBest(host)
  if (!prev) {
    if (best) switchRoute(host, best.ip, 'initial')
  } else if (!best) {
    log(`refresh ${host}: 无可用候选，保留 ${prev}`)
  } else {
    // 切换迟滞（Issue #10）：样本量 → 改善幅度 → 连续更优 → 最短驻留。
    // **硬故障不受任何约束** —— cooling/half_open/不可评分时立即切走。
    const now = deps.now()
    const prevScore = scoreOf(host, prev, now)
    const sst = getSwitchState(host)
    const prevStat = statOf(host, prev)
    const bestStat = statOf(host, best.ip)

    const verdict = decideSwitch({
      prevIp: prev,
      prevScore,
      bestIp: best.ip,
      bestScore: best.score,
      prevHealth: getHealthState(host, prev),
      roundsBetter: sst.roundsBetter,
      lastSwitchAt: sst.lastSwitchAt,
      now,
      // 样本量取探测样本数：这是「这条线路被真实测过几次」的判据
      prevSamples: prevStat.samples?.probeTtfb || 0,
      bestSamples: bestStat.samples?.probeTtfb || 0,
      cfg: {
        minImprovementRatio: cfg.minImprovementRatio,
        consecutiveBetterRounds: cfg.consecutiveBetterRounds,
        minDwellTimeMs: cfg.minDwellTimeMs,
        minSamples: cfg.minSamples,
      },
    })

    sst.roundsBetter = verdict.roundsBetter

    if (verdict.switch) {
      sst.lastSwitchAt = now
      sst.roundsBetter = 0
      switchRoute(host, best.ip, `${verdict.kind}: ${verdict.reason}`)
      log(`switch ${host} ${prev}→${best.ip} [${verdict.kind}] ${verdict.reason}`)
    } else if (verdict.blockedBy && verdict.blockedBy !== 'already_best' && verdict.blockedBy !== 'no_candidate') {
      log(`hold ${host} ${prev} (best ${best.ip}): ${verdict.blockedBy} — ${verdict.reason}`)
    }
  }
  log(`refresh ${host} → ${currentIp.get(host) || 'none'} (best ${best ? Math.round(best.score) + 'ms' : '-'})`)

  // 探测是状态变化最集中的时刻（候选池计数、指标、可能的切换），
  // 在这里统一 flush 一次（Issue #22 阶段 3）。节流由 flushState 内部判断。
  markStateDirty()
  flushState()
  return hosts.get(host)
}

async function refreshAll(opts) {
  await Promise.all((cfg.targets || []).map((h) => refreshHost(h, opts).catch(() => null)))
}

// ---------------------------------------------------------------------------
// 连接与转发
// ---------------------------------------------------------------------------

function agentFor(host, ip) {
  const key = `${host}|${ip}`
  // 走登记表：若该 key 的池正在 draining，这里会新建一代 active 池，
  // 而不是把新请求塞进正在排空的旧池（Issue #12）。
  const rec = poolRegistry.get(key, () => {
    const a = new https.Agent({
      keepAlive: cfg.keepAlive,
      maxSockets: cfg.maxSockets,
      keepAliveMsecs: 30000,
      timeout: 30000,
      lookup: pinLookup(ip),
      ...deps.tlsOptions,
    })
    agents.set(key, a)
    return a
  })
  return rec.agent
}

function directAgentFor(host) {
  const key = `${host}|direct`
  const rec = poolRegistry.get(key, () => {
    const a = new https.Agent({
      keepAlive: cfg.keepAlive,
      maxSockets: cfg.maxSockets,
      keepAliveMsecs: 30000,
      timeout: 30000,
      ...deps.tlsOptions,
    })
    directAgents.set(host, a)
    return a
  })
  return rec.agent
}

/**
 * 让某个 host 的所有池进入排空（Issue #12）。
 *
 * **不再直接 destroy**：该 host 上可能还有正在跑的请求。
 * 池会等它们结束，或由 drainTimeoutMs 兜底强杀。
 * 立即回收只保留给进程退出（dispose）。
 */
function dropAgents(host) {
  poolRegistry.drainAll((key) => key.startsWith(`${host}|`))
  // 从 agents / directAgents 索引里摘掉，避免后续误复用
  for (const key of [...agents.keys()]) {
    if (key.startsWith(`${host}|`)) agents.delete(key)
  }
  directAgents.delete(host)
}

/** 让 host|ip 这个池进入排空 */
function drainPoolFor(host, ip) {
  const key = `${host}|${ip}`
  poolRegistry.drain(key)
  agents.delete(key)
}

/**
 * 旧接口：记一次成功。现在只是 recordRequestSuccess 的薄封装。
 * 关键变化：**不再修改 currentIp** —— 那是 Issue #2 修的缺陷
 * （旧请求的迟到成功回调会把已经切走的线路改回来）。
 */
function noteSuccess(host, ip, ttfbMs) {
  recordRequestSuccess(host, ip, { ttfbMs }, null)
}

/**
 * 旧接口：记一次失败。薄封装到 recordRequestFailure。
 * generation 传 null 表示「按调用当下的状态判断」，与改造前语义等价。
 */
function noteFailure(host, ip, message, kind) {
  recordRequestFailure(host, ip, { message, kind }, null)
}

/**
 * 决定本次请求转发到哪个上游，**并完成四层 SSRF 校验**（Issue #6）。
 *
 * 改造前：`x-cf-target` 原样取用、Host 用 `split(':')[0]`、不校验白名单
 * —— 本机任何进程或浏览器页面都能把代理指向任意主机。
 *
 * 现在：结构化解析 → 白名单精确匹配 → （解析后）地址分类 → 连接钉在已验证地址上。
 *
 * @returns {{host: string, source: string} | {error: string, hint: string, target?: string}}
 */
function targetOf(req) {
  const explicit = req.headers['x-cf-target']
  const hostHeader = req.headers.host || ''

  /** 判断 Host 头是否指向本机代理自身（这种情况要退回配置的默认目标） */
  /**
   * 判断 Host 头是否指向本机代理自身。
   *
   * **不能用 normalizeAuthority 判断**：它按设计拒绝 IP 字面量与单段名，
   * 而这正是「指向自己」最常见的两种形态（127.0.0.1:8787、localhost:8787）。
   * 这里只做宽松提取：去端口、去方括号、小写、去末尾点。
   */
  const hostIsSelf = (() => {
    const raw = String(hostHeader || '').trim().toLowerCase()
    if (!raw) return false
    let h = raw
    // 去端口（IPv6 形如 [::1]:8787）
    if (h.startsWith('[')) {
      const end = h.indexOf(']')
      if (end > 0) h = h.slice(1, end)
    } else {
      const i = h.lastIndexOf(':')
      if (i >= 0) h = h.slice(0, i)
    }
    h = h.replace(/\.+$/, '')

    const selfHosts = new Set([String(cfg.listenHost || '').toLowerCase(), '127.0.0.1', 'localhost', '::1', '0.0.0.0', ''])
    // 注意：listenHost 是 0.0.0.0 时它是监听地址而非可达名，
    // 但此时「客户端连过来用的 Host」通常仍是 127.0.0.1/localhost，已被上面的集合覆盖。
    return selfHosts.has(h)
  })()

  let candidate
  let source
  if (typeof explicit === 'string' && explicit.trim()) {
    candidate = explicit
    source = 'x-cf-target'
  } else if (!hostIsSelf && hostHeader) {
    candidate = hostHeader
    source = 'host'
  } else {
    candidate = (cfg.targets || [])[0]
    source = 'default'
  }

  if (!candidate) {
    return {
      error: 'no_target',
      hint: '配置里 targets 为空，且请求没有带 x-cf-target 头。二选一：在配置里填 targets，或给每个请求加 x-cf-target: <域名>。',
    }
  }

  const parsed = normalizeAuthority(candidate)
  if (!parsed.ok) {
    return {
      error: 'invalid_target',
      target: String(candidate).slice(0, 120),
      hint: `目标格式非法（${parsed.reason}）：只接受纯域名，不能带协议、路径、用户信息、IPv6 字面量或 IP 地址。`,
    }
  }

  const allowed = cfg._allowedHosts
  if (!allowed || !allowed.has(parsed.host)) {
    return {
      error: 'target_not_allowed',
      target: parsed.host,
      hint: '该域名不在 targets 白名单里。要转发到它，请把它加进配置的 targets；不做后缀/通配匹配。',
    }
  }

  return { host: parsed.host, source }
}

/**
 * 发 JSON 响应。
 *
 * **不再无条件设置 `Access-Control-Allow-Origin: *`**（评审要求）。
 * 管理端点若能改运行状态，通配 CORS 等于允许任意网页跨站调用它 ——
 * 浏览器只要被访问，页面 JS 就能 POST /__router/reset。
 *
 * 需要跨源访问时由 `cfg.corsAllowOrigin` 显式配置单个来源（默认不发该头，
 * 浏览器同源策略会拦住跨源请求；命令行 / curl 不受影响）。
 */
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj, null, 2)
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  }
  const allowOrigin = cfg && cfg.corsAllowOrigin
  if (allowOrigin) headers['access-control-allow-origin'] = String(allowOrigin)
  res.writeHead(code, headers)
  res.end(body)
}

/** 发一个错误响应，统一结构 { ok:false, error, message, field? }（Issue #7 错误协议） */
function sendError(res, status, error, message, extra = {}) {
  sendJson(res, status, { ok: false, error, message, ...extra })
}

/** 405 + Allow 头 */
function sendMethodNotAllowed(res, allowMethods) {
  const body = JSON.stringify({
    ok: false,
    error: 'method_not_allowed',
    message: `该端点支持 ${allowMethods.join(', ')}`,
  }, null, 2)
  res.writeHead(405, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    allow: allowMethods.join(', '),
  })
  res.end(body)
}

// ---------------------------------------------------------------------------
// 管理接口（Issue #7）
// ---------------------------------------------------------------------------

/**
 * 管理接口的方法矩阵。`GET /__router/mode` 与 `POST /__router/mode` 共用同一路径，
 * 所以 `Allow` 头对 /mode 是 `GET, POST` —— 不能因为「GET 带 value 参数是旧写法」
 * 就给整条路径声明只允许 POST。
 *
 * | 方法 | 路径                  | 副作用 |
 * | ---- | --------------------- | ------ |
 * | GET  | /__router/status      | 无     |
 * | GET  | /__router/mode        | 无     |
 * | POST | /__router/mode        | 改运行模式（持久化） |
 * | POST | /__router/probe        | 触发探测 |
 * | POST | /__router/reset        | 清运行时统计/冷却/连接池 |
 * | POST | /__router/reset-mode   | 只清持久化的 routingMode |
 */
const CONTROL_ROUTES = {
  '/__router/status': ['GET'],
  '/__router/mode': ['GET', 'POST'],
  '/__router/probe': ['POST'],
  '/__router/reset': ['POST'],
  '/__router/reset-mode': ['POST'],
}

/** 各接口的请求体约束 */
/** 管理接口限流器（按来源 + 读写分类分桶），装载配置时重建 */
let adminLimiter = null
let adminLimiterSig = ''

/** 惰性解析的 Token 缓存：避免每个请求都读盘 */
let adminTokenCache = { value: null, at: 0 }
const ADMIN_TOKEN_TTL_MS = 10_000

function getAdminToken() {
  const t = deps.now()
  if (adminTokenCache.value != null && t - adminTokenCache.at < ADMIN_TOKEN_TTL_MS) {
    return adminTokenCache.value
  }
  const v = resolveAdminToken(cfg)
  adminTokenCache = { value: v, at: t }
  return v
}

function resetAdminTokenCache() {
  adminTokenCache = { value: null, at: 0 }
}

/** 按当前配置（重新）构建限流器；参数没变则复用 */
function ensureAdminLimiter() {
  const sig = `${cfg.adminRateLimit}|${cfg.adminRateWindowMs}`
  if (adminLimiter && adminLimiterSig === sig) return adminLimiter
  adminLimiter = createRateLimiter({
    limit: Math.max(1, Number(cfg.adminRateLimit) || 30),
    windowMs: Math.max(1000, Number(cfg.adminRateWindowMs) || 60000),
    now: deps.now,
  })
  adminLimiterSig = sig
  return adminLimiter
}

/** 是否修改型路由 */
function isMutatingRoute(route, method) {
  return method === 'POST'
}

const CONTROL_BODY = {
  // allowed: 允许的字段（空数组 = 不允许任何字段）
  // required: 必填字段
  // nullable: 允许空 body
  '/__router/probe': { allowed: [], required: [], nullable: true },
  '/__router/reset': { allowed: [], required: [], nullable: true },
  '/__router/reset-mode': { allowed: [], required: [], nullable: true },
  '/__router/mode': { allowed: ['mode'], required: ['mode'], nullable: false },
}

/** 读取并校验 POST 请求体。返回 { ok, value } 或 { ok:false, status, error, message, field? } */
function readControlBody(req, route) {
  const spec = CONTROL_BODY[route]
  if (!spec) return { ok: true, value: {} }

  const raw = req.__bodyText || ''
  const trimmed = raw.trim()

  if (!trimmed) {
    if (spec.nullable) return { ok: true, value: {} }
    return {
      ok: false,
      status: 400,
      error: 'missing_field',
      message: `${spec.required.join(', ') || 'body'} 不能为空`,
      field: spec.required[0] || undefined,
    }
  }

  // Content-Type 校验：允许 application/json（含 charset 后缀）
  const ctype = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase()
  if (ctype && ctype !== 'application/json') {
    return {
      ok: false,
      status: 415,
      error: 'unsupported_media_type',
      message: '请求体需为 application/json',
    }
  }

  let parsed
  try {
    parsed = JSON.parse(trimmed)
  } catch (e) {
    return { ok: false, status: 400, error: 'invalid_json', message: '请求体不是合法 JSON' }
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, status: 400, error: 'invalid_json', message: '请求体必须是 JSON 对象' }
  }

  for (const key of Object.keys(parsed)) {
    if (!spec.allowed.includes(key)) {
      return {
        ok: false,
        status: 400,
        error: 'unknown_field',
        message: `未知字段 ${key}；该接口只接受 ${spec.allowed.length ? spec.allowed.join(', ') : '空 body'}`,
        field: key,
      }
    }
  }
  for (const key of spec.required) {
    // 只有「键不存在」或值为 undefined 才算缺失。
    // 显式传 null 视为「提供了但值非法」—— 归 invalid_value，
    // 否则调用方改 null 会得到误导性的 missing_field。
    if (!(key in parsed) || parsed[key] === undefined) {
      return { ok: false, status: 400, error: 'missing_field', message: `缺少必填字段 ${key}`, field: key }
    }
  }

  return { ok: true, value: parsed }
}

/**
 * 处理管理接口。命中返回 true（已响应），否则返回 false（交给转发逻辑）。
 *
 * 注意：本函数**不做身份验证** —— 那是 Issue #8 的范围。
 * #7 只负责方法语义、请求校验与统一错误协议。中间过渡期端点必须只监听 loopback。
 */
function routeControl(req, res, route) {
  const method = String(req.method || 'GET').toUpperCase()
  const allow = CONTROL_ROUTES[route] || []
  if (!allow.includes(method)) {
    sendMethodNotAllowed(res, allow)
    return
  }

  // ---- 身份验证与访问保护（Issue #8）----
  // 顺序：方法已合法 → 校验来源与凭据 → 再处理请求。
  // 先校验方法而不是先鉴权，是为了让 405 与 401 的语义不混淆。
  const verdict = authorize({
    headers: req.headers,
    remoteAddr: req.socket?.remoteAddress || '',
    listenHost: cfg.listenHost,
    route,
    cfg,
    rl: ensureAdminLimiter(),
    mutating: isMutatingRoute(route, method),
    getToken: getAdminToken,
  })
  if (!verdict.ok) {
    sendError(res, verdict.status, verdict.error, verdict.message, verdict.extra || {})
    return
  }

  // ---- GET：只读 ----
  if (method === 'GET') {
    if (route === '/__router/status') {
      sendJson(res, 200, statusSnapshot())
      return
    }
    if (route === '/__router/mode') {
      // 旧写法 GET ?value=direct 曾用来改模式，现在必须拒绝（Issue #7）
      const q = new URL(req.url, 'http://127.0.0.1')
      const legacy = q.searchParams.get('value') || q.searchParams.get('mode')
      if (legacy != null) {
        sendMethodNotAllowed(res, ['GET', 'POST'])
        return
      }
      sendJson(res, 200, {
        ok: true,
        routingMode: currentMode(),
        statePath,
        allowed: ['auto', 'direct'],
        ...api8AuthHint(),
      })
      return
    }
    return
  }

  // ---- POST：需要请求体校验 ----
  const body = readControlBody(req, route)
  if (!body.ok) {
    sendError(res, body.status, body.error, body.message, body.field ? { field: body.field } : {})
    return
  }

  if (route === '/__router/probe') {
    refreshAll()
      .then(() => sendJson(res, 200, statusSnapshot()))
      .catch((err) => sendError(res, 500, 'probe_failed', String(err?.message || err)))
    return
  }

  if (route === '/__router/reset') {
    const clearedAgents = resetAll()
    sendJson(res, 200, {
      ok: true,
      clearedAgents,
      // 明确不宣称「不影响活动连接」—— #12 才会解决 Agent 回收，
      // 当前 resetAll() 会销毁 Agent，可能影响同 Agent 上仍在跑的请求。
      note: '运行时统计与连接池已清空；活动连接的回收语义见 Issue #12',
    })
    return
  }

  if (route === '/__router/reset-mode') {
    const r = resetRoutingMode()
    sendJson(res, r.ok === false ? 500 : 200, r)
    return
  }

  if (route === '/__router/mode') {
    const value = String(body.value.mode || '').trim()
    if (!['auto', 'direct'].includes(value)) {
      sendError(res, 400, 'invalid_value', 'mode 必须是 auto 或 direct', { field: 'mode' })
      return
    }
    sendJson(res, 200, setRoutingMode(value))
    return
  }
}

/** #8 落地前的占位提示，让调用方知道端点当前没有鉴权 */
function api8AuthHint() {
  const hasToken = Boolean(getAdminToken())
  return {
    authRequired: hasToken || Boolean(cfg.adminProtectStatus),
    tokenConfigured: hasToken,
    // 不暴露 Token 本身，也不暴露它的长度/前缀
    statusProtected: Boolean(cfg.adminProtectStatus),
    allowedOrigins: (cfg.adminAllowedOrigins || []).length,
  }
}

function handleProxy(req, res) {
  // 控制端点在目标校验之前处理：它们只操作本机状态，不需要上游目标。
  // 但需要先收齐请求体才能做 POST 校验，所以在 createProxy 里已把体读进 req.__bodyText。
  const controlRoute = String(req.url || '').split('?')[0]
  if (CONTROL_ROUTES[controlRoute]) {
    routeControl(req, res, controlRoute)
    return
  }

  const target = targetOf(req)
  const host = target.host || null

  // 目标校验失败：区分「未配置」与「配置了但不在白名单/格式非法」，
  // 都比把 undefined 丢给 https.request 变成 ECONNREFUSED 有用（Issue #6）。
  if (!host) {
    sendJson(res, target.error === 'target_not_allowed' ? 403 : 400, {
      ...target,
      listen: `http://${cfg.listenHost}:${cfg.listenPort}`,
      allowedTargets: Array.from(cfg._allowedHosts || []),
    })
    return
  }

  let ip = currentMode() === 'direct' ? null : (currentIp.get(host) || null)
  // 当前 IP 若在冷却，先选一个新的
  if (ip) {
    const s = statOf(host, ip)
    if (s.penaltyUntil > deps.now()) {
      const next = chooseBest(host, ip)
      if (next) {
        switchRoute(host, next.ip, 'request:penalized')
        ip = next.ip
      } else {
        ip = null
      }
    }
  }
  // 从来没有 IP（探测未完成 / 全失败）
  if (!ip && currentMode() !== 'direct') {
    const next = chooseBest(host)
    if (next) {
      switchRoute(host, next.ip, 'request:first')
      ip = next.ip
    }
  }

  /**
   * 请求出发时的线路快照。回调阶段一律用它，**不重新读 currentIp** ——
   * 重新读就等于让迟到的旧请求按新状态结算，正是 Issue #2 要防的。
   */
  const requestRoute = { host, ip, generation: getRouteGeneration(host) }

  // 请求头过滤（Issue #5）：不是「删掉看起来特殊的」，而是守住端到端/逐跳边界。
  // 剥离 Connection 动态列出的字段、transfer-encoding 等逐跳字段，
  // 保留 content-encoding / content-type / authorization 等端到端字段。
  const headers = filterRequestHeaders(req.headers, {
    targetHost: host,
    dropExtra: ['x-cf-target'],
  })

  stats.requests += 1
  lastRequestAt = deps.now()
  /**
   * 用 hrtime 计时，不用 deps.now()：后者是 Date.now()，会被系统时间调整影响，
   * 而且精度只有毫秒。假时钟注入只用于冷却/驻留这种长尺度判断，不用于耗时测量。
   */
  const t0 = process.hrtime.bigint()
  const elapsed = () => Number(process.hrtime.bigint() - t0) / 1e6
  const modeIsDirect = currentMode() === 'direct'
  const useDirect = modeIsDirect || (!ip && cfg.allowDirectFallback)

  if (!ip && !useDirect) {
    sendJson(res, 503, {
      error: 'no_upstream',
      host,
      hint: '所有候选都在冷却且未开启直连兜底，稍后自动恢复',
      detail: hosts.get(host)?.error || null,
    })
    return
  }
  // 两者语义不同，分开统计：direct 是主动选择，fallback 是 auto 下的被动兜底
  if (modeIsDirect) stats.directRequests += 1
  else if (useDirect) stats.directFallback += 1

  const opts = {
    host,
    port: deps.upstreamPort,
    path: req.url,
    method: req.method,
    headers,
    servername: host,
    ...deps.tlsOptions,
  }
  if (ip) opts.agent = agentFor(host, ip)
  else opts.agent = directAgentFor(host)

  /**
   * 活动请求计数（Issue #12 阶段 2）。
   *
   * 必须在 `up` 创建**之前**占位，并在**所有**退出路径归还：
   * success / error / client-close 三条路都可能先到，所以 release 必须幂等。
   * 计数漏减会让排空永远等不到归零，池只能被超时强杀。
   */
  poolRegistry.acquire(opts.agent)
  let poolReleased = false
  const releasePoolSlot = () => {
    if (poolReleased) return
    poolReleased = true
    poolRegistry.release(opts.agent)
  }

  let firstByteSeen = false
  let settled = false
  /**
   * 错误处理的独立幂等守卫（Issue #9 阶段 6）。
   *
   * **不能用 `settled`** —— 它在 `up.on('response')` 里也会被置 true，
   * 而「已收到响应头」之后仍可能发生流式传输失败，那时必须记账。
   * 方案 §11.1 明确点出了这一点，直接套 settled 会吞掉真实的传输失败。
   */
  let errorHandled = false

  /**
   * 真实请求的四段计时（Issue #3 §3.4）。
   *
   * 采不到的一律 null，绝不用别的指标顶替：
   *   tcpMs    socket 创建 → connect
   *   tlsMs    TCP connect → secureConnect
   *   ttfbMs   请求发出    → 收到响应头
   *   reused   本次是否复用了已有连接
   */
  let tcpMs = null
  let tlsMs = null
  let tlsDone = false
  let reused = null
  const firstByteTimer = setTimeout(() => {
    if (settled || firstByteSeen) return
    try {
      up.destroy(new Error('first_byte_timeout'))
    } catch {}
  }, Math.max(5000, cfg.firstByteTimeoutMs))

  const up = https.request(opts, (upRes) => {
    firstByteSeen = true
    clearTimeout(firstByteTimer)
    if (ip) {
      recordRequestSuccess(
        host,
        ip,
        { tcpMs, tlsMs, ttfbMs: elapsed(), reused: Boolean(reused) },
        requestRoute.generation,
      )
    }
    // 响应头过滤（Issue #5）：剥离逐跳字段，保留 content-encoding 等端到端字段
    const outHeaders = filterResponseHeaders(upRes.headers, { statusCode: upRes.statusCode })

    // SSE 需要额外的「不缓冲」处理：Node 默认会给响应加自己的缓冲与
    // 自动 content-length 推断，那会让流式事件攒批后才到客户端。
    if (isEventStream(outHeaders)) {
      outHeaders['cache-control'] = outHeaders['cache-control'] || 'no-cache'
      outHeaders['x-accel-buffering'] = 'no'
      // 明确禁用 Nagle 攒包
      try { res.socket?.setNoDelay?.(true) } catch { /* ignore */ }
    }

    res.writeHead(upRes.statusCode || 502, outHeaders)
    if (typeof res.flushHeaders === 'function') res.flushHeaders()
    upRes.on('data', (chunk) => {
      stats.bytesIn += chunk.length
      // SSE 每块到达就立刻 flush，否则客户端会等整段才渲染
      if (outHeaders['content-type'] && String(outHeaders['content-type']).startsWith('text/event-stream')) {
        try { res.flushHeaders() } catch { /* ignore */ }
      }
    })

    /**
     * **响应体传输中断必须接住**（Issue #9 阶段 6 发现的原缺陷）。
     *
     * up.on('error') 只覆盖「请求阶段」的错误；响应体已经流到一半时断开，
     * 错误是发在 `upRes` 上的，没人监听就会变成未捕获异常 ——
     * 实测表现为整个进程挂死（用例跑了 400 秒不返回）。
     */
    let responseFailureRecorded = false
    const recordResponseFailure = (msg) => {
      if (responseFailureRecorded || errorHandled) return
      // 判据只看「上游响应体是否完整送达」。**不看 ctx.clientAborted** ——
      // 它在该场景下会被 res.close 提前置位，用它会漏掉「上游自己断流」。
      // 上游主动切断（fixture 的 socket.destroy）与客户端断开在代理侧
      // 表现一致，都该记一次传输失败。
      if (ctx.upstreamEnded) return           // 已经正常读完
      responseFailureRecorded = true
      errorHandled = true
      release()
      if (ip) {
        recordRequestFailure(
          host, ip,
          { message: msg, kind: 'error', clientAborted: false },
          requestRoute.generation,
        )
      }
    }

    upRes.on('error', (err) => {
      const msg = String(err?.message || err)
      recordResponseFailure(`response_aborted: ${msg}`)
      setImmediate(() => { try { res.destroy() } catch { /* ignore */ } })
      log(`upstream response error ${host}: ${msg}`)
    })

    // 上游响应体被提前关闭（socket 断）也归为传输中断
    upRes.on('close', () => {
      if (upRes.complete) return          // 正常读完
      recordResponseFailure('response_incomplete')
    })

    // 响应体传完 → 才归还池槽位。
    //
    // **不能在收到响应头时归还**：那样 SSE 一拿到头计数就归零，
    // 池会被立即回收，反而切断正在传输的 SSE —— 与保护目标正好相反。
    // 响应体传输期间 socket 仍在被使用，算「活动」。
    // 永不结束的 SSE 由排空超时兜底（方案 §6.3-D/F）。
    const onBodyDone = () => { releasePoolSlot() }
    upRes.on('end', onBodyDone)
    upRes.on('close', onBodyDone)
    upRes.on('error', onBodyDone)

    upRes.pipe(res)
  })

  let tcpDone = false
  up.on('socket', (sock) => {
    if (!sock) return
    // connecting=true 表示这是新建连接；否则是 Agent 复用了已有 socket。
    // 不能只看 socket 是否存在 —— 复用连接时 socket 早就连接好了。
    reused = !sock.connecting
    if (!sock.connecting) return

    sock.once('connect', () => {
      if (tcpDone) return
      tcpDone = true
      tcpMs = elapsed()
    })
    sock.once('secureConnect', () => {
      if (tlsDone) return
      tlsDone = true
      tlsMs = elapsed()
    })
  })

  /**
   * 统一请求上下文（Issue #4）。
   *
   * 改造前 `res.on('close')` 只清 timer 并记日志，**从不销毁上游请求** ——
   * 用户点了「停止生成」后上游照样跑完整个响应体。实测：客户端收首块就断开，
   * 上游仍把 8MB 写完（`aborted=0 completed=2`）。
   *
   * 三种状态必须分清，混淆就会把正常结束误判成取消：
   *   upstreamSettled  已收到响应头（后续是正常流式传输）
   *   upstreamEnded    响应体已正常写完
   *   clientAborted    客户端在完成前断开
   */
  const ctx = {
    upstreamSettled: false,
    upstreamEnded: false,
    clientAborted: false,
    released: false,
  }

  /** 清理计时器/超时。可重复调用，幂等。 */
  const release = () => {
    if (ctx.released) return
    ctx.released = true
    clearTimeout(firstByteTimer)
    try { up.setTimeout(0) } catch { /* ignore */ }
  }

  up.setTimeout(cfg.upstreamTimeoutMs, () => {
    up.destroy(new Error('upstream_timeout'))
  })

  up.on('response', () => {
    settled = true
    ctx.upstreamSettled = true
  })

  up.on('error', (err) => {
    settled = true
    releasePoolSlot()
    // 幂等：同一请求只处理一次错误。注意这里只挡「错误处理路径」，
    // 不影响收到响应头之后的正常流转。
    if (errorHandled) return
    errorHandled = true
    release()
    const msg = String(err?.message || err)

    // 我们主动销毁上游造成的错误：不是上游故障，不该计入 IP 失败
    if (ctx.clientAborted) {
      log(`client aborted ${req.url}（已取消上游）`)
      return
    }
    // 客户端已断、上游随后报 ECONNRESET 的竞态也归为取消
    if ((err?.code === 'ECONNRESET') && res.destroyed) {
      log(`client aborted ${req.url}`)
      return
    }

    if (ip) {
      // 把原始 err 一并交给分类器：它优先用 err.code，不做消息模糊匹配
      const kind = msg.includes('timeout') ? 'timeout' : 'error'
      recordRequestFailure(
        host, ip,
        { message: msg, kind, err, clientAborted: ctx.clientAborted },
        requestRoute.generation,
      )
    }
    if (!res.headersSent) {
      sendJson(res, 502, { error: 'upstream_error', host, ip: ip || 'direct', message: msg })
    } else {
      try {
        res.destroy()
      } catch {}
    }
  })

  req.on('data', (chunk) => {
    stats.bytesOut += chunk.length
  })

  // 上游响应体正常写完 —— 这是「不是取消」的判据
  res.on('finish', () => { ctx.upstreamEnded = true })

  // Node 在客户端提前断开且请求体没读完时触发
  req.on('aborted', () => { ctx.clientAborted = true })

  req.pipe(up)

  res.on('close', () => {
    const finishedNormally = res.writableFinished === true || ctx.upstreamEnded

    if (!finishedNormally) {
      // 客户端在响应写完前断开 —— 立刻取消上游。
      //
      // **不能在这里置 errorHandled**：实测 res.close 可能先于 upRes.error
      // 触发（客户端读一半断开 → 我们的 socket 先 close → 上游的 ECONNRESET
      // 稍后才到）。提前置位会让那次失败记账被跳过，正是它该被记下的场景。
      //
      // 由取消路径自己判断（ctx.clientAborted）来避免重复记账。
      // **区分「上游先断」与「客户端先断」。**
      // 两者在 res.close 这一刻无法直接分辨，但当时代理还没读到完整体，
      // 且上游侧也没报错 —— 视为客户端断开。若上游接下来报错，
      // 由 recordResponseFailure 兜住（它用「上游是否已 complete」判断，
      // 不看 clientAborted 这个可能被提前置位的标记）。
      ctx.clientAborted = true
      // 先 unpipe 再 destroy：避免 destroy 触发的 error 又走一遍响应路径
      try { up.unpipe(res) } catch { /* ignore */ }
      try { req.unpipe(up) } catch { /* ignore */ }
      try {
        if (!ctx.upstreamEnded) up.destroy(new Error('client_aborted'))
      } catch { /* ignore */ }
    }

    // 兜底：客户端断开等路径也必须归还，否则计数泄漏
    releasePoolSlot()
    release()
    log(`${req.method} ${req.url} via ${ip || 'direct'} ${Math.round(elapsed())}ms${ctx.clientAborted ? ' (client aborted)' : ''}`)
  })
}

function createProxy() {
  const existing = globalThis[SERVER_KEY]
  if (existing) {
    try {
      existing.closeAllConnections?.()
      existing.close()
    } catch {}
    globalThis[SERVER_KEY] = null
  }

  const server = http.createServer((req, res) => {
    // 管理接口的 POST 需要读完请求体才能做 JSON 校验；转发路径则走流式 pipe，
    // 不能预读（会破坏 SSE 首字节延迟与 backpressure）。
    // 所以只对管理路由预读，其余保持原样。
    const controlRoute = String(req.url || '').split('?')[0]
    if (CONTROL_ROUTES[controlRoute] && String(req.method || '').toUpperCase() === 'POST') {
      const chunks = []
      let size = 0
      const LIMIT = 64 * 1024
      req.on('data', (c) => {
        size += c.length
        if (size > LIMIT) {
          // 管理接口的请求体不该这么大；直接拒绝，避免内存放大
          if (!res.headersSent) {
            sendError(res, 413, 'payload_too_large', `请求体超过 ${LIMIT} 字节`)
            try { req.destroy() } catch { /* ignore */ }
          }
          return
        }
        chunks.push(c)
      })
      req.on('end', () => {
        if (res.headersSent) return
        req.__bodyText = Buffer.concat(chunks).toString('utf8')
        try {
          handleProxy(req, res)
        } catch (err) {
          try { sendError(res, 500, 'router_internal', String(err?.message || err)) } catch { /* ignore */ }
        }
      })
      req.on('error', () => {
        if (!res.headersSent) {
          try { sendError(res, 400, 'bad_request', '读取请求体失败') } catch { /* ignore */ }
        }
      })
      return
    }

    try {
      handleProxy(req, res)
    } catch (err) {
      try {
        sendJson(res, 500, { error: 'router_internal', message: String(err?.message || err) })
      } catch {}
    }
  })
  server.keepAliveTimeout = 65000
  server.headersTimeout = 66000
  server.requestTimeout = 0

  server.on('error', (err) => {
    log(`proxy listen error: ${err?.code || err?.message}`)
    if (err?.code === 'EADDRINUSE') {
      // 热重载时旧实例可能还占着端口，稍后重试
      setTimeout(() => {
        try {
          server.listen(cfg.listenPort, cfg.listenHost)
        } catch {}
      }, 800)
    }
  })

  server.listen(cfg.listenPort, cfg.listenHost)
  globalThis[SERVER_KEY] = server
  proxyServer = server
  return server
}

function closeProxy() {
  const server = globalThis[SERVER_KEY] || proxyServer
  if (!server) return
  try {
    server.closeAllConnections?.()
    server.close()
  } catch {}
  globalThis[SERVER_KEY] = null
  proxyServer = null
}

// ---------------------------------------------------------------------------
// 健康巡检
// ---------------------------------------------------------------------------

function healthTick() {
  const now = deps.now()

  // 连接池回收（Issue #12）：把已排空的池销毁，超时的强制回收。
  // 放在 tick 里而不是立即 destroy —— 活动请求需要时间跑完。
  try {
    const r = poolRegistry.reclaim(cfg.drainTimeoutMs)
    if (r.destroyed.length) {
      log(`pool reclaim: 销毁 ${r.destroyed.length} 个` +
        (r.forced.length ? `（其中 ${r.forced.length} 个超时强杀）` : ''))
    }
  } catch (e) {
    log(`pool reclaim 异常: ${String(e?.message || e)}`)
  }

  for (const host of hosts.keys()) {
    // ---- 阶段 4：先把到期的 cooling 推进到 half_open 并发起恢复探测 ----
    // 注意：advanceHealthState 只推进状态，不判断探测；探测单独发起。
    const entry = hosts.get(host)
    if (entry && Array.isArray(entry.results)) {
      for (const r of entry.results) {
        const st = getHealthState(host, r.ip)
        if (st === 'cooling') {
          const adv = advanceHealthState(host, r.ip)
          if (adv.to === 'half_open') {
            // 不 await：healthTick 是同步定时器回调，探测在后台跑
            runRecoveryProbe(host, r.ip).catch(() => null)
          }
        } else if (st === 'half_open') {
          // 状态已推进但探测未发出（例如上一轮异常）→ 补发一次
          const hs = statOf(host, r.ip).health
          if (!hs || hs.halfOpenInFlight === 0) {
            runRecoveryProbe(host, r.ip).catch(() => null)
          }
        }
      }
    }

    const cur = currentIp.get(host) || null
    if (cur) {
      const s = statOf(host, cur)
      if (s.penaltyUntil > now) {
        const next = chooseBest(host, cur)
        if (next) switchRoute(host, next.ip, 'health:penalized')
        else switchRoute(host, null, 'health:all-penalized')
      }
      continue
    }
    // 当前没有 IP：看看有没有新候选（cooling/half_open 的会被 scoreOf 过滤掉）
    const next = chooseBest(host)
    if (next) {
      switchRoute(host, next.ip, 'health:recover')
    } else if (!hosts.get(host) || deps.now() - (hosts.get(host).lastProbeAt || 0) > cfg.probeIntervalMs) {
      refreshHost(host).catch(() => {})
    }
  }
}

// ---------------------------------------------------------------------------
// 状态快照
// ---------------------------------------------------------------------------

function statusSnapshot() {
  const now = deps.now()
  const list = []
  for (const [host, entry] of hosts) {
    const cur = currentIp.get(host) || null
    list.push({
      host,
      current: cur,
      candidates: (entry.results || []).map((r) => {
        const s = statOf(host, r.ip)
        const penaltyLeft = Math.max(0, s.penaltyUntil - now)
        const m = s.metrics || emptyMetrics()
        const sm = s.samples || emptySamples()
        const nn = (v) => (v == null || !Number.isFinite(v) ? null : round(v))
        return {
          ip: r.ip,
          colo: r.colo || null,
          excluded: r.excluded || null,

          // 探测聚合（每个指标单独取中位数）
          probeTtfbMs: nn(r.ttfbMedian),
          probeBestTtfbMs: nn(r.ttfbBest),
          probeTotalMs: nn(r.totalMedian),
          probeTcpMs: nn(r.tcpMedian),
          probeTlsMs: nn(r.tlsMedian),
          probeOk: `${r.okCount}/${r.samples}`,

          // 兼容字段：probeMs / probeBestMs 现在表示 TTFB
          probeMs: nn(r.ttfbMedian),
          probeBestMs: nn(r.ttfbBest),

          // 六个独立 EWMA（Issue #3）
          metrics: {
            tcpEwmaMs: nn(m.tcpEwmaMs),
            tlsEwmaMs: nn(m.tlsEwmaMs),
            probeTtfbEwmaMs: nn(m.probeTtfbEwmaMs),
            probeTotalEwmaMs: nn(m.probeTotalEwmaMs),
            freshTtfbEwmaMs: nn(m.freshTtfbEwmaMs),
            reusedTtfbEwmaMs: nn(m.reusedTtfbEwmaMs),
          },
          samples: {
            tcp: sm.tcp,
            tls: sm.tls,
            probeTtfb: sm.probeTtfb,
            probeTotal: sm.probeTotal,
            freshTtfb: sm.freshTtfb,
            reusedTtfb: sm.reusedTtfb,
            // 超出 ewmaMaxMs 的样本数：计入 EWMA，但单独标出来供判断数据质量
            freshTtfbOverCap: sm.freshTtfbOverCap || 0,
            reusedTtfbOverCap: sm.reusedTtfbOverCap || 0,
            probeTtfbOverCap: sm.probeTtfbOverCap || 0,
          },

          // 最近 20 条原始 TTFB（不过滤），用于事后判断「稳定的慢」还是「偶发被 prefill 拖慢」
          recentTtfbMs: (s.recentTtfbMs || []).slice(-20),

          // 最近一次真实请求的原始观察值
          lastTtfbMs: nn(s.lastTtfbMs),
          lastReused: s.lastReused == null ? null : Boolean(s.lastReused),

          ok: s.ok,
          fail: s.fail,
          consecutiveFail: s.consecutiveFail,
          // 健康状态（Issue #9 阶段 3）：与 cooldownMsLeft 并存，不替换任何旧字段
          health: {
            state: getHealthState(host, r.ip),
            failureScore: Math.round((s.failureScore || 0) * 100) / 100,
            halfOpenInFlight: s.health?.halfOpenInFlight || 0,
            recoveryProbeSuccesses: s.health?.recoveryProbeSuccesses || 0,
            // 冷却到期时刻（null 表示没在冷却）——便于判断「还有多久能恢复」
            cooldownUntil: s.penaltyUntil > now ? s.penaltyUntil : null,
            metricsStale: Boolean(s.health?.metricsStale),
            lastRecoveryAt: s.health?.lastRecoveryAt || null,
          },
          cooldownMsLeft: penaltyLeft > 0 ? penaltyLeft : 0,
          score: Number.isFinite(scoreOf(host, r.ip, now)) ? round(scoreOf(host, r.ip, now)) : null,
        }
      }),
      lastProbeAt: entry.lastProbeAt,
      error: entry.error,
    })
  }
  return {
    ok: true,
    listen: `http://${cfg.listenHost}:${cfg.listenPort}`,
    baseUrlHint: `http://${cfg.listenHost}:${cfg.listenPort}`,
    keepAlive: cfg.keepAlive,
    probeIntervalMs: cfg.probeIntervalMs,
    healthCheckMs: cfg.healthCheckMs,
    failThreshold: cfg.failThreshold,
    cooldownMs: cfg.cooldownMs,
    routingMode: currentMode(),
    /**
     * 三个来源分开暴露。冲突时（stateFileMode 与 configMode 不同）
     * 看一眼就知道为什么生效值不是配置里写的那个。
     */
    /**
     * 配置的「写了什么」与「实际按什么跑」分开暴露（Issue #17 评审要求）。
     * 只贴 cfg 的原始值等于骗人：配 300 而代码按 Math.max(5000, 300) 执行时，
     * 接口必须显示 5000。凡是代码里有夹取的地方都在这里列出。
     */
    /**
     * 健康汇总（Issue #9 阶段 5）：一眼看出当前有多少 IP 处于哪个状态，
     * 以及还有多久恢复。逐候选明细在 hosts[].candidates[].health。
     */
    healthSummary: (() => {
      const counts = { healthy: 0, cooling: 0, half_open: 0 }
      let pendingRecovery = 0
      let staleMetrics = 0
      const t = deps.now()
      for (const [host, entry] of hosts) {
        for (const r of entry.results || []) {
          const st = getHealthState(host, r.ip)
          counts[st] = (counts[st] || 0) + 1
          const hs = statOf(host, r.ip).health || {}
          if (st === 'half_open' && (hs.halfOpenInFlight || 0) > 0) pendingRecovery += 1
          if (hs.metricsStale) staleMetrics += 1
        }
      }
      void t
      return { counts, pendingRecovery, staleMetrics }
    })(),
    /**
     * 切换迟滞状态（Issue #10）：每个 host 的连续更优轮次、
     * 上次切换时刻、还需驻留多久。
     */
    switchHysteresis: (() => {
      const out = []
      const t = deps.now()
      for (const [host, st] of switchState) {
        const dwell = Number(cfg.minDwellTimeMs) || 0
        out.push({
          host,
          roundsBetter: st.roundsBetter,
          lastSwitchAt: st.lastSwitchAt || null,
          minDwellTimeMs: dwell,
          dwellRemainingMs: st.lastSwitchAt ? Math.max(0, dwell - (t - st.lastSwitchAt)) : 0,
        })
      }
      return out
    })(),
    /**
     * 连接池（Issue #12）：active / draining 数量、在飞请求数、
     * 每个排空池还有多久会被强制回收。
     */
    connectionPools: (() => {
      const st = poolRegistry.stats()
      const timeout = Number(cfg.drainTimeoutMs) || 120000
      return {
        ...st,
        drainTimeoutMs: timeout,
        drainingPools: st.drainingPools.map((p) => ({
          ...p,
          forcedReclaimInMs: Math.max(0, timeout - p.drainingForMs),
        })),
      }
    })(),
    /**
     * 候选池汇总（Issue #11）：每个 host 的池大小、来源分布、
     * 以及**是否因 DNS 兜底而超出容量上限**。
     */
    candidatePools: (() => {
      const out = []
      for (const [host, pool] of candidatePools) {
        let dns = 0; let discovered = 0
        for (const c of pool.candidates.values()) {
          if (c.source === SOURCE_DNS) dns += 1
          else discovered += 1
        }
        const max = Number(cfg.candidatePoolMaxSize) || 64
        out.push({
          host,
          size: pool.candidates.size,
          maxSize: max,
          dnsCount: dns,
          discoveredCount: discovered,
          // 受保护对象导致的实际超额：如实报告，不静默
          overCapacity: Math.max(0, pool.candidates.size - max),
          lastRefreshAt: pool.lastRefreshAt || null,
          ratios: cfg._candidateRatios || null,
        })
      }
      return out
    })(),
    /** 白名单：生效的与装载期被剔除的条目（Issue #6） */
    allowedTargets: Array.from(cfg._allowedHosts || []),
    rejectedTargets: cfg._allowedRejected || [],
    /** 启动恢复摘要（Issue #22） */
    restore: lastRestoreSummary,
    /** 写盘节流状态（Issue #22 阶段 3） */
    statePersistence: {
      dirty: stateDirty,
      lastFlushAt: lastStateFlushAt || null,
      minIntervalMs: Number(cfg.stateFlushMinIntervalMs) || 0,
    },
    /** 状态文件 schema 版本（Issue #13） */
    stateSchema: {
      version: STATE_SCHEMA_VERSION,
      loadedFrom: stateFileSchema,
      path: statePath || null,
    },
    configEffective: {
      firstByteTimeoutMs: {
        configured: numOrNull(cfg.firstByteTimeoutMs),
        effective: Math.max(5000, Number(cfg.firstByteTimeoutMs) || 60000),
        floorMs: 5000,
      },
      cooldownMs: {
        configured: numOrNull(cfg.cooldownMs),
        effective: Math.max(1000, Number(cfg.cooldownMs) || 60000),
        floorMs: 1000,
      },
      probeIntervalMs: {
        configured: numOrNull(cfg.probeIntervalMs),
        effective: Math.max(30000, Number(cfg.probeIntervalMs) || 300000),
        floorMs: 30000,
      },
      healthCheckMs: {
        configured: numOrNull(cfg.healthCheckMs),
        effective: Math.max(5000, Number(cfg.healthCheckMs) || 30000),
        floorMs: 5000,
      },
      ewmaMaxMs: {
        configured: numOrNull(cfg.ewmaMaxMs),
        effective: Math.max(200, Number(cfg.ewmaMaxMs) || 3000),
        floorMs: 200,
        note: '分级阈值（不是过滤阈值）：超过它的 TTFB 样本仍保留，只标记 overCap',
      },
    },
    routingModeSources: {
      configMode,
      stateFileMode,
      effectiveMode: currentMode(),
      stateFileWins: stateFileMode != null && stateFileMode !== configMode,
    },
    statePath,
    idleSkipMs: cfg.idleSkipMs,
    idleSkips,
    lastRequestAt: lastRequestAt || null,
    discover: cfg.discoverEnabled
      ? { perRange: cfg.discoverPerRange, ranges: (cfg.discoverRanges || []).length }
      : false,
    coloAllow: cfg.coloAllow || [],
    stats,
    switches: switches.slice(-10),
    hosts: list,
    bootError,
  }
}


/** 取数字或 null（用于状态接口展示配置原值，不伪造） */
function resetAll() {
  const cleared = agents.size
  for (const host of hosts.keys()) dropAgents(host)
  ipStats.clear()
  agents.clear()
  // 候选池与运行时统计同属「运行态」，一并清空（Issue #11）
  candidatePools.clear()
  switchState.clear()
  currentIp.clear()
  routeGenerations.clear()
  probeGenerations.clear()
  switches.length = 0
  stats = { requests: 0, errors: 0, switches: 0, timeouts: 0, directFallback: 0, directRequests: 0, bytesIn: 0, bytesOut: 0 }
  recent.length = 0
  return cleared
}

// ---------------------------------------------------------------------------
// 应用
// ---------------------------------------------------------------------------

export function apply(ctx, config) {
  cfg = config || {}
  try {
    // 按「stateFile 有效则优先，否则配置，再否则 auto」定初始模式，
    // 并同时记下三个来源供状态接口与冲突告警使用（Issue #18）
    resolveInitialMode(cfg)
    resetAdminTokenCache()
    ensureAdminLimiter()
  } catch (e) {
    bootError = 'init: ' + errText(e)
  }

  try {
  createProxy()
  refreshAll().catch(() => {})

  if (probeTimer) clearInterval(probeTimer)
  probeTimer = setInterval(() => {
    // 长时间没有真实请求就不必再测：省掉一轮几十个探测请求
    const idle = Number(cfg.idleSkipMs) || 0
    if (idle > 0 && lastRequestAt > 0 && deps.now() - lastRequestAt > idle) {
      idleSkips += 1
      return
    }
    refreshAll().catch(() => {})
  }, Math.max(30000, cfg.probeIntervalMs))
  if (typeof probeTimer.unref === 'function') probeTimer.unref()

  if (healthTimer) clearInterval(healthTimer)
  healthTimer = setInterval(healthTick, Math.max(5000, cfg.healthCheckMs))
  if (typeof healthTimer.unref === 'function') healthTimer.unref()
  } catch (e) {
    bootError = (bootError ? bootError + ' | ' : '') + 'start: ' + errText(e)
  }

  ctx.tools.register(defineTool({
    name: 'cf_router_status',
    description: 'dsh-cf-router 状态：当前选中的 IPv4、各候选的探测中位数/真实 TTFB EWMA/成功失败数/冷却剩余、最近的自动切换事件、转发统计。',
    parameters: {
      host: { type: 'string', description: '只看某个域名（可省略）' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const snap = statusSnapshot()
      if (args && args.host) snap.hosts = snap.hosts.filter((h) => h.host === args.host)
      return snap
    },
  }))

  ctx.tools.register(defineTool({
    name: 'cf_router_probe',
    description: '立即重新测速（每个 IP 多次取样取中位数），并据结果更新当前最优 IP。可选只测一个域名。',
    parameters: {
      host: { type: 'string', description: '只探测这个域名（可省略则全部）' },
      samples: { type: 'integer', description: '每个 IP 取样次数，默认用配置值' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const targets = args && args.host ? [args.host] : (cfg.targets || [])
      await Promise.all(targets.map((h) => refreshHost(h, { samples: args && args.samples }).catch(() => null)))
      const snap = statusSnapshot()
      if (args && args.host) snap.hosts = snap.hosts.filter((h) => h.host === args.host)
      return snap
    },
  }))

  ctx.tools.register(defineTool({
    name: 'cf_router_reset',
    description: '清空失败计数、冷却状态与连接池，让下一次请求重新选路（换网络或怀疑连接池卡住时用）。',
        parameters: {},
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute() {
      const cleared = resetAll()
      return { ok: true, clearedAgents: cleared }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'cf_router_mode',
    description: "切换上游连接方式：auto=优选最快的 IPv4 并失败自动切换（默认）；direct=不做优选，按系统 DNS 直连（仍经过本地代理，用于排查优选本身出问题）。不传 mode 则只查询当前值。选择会写入 stateFile，重启后保留。",
    parameters: {
      mode: { type: 'string', description: 'auto 或 direct；省略则查询' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const value = String((args && args.mode) || '').trim()
      if (!value) return { ok: true, routingMode: currentMode(), statePath, allowed: ['auto', 'direct'] }
      return setRoutingMode(value)
    },
  }))

  log('dsh-cf-router ready')
}

export function dispose() {
  // 退出前必须真写一次：节流可能让最后一次变化还在内存里（Issue #22 阶段 3）
  try { flushState(true) } catch { /* 退出路径不因写盘失败中断 */ }
  if (probeTimer) {
    clearInterval(probeTimer)
    probeTimer = null
  }
  if (healthTimer) {
    clearInterval(healthTimer)
    healthTimer = null
  }
  // 进程退出：不等排空，直接销毁（#12 的排空只用于运行时切换）
  poolRegistry.destroyAll()
  agents.clear()
  directAgents.clear()
  closeProxy()
}

// ---------------------------------------------------------------------------
// 测试接口（生产代码不引用；仅供 node:test 驱动）
// ---------------------------------------------------------------------------

/**
 * 清空全部模块级状态，并复位注入依赖。
 * 存在的理由：本文件的状态是模块单例（hosts / ipStats / currentIp / agents ...），
 * 测试之间不隔离就会互相污染。生产环境永远不会调用它。
 */
export function __resetForTest() {
  if (probeTimer) { clearInterval(probeTimer); probeTimer = null }
  if (healthTimer) { clearInterval(healthTimer); healthTimer = null }

  for (const agent of agents.values()) { try { agent.destroy() } catch {} }
  agents.clear()
  for (const agent of directAgents.values()) { try { agent.destroy() } catch {} }
  directAgents.clear()

  hosts.clear()
  ipStats.clear()
  candidatePools.clear()
  currentIp.clear()
  routeGenerations.clear()
  probeGenerations.clear()
  switches.length = 0
  recent.length = 0

  stats = { requests: 0, errors: 0, switches: 0, timeouts: 0, directFallback: 0, directRequests: 0, bytesIn: 0, bytesOut: 0 }
  lastRequestAt = 0
  idleSkips = 0
  routingMode = 'auto'
  configMode = 'auto'
  stateFileMode = null
  adminLimiter = null
  adminLimiterSig = ''
  stateFileSchema = null
  lastRestoreSummary = null
  stateDirty = false
  lastStateFlushAt = 0
  resetAdminTokenCache()
  lastCfgMode = ''
  bootError = ''
  statePath = ''
  cfg = null

  try { closeProxy() } catch {}
  try {
    const srv = globalThis[SERVER_KEY]
    if (srv) { srv.closeAllConnections?.(); srv.close() }
  } catch {}
  globalThis[SERVER_KEY] = null
  proxyServer = null

  deps.resolve4 = (host, cb) => dns.resolve4(host, cb)
  deps.now = () => Date.now()
  deps.upstreamPort = 443
  deps.tlsOptions = {}
}

/** 内部句柄，供单元/集成测试直接驱动，避免为了测试去改生产调用路径 */
export const __testApi = {
  deps,
  reset: __resetForTest,
  /**
   * 不经过 Config 校验直接装配置（测试用）。
   * 与 apply() 走完全相同的初始化路径（resolveInitialMode），
   * 否则测试跑的是另一套逻辑，测不出真实行为。
   */
  configure: (config) => {
    cfg = { ...withDefaults(config) }
    try {
      resolveInitialMode(cfg)
      resetAdminTokenCache()
      ensureAdminLimiter()
    } catch (e) {
      bootError = 'init: ' + errText(e)
    }
    return cfg
  },
  state: () => ({ hosts, ipStats, currentIp, stats, switches, recent, agents, directAgents, routingMode }),
  getCfg: () => cfg,
  getStatePath: () => statePath,
  statOf, scoreOf, chooseBest, recordSwitch,
  noteSuccess, noteFailure,
  setRoutingMode, resetRoutingMode, currentMode, statusSnapshot, resetAll,
  switchRoute, getRouteGeneration, getProbeGeneration, beginProbe, commitProbeResult,
  recordRequestSuccess, recordRequestFailure, recordProbeSample,
  updateEwma, emptyMetrics, emptySamples,
  classifyError,
  HEALTH_STATES, HEALTH_TRANSITIONS,
  getHealthState, transitionHealth, advanceHealthState, runRecoveryProbe,
  migrateState, buildState, writeStateAtomic, STATE_SCHEMA_VERSION, isValidModeState,
  saveState, serializeHosts, parseHosts, restoreRuntimeState,
  markStateDirty, flushState,
  switchState, getSwitchState, decideSwitch,
  candidatePools, getCandidatePool, isCandidateSelectable,
  poolRegistry, createPoolRegistry, DEFAULT_DRAIN_TIMEOUT_MS,
  dropAgents, drainPoolFor, agentFor, directAgentFor,
  makePool, mergeCandidates, candidateIps, upsertCandidate,
  markProbed, markSuccess, markSelected, SOURCE_DNS, SOURCE_DISCOVERED,
  selectCandidates, shouldExplore, pickExploration, applyExploration,
  pruneCandidatePool, expireCandidatePool,
  resolveIps, discoverIps, sampleFromRanges, randInCidr, ipToInt, intToIp,
  tcpProbe, tcpProbeAll, probeOnce, measureIp, refreshHost, refreshAll,
  handleProxy, createProxy, closeProxy,
  listen: () => (globalThis[SERVER_KEY] || null),
}
