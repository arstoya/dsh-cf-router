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
  return out
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
let stats = { requests: 0, errors: 0, switches: 0, timeouts: 0, directFallback: 0, bytesIn: 0, bytesOut: 0 }

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

function loadState() {
  statePath = resolveStatePath()
  try {
    if (!fs.existsSync(statePath)) return
    const raw = JSON.parse(fs.readFileSync(statePath, 'utf8'))
    if (raw && isValidMode(raw.routingMode)) {
      routingMode = raw.routingMode
      log(`loaded routingMode=${routingMode} from ${statePath}`)
    }
  } catch (err) {
    log(`loadState failed: ${String(err?.message || err)}`)
  }
}

function saveState() {
  try {
    fs.mkdirSync(path.dirname(statePath), { recursive: true })
    fs.writeFileSync(statePath, JSON.stringify({ routingMode, updatedAt: new Date().toISOString() }, null, 2), 'utf8')
    return true
  } catch (err) {
    log(`saveState failed: ${String(err?.message || err)}`)
    return false
  }
}

function setRoutingMode(value) {
  if (!isValidMode(value)) return { ok: false, error: 'invalid_mode', allowed: ['auto', 'direct'] }
  const previous = routingMode
  routingMode = value
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

  const generation = getRouteGeneration(host) + 1
  routeGenerations.set(host, generation)
  recordSwitch(host, prev, next, reason)
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
  const s = statOf(host, ip)
  s.ok += 1
  s.consecutiveFail = 0

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

  // 真实请求 TTFB：新连接与复用连接分开统计
  const ttfbMs = metrics.ttfbMs
  if (Number.isFinite(ttfbMs) && ttfbMs > 0) {
    s.lastTtfbMs = ttfbMs
    s.lastReused = Boolean(metrics.reused)
    if (ttfbAcceptable(ttfbMs)) {
      if (metrics.reused) {
        s.metrics.reusedTtfbEwmaMs = updateEwma(s.metrics.reusedTtfbEwmaMs, ttfbMs, a)
        bumpSample(s, 'reusedTtfb')
      } else {
        s.metrics.freshTtfbEwmaMs = updateEwma(s.metrics.freshTtfbEwmaMs, ttfbMs, a)
        bumpSample(s, 'freshTtfb')
      }
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
  // 探测 TTFB 同样可能被 prefill 污染（探测路径若也命中模型接口），沿用同一阈值
  if (ttfbAcceptable(sample.ttfbMs)) {
    s.metrics.probeTtfbEwmaMs = updateEwma(s.metrics.probeTtfbEwmaMs, sample.ttfbMs, a)
    bumpSample(s, 'probeTtfb')
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

  stats.errors += 1
  if (kind === 'timeout') stats.timeouts += 1

  const s = statOf(host, ip)
  s.fail += 1
  s.consecutiveFail += 1
  s.lastFailAt = deps.now()
  log(`fail ${host} ${ip} (${s.consecutiveFail}/${cfg.failThreshold}) ${message}`)

  if (s.consecutiveFail < cfg.failThreshold) return

  // 判死：进冷却。这一步与版本无关 —— 这个 IP 确实失败够了，统计必须反映事实
  s.consecutiveFail = 0
  s.penaltyUntil = deps.now() + Math.max(1000, cfg.cooldownMs)
  try {
    agents.get(`${host}|${ip}`)?.destroy()
  } catch {}
  agents.delete(`${host}|${ip}`)

  // 只有「它仍是当前线路」才轮到我们切换。否则说明期间已经有别的决策接管了，
  // 旧请求不许越权把非当前线路重新设回当前（场景 B）。
  const isCurrent = currentIp.get(host) === ip
  if (!isCurrent) {
    log(`fail ${host} ${ip}: 已不是当前线路，只记统计不切换 (req gen=${generation} 当前 gen=${getRouteGeneration(host)})`)
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
function emptyMetrics() {
  return {
    tcpEwmaMs: null,
    tlsEwmaMs: null,
    probeTtfbEwmaMs: null,
    probeTotalEwmaMs: null,
    freshTtfbEwmaMs: null,
    reusedTtfbEwmaMs: null,
  }
}

function emptySamples() {
  return { tcp: 0, tls: 0, probeTtfb: 0, probeTotal: 0, freshTtfb: 0, reusedTtfb: 0 }
}

function statOf(host, ip) {
  const key = `${host}|${ip}`
  let s = ipStats.get(key)
  if (!s) {
    s = {
      ok: 0,
      fail: 0,
      consecutiveFail: 0,
      penaltyUntil: 0,
      lastFailAt: 0,
      metrics: emptyMetrics(),
      samples: emptySamples(),
      /** 最近一次真实请求的原始 TTFB（不参与 EWMA 也可能有价值） */
      lastTtfbMs: null,
      /** 最近一次真实请求是否复用了连接 */
      lastReused: null,
    }
    ipStats.set(key, s)
  }
  return s
}

/**
 * 通用 EWMA。脏样本（非有限、≤0、非数字）一律不改变原值。
 * alpha 夹在 [0.05, 0.9]：太小学不动，太大会被单次尖刺带偏。
 */
function updateEwma(previous, sample, alpha) {
  // 只接受真正的数字。刻意不做隐式转换：把 '100' 悄悄当 100 用，
  // 会掩盖上游传错类型的 bug，而指标一旦被脏数据污染就查不出来了。
  if (typeof sample !== 'number' || !Number.isFinite(sample) || sample <= 0) return previous
  const a = Math.min(0.9, Math.max(0.05, Number(alpha)))
  if (previous == null) return sample
  return previous * (1 - a) + sample * a
}

/** 采样计数 +1（只有真正采纳的样本才计） */
function bumpSample(s, key) {
  if (key in s.samples) s.samples[key] += 1
}

/** TTFB 类样本是否超出 prefill 污染阈值 */
function ttfbAcceptable(ms) {
  const maxSample = Math.max(200, Number(cfg.ewmaMaxMs) || 3000)
  return Number.isFinite(ms) && ms > 0 && ms <= maxSample
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
  if (s.penaltyUntil > now) return Infinity

  const entry = hosts.get(host)
  const r = entry?.results?.find((x) => x.ip === ip)
  if (!r) return Infinity

  const ttfb = Number.isFinite(r.ttfbMedian)
    ? r.ttfbMedian
    : (r.okCount > 0 && Number.isFinite(r.ttfbBest) ? r.ttfbBest : null)
  if (ttfb != null) return ttfb

  // 没有探测样本时，退到该 IP 的探测 TTFB EWMA（仍是同一量纲）
  if (s.metrics.probeTtfbEwmaMs != null) return s.metrics.probeTtfbEwmaMs

  return Infinity
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

function resolveIps(host) {
  return new Promise((resolve) => {
    deps.resolve4(host, (err, addrs) => {
      if (err || !addrs || !addrs.length) resolve([])
      else resolve([...new Set(addrs)])
    })
  })
}

function ipToInt(ip) {
  const p = String(ip).split('.').map(Number)
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return NaN
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]
}

function intToIp(n) {
  const v = n >>> 0
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`
}

/** 在 CIDR 里随机取一个 IPv4；非法输入返回 null */
function randInCidr(cidr) {
  const [base, bitsRaw] = String(cidr).split('/')
  const bits = Number(bitsRaw)
  if (!base || !Number.isFinite(bits) || bits < 8 || bits > 32) return null
  const start = ipToInt(base)
  if (!Number.isFinite(start)) return null
  const size = 2 ** (32 - bits)
  return intToIp(start + Math.floor(Math.random() * size))
}

function sampleFromRanges(ranges, perRange) {
  const n = Math.max(0, Math.min(10, Number(perRange) || 0))
  if (!n) return []
  const out = []
  for (const r of ranges || []) {
    for (let i = 0; i < n; i += 1) {
      const ip = randInCidr(r)
      if (ip) out.push(ip)
    }
  }
  return out
}

/**
 * 候选池：DNS 返回的 IP 一定保留（保底），再从 CF 公开网段抽样补充。
 * 只靠 DNS 的话永远只有 3 个候选，挑不出真正更快的。
 */
async function discoverIps(host) {
  const dnsIps = await resolveIps(host)
  if (!cfg.discoverEnabled) return dnsIps
  const sampled = sampleFromRanges(cfg.discoverRanges, cfg.discoverPerRange)
  return [...new Set([...dnsIps, ...sampled])]
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

function pinLookup(ip) {
  return (_hostname, options, cb) => {
    if (options && options.all) cb(null, [{ address: ip, family: 4 }])
    else cb(null, ip, 4)
  }
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

  const dnsIps = await resolveIps(host)
  const ips = cfg.discoverEnabled
    ? [...new Set([...dnsIps, ...sampleFromRanges(cfg.discoverRanges, cfg.discoverPerRange)])]
    : dnsIps
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
    // DNS 返回的 IP 是保底，即使 TCP 超时也进二级（可能是握手慢而非不通）
    alive = [...new Set([...ok.slice(0, topN), ...dnsIps])]
    if (!alive.length) alive = ips.slice(0, Math.min(3, ips.length))
  }

  const results = await Promise.all(alive.map((ip) => measureIp(host, ip, samples, timeoutMs, path)))

  // 探测样本入指标（Issue #3）：四个计时分别入库，互不串味
  for (const r of results) {
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
    const prevScore = scoreOf(host, prev, deps.now())
    // 只有旧 IP 被判死，或新 IP 比它快 30% 以上才切，避免抖动
    if (!Number.isFinite(prevScore) || (Number.isFinite(prevScore) && best.score > 0 && prevScore > best.score * 1.3)) {
      switchRoute(host, best.ip, `probe ${Math.round(prevScore)}→${Math.round(best.score)}ms`)
    }
  }
  log(`refresh ${host} → ${currentIp.get(host) || 'none'} (best ${best ? Math.round(best.score) + 'ms' : '-'})`)
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
  let agent = agents.get(key)
  if (!agent) {
    agent = new https.Agent({
      keepAlive: cfg.keepAlive,
      maxSockets: cfg.maxSockets,
      keepAliveMsecs: 30000,
      timeout: 30000,
      lookup: pinLookup(ip),
      ...deps.tlsOptions,
    })
    agents.set(key, agent)
  }
  return agent
}

function directAgentFor(host) {
  let agent = directAgents.get(host)
  if (!agent) {
    agent = new https.Agent({
      keepAlive: cfg.keepAlive,
      maxSockets: cfg.maxSockets,
      keepAliveMsecs: 30000,
      timeout: 30000,
      ...deps.tlsOptions,
    })
    directAgents.set(host, agent)
  }
  return agent
}

function dropAgents(host) {
  for (const [key, agent] of agents) {
    if (!key.startsWith(`${host}|`)) continue
    try {
      agent.destroy()
    } catch {}
    agents.delete(key)
  }
  const d = directAgents.get(host)
  if (d) {
    try {
      d.destroy()
    } catch {}
    directAgents.delete(host)
  }
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

function targetOf(req) {
  const explicit = req.headers['x-cf-target']
  if (typeof explicit === 'string' && explicit.trim()) return explicit.trim()
  const hostHeader = req.headers.host || ''
  const hostOnly = hostHeader.split(':')[0]
  // 本地代理的 Host 是 127.0.0.1:8787，不能用；退回配置的默认目标
  if (!hostOnly || hostOnly === '127.0.0.1' || hostOnly === 'localhost' || hostOnly === cfg.listenHost) {
    return (cfg.targets || [])[0] || null
  }
  return hostOnly
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj, null, 2)
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'access-control-allow-origin': '*',
  })
  res.end(body)
}

function handleProxy(req, res) {
  const host = targetOf(req)

  // 本地控制端点
  if (req.url === '/__router/status') {
    sendJson(res, 200, statusSnapshot())
    return
  }
  if (req.url === '/__router/probe') {
    refreshAll().then(() => sendJson(res, 200, statusSnapshot())).catch((err) => {
      sendJson(res, 500, { error: 'probe_failed', message: String(err?.message || err) })
    })
    return
  }
  if (req.url === '/__router/reset') {
    resetAll()
    sendJson(res, 200, { ok: true })
    return
  }
  if (req.url && req.url.startsWith('/__router/mode')) {
    const q = new URL(req.url, 'http://127.0.0.1')
    const value = String(q.searchParams.get('value') || q.searchParams.get('mode') || '').trim()
    if (!value) {
      sendJson(res, 200, { ok: true, routingMode: currentMode(), statePath, allowed: ['auto', 'direct'] })
      return
    }
    sendJson(res, 200, setRoutingMode(value))
    return
  }

  // 没有目标：要么 targets 没配，要么 Host 头是本地地址。给明确的自解释错误，
  // 而不是把 undefined 丢给 https.request 变成 ECONNREFUSED 之类的怪错。
  if (!host) {
    sendJson(res, 400, {
      error: 'no_target',
      hint: '配置里 targets 为空，且请求没有带 x-cf-target 头。二选一：在插件配置里填 targets，或给每个请求加 x-cf-target: <域名>。',
      listen: `http://${cfg.listenHost}:${cfg.listenPort}`,
      targets: cfg.targets || [],
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

  const headers = { ...req.headers }
  delete headers['x-cf-target']
  headers.host = host

  stats.requests += 1
  lastRequestAt = deps.now()
  /**
   * 用 hrtime 计时，不用 deps.now()：后者是 Date.now()，会被系统时间调整影响，
   * 而且精度只有毫秒。假时钟注入只用于冷却/驻留这种长尺度判断，不用于耗时测量。
   */
  const t0 = process.hrtime.bigint()
  const elapsed = () => Number(process.hrtime.bigint() - t0) / 1e6
  const useDirect = currentMode() === 'direct' || (!ip && cfg.allowDirectFallback)

  if (!ip && !useDirect) {
    sendJson(res, 503, {
      error: 'no_upstream',
      host,
      hint: '所有候选都在冷却且未开启直连兜底，稍后自动恢复',
      detail: hosts.get(host)?.error || null,
    })
    return
  }
  if (useDirect) stats.directFallback += 1

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

  let firstByteSeen = false
  let settled = false

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
    res.writeHead(upRes.statusCode || 502, upRes.headers)
    if (typeof res.flushHeaders === 'function') res.flushHeaders()
    upRes.on('data', (chunk) => {
      stats.bytesIn += chunk.length
    })
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

  up.setTimeout(cfg.upstreamTimeoutMs, () => {
    up.destroy(new Error('upstream_timeout'))
  })

  up.on('response', () => {
    settled = true
  })

  up.on('error', (err) => {
    settled = true
    clearTimeout(firstByteTimer)
    const msg = String(err?.message || err)
    const code = err?.code || ''
    // 客户端主动断开不算上游失败
    if (code === 'ECONNRESET' && res.destroyed) {
      log(`client aborted ${req.url}`)
      return
    }
    if (ip) {
      const kind = msg.includes('timeout') ? 'timeout' : 'error'
      recordRequestFailure(host, ip, { message: msg, kind }, requestRoute.generation)
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
  req.pipe(up)

  res.on('close', () => {
    clearTimeout(firstByteTimer)
    log(`${req.method} ${req.url} via ${ip || 'direct'} ${Math.round(elapsed())}ms`)
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
  for (const host of hosts.keys()) {
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
    // 当前没有 IP：看看冷却是不是过期了 / 有没有新候选
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
          },

          // 最近一次真实请求的原始观察值
          lastTtfbMs: nn(s.lastTtfbMs),
          lastReused: s.lastReused == null ? null : Boolean(s.lastReused),

          ok: s.ok,
          fail: s.fail,
          consecutiveFail: s.consecutiveFail,
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

function round(n) {
  return Number.isFinite(n) ? Math.round(n) : null
}

function resetAll() {
  const cleared = agents.size
  for (const host of hosts.keys()) dropAgents(host)
  ipStats.clear()
  agents.clear()
  currentIp.clear()
  routeGenerations.clear()
  probeGenerations.clear()
  switches.length = 0
  stats = { requests: 0, errors: 0, switches: 0, timeouts: 0, directFallback: 0, bytesIn: 0, bytesOut: 0 }
  recent.length = 0
  return cleared
}

// ---------------------------------------------------------------------------
// 应用
// ---------------------------------------------------------------------------

export function apply(ctx, config) {
  cfg = config || {}
  try {
    loadState()
  {
    // 把设置页当前值记为基准，避免 loadState 读到的 override 被 currentMode() 立刻当成设置页改过而覆盖
    const raw = cfg.routingMode
      lastCfgMode = String((raw && typeof raw.get === 'function' ? raw.get() : raw) || 'auto')
    }
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
  if (probeTimer) {
    clearInterval(probeTimer)
    probeTimer = null
  }
  if (healthTimer) {
    clearInterval(healthTimer)
    healthTimer = null
  }
  for (const host of hosts.keys()) dropAgents(host)
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
  currentIp.clear()
  routeGenerations.clear()
  probeGenerations.clear()
  switches.length = 0
  recent.length = 0

  stats = { requests: 0, errors: 0, switches: 0, timeouts: 0, directFallback: 0, bytesIn: 0, bytesOut: 0 }
  lastRequestAt = 0
  idleSkips = 0
  routingMode = 'auto'
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
   * 顺序刻意与 apply() 一致：装配置 → loadState() → 记录 lastCfgMode 基准，
   * 否则测试跑的是另一套初始化路径，测不出真实行为。
   */
  configure: (config) => {
    cfg = { ...withDefaults(config) }
    try {
      loadState()
      const raw = cfg.routingMode
      lastCfgMode = String((raw && typeof raw.get === 'function' ? raw.get() : raw) || 'auto')
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
  setRoutingMode, currentMode, statusSnapshot, resetAll,
  switchRoute, getRouteGeneration, getProbeGeneration, beginProbe, commitProbeResult,
  recordRequestSuccess, recordRequestFailure, recordProbeSample,
  updateEwma, emptyMetrics, emptySamples,
  resolveIps, discoverIps, sampleFromRanges, randInCidr, ipToInt, intToIp,
  tcpProbe, tcpProbeAll, probeOnce, measureIp, refreshHost, refreshAll,
  handleProxy, createProxy, closeProxy,
  listen: () => (globalThis[SERVER_KEY] || null),
}
