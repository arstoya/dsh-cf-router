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
function applyTargetGuard(cfgObj) {
  const { allowed, rejected } = normalizeAllowlist(cfgObj.targets)
  cfgObj._allowedHosts = allowed
  cfgObj._allowedRejected = rejected
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
function loadState() {
  statePath = resolveStatePath()
  try {
    if (!fs.existsSync(statePath)) return { found: false, mode: null }
    const raw = JSON.parse(fs.readFileSync(statePath, 'utf8'))
    if (raw && isValidMode(raw.routingMode)) {
      log(`loaded routingMode=${raw.routingMode} from ${statePath}`)
      return { found: true, mode: raw.routingMode }
    }
    log(`loadState: ${statePath} 存在但没有有效 routingMode`)
    return { found: false, mode: null }
  } catch (err) {
    log(`loadState failed: ${String(err?.message || err)}`)
    return { found: false, mode: null }
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

  routingMode = persisted.found ? persisted.mode : configMode
  // 基准与「运行时当前值」保持一致，避免 currentMode() 首次调用把 stateFile 值盖掉
  lastCfgMode = configMode
  return { configMode, stateFileMode, effectiveMode: routingMode }
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
        const next = { ...raw }
        delete next.routingMode
        next.routingModeResetAt = new Date().toISOString()
        kept = Object.keys(next)
        // 原子写：先写临时文件再 rename，避免半截文件
        const tmp = `${resolved}.tmp`
        fs.writeFileSync(tmp, JSON.stringify(next, null, 2), 'utf8')
        fs.renameSync(tmp, resolved)
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
  // TODO(#12)：这里直接 destroy Agent 会影响同 Agent 上的活动请求。
  // #12 会改为 Draining + 安全回收，本次不动（方案 §12 职责边界）。
  s.penaltyUntil = deps.now() + Math.max(1000, cfg.cooldownMs)
  try {
    agents.get(`${host}|${ip}`)?.destroy()
  } catch {}
  agents.delete(`${host}|${ip}`)

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
      // 客户端在响应写完前断开 —— 立刻取消上游
      ctx.clientAborted = true
      // 先 unpipe 再 destroy：避免 destroy 触发的 error 又走一遍响应路径
      try { up.unpipe(res) } catch { /* ignore */ }
      try { req.unpipe(up) } catch { /* ignore */ }
      try {
        if (!ctx.upstreamEnded) up.destroy(new Error('client_aborted'))
      } catch { /* ignore */ }
    }

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
    /** 白名单：生效的与装载期被剔除的条目（Issue #6） */
    allowedTargets: Array.from(cfg._allowedHosts || []),
    rejectedTargets: cfg._allowedRejected || [],
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

function round(n) {
  return Number.isFinite(n) ? Math.round(n) : null
}

/** 取数字或 null（用于状态接口展示配置原值，不伪造） */
function numOrNull(v) {
  const n = Number(v)
  return Number.isFinite(n) ? n : null
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

  stats = { requests: 0, errors: 0, switches: 0, timeouts: 0, directFallback: 0, directRequests: 0, bytesIn: 0, bytesOut: 0 }
  lastRequestAt = 0
  idleSkips = 0
  routingMode = 'auto'
  configMode = 'auto'
  stateFileMode = null
  adminLimiter = null
  adminLimiterSig = ''
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
  resolveIps, discoverIps, sampleFromRanges, randInCidr, ipToInt, intToIp,
  tcpProbe, tcpProbeAll, probeOnce, measureIp, refreshHost, refreshAll,
  handleProxy, createProxy, closeProxy,
  listen: () => (globalThis[SERVER_KEY] || null),
}
