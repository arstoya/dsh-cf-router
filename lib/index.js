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
// 状态
// ---------------------------------------------------------------------------

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
    // 直连模式不再 pin IP，清掉现有连接池让下一次请求按系统 DNS 重新解析
    for (const host of hosts.keys()) dropAgents(host)
    currentIp.clear()
  } else {
    for (const host of hosts.keys()) {
      const next = chooseBest(host)
      if (next) currentIp.set(host, next.ip)
    }
  }
  const persisted = saveState()
  return { ok: true, previous, routingMode, persisted, statePath }
}


const SERVER_KEY = Symbol.for('dsh-cf-router.server')

function log(line) {
  if (!cfg?.verbose) return
  recent.push({ at: Date.now(), line: String(line).slice(0, 300) })
  if (recent.length > 200) recent.shift()
}

function recordSwitch(host, from, to, reason) {
  stats.switches += 1
  switches.push({ at: Date.now(), host, from: from || null, to: to || null, reason })
  if (switches.length > 20) switches.shift()
  log(`switch ${host} ${from || '-'} → ${to || '-'} (${reason})`)
}

// ---------------------------------------------------------------------------
// 每 IP 的运行指标
// ---------------------------------------------------------------------------

function statOf(host, ip) {
  const key = `${host}|${ip}`
  let s = ipStats.get(key)
  if (!s) {
    s = { ok: 0, fail: 0, consecutiveFail: 0, ewmaMs: null, penaltyUntil: 0, lastFailAt: 0 }
    ipStats.set(key, s)
  }
  return s
}

/** 分数越小越好；Infinity 表示不可用 */
function scoreOf(host, ip, now) {
  const s = statOf(host, ip)
  if (s.penaltyUntil > now) return Infinity
  const entry = hosts.get(host)
  const r = entry?.results?.find((x) => x.ip === ip)
  const probeRef = r && Number.isFinite(r.median) ? r.median : (r && r.okCount > 0 ? r.best : null)
  // EWMA 采样的是 TLS 握手耗时（不受上游 prefill 影响），探测是完整 HTTP 往返，
  // 两者量纲不同；EWMA 样本又少、容易被单次峰值主导（实测同一 IP：probe 618ms / ewma 1465ms）。
  // 直接比会把最快的 IP 判成最慢，所以取较小值：任一指标显示快就不判它慢，两个都慢才是真慢。
  // 超出 probeRef*4 的样本仍视为被 prefill 污染，直接丢弃。
  if (s.ewmaMs != null && (probeRef == null || s.ewmaMs <= probeRef * 4)) {
    return probeRef == null ? s.ewmaMs : Math.min(s.ewmaMs, probeRef)
  }
  if (probeRef != null) return probeRef
  return Infinity
}

/** 在候选里挑当前最优；返回 { ip, score } 或 null */
function chooseBest(host, excludeIp) {
  const entry = hosts.get(host)
  if (!entry || !entry.results?.length) return null
  const now = Date.now()
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
    dns.resolve4(host, (err, addrs) => {
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
    const sock = net.connect({ host: ip, port: 443 })
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

function probeOnce(host, ip, timeoutMs, path) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint()
    let settled = false
    let colo = ''
    const finish = (ok, detail) => {
      if (settled) return
      settled = true
      const ms = Number(process.hrtime.bigint() - t0) / 1e6
      resolve({ ok, ms, detail, colo })
    }
    let req
    try {
      req = https.request({
        host,
        port: 443,
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
      })
    } catch (err) {
      finish(false, String(err?.message || err))
      return
    }
    req.on('response', (res) => {
      // cf-ray 形如 "8c8f...-HKG"，后半段是这个 IP 实际落到的边缘节点
      colo = String(res.headers['cf-ray'] || '').split('-')[1] || ''
      res.resume()
      res.on('end', () => finish(true, `http ${res.statusCode}`))
      res.on('error', (err) => finish(false, String(err?.message || err)))
    })
    req.on('error', (err) => finish(false, String(err?.message || err)))
    req.on('timeout', () => {
      req.destroy()
      finish(false, 'timeout')
    })
    req.end()
  })
}

async function measureIp(host, ip, samples, timeoutMs, path) {
  const runs = []
  for (let i = 0; i < samples; i += 1) {
    runs.push(await probeOnce(host, ip, timeoutMs, path))
  }
  const okRuns = runs.filter((r) => r.ok)
  const times = okRuns.map((r) => r.ms).sort((a, b) => a - b)
  const median = times.length ? times[Math.floor(times.length / 2)] : Infinity
  const best = times.length ? times[0] : Infinity
  const colo = okRuns.map((r) => r.colo).find(Boolean) || ''
  const coloOk = !cfg.coloAllow || !cfg.coloAllow.length || (colo && cfg.coloAllow.includes(colo))
  return {
    ip,
    okCount: times.length,
    samples,
    median,
    best,
    colo,
    excluded: coloOk ? null : `colo ${colo || 'unknown'}`,
  }
}

async function refreshHost(host, opts = {}) {
  const path = opts.path || cfg.probePath
  const samples = Math.max(1, Math.min(5, opts.samples || cfg.probeSamples))
  const timeoutMs = opts.timeoutMs || cfg.probeTimeoutMs

  const dnsIps = await resolveIps(host)
  const ips = cfg.discoverEnabled
    ? [...new Set([...dnsIps, ...sampleFromRanges(cfg.discoverRanges, cfg.discoverPerRange)])]
    : dnsIps
  if (!ips.length) {
    hosts.set(host, { ips: [], results: [], lastProbeAt: Date.now(), error: 'DNS 无 A 记录' })
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
  const usable = results.filter((r) => !r.excluded)
  const entry = {
    ips,
    results: results.sort((a, b) => {
      if (a.excluded && !b.excluded) return 1
      if (!a.excluded && b.excluded) return -1
      return a.median - b.median
    }),
    lastProbeAt: Date.now(),
    error: usable.some((r) => r.okCount > 0) ? null : '所有 IP 探测失败',
  }
  hosts.set(host, entry)

  // 探测刷新后重新判定当前 IP：如果它已经不在最优位（且差距明显）就切
  const prev = currentIp.get(host) || null
  const best = chooseBest(host)
  if (!prev) {
    if (best) {
      currentIp.set(host, best.ip)
      recordSwitch(host, null, best.ip, 'initial')
    }
  } else if (!best) {
    log(`refresh ${host}: 无可用候选，保留 ${prev}`)
  } else {
    const prevScore = scoreOf(host, prev, Date.now())
    // 只有旧 IP 被判死，或新 IP 比它快 30% 以上才切，避免抖动
    if (!Number.isFinite(prevScore) || (Number.isFinite(prevScore) && best.score > 0 && prevScore > best.score * 1.3)) {
      currentIp.set(host, best.ip)
      recordSwitch(host, prev, best.ip, `probe ${Math.round(prevScore)}→${Math.round(best.score)}ms`)
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

/** 记一次成功：更新 EWMA，清零连败 */
function noteSuccess(host, ip, ttfbMs) {
  const s = statOf(host, ip)
  s.ok += 1
  s.consecutiveFail = 0
  if (currentIp.get(host) !== ip) currentIp.set(host, ip)
  // TTFB 里混着上游 prefill：大 prompt 常常 10s 以上才回响应头，那不是网络质量。
  // 超阈值的样本直接丢弃，否则"刚好处理过一次大请求的 IP"会被误判成差线路。
  const maxSample = Math.max(200, Number(cfg.ewmaMaxMs) || 3000)
  if (!Number.isFinite(ttfbMs) || ttfbMs <= 0 || ttfbMs > maxSample) return
  const a = Math.min(0.9, Math.max(0.05, cfg.ewmaAlpha))
  s.ewmaMs = s.ewmaMs == null ? ttfbMs : s.ewmaMs * (1 - a) + ttfbMs * a
}

/** 记一次失败：连败达阈值就判死、冷却、立刻切走 */
function noteFailure(host, ip, message, kind) {
  stats.errors += 1
  if (kind === 'timeout') stats.timeouts += 1
  const s = statOf(host, ip)
  s.fail += 1
  s.consecutiveFail += 1
  s.lastFailAt = Date.now()
  log(`fail ${host} ${ip} (${s.consecutiveFail}/${cfg.failThreshold}) ${message}`)

  if (s.consecutiveFail < cfg.failThreshold) return

  // 判死：进冷却
  s.consecutiveFail = 0
  s.penaltyUntil = Date.now() + Math.max(1000, cfg.cooldownMs)
  try {
    agents.get(`${host}|${ip}`)?.destroy()
  } catch {}
  agents.delete(`${host}|${ip}`)

  // 立刻切到次优，不等下一轮探测
  const next = chooseBest(host)
  if (next) {
    currentIp.set(host, next.ip)
    recordSwitch(host, ip, next.ip, `fail×${cfg.failThreshold} ${message}`)
  } else {
    recordSwitch(host, ip, null, `fail×${cfg.failThreshold} 无可用候选`)
    // 没有候选了，触发一次重探测（可能 DNS 也变了）
    setTimeout(() => {
      refreshHost(host).catch(() => {})
    }, 200)
  }
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
    if (s.penaltyUntil > Date.now()) {
      const next = chooseBest(host, ip)
      if (next) {
        currentIp.set(host, next.ip)
        recordSwitch(host, ip, next.ip, 'request:penalized')
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
      currentIp.set(host, next.ip)
      recordSwitch(host, null, next.ip, 'request:first')
      ip = next.ip
    }
  }

  const headers = { ...req.headers }
  delete headers['x-cf-target']
  headers.host = host

  stats.requests += 1
  lastRequestAt = Date.now()
  const t0 = Date.now()
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
    port: 443,
    path: req.url,
    method: req.method,
    headers,
    servername: host,
  }
  if (ip) opts.agent = agentFor(host, ip)
  else opts.agent = directAgentFor(host)

  let firstByteSeen = false
  let settled = false
  /**
   * TLS 握手完成时间。只有新建连接才采得到，复用连接时为 null。
   * 它不受上游 prefill 影响，是比 TTFB 更干净的网络质量指标 ——
   * 大 prompt 的 TTFB 常常 10s+，全部会被 ewmaMaxMs 丢掉，导致 EWMA 永远没有样本。
   */
  let tlsMs = null
  const firstByteTimer = setTimeout(() => {
    if (settled || firstByteSeen) return
    try {
      up.destroy(new Error('first_byte_timeout'))
    } catch {}
  }, Math.max(5000, cfg.firstByteTimeoutMs))

  const up = https.request(opts, (upRes) => {
    firstByteSeen = true
    clearTimeout(firstByteTimer)
    const ttfb = Date.now() - t0
    if (ip) noteSuccess(host, ip, tlsMs != null ? tlsMs : ttfb)
    res.writeHead(upRes.statusCode || 502, upRes.headers)
    if (typeof res.flushHeaders === 'function') res.flushHeaders()
    upRes.on('data', (chunk) => {
      stats.bytesIn += chunk.length
    })
    upRes.pipe(res)
  })

  up.on('socket', (sock) => {
    if (!sock || !sock.connecting) return
    sock.once('secureConnect', () => { tlsMs = Date.now() - t0 })
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
      noteFailure(host, ip, msg, kind)
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
    log(`${req.method} ${req.url} via ${ip || 'direct'} ${Date.now() - t0}ms`)
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
  const now = Date.now()
  for (const host of hosts.keys()) {
    const cur = currentIp.get(host) || null
    if (cur) {
      const s = statOf(host, cur)
      if (s.penaltyUntil > now) {
        const next = chooseBest(host, cur)
        if (next) {
          currentIp.set(host, next.ip)
          recordSwitch(host, cur, next.ip, 'health:penalized')
        } else {
          currentIp.delete(host)
          recordSwitch(host, cur, null, 'health:all-penalized')
        }
      }
      continue
    }
    // 当前没有 IP：看看冷却是不是过期了 / 有没有新候选
    const next = chooseBest(host)
    if (next) {
      currentIp.set(host, next.ip)
      recordSwitch(host, null, next.ip, 'health:recover')
    } else if (!hosts.get(host) || Date.now() - (hosts.get(host).lastProbeAt || 0) > cfg.probeIntervalMs) {
      refreshHost(host).catch(() => {})
    }
  }
}

// ---------------------------------------------------------------------------
// 状态快照
// ---------------------------------------------------------------------------

function statusSnapshot() {
  const now = Date.now()
  const list = []
  for (const [host, entry] of hosts) {
    const cur = currentIp.get(host) || null
    list.push({
      host,
      current: cur,
      candidates: (entry.results || []).map((r) => {
        const s = statOf(host, r.ip)
        const penaltyLeft = Math.max(0, s.penaltyUntil - now)
        return {
          ip: r.ip,
          colo: r.colo || null,
          excluded: r.excluded || null,
          probeMs: Number.isFinite(r.median) ? round(r.median) : null,
          probeBestMs: Number.isFinite(r.best) ? round(r.best) : null,
          probeOk: `${r.okCount}/${r.samples}`,
          ewmaMs: s.ewmaMs == null ? null : round(s.ewmaMs),
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
    if (idle > 0 && lastRequestAt > 0 && Date.now() - lastRequestAt > idle) {
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
