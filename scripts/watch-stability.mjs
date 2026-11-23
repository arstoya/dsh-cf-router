#!/usr/bin/env node
/**
 * watch-stability.mjs — 长稳监测（Issue #15 15-B）
 *
 * 周期性采样运行中的 cf-router，落 JSONL，并给出泄漏判据。
 *
 * 为什么要这个脚本：24 小时稳定性测试的价值不在"跑满 24 小时"，
 * 而在"能看出哪个指标在单调增长"。没有基线就没法判断 —— 一个
 * 500 MB 的 RSS 可能是泄漏也可能是正常缓存。
 *
 * 用法：
 *   node scripts/watch-stability.mjs                    # 默认 5 分钟一次，直到 Ctrl-C
 *   node scripts/watch-stability.mjs --interval 60      # 1 分钟一次
 *   node scripts/watch-stability.mjs --duration 3600    # 跑 1 小时
 *   node scripts/watch-stability.mjs --analyze <file>   # 只分析已有的 JSONL
 *
 * 判据（分析阶段）：
 *   · 单调增长且斜率 > 阈值 → 疑似泄漏，标 LEAK
 *   · 稳定波动 → OK
 *   · 样本不足 → INSUFFICIENT
 */

import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { execFileSync } from 'node:child_process'

const argv = process.argv.slice(2)
const arg = (name, fallback) => {
  const i = argv.indexOf(name)
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback
}

const INTERVAL_MS = Number(arg('--interval', '300')) * 1000
const DURATION_MS = Number(arg('--duration', '0')) * 1000    // 0 = 不限
const TARGET = arg('--url', 'http://127.0.0.1:8787/__router/status')
const ANALYZE = arg('--analyze', null)
const OUT_DIR = path.resolve(arg('--out', 'logs/stability'))
const PID = Number(arg('--pid', '0')) || 0

/**
 * 从本地端口反查监听进程 PID（仅 Windows）。
 *
 * 必须拿到宿主进程：process.memoryUsage() 读的是本脚本自己，
 * 和插件进程毫无关系。拿它当插件内存会得出完全错误的结论。
 */
function pidFromPort(port) {
  try {
    const out = execFileSync('netstat', ['-ano'], { encoding: 'utf8', windowsHide: true })
    for (const line of out.split(/\r?\n/)) {
      if (!line.includes(':' + port) || !line.includes('LISTENING')) continue
      const parts = line.trim().split(/\s+/)
      const pid = Number(parts.at(-1))
      if (Number.isFinite(pid) && pid > 0) return pid
    }
  } catch { /* 非 Windows 或 netstat 不可用 */ }
  return 0
}

/** 读某个进程的常驻内存（MB）。拿不到返回 null，不要编造。 */
function rssOfPid(pid) {
  if (!pid) return null
  try {
    const out = execFileSync('tasklist', ['/FI', 'PID eq ' + pid, '/FO', 'CSV', '/NH'],
      { encoding: 'utf8', windowsHide: true })
    const m = /"([^"]+)","(\d+)".*?"([0-9,]+)\s*K"/.exec(out)
    if (!m) return null
    const kb = Number(m[3].replace(/[,\s]/g, ''))
    return Number.isFinite(kb) ? kb / 1024 : null
  } catch {
    return null
  }
}

/* ============================================================
 * 分析
 * ============================================================ */

/**
 * 相邻增量的同号比例。1 = 完全单调上升，0 = 完全震荡。
 *
 * 为什么需要它：短跨度上线性外推会把噪声放大成假泄漏 ——
 * 实测 18 秒内 RSS 涨 3 MB，外推成 +633 MB/h。真泄漏是单调的，
 * 噪声不是。所以「斜率大」必须配合「够单调」才算证据。
 */
export function monotonicRatio(ys) {
  if (ys.length < 3) return 0
  let up = 0
  let down = 0
  for (let i = 1; i < ys.length; i += 1) {
    const d = ys[i] - ys[i - 1]
    if (d > 0) up += 1
    else if (d < 0) down += 1
  }
  const total = up + down
  return total === 0 ? 0 : Math.max(up, down) / total
}

/** 线性回归斜率（每毫秒的变化量） */
export function slope(xs, ys) {
  const n = xs.length
  if (n < 2) return 0
  const mx = xs.reduce((a, b) => a + b, 0) / n
  const my = ys.reduce((a, b) => a + b, 0) / n
  let num = 0
  let den = 0
  for (let i = 0; i < n; i += 1) {
    num += (xs[i] - mx) * (ys[i] - my)
    den += (xs[i] - mx) ** 2
  }
  return den === 0 ? 0 : num / den
}

/**
 * 单个指标的趋势判定（纯函数，供测试与 analyze 共用）。
 *
 * LEAK? 要求同时满足：斜率超阈值 **且** 相邻增量够单调。
 * 只用斜率会在短跨度上把 GC 波动放大成假泄漏（实测 18 秒涨 3MB →
 * 外推 633MB/h）。
 *
 * @returns {'OK'|'LEAK?'|'DECREASING'|'NOISY'|'INSUFFICIENT'}
 */
export function judgeTrend(xs, ys, warnPerHour, spanMs, minSpanMs = 600_000) {
  if (!Array.isArray(ys) || ys.length < 3) return 'INSUFFICIENT'
  if (ys.some((v) => typeof v !== 'number' || !Number.isFinite(v))) return 'INSUFFICIENT'
  const perHour = slope(xs, ys) * 3_600_000
  if (Math.abs(perHour) < warnPerHour) return 'OK'
  if (spanMs < minSpanMs) return 'INSUFFICIENT'
  if (monotonicRatio(ys) >= 0.8) return perHour > 0 ? 'LEAK?' : 'DECREASING'
  return 'NOISY'
}

function analyze(file) {
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean)
  const rows = lines.map((l) => {
    try { return JSON.parse(l) } catch { return null }
  }).filter(Boolean)

  if (rows.length < 3) {
    console.log(`样本不足（${rows.length} 条），至少需要 3 条才能看趋势`)
    return
  }

  const t0 = rows[0].at
  const xs = rows.map((r) => r.at - t0)

  const series = {
    rssMB: rows.map((r) => r.rssMB),
    activePools: rows.map((r) => r.activePools),
    drainingPools: rows.map((r) => r.drainingPools),
    totalInFlight: rows.map((r) => r.totalInFlight),
    hosts: rows.map((r) => r.hosts),
    candidates: rows.map((r) => r.candidatePools),
    requests: rows.map((r) => r.requests),
  }

  const spanMs = rows.at(-1).at - t0
  const spanMin = spanMs / 60000
  const MIN_SPAN_MS = 10 * 60 * 1000          // 少于 10 分钟不判定趋势
  const MIN_MONOTONIC = 0.8                    // 至少 80% 相邻增量同号

  console.log(`\n=== 长稳分析：${path.basename(file)} ===`)
  console.log(`样本 ${rows.length} 条，跨度 ${spanMin.toFixed(1)} 分钟`)
  if (spanMs < MIN_SPAN_MS) {
    console.log(`\n⚠ 跨度不足 ${MIN_SPAN_MS / 60000} 分钟，趋势外推会被噪声放大。` +
      `\n  下面的判定仅供参考，不要当成泄漏结论。建议至少采 30 分钟。`)
  }

  /** 每个指标的判据：斜率换算成「每小时增量」 */
  const checks = [
    { key: 'rssMB', label: 'RSS', warnPerHour: 50, unit: 'MB' },
    { key: 'activePools', label: 'active 池', warnPerHour: 10, unit: '个' },
    { key: 'drainingPools', label: 'draining 池', warnPerHour: 10, unit: '个' },
    { key: 'hosts', label: 'hosts', warnPerHour: 5, unit: '个' },
    { key: 'candidates', label: '候选总数', warnPerHour: 100, unit: '个' },
  ]

  console.log('\n指标                 首值      末值     每小时变化   单调性  判定')
  for (const c of checks) {
    const ys = series[c.key]
    if (ys.some((v) => typeof v !== 'number')) continue
    const perHour = slope(xs, ys) * 3_600_000
    const mono = monotonicRatio(ys)
    const verdict = judgeTrend(xs, ys, c.warnPerHour, spanMs, MIN_SPAN_MS)
    console.log(
      `${c.label.padEnd(18)} ${String(ys[0]).padStart(8)} ${String(ys.at(-1)).padStart(8)} ` +
      `${(perHour >= 0 ? '+' : '') + perHour.toFixed(1)} ${c.unit}/h`.padStart(14) +
      `   ${(mono * 100).toFixed(0).padStart(3)}%   ${verdict}`,
    )
  }

  const reqDelta = series.requests.at(-1) - series.requests[0]
  console.log(`\n处理请求 ${reqDelta} 个，跨度 ${spanMin.toFixed(1)} 分钟` +
    (spanMin > 0 ? `（${(reqDelta / spanMin).toFixed(2)} req/min）` : ''))

  const errGrowth = rows.at(-1).errors - rows[0].errors
  console.log(`错误增量 ${errGrowth}`)

  console.log('\n判读提示：')
  console.log('  · LEAK? 要求「斜率超阈值 + 至少 80% 相邻增量同号」—— 真泄漏是单调的，噪声不是')
  console.log('  · INSUFFICIENT 表示跨度不足 10 分钟，外推不可信，别下结论')
  console.log('  · NOISY 表示在涨但震荡，通常是 GC 或流量波动')
  console.log('  · 真正的泄漏长这样：requests 不涨，但 RSS/池数量持续单调上升')
  console.log('  · drainingPools 应长期接近 0；持续 > 0 说明有池排不空')
}

/* ============================================================
 * 采集
 * ============================================================ */

async function sample() {
  const res = await fetch(TARGET, { signal: AbortSignal.timeout(10_000) })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const s = await res.json()

  const cp = s.connectionPools || {}
  const pid = PID || pidFromPort(Number(new URL(TARGET).port || 80))
  const rss = rssOfPid(pid)
  const cps = s.candidatePools || []

  return {
    at: Date.now(),
    // 宿主进程的真实 RSS（MB）。拿不到就是 null —— 不用本脚本的内存冒充。
    rssMB: rss,
    pid: pid || null,
    requests: s.stats?.requests ?? 0,
    errors: s.stats?.errors ?? 0,
    switches: s.stats?.switches ?? 0,
    timeouts: s.stats?.timeouts ?? 0,
    activePools: cp.activeCount ?? 0,
    drainingPools: cp.drainingCount ?? 0,
    totalInFlight: cp.totalInFlight ?? 0,
    hosts: (s.hosts || []).length,
    candidatePools: cps.reduce((a, p) => a + (p.size || 0), 0),
    healthy: s.healthSummary?.counts?.healthy ?? 0,
    cooling: s.healthSummary?.counts?.cooling ?? 0,
    halfOpen: s.healthSummary?.counts?.half_open ?? 0,
    dirty: s.statePersistence?.dirty ?? null,
  }
}

async function watch() {
  fs.mkdirSync(OUT_DIR, { recursive: true })
  const file = path.join(OUT_DIR, `stability-${new Date().toISOString().replace(/[:.]/g, '-')}.jsonl`)
  const stream = fs.createWriteStream(file, { flags: 'a' })

  console.log(`采样 ${TARGET}`)
  console.log(`间隔 ${INTERVAL_MS / 1000}s` + (DURATION_MS ? `，时长 ${DURATION_MS / 60000} 分钟` : '，Ctrl-C 结束'))
  console.log(`输出 ${file}`)
  const autoPid = PID || pidFromPort(Number(new URL(TARGET).port || 80))
  console.log(autoPid
    ? `监测进程 PID ${autoPid}（RSS 可采）` + '\n'
    : '未能从端口反查 PID，RSS 将记为 null（不影响池/请求指标）' + '\n')

  const startedAt = Date.now()
  let n = 0
  let stopping = false
  const stop = () => {
    stopping = true
    stream.end()
    console.log(`\n已采样 ${n} 条 → ${file}`)
    console.log(`分析：node scripts/watch-stability.mjs --analyze "${file}"`)
    process.exit(0)
  }
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)

  while (!stopping) {
    try {
      const row = await sample()
      stream.write(JSON.stringify(row) + '\n')
      n += 1
      const oneLine = `[${n}] req=${row.requests} err=${row.errors} ` +
        `pools=${row.activePools}/${row.drainingPools} inFlight=${row.totalInFlight} ` +
        `cand=${row.candidatePools} health=${row.healthy}/${row.cooling}/${row.halfOpen}`
      console.log(oneLine)
    } catch (e) {
      console.log(`[${n}] 采样失败: ${String(e?.message || e)}`)
    }
    if (DURATION_MS && Date.now() - startedAt >= DURATION_MS) break
    await new Promise((r) => setTimeout(r, INTERVAL_MS))
  }
  stop()
}

/**
 * CLI 守卫：只有「直接运行本文件」才启动采集循环。
 *
 * 没有这个守卫时，`import()` 会连带执行 watch()，测试里 import 一下
 * 就挂死（实测：import 后进程不退，被后台任务杀掉）。
 * 纯函数（slope / monotonicRatio / judgeTrend）必须能被安全 import。
 */
const isMain = (() => {
  try {
    return process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
  } catch { return false }
})()

if (isMain) {
  if (ANALYZE) {
    analyze(path.resolve(ANALYZE))
  } else {
    watch().catch((e) => {
      console.error('失败:', e.message)
      process.exit(1)
    })
  }
}
