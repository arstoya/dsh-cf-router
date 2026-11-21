/**
 * routing-mode.test.js — #18 启动 routingMode 解析（评审确认的优先级表）
 *
 * 核心：必须区分「stateFile 里真的保存了模式」与「程序只是在用默认值」。
 * 修复前靠 lastCfgMode 用配置值初始化，等于告诉 currentMode()
 * 「设置页已是这个值、跳过同步」，配置永远不生效且无提示。
 *
 * 评审确认的优先级：
 *   没有 stateFile，配置 direct        → direct
 *   stateFile=auto，配置 direct        → auto（stateFile 赢）
 *   stateFile=direct，配置 auto        → direct（stateFile 赢）
 *   stateFile 存在但无有效 routingMode → 配置值
 *   无配置、无 stateFile               → auto
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin, tempStateFile } from '../helpers/setup.mjs'

const api = mod.__testApi
const HOST = 'localhost'

/** 写一个只含 routingMode 的 stateFile */
function writeStateFile(mode) {
  const p = tempStateFile('routing')
  fs.writeFileSync(p, JSON.stringify({ routingMode: mode, updatedAt: new Date().toISOString() }), 'utf8')
  return p
}

/** 装配：显式指定 stateFile，模拟「有/无持久化状态」 */
function setup({ configMode = 'auto', stateFile = null } = {}) {
  return setupPlugin({
    targets: [HOST],
    discoverEnabled: false,
    routingMode: configMode,
    stateFile: stateFile || tempStateFile('none'),
  })
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 评审给出的优先级表
 * ============================================================ */

test('没有 stateFile + 配置 direct → effective = direct', () => {
  setup({ configMode: 'direct' })
  assert.equal(api.currentMode(), 'direct')
})

test('stateFile=auto + 配置 direct → effective = auto（stateFile 赢）', () => {
  setup({ configMode: 'direct', stateFile: writeStateFile('auto') })
  assert.equal(api.currentMode(), 'auto')
})

test('stateFile=direct + 配置 auto → effective = direct（stateFile 赢）', () => {
  setup({ configMode: 'auto', stateFile: writeStateFile('direct') })
  assert.equal(api.currentMode(), 'direct')
})

test('stateFile 存在但没有有效 routingMode → 用配置值', () => {
  const p = tempStateFile('invalid')
  fs.writeFileSync(p, JSON.stringify({ updatedAt: '2026-01-01' }), 'utf8')
  setup({ configMode: 'direct', stateFile: p })
  assert.equal(api.currentMode(), 'direct')
})

test('stateFile 损坏 → 不阻止启动，退回配置值', () => {
  const p = tempStateFile('broken')
  fs.writeFileSync(p, '{ this is not json', 'utf8')
  setup({ configMode: 'direct', stateFile: p })
  assert.equal(api.currentMode(), 'direct')
})

test('无配置、无 stateFile → 默认 auto', () => {
  setup({})
  assert.equal(api.currentMode(), 'auto')
})

test('stateFile 里是非法模式值 → 视为无有效值，用配置', () => {
  setup({ configMode: 'direct', stateFile: writeStateFile('turbo') })
  assert.equal(api.currentMode(), 'direct')
})

/* ============================================================
 * 三个来源的可观测性
 * ============================================================ */

test('statusSnapshot 暴露 configMode / stateFileMode / effectiveMode', () => {
  setup({ configMode: 'direct', stateFile: writeStateFile('auto') })
  const src = api.statusSnapshot().routingModeSources

  assert.equal(src.configMode, 'direct', '配置里写的是 direct')
  assert.equal(src.stateFileMode, 'auto', 'stateFile 里是 auto')
  assert.equal(src.effectiveMode, 'auto', '生效的是 auto')
  assert.equal(src.stateFileWins, true, '应标出「stateFile 覆盖了配置」')
})

test('无冲突时 stateFileWins = false', () => {
  setup({ configMode: 'direct' })
  const src = api.statusSnapshot().routingModeSources
  assert.equal(src.stateFileMode, null, '没有 stateFile 时应为 null')
  assert.equal(src.stateFileWins, false)
})

/* ============================================================
 * 运行时切换仍走现有机制，不被初始化逻辑干扰
 * ============================================================ */

test('setRoutingMode 立即生效并落盘', () => {
  const p = tempStateFile('switch')
  setup({ configMode: 'auto', stateFile: p })

  const r = api.setRoutingMode('direct')
  assert.equal(r.ok, true)
  assert.equal(api.currentMode(), 'direct')
  assert.equal(JSON.parse(fs.readFileSync(p, 'utf8')).routingMode, 'direct')
})

test('setRoutingMode 落盘后再 apply() → stateFile 优先，配置不覆盖', () => {
  const p = tempStateFile('persist')
  setup({ configMode: 'auto', stateFile: p })
  api.setRoutingMode('direct')

  // 模拟重启：配置仍是 auto，但 stateFile 里已是 direct
  api.configure({ ...api.getCfg(), routingMode: 'auto', stateFile: p })
  assert.equal(api.currentMode(), 'direct', '重启后应从 stateFile 恢复')
})

test('配置热更新经 apply() 生效（无 stateFile 时）', () => {
  setup({ configMode: 'auto' })
  assert.equal(api.currentMode(), 'auto')

  // 热重载配置为 direct
  api.configure({ ...api.getCfg(), routingMode: 'direct' })
  assert.equal(api.currentMode(), 'direct')
})

/* ============================================================
 * volatile 引用读取路径（生产形态）
 * ============================================================ */

test('配置以 volatile 引用传入时仍能读出正确的模式', () => {
  api.reset()
  const built = mod.Config({
    targets: [HOST],
    discoverEnabled: false,
    routingMode: 'direct',
    stateFile: tempStateFile('volatile'),
  })
  assert.equal(typeof built.routingMode, 'object', 'Config 应产出 volatile 引用')
  assert.equal(typeof built.routingMode.get, 'function')

  api.configure(built)
  assert.equal(api.currentMode(), 'direct', '必须经 .get() 读到 direct')
  assert.equal(api.statusSnapshot().routingModeSources.configMode, 'direct')
})

/* ============================================================
 * resetRoutingMode：只清 routingMode，保留其它键
 * ============================================================ */

test('resetRoutingMode 只移除 routingMode，保留其它状态字段', () => {
  const p = tempStateFile('reset')
  // 造一个含「未来会有的」其它字段的状态文件
  fs.writeFileSync(p, JSON.stringify({
    routingMode: 'direct',
    updatedAt: '2026-01-01T00:00:00Z',
    candidatePool: [{ ip: '203.0.113.9', score: 42 }],
  }), 'utf8')

  setup({ configMode: 'auto', stateFile: p })
  assert.equal(api.currentMode(), 'direct', '初始应从 stateFile 读到 direct')

  const r = api.resetRoutingMode()
  assert.equal(r.ok, true)
  assert.equal(r.removed, true)
  assert.equal(r.routingMode, 'auto', '清除后应回到配置值 auto')

  const after = JSON.parse(fs.readFileSync(p, 'utf8'))
  assert.equal('routingMode' in after, false, 'routingMode 应被移除')
  assert.ok('candidatePool' in after, '其它字段必须保留')
  assert.equal(after.candidatePool[0].score, 42)
  assert.ok(after.routingModeResetAt, '应留下重置时间戳')
})

test('resetRoutingMode 在没有 stateFile 时安全返回', () => {
  const p = tempStateFile('noreset')
  setup({ configMode: 'direct', stateFile: p })

  const r = api.resetRoutingMode()
  assert.equal(r.ok, true)
  assert.equal(r.removed, false, '没有可移除的内容')
  assert.equal(api.currentMode(), 'direct', '仍用配置值')
})

test('resetRoutingMode 后配置重新生效（评审的原始诉求）', () => {
  const p = tempStateFile('reclaim')
  setup({ configMode: 'auto', stateFile: p })
  api.setRoutingMode('direct')
  assert.equal(api.currentMode(), 'direct')

  // 把配置改成 direct 之外的意图：这里验证「清掉持久化后配置说了算」
  api.configure({ ...api.getCfg(), routingMode: 'auto', stateFile: p })
  assert.equal(api.currentMode(), 'direct', 'stateFile 仍优先')

  api.resetRoutingMode()
  assert.equal(api.currentMode(), 'auto', '清除持久化后应回到配置的 auto')
})

/* ============================================================
 * directFallback 与 directRequests 语义分离
 * ============================================================ */

test('direct 模式计入 directRequests，不计入 directFallback', async () => {
  const { startHttpsUpstream } = await import('../fixtures/https-server.js')
  const { freePort } = await import('../helpers/deferred.mjs')
  const http = await import('node:http')

  const up = await startHttpsUpstream({ status: 200, body: '{}' })
  const port = await freePort()
  try {
    setup({ configMode: 'direct', stateFile: tempStateFile('dreq') })
    api.deps.upstreamPort = up.port
    api.deps.tlsOptions = { ca: up.cert }
    api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
    api.configure({ ...api.getCfg(), listenHost: '127.0.0.1', listenPort: port, targets: [HOST] })

    const srv = api.createProxy()
    await new Promise((r) => srv.once('listening', r))

    await new Promise((res) => {
      const q = http.request({ host: '127.0.0.1', port, path: '/x', method: 'POST' }, (x) => {
        x.resume(); x.on('end', res)
      })
      q.end('{}')
    })

    const st = api.statusSnapshot().stats
    assert.equal(st.directRequests, 1, 'direct 模式应计入 directRequests')
    assert.equal(st.directFallback, 0, 'direct 模式不该计入 directFallback')
  } finally {
    try { api.closeProxy() } catch { /* ignore */ }
    await up.close()
  }
})

test('统计字段结构完整（含新增的 directRequests）', () => {
  setup({})
  const st = api.statusSnapshot().stats
  for (const k of ['requests', 'errors', 'switches', 'timeouts', 'directFallback', 'directRequests', 'bytesIn', 'bytesOut']) {
    assert.equal(typeof st[k], 'number', `stats.${k} 应为数字`)
  }
})
