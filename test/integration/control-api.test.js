/**
 * control-api.test.js — 管理接口方法语义与请求校验（Issue #7）
 *
 * 方法矩阵（评审确认）：
 *   GET  /__router/status      只读
 *   GET  /__router/mode        只读
 *   POST /__router/mode        改运行模式（持久化）
 *   POST /__router/probe       触发探测
 *   POST /__router/reset       清运行时统计/冷却/连接池
 *   POST /__router/reset-mode  只清持久化的 routingMode
 *
 * 注意 /mode 同时支持 GET 与 POST，所以它的 Allow 是 `GET, POST` ——
 * 不能因为「旧的 GET ?value= 写法被拒」就给整条路径声明只允许 POST。
 *
 * 本文件不测鉴权（那是 #8）。#7 只负责方法语义、请求校验与统一错误协议。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import fs from 'node:fs'

import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin, tempStateFile } from '../helpers/setup.mjs'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'

/** 起代理；返回 { port } */
const TEST_TOKEN = 'test-admin-token-0123456789'

async function boot(overrides = {}) {
  const listenPort = await freePort()
  setupPlugin({
    targets: [HOST],
    listenHost: '127.0.0.1',
    listenPort,
    allowPrivateTargets: true,
    // Issue #8 之后修改型接口必须带 Token。这里注入一个测试用 Token，
    // 好让本文件专注于 #7 的方法语义与请求校验。
    adminToken: TEST_TOKEN,
    // 限流放宽，避免用例互相触发 429（限流本身在 security/admin-auth.test.js 里单独测）
    adminRateLimit: 10000,
    ...overrides,
  })
  const server = api.createProxy()
  await new Promise((r) => server.once('listening', r))
  return { port: server.address().port }
}

const AUTH = { authorization: `Bearer ${TEST_TOKEN}` }

/** 原始请求，返回 { status, headers, body, json } */
function req(port, { method = 'GET', path = '/', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const q = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString()
        let json = null
        try { json = JSON.parse(text) } catch { /* 非 JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, body: text, json })
      })
    })
    q.on('error', reject)
    if (body != null) q.write(typeof body === 'string' ? body : JSON.stringify(body))
    q.end()
  })
}

function postJson(port, path, obj, headers = {}) {
  return req(port, {
    method: 'POST',
    path,
    headers: { 'content-type': 'application/json', ...AUTH, ...headers },
    body: obj == null ? '' : JSON.stringify(obj),
  })
}

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 方法矩阵
 * ============================================================ */

test('GET /status 只读，返回快照', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/status' })
  assert.equal(r.status, 200)
  assert.equal(r.json.ok, true)
  assert.ok(Array.isArray(r.json.hosts))
})

test('GET /mode 只读查询', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/mode' })
  assert.equal(r.status, 200)
  assert.ok(['auto', 'direct'].includes(r.json.routingMode))
  assert.deepEqual(r.json.allowed, ['auto', 'direct'])
})

test('POST /mode 改模式并持久化', async () => {
  const stateFile = tempStateFile('mode')
  const { port } = await boot({ stateFile })

  const r = await postJson(port, '/__router/mode', { mode: 'direct' })
  assert.equal(r.status, 200)
  assert.equal(r.json.routingMode, 'direct')
  assert.equal(JSON.parse(fs.readFileSync(stateFile, 'utf8')).routingMode, 'direct', '应落盘')
})

test('POST /probe 允许空 body', async () => {
  const { port } = await boot()
  const r = await req(port, { method: 'POST', path: '/__router/probe', headers: AUTH })
  assert.equal(r.status, 200, '空 body 应被接受')
  assert.equal(r.json.ok, true)
})

test('POST /reset 允许空 body，清运行时统计', async () => {
  const { port } = await boot()
  api.state().stats.requests = 42
  const r = await req(port, { method: 'POST', path: '/__router/reset', headers: AUTH })
  assert.equal(r.status, 200)
  assert.equal(r.json.ok, true)
  assert.equal(api.state().stats.requests, 0, '运行时统计应被清空')
})

test('POST /reset-mode 只清持久化模式，不动运行时统计', async () => {
  const stateFile = tempStateFile('resetmode')
  fs.writeFileSync(stateFile, JSON.stringify({
    routingMode: 'direct',
    candidatePool: [{ ip: '203.0.113.9' }],
  }), 'utf8')

  const { port } = await boot({ stateFile })
  api.state().stats.requests = 7

  const r = await req(port, { method: 'POST', path: '/__router/reset-mode', headers: AUTH })
  assert.equal(r.status, 200)
  assert.equal(r.json.ok, true)

  const after = JSON.parse(fs.readFileSync(stateFile, 'utf8'))
  assert.equal('routingMode' in after, false, 'routingMode 应被移除')
  assert.ok('candidatePool' in after, '其它状态必须保留')
  assert.equal(api.state().stats.requests, 7, 'reset-mode 不该动运行时统计')
})

test('POST /reset 不修改持久化 routingMode', async () => {
  const stateFile = tempStateFile('resetkeep')
  const { port } = await boot({ stateFile })
  await postJson(port, '/__router/mode', { mode: 'direct' })

  const r = await req(port, { method: 'POST', path: '/__router/reset', headers: AUTH })
  assert.equal(r.status, 200)

  const after = JSON.parse(fs.readFileSync(stateFile, 'utf8'))
  assert.equal(after.routingMode, 'direct', 'reset 不该动持久化模式')
})

/* ============================================================
 * 旧 GET 修改操作必须 405，且 Allow 正确
 * ============================================================ */

test('GET /probe → 405 + Allow: POST', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/probe' })
  assert.equal(r.status, 405)
  assert.equal(r.headers.allow, 'POST')
  assert.equal(r.json.error, 'method_not_allowed')
})

test('GET /reset → 405 + Allow: POST', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/reset' })
  assert.equal(r.status, 405)
  assert.equal(r.headers.allow, 'POST')
})

test('GET /reset-mode → 405 + Allow: POST', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/reset-mode' })
  assert.equal(r.status, 405)
  assert.equal(r.headers.allow, 'POST')
})

test('GET /mode?value=direct → 405，Allow 是 GET, POST（/mode 本身两种都支持）', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/mode?value=direct' })

  assert.equal(r.status, 405, '旧的 GET 修改写法必须被拒')
  assert.equal(r.headers.allow, 'GET, POST', '不能因为旧写法被拒就给整条路径只留 POST')
  assert.equal(api.currentMode(), 'auto', '不允许 GET 产生副作用')
})

test('GET /mode?mode=direct 同样被拒（两个旧参数名都要挡）', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/mode?mode=direct' })
  assert.equal(r.status, 405)
  assert.equal(api.currentMode(), 'auto')
})

test('不支持的方法统一 405', async () => {
  const { port } = await boot()
  for (const [method, path] of [
    ['PUT', '/__router/status'],
    ['DELETE', '/__router/reset'],
    ['PATCH', '/__router/mode'],
    ['GET', '/__router/reset'],
  ]) {
    const r = await req(port, { method, path })
    assert.equal(r.status, 405, `${method} ${path}`)
    assert.equal(r.json.error, 'method_not_allowed')
    assert.ok(r.headers.allow, `${method} ${path} 应带 Allow 头`)
  }
})

/* ============================================================
 * 请求体校验与统一错误协议
 * ============================================================ */

test('非法 JSON → invalid_json', async () => {
  const { port } = await boot()
  const r = await postJson(port, '/__router/mode', null, { 'content-type': 'application/json' })
  // 空 body 走 missing_field；这里用真正的坏 JSON
  const bad = await req(port, {
    method: 'POST',
    path: '/__router/mode',
    headers: { 'content-type': 'application/json', ...AUTH },
    body: '{ not json',
  })
  assert.equal(bad.status, 400)
  assert.equal(bad.json.error, 'invalid_json')
})

test('空 body 在 /mode 上 → missing_field', async () => {
  const { port } = await boot()
  const r = await req(port, {
    method: 'POST',
    path: '/__router/mode',
    headers: { 'content-type': 'application/json', ...AUTH },
  })
  assert.equal(r.status, 400)
  assert.equal(r.json.error, 'missing_field')
  assert.equal(r.json.field, 'mode')
})

test('缺必填字段 → missing_field', async () => {
  const { port } = await boot()
  const r = await postJson(port, '/__router/mode', {})
  assert.equal(r.status, 400)
  assert.equal(r.json.error, 'missing_field')
  assert.equal(r.json.field, 'mode')
})

test('未知字段 → unknown_field', async () => {
  const { port } = await boot()
  const r = await postJson(port, '/__router/mode', { mode: 'direct', evil: 1 })
  assert.equal(r.status, 400)
  assert.equal(r.json.error, 'unknown_field')
  assert.equal(r.json.field, 'evil')
})

test('非法模式值 → invalid_value', async () => {
  const { port } = await boot()
  for (const bad of ['turbo', '', 'AUTO ', 123, null]) {
    const r = await postJson(port, '/__router/mode', { mode: bad })
    assert.equal(r.status, 400, `mode=${JSON.stringify(bad)}`)
    assert.equal(r.json.error, 'invalid_value')
    assert.equal(r.json.field, 'mode')
  }
})

test('Content-Type 不支持 → 415 unsupported_media_type', async () => {
  const { port } = await boot()
  const r = await req(port, {
    method: 'POST',
    path: '/__router/mode',
    headers: { 'content-type': 'text/plain', ...AUTH },
    body: '{"mode":"direct"}',
  })
  assert.equal(r.status, 415)
  assert.equal(r.json.error, 'unsupported_media_type')
})

test('所有错误响应结构一致：ok=false + error + message', async () => {
  const { port } = await boot()
  const samples = [
    await req(port, { path: '/__router/probe' }),                                  // 405
    await req(port, { method: 'POST', path: '/__router/mode', headers: AUTH }),       // 400 missing
    await postJson(port, '/__router/mode', { mode: 'nope' }),                       // 400 invalid
    await postJson(port, '/__router/mode', { junk: 1 }),                            // 400 unknown/missing
    await req(port, { method: 'POST', path: '/__router/mode', headers: { 'content-type': 'text/plain', ...AUTH }, body: 'x' }), // 415
  ]
  for (const r of samples) {
    assert.equal(r.json.ok, false, `${r.status} 应 ok=false`)
    assert.equal(typeof r.json.error, 'string', 'error 应为字符串')
    assert.equal(typeof r.json.message, 'string', 'message 应为字符串')
  }
})

test('POST 请求体上限：超大 body 被拒', async () => {
  const { port } = await boot()
  const r = await req(port, {
    method: 'POST',
    path: '/__router/reset',
    headers: { 'content-type': 'application/json', ...AUTH },
    body: 'x'.repeat(80 * 1024),
  })
  assert.equal(r.status, 413)
  assert.equal(r.json.error, 'payload_too_large')
})

/* ============================================================
 * CORS 不再无条件开放
 * ============================================================ */

test('默认不发 Access-Control-Allow-Origin', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/status' })
  assert.equal(r.headers['access-control-allow-origin'], undefined, '默认不该有通配 CORS')
})

test('显式配置后才发 CORS 头', async () => {
  const { port } = await boot({ corsAllowOrigin: 'https://example.com' })
  const r = await req(port, { path: '/__router/status' })
  assert.equal(r.headers['access-control-allow-origin'], 'https://example.com')
})

/* ============================================================
 * DSH 工具不受影响
 * ============================================================ */

test('四个 DSH 工具名称与参数不变', () => {
  api.reset()
  const registered = []
  const ctx = { tools: { register: (t) => registered.push(t) } }
  mod.apply(ctx, mod.Config({ targets: [], listenHost: '127.0.0.1', listenPort: 0, discoverEnabled: false }))

  assert.deepEqual(registered.map((t) => t.name).sort(),
    ['cf_router_mode', 'cf_router_probe', 'cf_router_reset', 'cf_router_status'])

  const byName = Object.fromEntries(registered.map((t) => [t.name, t]))
  assert.deepEqual(Object.keys(byName.cf_router_probe.parameters), ['host', 'samples'])
  assert.deepEqual(Object.keys(byName.cf_router_reset.parameters), [])
  assert.deepEqual(Object.keys(byName.cf_router_mode.parameters), ['mode'])

  mod.dispose()
  mod.__resetForTest()
})
