/**
 * admin-auth.test.js — 管理接口身份验证与访问保护（Issue #8）
 *
 * 三层防护，各自独立可测：
 *   1 来源层：Host（防 rebinding）、Origin（防浏览器跨站）
 *   2 凭据层：Bearer Token，时序安全比较
 *   3 频率层：按来源+读写分类限流
 *
 * 关键约束（评审）：Origin 缺失的非浏览器客户端不受 Origin 检查影响，
 * 凭据是 Token；DSH 工具是进程内调用，不经过 HTTP，不该被迫重新认证。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import {
  generateToken, safeTokenEqual, extractBearer, checkHost, checkOrigin,
  createRateLimiter, readTokenFile, resolveAdminToken, hostnameOf, isLoopbackHost,
} from '../../lib/admin-auth.mjs'
import * as mod from '../../lib/index.js'
import { setupPlugin, teardownPlugin, tempStateFile } from '../helpers/setup.mjs'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'
const TOKEN = 'unit-test-token-abcdefghijklmnop'

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 凭据层：Token 生成与比较
 * ============================================================ */

test('Token 由密码学安全随机源生成，长度足够', () => {
  const a = generateToken(32)
  const b = generateToken(32)
  assert.notEqual(a, b, '两次生成必须不同')
  assert.ok(a.length >= 40, `base64url(32B) 应 ≥40 字符，实际 ${a.length}`)
  assert.match(a, /^[A-Za-z0-9_-]+$/, 'base64url 只含安全字符')
})

test('Token 比较是时序安全的，且拒绝长度不同/空值', () => {
  assert.equal(safeTokenEqual('abc', 'abc'), true)
  assert.equal(safeTokenEqual('abc', 'abd'), false)
  assert.equal(safeTokenEqual('abc', 'abcd'), false, '长度不同直接 false')
  assert.equal(safeTokenEqual('', ''), false, '空 Token 不算匹配')
  assert.equal(safeTokenEqual(null, 'a'), false)
  assert.equal(safeTokenEqual('a', undefined), false)
})

test('Bearer 头大小写与多余空格都兼容，非 Bearer 方案不认', () => {
  assert.equal(extractBearer({ authorization: 'Bearer tok' }), 'tok')
  assert.equal(extractBearer({ authorization: 'bearer tok' }), 'tok')
  assert.equal(extractBearer({ authorization: 'BEARER   tok   ' }), 'tok')
  assert.equal(extractBearer({ authorization: 'Basic tok' }), '')
  assert.equal(extractBearer({ authorization: 'tok' }), '', '裸 Token 不算')
  assert.equal(extractBearer({}), '')
})

test('Token 文件读取：支持注释与空行，取第一个有效行', () => {
  const p = path.join(os.tmpdir(), `cfr-token-${process.pid}-${Date.now()}.txt`)
  fs.writeFileSync(p, '# 这是注释\n\n  real-token-value  \ntrailing\n', 'utf8')
  assert.equal(readTokenFile(p), 'real-token-value')
  fs.unlinkSync(p)

  assert.equal(readTokenFile('/nonexistent/path'), '', '缺失文件返回空串')
  assert.equal(readTokenFile(''), '')
})

test('resolveAdminToken：配置直填优先于文件', () => {
  const p = path.join(os.tmpdir(), `cfr-token2-${process.pid}.txt`)
  fs.writeFileSync(p, 'from-file\n', 'utf8')

  assert.equal(resolveAdminToken({ adminToken: 'from-config', adminTokenFile: p }), 'from-config')
  assert.equal(resolveAdminToken({ adminToken: '', adminTokenFile: p }), 'from-file')
  assert.equal(resolveAdminToken({}), '')
  fs.unlinkSync(p)
})

/* ============================================================
 * 来源层：Host 与 Origin
 * ============================================================ */

test('Host 校验：监听回环时只接受回环/本机 Host', () => {
  for (const ok of ['127.0.0.1:8787', 'localhost:8787', '[::1]:8787']) {
    assert.equal(checkHost(ok, '127.0.0.1'), null, `${ok} 应通过`)
  }
  for (const bad of ['evil.example.com:8787', 'attacker.test', '10.0.0.1:8787']) {
    assert.equal(checkHost(bad, '127.0.0.1'), 'host_not_loopback', `${bad} 应被拒`)
  }
  assert.equal(checkHost('', '127.0.0.1'), 'missing_host')
})

test('Host 校验：监听非回环地址时不限制（部署者已显式放开）', () => {
  // 0.0.0.0 / 空 = 监听所有接口，不是「回环部署」，不该再套回环 Host 校验
  assert.equal(checkHost('api.internal:8787', '0.0.0.0'), null)
  assert.equal(checkHost('api.internal:8787', ''), null)
  assert.equal(checkHost('anything.example', '192.168.1.5'), null)
})

test('Origin 校验：无 Origin 的请求放行（curl / DSH）', () => {
  assert.equal(checkOrigin('', []), null, '不带 Origin 的非浏览器客户端不该被误伤')
  assert.equal(checkOrigin(undefined, []), null)
})

test('Origin 校验：默认拒绝任何跨源浏览器请求', () => {
  assert.equal(checkOrigin('https://evil.example', []), 'origin_not_allowed')
})

test('Origin 校验：只放行显式白名单', () => {
  const allow = ['https://ok.example', 'http://localhost:3000']
  assert.equal(checkOrigin('https://ok.example', allow), null)
  assert.equal(checkOrigin('http://localhost:3000', allow), null)
  assert.equal(checkOrigin('https://evil.example', allow), 'origin_not_allowed')
  assert.equal(checkOrigin('https://ok.example.evil.test', allow), 'origin_not_allowed', '不做后缀匹配')
})

test('hostnameOf / isLoopbackHost 基础判定', () => {
  assert.equal(hostnameOf('LocalHost:8787'), 'localhost')
  assert.equal(hostnameOf('[::1]:8787'), '::1')
  assert.equal(hostnameOf('example.com.'), 'example.com')
  assert.equal(isLoopbackHost('127.0.0.1'), true)
  assert.equal(isLoopbackHost('example.com'), false)
})

/* ============================================================
 * 频率层
 * ============================================================ */

test('限流器：窗口内超额返回拒绝并给出 retryAfter', () => {
  let t = 1000
  const rl = createRateLimiter({ limit: 3, windowMs: 1000, now: () => t })

  assert.equal(rl.hit('k').ok, true)
  assert.equal(rl.hit('k').ok, true)
  assert.equal(rl.hit('k').ok, true)
  const r = rl.hit('k')
  assert.equal(r.ok, false, '第 4 次应被限')
  assert.ok(r.retryAfterMs > 0)

  t += 1001
  assert.equal(rl.hit('k').ok, true, '窗口过期后恢复')
})

test('限流器：按 key 分桶，读写互不影响', () => {
  const rl = createRateLimiter({ limit: 1, windowMs: 1000 })
  assert.equal(rl.hit('1.2.3.4|write').ok, true)
  assert.equal(rl.hit('1.2.3.4|write').ok, false, '同键第二次被限')
  assert.equal(rl.hit('1.2.3.4|read').ok, true, '读桶独立')
  assert.equal(rl.hit('5.6.7.8|write').ok, true, '其它来源独立')
})

/* ============================================================
 * 端到端
 * ============================================================ */

async function boot(overrides = {}) {
  const listenPort = await freePort()
  setupPlugin({
    targets: [HOST],
    listenHost: '127.0.0.1',
    listenPort,
    allowPrivateTargets: true,
    adminToken: TOKEN,
    adminRateLimit: 10000,
    ...overrides,
  })
  const server = api.createProxy()
  await new Promise((r) => server.once('listening', r))
  return { port: server.address().port }
}

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
    if (body != null) q.write(body)
    q.end()
  })
}

const AUTH = { authorization: `Bearer ${TOKEN}` }
const JSON_CT = { 'content-type': 'application/json' }

test('修改型接口无 Token → 401', async () => {
  const { port } = await boot()
  const r = await req(port, { method: 'POST', path: '/__router/reset-mode', headers: JSON_CT })
  assert.equal(r.status, 401)
  assert.equal(r.json.error, 'unauthorized')
  assert.equal(r.json.ok, false)
})

test('错误 Token → 401，且响应里不含 Token 本身', async () => {
  const { port } = await boot()
  const wrong = 'wrong-token-should-not-echo'
  const r = await req(port, {
    method: 'POST', path: '/__router/reset-mode',
    headers: { ...JSON_CT, authorization: `Bearer ${wrong}` },
  })
  assert.equal(r.status, 401)
  assert.equal(r.json.error, 'unauthorized')
  assert.equal(r.body.includes(wrong), false, '响应不得回显 Token')
  assert.equal(r.body.includes(TOKEN), false, '响应不得回显正确 Token')
})

test('正确 Token 可以管理', async () => {
  const { port } = await boot()
  const r = await req(port, {
    method: 'POST', path: '/__router/mode',
    headers: { ...JSON_CT, ...AUTH },
    body: JSON.stringify({ mode: 'direct' }),
  })
  assert.equal(r.status, 200)
  assert.equal(r.json.routingMode, 'direct')
})

test('非 Bearer 方案（Basic）不被接受', async () => {
  const { port } = await boot()
  const r = await req(port, {
    method: 'POST', path: '/__router/reset-mode',
    headers: { ...JSON_CT, authorization: 'Basic ' + TOKEN },
  })
  assert.equal(r.status, 401)
})

test('只读接口默认不需要 Token（DSH 工具/监控要用）', async () => {
  const { port } = await boot()
  for (const p of ['/__router/status', '/__router/mode']) {
    const r = await req(port, { path: p })
    assert.equal(r.status, 200, `${p} 默认应可读`)
  }
})

test('adminProtectStatus=true 时只读接口也要 Token', async () => {
  const { port } = await boot({ adminProtectStatus: true })
  const noAuth = await req(port, { path: '/__router/status' })
  assert.equal(noAuth.status, 401, '开启保护后应要求 Token')

  const withAuth = await req(port, { path: '/__router/status', headers: AUTH })
  assert.equal(withAuth.status, 200)
})

test('未配置 Token 时修改型操作被禁用（不静默开放）', async () => {
  const { port } = await boot({ adminToken: '', adminTokenFile: '' })
  const r = await req(port, {
    method: 'POST', path: '/__router/reset',
    headers: JSON_CT,
  })
  assert.equal(r.status, 403)
  assert.equal(r.json.error, 'admin_token_not_configured')
  assert.equal(r.json.tokenConfigured, false, '应告知未配置')
})

test('逃生舱：明确开启后仅回环来源可改状态', async () => {
  const { port } = await boot({ adminToken: '', adminTokenFile: '', allowUnauthenticatedLocalAdmin: true })
  const r = await req(port, { method: 'POST', path: '/__router/reset', headers: JSON_CT })
  assert.equal(r.status, 200, '回环来源 + 显式逃生舱应放行')
})

test('Host 不是回环 → 403（防 DNS rebinding）', async () => {
  const { port } = await boot()
  const r = await req(port, {
    method: 'POST', path: '/__router/reset-mode',
    headers: { ...JSON_CT, ...AUTH, host: 'evil.example.com:8787' },
  })
  assert.equal(r.status, 403)
  assert.equal(r.json.error, 'forbidden_host')
})

test('跨源浏览器请求默认被拒', async () => {
  const { port } = await boot()
  const r = await req(port, {
    method: 'POST', path: '/__router/reset-mode',
    headers: { ...JSON_CT, ...AUTH, origin: 'https://evil.example' },
  })
  assert.equal(r.status, 403)
  assert.equal(r.json.error, 'forbidden_origin')
})

test('白名单内的 Origin 可以调用', async () => {
  const { port } = await boot({ adminAllowedOrigins: ['https://ok.example'] })
  const r = await req(port, {
    method: 'POST', path: '/__router/reset-mode',
    headers: { ...JSON_CT, ...AUTH, origin: 'https://ok.example' },
  })
  assert.equal(r.status, 200)
})

test('频率限制生效，且 429 带 retryAfterMs', async () => {
  const { port } = await boot({ adminRateLimit: 3, adminRateWindowMs: 60000 })
  const hit = () => req(port, {
    method: 'POST', path: '/__router/reset',
    headers: { ...JSON_CT, ...AUTH },
  })

  const a = await hit()
  const b = await hit()
  const c = await hit()
  assert.equal([a, b, c].every((x) => x.status === 200), true, '前三次应放行')

  const d = await hit()
  assert.equal(d.status, 429)
  assert.equal(d.json.error, 'rate_limited')
  assert.ok(d.json.retryAfterMs >= 0)
})

test('频率限制按读写分桶：写被限不影响读', async () => {
  const { port } = await boot({ adminRateLimit: 1, adminRateWindowMs: 60000 })
  await req(port, { method: 'POST', path: '/__router/reset', headers: { ...JSON_CT, ...AUTH } })
  const limited = await req(port, { method: 'POST', path: '/__router/reset', headers: { ...JSON_CT, ...AUTH } })
  assert.equal(limited.status, 429)

  const read = await req(port, { path: '/__router/status' })
  assert.equal(read.status, 200, '读接口应不受写限流影响')
})

test('status 快照不含 Token，但告知是否已配置', async () => {
  const { port } = await boot()
  const r = await req(port, { path: '/__router/status' })
  assert.equal(r.body.includes(TOKEN), false, '快照绝不能含 Token')
  const mode = await req(port, { path: '/__router/mode' })
  assert.equal(mode.json.tokenConfigured, true)
  assert.equal(mode.json.authRequired, true)
  assert.equal(mode.body.includes(TOKEN), false)
})

test('Token 从文件读取时同样生效', async () => {
  const tokenFile = path.join(os.tmpdir(), `cfr-admin-${process.pid}-${Date.now()}.txt`)
  fs.writeFileSync(tokenFile, `# generated\nfile-token-xyz\n`, 'utf8')

  try {
    const { port } = await boot({ adminToken: '', adminTokenFile: tokenFile })
    const ok = await req(port, {
      method: 'POST', path: '/__router/reset-mode',
      headers: { ...JSON_CT, authorization: 'Bearer file-token-xyz' },
    })
    assert.equal(ok.status, 200)

    const bad = await req(port, {
      method: 'POST', path: '/__router/reset-mode',
      headers: { ...JSON_CT, authorization: `Bearer ${TOKEN}` },
    })
    assert.equal(bad.status, 401, '配置文件里的 Token 应覆盖旧的')
  } finally {
    fs.unlinkSync(tokenFile)
  }
})

test('DSH 工具不经过 HTTP，无需 Token', async () => {
  api.reset()
  const registered = []
  const ctx = { tools: { register: (t) => registered.push(t) } }
  mod.apply(ctx, mod.Config({
    targets: [], listenHost: '127.0.0.1', listenPort: 0,
    discoverEnabled: false, adminToken: TOKEN,
  }))

  const byName = Object.fromEntries(registered.map((t) => [t.name, t]))
  // 直接调工具执行函数——进程内调用，不该索要 Token
  const res = await byName.cf_router_mode.execute({ mode: 'direct' })
  assert.equal(res.ok, true)
  assert.equal(res.routingMode, 'direct')

  mod.dispose()
  mod.__resetForTest()
})
