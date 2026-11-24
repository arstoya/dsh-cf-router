/**
 * isolation.test.js — 契约层与入口的隔离（Issue #26 / A2）
 *
 * 方案 §5.1 的验收要求：
 *   「Core 不依赖代理入口类型（用一个假 Adapter 证明）」
 *
 * 这里用**静态检查 + 运行时证明**两条，后者比 mock 更硬：
 * import 图是静态事实，改不了。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import * as contract from '../../lib/contract/index.mjs'
import { makeRequestContext } from '../../lib/contract/request-context.mjs'
import { ClientUnauthorized } from '../../lib/contract/errors.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CONTRACT_DIR = path.resolve(HERE, '../../lib/contract')

/** 契约层的全部源文件 */
function contractFiles() {
  return fs.readdirSync(CONTRACT_DIR)
    .filter((f) => f.endsWith('.mjs'))
    .map((f) => ({ name: f, src: fs.readFileSync(path.join(CONTRACT_DIR, f), 'utf8') }))
}

/* ============================================================
 * 静态隔离：契约层不知道 HTTP 入口长什么样
 * ============================================================ */

test('契约层不 import node:http / node:https', () => {
  for (const { name, src } of contractFiles()) {
    for (const mod of ['node:http', 'node:https']) {
      assert.equal(
        src.includes(`'${mod}'`) || src.includes(`"${mod}"`),
        false,
        `${name} 不该 import ${mod} —— 一旦知道 HTTP 入口，Core 就会被绑死`,
      )
    }
  }
})

test('契约层不 import 任何 Adapter 或 Core 实现', () => {
  for (const { name, src } of contractFiles()) {
    const imports = [...src.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((m) => m[1])
    for (const spec of imports) {
      assert.equal(/adapter|core\.mjs|handler|proxy/i.test(spec), false,
        `${name} 不该 import ${spec}`)
    }
  }
})

test('契约层只依赖 node:crypto 与自身', () => {
  for (const { name, src } of contractFiles()) {
    const imports = [...src.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((m) => m[1])
    for (const spec of imports) {
      const ok = spec === 'node:crypto' || spec.startsWith('./')
      assert.ok(ok, `${name} 引入了非预期依赖 ${spec}`)
    }
  }
})

/* ============================================================
 * 运行时：两个假 Adapter 产出同一种 context
 * ============================================================ */

/** 假 Forward Adapter：只从「请求行 + header」构造，不碰任何 HTTP 对象 */
function fakeForwardAdapter({ url, headers, client }) {
  return makeRequestContext({
    clientId: client.id,
    routeGroupId: client.routeGroupId,
    mode: 'forward',
    method: headers[':method'],
    originalUrl: url,
    headers,
  })
}

/** 假 Reverse Adapter：从「路径 + header」构造，输入形状完全不同 */
function fakeReverseAdapter({ path: p, headers, client }) {
  return makeRequestContext({
    clientId: client.id,
    routeGroupId: client.routeGroupId,
    mode: 'reverse',
    method: headers[':method'],
    originalUrl: `https://internal.invalid${p}`,
    headers,
  })
}

const CLIENT = { id: 'c1', routeGroupId: 'g1' }

test('两个 Adapter 产出的 context 字段集合相同', () => {
  const f = fakeForwardAdapter({
    url: 'https://api.example.com/v1/x?a=1',
    headers: { ':method': 'GET', 'content-type': 'application/json' },
    client: CLIENT,
  })
  const r = fakeReverseAdapter({
    path: '/v1/x?a=1',
    headers: { ':method': 'GET', 'content-type': 'application/json' },
    client: CLIENT,
  })

  assert.deepEqual(Object.keys(f).sort(), Object.keys(r).sort())

  // 除 mode 与 originalUrl（入口不同，天然不同）外，其余必须一致
  for (const k of Object.keys(f)) {
    if (k === 'mode' || k === 'originalUrl' || k === 'requestId' || k === 'startedAt') continue
    assert.deepEqual(f[k], r[k], `字段 ${k} 必须一致`)
  }
  assert.equal(f.mode, 'forward')
  assert.equal(r.mode, 'reverse')
})

/** 假 Core：只读 context，不关心它从哪个入口来 */
function fakeCore(ctx) {
  // 刻意只访问契约字段。如果实现里出现 ctx.req / ctx.socket，这条就会暴露。
  return {
    key: `${ctx.clientId}|${ctx.routeGroupId}`,
    method: ctx.method,
    url: ctx.originalUrl,
    hasBody: ctx.body !== null,
    aborted: ctx.signal.aborted,
    elapsedOk: Number.isFinite(ctx.startedAt),
  }
}

test('同一个 Core 处理两种入口的 context，除入口相关字段外结果一致', () => {
  const f = fakeForwardAdapter({
    url: 'https://api.example.com/x',
    headers: { ':method': 'POST' },
    client: CLIENT,
  })
  const r = fakeReverseAdapter({
    path: '/x',
    headers: { ':method': 'POST' },
    client: CLIENT,
  })

  const rf = fakeCore(f)
  const rr = fakeCore(r)

  assert.equal(rf.key, rr.key)
  assert.equal(rf.method, rr.method)
  assert.equal(rf.hasBody, rr.hasBody)
  assert.equal(rf.elapsedOk, true)
  assert.equal(rr.elapsedOk, true)
})

test('Core 访问的字段全部属于契约（用 Proxy 记录实际访问）', () => {
  const ctx = fakeForwardAdapter({
    url: 'https://api.example.com/x',
    headers: { ':method': 'GET' },
    client: CLIENT,
  })

  const allowed = new Set(Object.keys(ctx))
  const touched = new Set()

  const watched = new Proxy(ctx, {
    get(target, prop) {
      if (typeof prop === 'string') touched.add(prop)
      return Reflect.get(target, prop)
    },
  })

  fakeCore(watched)

  const outside = [...touched].filter((k) => !allowed.has(k))
  assert.deepEqual(outside, [], `Core 访问了契约外的字段: ${outside.join(', ')}`)
})

/* ============================================================
 * 认证失败必须在构造 context 之前发生
 * ============================================================ */

test('认证失败抛 ClientUnauthorized，不会产出「半认证」的 context', () => {
  function authThenBuild({ client }) {
    if (!client || client.revoked) {
      throw new ClientUnauthorized('client revoked')
    }
    return fakeForwardAdapter({
      url: 'https://api.example.com/x',
      headers: { ':method': 'GET' },
      client,
    })
  }

  assert.throws(() => authThenBuild({ client: null }), ClientUnauthorized)
  assert.throws(() => authThenBuild({ client: { revoked: true } }), ClientUnauthorized)

  // 关键：正常路径下 clientId 一定非空 —— 因为工厂会在空值时抛 TypeError，
  // 所以「存在一个 clientId 为空的 context」这件事在类型层面就不可能
  const c = authThenBuild({ client: CLIENT })
  assert.ok(c.clientId.length > 0)
})

test('客户端自报的身份字段无法进入 context', () => {
  // B2 要求：客户端提供的 x-client-id / x-route-group 必须被忽略。
  // 契约层无法阻止调用方犯错，但可以保证**字段值只来自入参**，
  // 不会因为 header 里同名而被覆盖。
  const c = makeRequestContext({
    clientId: 'real-client',
    routeGroupId: 'real-group',
    mode: 'forward',
    method: 'GET',
    originalUrl: 'https://x/',
    headers: {
      'x-client-id': 'spoofed',
      'x-route-group': 'spoofed-group',
    },
  })

  assert.equal(c.clientId, 'real-client', 'header 不能覆盖身份')
  assert.equal(c.routeGroupId, 'real-group')
  // header 仍在 headers 里（作为普通 header），但不影响身份字段
  assert.equal(c.headers['x-client-id'], 'spoofed')
})

/* ============================================================
 * 统一出口
 * ============================================================ */

test('index.mjs 导出全部契约成员', () => {
  const required = [
    'ProxyError', 'TargetDenied', 'ClientUnauthorized', 'DnsFailure', 'ConnectFailure',
    'TlsFailure', 'UpstreamTimeout', 'ClientCancelled', 'StreamFailure', 'RetryNotAllowed',
    'ERROR_CODES', 'errorFromCode', 'isProxyError',
    'makeRequestContext', 'isRequestContext', 'REQUEST_MODES',
    'makeUpstream', 'makeUpstreamGroup', 'makeProxyClient', 'makeRetryPolicy',
    'validateGroupReferences', 'UPSTREAM_PROTOCOLS', 'ROUTING_MODES',
  ]
  for (const k of required) {
    assert.ok(k in contract, `index.mjs 缺少导出 ${k}`)
  }
})

test('统一出口导出的工厂函数可用', () => {
  const u = contract.makeUpstream({ id: 'a', hostname: 'h' })
  const g = contract.makeUpstreamGroup({ id: 'g', upstreamIds: ['a'] })
  assert.equal(contract.validateGroupReferences(g, [u]).ok, true)
})
