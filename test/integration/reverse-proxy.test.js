/**
 * reverse-proxy.test.js — 通用反向代理 Adapter 集成测试（E1）
 *
 * 覆盖三条线：
 *   · 纯函数层：parseReversePath / buildTargetUrl 的解析与拒绝语义
 *   · 集成层：真实 http server + 注入 stub core，走完整个 handle 流程
 *   · 安全线：越权分组、路径穿越、伪造转发头、断连取消
 *
 * 不依赖真实上游：core 是注入点，测试用 stub core 捕获 RequestContext 并
 * 返回固定响应。目标验证用注入的 resolve（不产生真实 DNS），allowlist
 * 刻意只放 fixture 域名 —— 这本身就是「白名单精确匹配」的一次验证。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import {
  parseReversePath,
  buildTargetUrl,
  createReverseAdapter,
} from '../../lib/reverse-proxy.mjs'
import { makeUpstream, makeProxyClient } from '../../lib/contract/upstream.mjs'
import { TargetDenied } from '../../lib/contract/errors.mjs'
import { generateClientToken } from '../../lib/client-auth.mjs'

/* ============================================================
 * fixtures
 * ============================================================ */

/** fixture 上游：域名 + 非默认端口（8443，用于断言 Host 必须含端口） */
const UP = makeUpstream({ id: 'u1', hostname: 'upstream.example', port: 8443 })
/** 元数据地址上游：即使 allowPrivate 放开也必须被目标验证拒绝 */
const META_UP = makeUpstream({ id: 'meta', hostname: '169.254.169.254', port: 8443 })

const VALIDATOR = {
  allowlist: ['upstream.example', '169.254.169.254'],
  allowPrivate: true,
  allowedPorts: [8443, 443],
  // 测试注入假解析：127.0.0.1 走 loopback 分类，由 allowPrivate 放行
  resolve: async () => [{ address: '127.0.0.1', family: 4 }],
}

const { token: CLIENT_TOKEN, authTokenHash } = generateClientToken()
const CLIENT = makeProxyClient({ id: 'c1', routeGroupId: 'g1', authTokenHash })
const AUTH = [CLIENT]

/** 服务端绑定裁决：客户端绑什么分组是配置事实，URL 里写什么都不算数 */
function resolveGroup(clientId, groupFromUrl) {
  const client = AUTH.find((c) => c.id === clientId)
  if (client && client.routeGroupId === groupFromUrl) return client.routeGroupId
  return null
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** stub core：捕获 ctx 并返回固定响应 */
function recordingCore(response) {
  const calls = []
  return {
    calls,
    fn: async (ctx) => {
      calls.push(ctx)
      return response
    },
  }
}

/** 组装 adapter（默认配置与 fixtures 对齐，测试可覆盖任意字段） */
function makeAdapter(overrides = {}) {
  return createReverseAdapter({
    core: overrides.core,
    resolveGroup: overrides.resolveGroup ?? resolveGroup,
    resolveUpstream: overrides.resolveUpstream ?? (() => UP),
    validatorOptions: overrides.validatorOptions ?? VALIDATOR,
    stripPrefix: overrides.stripPrefix ?? null,
    upstreamPathPrefix: overrides.upstreamPathPrefix ?? null,
    auth: overrides.auth === undefined ? AUTH : overrides.auth,
    logger: overrides.logger,
  })
}

async function startServer(adapter) {
  const server = http.createServer((req, res) => {
    void adapter.handle(req, res)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return server
}

async function closeServer(server) {
  if (!server) return
  // Node 19+ 的全局 agent 默认 keep-alive：空闲连接会让 server.close()
  // 一直等下去（实测挂死过）。先摘空闲连接，close 之后再强制断剩余连接。
  server.closeIdleConnections?.()
  await new Promise((resolve) => server.close(() => resolve()))
  server.closeAllConnections?.()
}

/** 同步客户端请求 helper */
function httpRequest(port, { method = 'GET', path = '/', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const q = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        })
      })
      res.on('error', reject)
    })
    q.on('error', reject)
    if (body != null) q.write(body)
    q.end()
  })
}

function jsonOf(res) {
  try {
    return JSON.parse(res.body)
  } catch {
    return {}
  }
}

const ENTRY = '/__proxy/r/g1'

/* ============================================================
 * R1 正常 GET 转发
 * ============================================================ */
test('R1: 正常 GET 转发——路径、身份、mode 全部正确到达 core', async () => {
  const { fn: core, calls } = recordingCore({
    statusCode: 200,
    headers: { 'content-type': 'text/plain' },
    body: null,
  })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    const res = await httpRequest(server.address().port, {
      path: `${ENTRY}/hello`,
      headers: { authorization: `Bearer ${CLIENT_TOKEN}`, 'x-request-id': 'rid-1' },
    })
    assert.equal(res.status, 200)
    assert.equal(res.body, '')
    assert.equal(calls.length, 1, 'core 恰好被调用一次')
    const ctx = calls[0]
    assert.equal(ctx.mode, 'reverse')
    assert.equal(ctx.method, 'GET')
    assert.equal(ctx.originalUrl, `${ENTRY}/hello`)
    assert.equal(ctx.clientId, 'c1', '身份来自服务端认证，不来自请求头')
    assert.equal(ctx.routeGroupId, 'g1', '分组来自服务端绑定')
    assert.equal(ctx.headers['x-request-id'], 'rid-1')
    assert.equal(ctx.body, null, 'GET 无请求体')
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R2 五种方法
 * ============================================================ */
test('R2: GET/POST/PUT/DELETE/PATCH 方法与请求体正确进入 core', async () => {
  const methods = [
    ['GET', null],
    ['POST', 'post-body'],
    ['PUT', 'put-body'],
    ['DELETE', null],
    ['PATCH', 'patch-body'],
  ]
  for (const [method, body] of methods) {
    const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
    const adapter = makeAdapter({ core })
    const server = await startServer(adapter)
    try {
      const res = await httpRequest(server.address().port, {
        method,
        path: `${ENTRY}/m-${method.toLowerCase()}`,
        headers: {
          authorization: `Bearer ${CLIENT_TOKEN}`,
          ...(body != null ? { 'content-type': 'text/plain' } : {}),
        },
        body,
      })
      assert.equal(res.status, 200, `${method} 应成功`)
      assert.equal(calls.length, 1)
      assert.equal(calls[0].method, method)
      if (body != null) {
        assert.notEqual(calls[0].body, null, `${method} 带体时 core 应拿到流`)
      } else {
        assert.equal(calls[0].body, null)
      }
    } finally {
      await closeServer(server)
    }
  }
})

/* ============================================================
 * R3 查询参数原样传递
 * ============================================================ */
test('R3: 查询参数原样保留在目标 URL 上', async () => {
  const rawUrl = `${ENTRY}/a?x=1&y=%E4%B8%AD`
  const parsed = parseReversePath(rawUrl, {})
  assert.equal(parsed.query, '?x=1&y=%E4%B8%AD', 'query 原样保留（含转义）')

  const target = buildTargetUrl(UP, parsed.restPath, { query: parsed.query })
  assert.equal(target.search, '?x=1&y=%E4%B8%AD', '拼接到目标后不被改写')
  assert.equal(target.pathname, '/a')

  // 集成面：originalUrl 带着原始 query 交给 core
  const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    await httpRequest(server.address().port, {
      path: rawUrl,
      headers: { authorization: `Bearer ${CLIENT_TOKEN}` },
    })
    assert.equal(calls[0].originalUrl, rawUrl)
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R4 越权 RouteGroup
 * ============================================================ */
test('R4: URL 写未绑定的分组 → 403 且 core 未被调用', async () => {
  const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    const res = await httpRequest(server.address().port, {
      path: '/__proxy/r/g2/data',
      headers: { authorization: `Bearer ${CLIENT_TOKEN}` },
    })
    assert.equal(res.status, 403)
    assert.equal(jsonOf(res).error, 'group_denied')
    assert.equal(calls.length, 0, '越权请求连 core 的影子都不该看到')
    assert.equal(adapter.stats().errors, 1)
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R5 路径穿越被拒
 * ============================================================ */
test('R5: ../ 与 %2e%2e%2f（及双重编码）一律 403', async () => {
  const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    const port = server.address().port
    const cases = [
      [`${ENTRY}/a/../secret`, '原始 ../'],
      [`${ENTRY}/%2e%2e/secret`, '单层编码 %2e%2e'],
      [`${ENTRY}/%2e%2e%2fsecret`, '段内编码 %2e%2e%2f'],
      [`${ENTRY}/%252e%252e/secret`, '双重编码 %252e%252e'],
    ]
    for (const [path, label] of cases) {
      const res = await httpRequest(port, {
        path,
        headers: { authorization: `Bearer ${CLIENT_TOKEN}` },
      })
      assert.equal(res.status, 403, `${label} 必须被拒`)
      assert.equal(jsonOf(res).error, 'target_denied', `${label} 的错误码应为 target_denied`)
    }
    assert.equal(calls.length, 0, '穿越路径绝不能到达 core')
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R6 stripPrefix 语义
 * ============================================================ */
test('R6: stripPrefix 剥离入口前缀；不匹配则拒绝', () => {
  const target = buildTargetUrl(UP, '/api/v1/x', { stripPrefix: '/api' })
  assert.equal(target.pathname, '/v1/x')
  assert.equal(target.host, 'upstream.example:8443')

  // 入口路径与剥离前缀不一致：属于路由配置错位，硬转发只会把错误的
  // 路径送到上游，必须拒绝
  assert.throws(
    () => buildTargetUrl(UP, '/other/v1/x', { stripPrefix: '/api' }),
    TargetDenied,
  )
})

/* ============================================================
 * R7 upstreamPathPrefix 语义
 * ============================================================ */
test('R7: upstreamPathPrefix 追加在上游路径前，与 stripPrefix 可组合', () => {
  const only = buildTargetUrl(UP, '/v1/x', { upstreamPathPrefix: '/edge' })
  assert.equal(only.pathname, '/edge/v1/x')

  const both = buildTargetUrl(UP, '/api/v1/x', {
    stripPrefix: '/api',
    upstreamPathPrefix: '/edge',
  })
  assert.equal(both.pathname, '/edge/v1/x')

  // 前缀拼在根路径上不应出现双斜杠
  const root = buildTargetUrl(UP, '/', { upstreamPathPrefix: '/edge' })
  assert.equal(root.pathname, '/edge')
})

/* ============================================================
 * R8 伪造 X-Forwarded-Host 不影响目标
 * ============================================================ */
test('R8: 伪造 X-Forwarded-Host/Proto 被删除，并以服务端事实重写', async () => {
  const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    const res = await httpRequest(server.address().port, {
      path: `${ENTRY}/fwd`,
      headers: {
        authorization: `Bearer ${CLIENT_TOKEN}`,
        'x-forwarded-host': 'evil.example',
        'x-forwarded-proto': 'http',
      },
    })
    assert.equal(res.status, 200)
    const ctx = calls[0]
    assert.equal(
      ctx.headers['x-forwarded-host'],
      'upstream.example:8443',
      '转发主机必须是服务端算出的事实',
    )
    assert.equal(ctx.headers['x-forwarded-proto'], 'https', '协议来自 upstream，不是客户端')
    assert.notEqual(ctx.headers['x-forwarded-host'], 'evil.example')
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R9 Host 由目标决定
 * ============================================================ */
test('R9: Host 头完全由目标 upstream 决定', async () => {
  const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    const res = await httpRequest(server.address().port, {
      path: `${ENTRY}/host`,
      headers: {
        authorization: `Bearer ${CLIENT_TOKEN}`,
        host: 'attacker.example',
      },
    })
    assert.equal(res.status, 200)
    assert.equal(
      calls[0].headers['host'],
      'upstream.example:8443',
      '非默认端口必须体现在 Host 里',
    )
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R10 逐跳剥离、端到端保留
 * ============================================================ */
test('R10: 逐跳头（含 Connection 动态声明）被剥离，端到端头保留', async () => {
  const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    const res = await httpRequest(server.address().port, {
      path: `${ENTRY}/hdr`,
      headers: {
        authorization: `Bearer ${CLIENT_TOKEN}`,
        connection: 'X-Internal',
        'x-internal': 'hop-secret',
        'te': 'trailers',
        'x-request-id': 'rid-2',
        'accept-language': 'zh-CN',
      },
    })
    assert.equal(res.status, 200)
    const h = calls[0].headers
    assert.equal(h['connection'], undefined, 'connection 是逐跳字段')
    assert.equal(h['x-internal'], undefined, 'Connection 动态声明的字段同样是逐跳字段')
    assert.equal(h['te'], undefined)
    assert.equal(h['x-request-id'], 'rid-2', '端到端字段必须原样保留')
    assert.equal(h['accept-language'], 'zh-CN')
    assert.equal(h['authorization'], `Bearer ${CLIENT_TOKEN}`, '凭据是端到端字段')
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R11 认证失败 → 401
 * ============================================================ */
test('R11: 缺凭据与错凭据都返回 401，core 不被调用', async () => {
  const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    const port = server.address().port
    const noAuth = await httpRequest(port, { path: `${ENTRY}/x` })
    assert.equal(noAuth.status, 401)
    assert.equal(jsonOf(noAuth).error, 'client_unauthorized')

    const wrong = await httpRequest(port, {
      path: `${ENTRY}/x`,
      headers: { authorization: 'Bearer not-the-right-token' },
    })
    assert.equal(wrong.status, 401)

    // 冒名自报身份头不能救回来：剥掉之后凭据照样无效
    const spoof = await httpRequest(port, {
      path: `${ENTRY}/x`,
      headers: {
        authorization: 'Bearer not-the-right-token',
        'x-client-id': 'c1',
        'x-route-group': 'g1',
      },
    })
    assert.equal(spoof.status, 401, '自报身份头必须被剥掉，不能替代认证')

    assert.equal(calls.length, 0)
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R12 上游验证失败 → 403
 * ============================================================ */
test('R12: 目标是云元数据地址 → 目标验证拒绝 → 403', async () => {
  const { fn: core, calls } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({
    core,
    resolveUpstream: () => META_UP,
  })
  const server = await startServer(adapter)
  try {
    const res = await httpRequest(server.address().port, {
      path: `${ENTRY}/meta`,
      headers: { authorization: `Bearer ${CLIENT_TOKEN}` },
    })
    assert.equal(res.status, 403)
    assert.equal(jsonOf(res).error, 'target_denied')
    assert.equal(calls.length, 0, '验证失败不得进入 core')
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * R13 客户端断连后 body 被取消
 * ============================================================ */
test('R13: 客户端断连 → 响应体流被立刻取消', async () => {
  const cancelDone = deferred()
  let cancelled = false
  let interval = null
  const encoder = new TextEncoder()
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('chunk-1'))
      interval = setInterval(() => {
        try {
          controller.enqueue(encoder.encode('tick'))
        } catch {
          // 流已被取消：定时器会在 cancel 回调里清掉，这里只是兜底
        }
      }, 50)
      // 兜底：即使 cancel 因缺陷未被触发，也不能让定时器拖住进程退出
      interval.unref?.()
    },
    cancel() {
      cancelled = true
      if (interval) clearInterval(interval)
      cancelDone.resolve()
    },
  })

  const { fn: core } = recordingCore({ statusCode: 200, headers: {}, body })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    await new Promise((resolve, reject) => {
      const q = http.request(
        {
          host: '127.0.0.1',
          port: server.address().port,
          path: `${ENTRY}/stream`,
          // 没有凭据会在认证层被 401，core 根本不会执行——
          // 那样断言的就不是「断连取消」而是「没走到转发」
          headers: { authorization: `Bearer ${CLIENT_TOKEN}` },
        },
        (res) => {
          res.once('data', () => {
            res.destroy()
            resolve()
          })
          res.on('error', () => { /* 客户端主动断开，error 预期出现 */ })
        },
      )
      q.on('error', reject)
      q.end()
    })

    // 给取消一个有界等待：超过 5 秒还没取消就是缺陷，不能让测试挂死
    await Promise.race([
      cancelDone.promise,
      sleep(5000).then(() => {
        throw new Error('客户端断开 5s 后响应体仍未被取消')
      }),
    ])
    assert.equal(cancelled, true, '上游响应体必须收到 cancel')
  } finally {
    await closeServer(server)
  }
})

/* ============================================================
 * 附加：纯函数边界
 * ============================================================ */

test('R14: parseReversePath 边界——前缀不匹配 / 无分组段 / 分组段含 %2f 都返回 null', () => {
  assert.equal(parseReversePath('/nope/r/g1', {}), null, '前缀不匹配')
  assert.equal(parseReversePath('/__proxy/r', {}), null, '只有前缀没有分组段')
  assert.equal(parseReversePath('/__proxy/r/g%2f1/x', {}), null, '分组段解码出 /')
  assert.equal(parseReversePath('', {}), null)
  const ok = parseReversePath('/__proxy/r/g1/x?y=2', {})
  assert.notEqual(ok, null)
  assert.equal(ok.groupFromUrl, 'g1')
  assert.equal(ok.restPath, '/x')
  assert.equal(ok.query, '?y=2')

  // 前缀是段级匹配：/__proxy/rect 不能命中 /__proxy/r
  assert.equal(parseReversePath('/__proxy/rect/x', {}), null)
})

test('R15: buildTargetUrl 拒绝 raw ../ 与双重编码；协议与 Host 完全来自 upstream', () => {
  assert.throws(() => buildTargetUrl(UP, '/../x', {}), TargetDenied)
  assert.throws(() => buildTargetUrl(UP, '/%252e%252e/x', {}), TargetDenied)
  assert.throws(() => buildTargetUrl(UP, '/a%2fb', {}), TargetDenied, '段内嵌 %2f 也是穿越变体')

  const t = buildTargetUrl(UP, '/x', {})
  assert.equal(t.protocol, 'https:')
  assert.equal(t.host, 'upstream.example:8443')
})

test('R16: stats 计数随请求累积', async () => {
  const { fn: core } = recordingCore({ statusCode: 200, headers: {}, body: null })
  const adapter = makeAdapter({ core })
  const server = await startServer(adapter)
  try {
    const port = server.address().port
    await httpRequest(port, { path: `${ENTRY}/s1`, headers: { authorization: `Bearer ${CLIENT_TOKEN}` } })
    await httpRequest(port, { path: '/__proxy/r/g2/s2', headers: { authorization: `Bearer ${CLIENT_TOKEN}` } })
    await httpRequest(port, { path: `${ENTRY}/s3` })
    const s = adapter.stats()
    assert.equal(s.requests, 3)
    assert.equal(s.ok, 1)
    assert.equal(s.errors, 2)
  } finally {
    await closeServer(server)
  }
})
