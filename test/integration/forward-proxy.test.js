/**
 * forward-proxy.test.js — 正向代理 Adapter（D1）
 *
 * 全部走真实 http.createServer + http.request：正向代理的输入形态
 * （absolute-form 请求行、chunked 请求体、客户端中途断开）只有在真实
 * 的 Node HTTP 栈里才长得出来，手搓桩测不出协议层的意外。
 * 上游用假 core，不连外网 —— Adapter 的职责边界（§5.8：不选路）正是
 * 用「core 被调用几次」来钉死的。
 *
 * 判据都是可观测量：
 *   · 旁路 = core 调用次数 vs 收到的请求数；
 *   · Host 决定权 = core 收到的 headers.host；
 *   · 流式 = 客户端 data 事件的时间差与分块数；
 *   · 取消 = core 读请求体时 read() 拒绝 + ctx.signal.aborted。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import { createForwardAdapter, parseForwardRequest } from '../../lib/forward-proxy.mjs'
import { makeProxyClient } from '../../lib/contract/upstream.mjs'
import { generateClientToken } from '../../lib/client-auth.mjs'
import { ClientUnauthorized } from '../../lib/contract/errors.mjs'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/* ============================================================
 * 固定夹具
 * ============================================================ */

// Token 明文只在测试进程内存里出现；配置面存的是 sha256 摘要
const { token: TOKEN, authTokenHash: TOKEN_HASH } = generateClientToken()
const AUTH = { authorization: `Bearer ${TOKEN}` }

const CLIENTS = [
  makeProxyClient({ id: 'c1', name: '测试客户端', routeGroupId: 'g1', authTokenHash: TOKEN_HASH }),
]

/** 目标验证用的假解析：upstream.test → 一个公网地址，绝不出网 */
const VALIDATOR_OPTIONS = {
  allowlist: ['upstream.test'],
  resolve: async () => [{ address: '93.184.216.34', family: 4 }],
}

/* ============================================================
 * 辅助
 * ============================================================ */

/** 把一段文本包成一次性读完的 Web 流（Core 返回体的最小实现） */
function streamOf(text) {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(text))
      controller.close()
    },
  })
}

/** 把请求体流读成文本（测试里用，生产路径禁止整读） */
async function readBodyText(body) {
  if (!body) return ''
  const reader = body.getReader()
  /** @type {Buffer[]} */
  const chunks = []
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(Buffer.from(value))
  }
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * 起一个真实 HTTP 服务，挂上被测 Adapter。
 * listen(0) 拿随机端口，避免并发跑测试时端口互踩。
 */
async function startServer(overrides = {}) {
  const adapter = createForwardAdapter({
    clients: CLIENTS,
    validatorOptions: VALIDATOR_OPTIONS,
    ...overrides,
  })
  const server = http.createServer((req, res) => {
    void adapter.handle(req, res).catch(() => { /* handle 自身有 catch-all，这里只兜底 */ })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = /** @type {import('node:net').AddressInfo} */ (server.address())
  return {
    server,
    adapter,
    port: addr.port,
    close: () => new Promise((resolve) => server.close(() => resolve(null))),
  }
}

/**
 * 真实客户端请求。path 必须是完整 absolute-form（正向代理的客户端形态）。
 */
function proxyRequest(port, { method = 'GET', target, headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, method, path: target, headers },
      (res) => {
        /** @type {Buffer[]} */
        const chunks = []
        res.on('data', (c) => chunks.push(/** @type {Buffer} */ (c)))
        res.on('end', () => resolve({
          status: res.statusCode,
          headers: res.headers,
          text: Buffer.concat(chunks).toString('utf8'),
        }))
        res.on('error', reject)
      },
    )
    req.on('error', reject)
    if (body != null) req.write(body)
    req.end()
  })
}

/** 记录调用的假 core；默认回显方法与路径 */
function makeEchoCore(calls) {
  return async (ctx) => {
    calls.push(ctx)
    const bodyText = ctx.body ? await readBodyText(ctx.body) : ''
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'x-echo-method': ctx.method },
      body: streamOf(`${ctx.method} ${ctx.originalUrl} body=${bodyText}`),
    }
  }
}

/* ============================================================
 * 1-2. 正常转发与方法覆盖
 * ============================================================ */

test('1. 正常 GET：absolute-form 转发，身份与上下文正确', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close, adapter } = await startServer({ core: makeEchoCore(calls) })
  try {
    const res = await proxyRequest(port, {
      target: 'http://upstream.test/hello?x=1',
      headers: { ...AUTH, accept: 'application/json' },
    })

    assert.equal(res.status, 200, `应转发成功，实际 ${res.status} ${res.text}`)
    assert.equal(res.headers['x-echo-method'], 'GET')
    assert.equal(res.text, 'GET http://upstream.test/hello?x=1 body=')

    assert.equal(calls.length, 1, 'core 应恰好被调用一次')
    const ctx = calls[0]
    assert.equal(ctx.mode, 'forward')
    assert.equal(ctx.method, 'GET')
    assert.equal(ctx.originalUrl, 'http://upstream.test/hello?x=1')
    assert.equal(ctx.clientId, 'c1', '身份必须来自服务端认证结果')
    assert.equal(ctx.routeGroupId, 'g1')
    assert.ok(ctx.requestId && typeof ctx.requestId === 'string')
    assert.ok(Number.isFinite(ctx.startedAt))
    assert.equal(ctx.signal.aborted, false)
    assert.equal(ctx.headers.accept, 'application/json')
    assert.equal(adapter.stats().active, 0, '请求结束后不应有悬挂的计数')
  } finally {
    await close()
  }
})

test('2. 五种方法全部转发', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
      const hasBody = method === 'POST' || method === 'PUT'
      const res = await proxyRequest(port, {
        method,
        target: `http://upstream.test/m/${method.toLowerCase()}`,
        headers: AUTH,
        body: hasBody ? 'payload-1' : null,
      })
      assert.equal(res.status, 200, `${method} 应转发成功`)
      assert.equal(res.headers['x-echo-method'], method)
      const expected = hasBody ? 'body=payload-1' : 'body='
      assert.equal(res.text, `${method} http://upstream.test/m/${method.toLowerCase()} ${expected}`)
    }
    assert.equal(calls.length, 5)
    assert.deepEqual(calls.map((c) => c.method), ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
  } finally {
    await close()
  }
})

/* ============================================================
 * 3. 查询参数完整性
 * ============================================================ */

test('3. 查询参数原样保留（多参数、编码、空值）', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    // %E4%B8%AD = 中；%20 = 空格；%2B = +；c= 空值。原样穿透，不重编码
    const target = 'http://upstream.test/p?a=1&b=%E4%B8%AD&c=&d=%20&f=a%2Bb'
    const res = await proxyRequest(port, { target, headers: AUTH })
    assert.equal(res.status, 200)
    assert.equal(calls[0].originalUrl, target, 'core 拿到的 URL 必须与客户端发的逐字节一致')
    assert.equal(res.text, `GET ${target} body=`)
  } finally {
    await close()
  }
})

/* ============================================================
 * 4-6. 解析层拒绝
 * ============================================================ */

test('4. origin-form 被拒（400），core 未被调用', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    const res = await proxyRequest(port, { target: '/reverse/path', headers: AUTH })
    assert.equal(res.status, 400)
    const parsed = JSON.parse(res.text)
    assert.equal(parsed.code, 'bad_request')
    assert.equal(parsed.reason, 'origin_form')
    assert.equal(calls.length, 0, '被拒的请求绝不能到 core')
  } finally {
    await close()
  }
})

test('5. userinfo 被拒（400）', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    const res = await proxyRequest(port, { target: 'http://user:pass@upstream.test/', headers: AUTH })
    assert.equal(res.status, 400)
    const parsed = JSON.parse(res.text)
    assert.equal(parsed.code, 'bad_request')
    assert.equal(parsed.reason, 'userinfo')
    assert.equal(calls.length, 0)
  } finally {
    await close()
  }
})

test('6. 非法百分号编码被拒（400）', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    const res = await proxyRequest(port, { target: 'http://upstream.test/p%zz', headers: AUTH })
    assert.equal(res.status, 400)
    const parsed = JSON.parse(res.text)
    assert.equal(parsed.code, 'bad_request')
    assert.equal(parsed.reason, 'bad_percent_encoding')
    assert.equal(calls.length, 0)
  } finally {
    await close()
  }
})

/* ============================================================
 * 7. 无旁路
 * ============================================================ */

test('7. core 调用次数 == 到达转发的请求数（Adapter 无旁路）', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close, adapter } = await startServer({ core: makeEchoCore(calls) })
  try {
    const r1 = await proxyRequest(port, { target: 'http://upstream.test/a', headers: AUTH })
    const r2 = await proxyRequest(port, { target: '/origin-form', headers: AUTH }) // 400，被拒
    const r3 = await proxyRequest(port, { target: 'http://upstream.test/b', headers: {} }) // 401，被拒
    const r4 = await proxyRequest(port, { target: 'http://upstream.test/c', headers: AUTH })
    const r5 = await proxyRequest(port, { target: 'http://not-allowed.test/x', headers: AUTH }) // 403，被拒
    const r6 = await proxyRequest(port, { target: 'http://upstream.test/d', headers: AUTH })

    assert.equal(r1.status, 200)
    assert.equal(r2.status, 400)
    assert.equal(r3.status, 401)
    assert.equal(r4.status, 200)
    assert.equal(r5.status, 403)
    assert.equal(r6.status, 200)

    assert.equal(calls.length, 3, '只有通过全部门禁的请求才会到 core')
    const stats = adapter.stats()
    assert.equal(stats.total, 6)
    assert.equal(stats.rejected, 3, '400/401/403 三次被拒')
    assert.equal(stats.ok, 3)
    assert.equal(stats.active, 0)
  } finally {
    await close()
  }
})

/* ============================================================
 * 8-9. Header 处理
 * ============================================================ */

test('8. 逐跳头剥离、端到端头保留', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    const res = await proxyRequest(port, {
      target: 'http://upstream.test/headers',
      headers: {
        ...AUTH,
        connection: 'keep-alive, x-internal', // 动态声明的逐跳字段必须一并剥
        'keep-alive': 'timeout=5',
        te: 'trailers',
        'proxy-authorization': 'Basic dXNlcjpwYXNz',
        'x-internal': 'leak-me',
        accept: 'application/json',
        'x-request-id': 'req-8',
      },
    })
    assert.equal(res.status, 200)

    const h = calls[0].headers
    assert.equal(h.connection, undefined)
    assert.equal(h['keep-alive'], undefined)
    assert.equal(h.te, undefined)
    assert.equal(h['proxy-authorization'], undefined)
    assert.equal(h['x-internal'], undefined, 'Connection 动态声明的字段也必须剥掉')
    assert.equal(h.authorization, `Bearer ${TOKEN}`, '端到端字段必须原样保留')
    assert.equal(h.accept, 'application/json')
    assert.equal(h['x-request-id'], 'req-8')
  } finally {
    await close()
  }
})

test('9. Host 由目标决定，伪造 Host 头不生效', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    const res = await proxyRequest(port, {
      target: 'http://upstream.test/who',
      headers: { ...AUTH, host: 'evil.example' },
    })
    assert.equal(res.status, 200)
    const h = calls[0].headers
    assert.equal(h.host, 'upstream.test', 'Host 必须改写为请求行 authority')
    assert.ok(
      !JSON.stringify(h).includes('evil.example'),
      '客户端伪造的 Host 不得以任何形式出现在转发头里',
    )
  } finally {
    await close()
  }
})

/* ============================================================
 * 10-11. 门禁
 * ============================================================ */

test('10. 认证失败 → 401（缺凭据与错凭据两种）', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    const noAuth = await proxyRequest(port, { target: 'http://upstream.test/x' })
    assert.equal(noAuth.status, 401)
    assert.equal(JSON.parse(noAuth.text).code, 'client_unauthorized')

    const badAuth = await proxyRequest(port, {
      target: 'http://upstream.test/x',
      headers: { authorization: 'Bearer not-the-token' },
    })
    assert.equal(badAuth.status, 401)
    assert.equal(JSON.parse(badAuth.text).code, 'client_unauthorized')

    assert.equal(calls.length, 0, '认证失败的请求绝不能到 core')
  } finally {
    await close()
  }
})

test('11. 目标验证失败 → 403', async () => {
  /** @type {any[]} */
  const calls = []
  const { port, close } = await startServer({ core: makeEchoCore(calls) })
  try {
    const res = await proxyRequest(port, {
      target: 'http://not-in-allowlist.test/x',
      headers: AUTH,
    })
    assert.equal(res.status, 403)
    const parsed = JSON.parse(res.text)
    assert.equal(parsed.code, 'target_denied')
    assert.equal(parsed.reason, 'not_allowlisted')
    assert.equal(calls.length, 0)
  } finally {
    await close()
  }
})

/* ============================================================
 * 12. 客户端取消
 * ============================================================ */

test('12. 客户端断连后请求体被取消', async () => {
  /** @type {any[]} */
  const calls = []
  /** @type {{ readError: unknown, aborted: boolean } | null} */
  let observed = null
  const firstChunkRead = /** @type {ReturnType<import('../helpers/deferred.mjs').deferred>} */ ({})
  const firstReadDone = {
    promise: new Promise((resolve) => { firstChunkRead.resolve = resolve }),
  }

  const core = async (ctx) => {
    calls.push(ctx)
    const reader = ctx.body.getReader()
    const first = await reader.read()
    firstChunkRead.resolve(first.value)
    // 第二块永远不会来：客户端此刻断开，read 必须以失败收场
    try {
      await reader.read()
    } catch (err) {
      observed = { readError: err, aborted: ctx.signal.aborted }
    }
    // 返回值无所谓：客户端已不在，Adapter 应当作取消收场而不是崩溃
    return { statusCode: 200, headers: {}, body: null }
  }

  const { port, close, adapter } = await startServer({ core })
  try {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: 'http://upstream.test/upload',
      headers: AUTH, // 无 content-length，Node 自动改用 chunked
    })
    req.on('error', () => { /* 客户端主动断开，错误可预期 */ })
    req.write('chunk-1-')

    // 等 core 真正读到第一块，再断开 —— 保证「读一半」这个状态真的发生过
    await firstReadDone.promise
    req.destroy()
    await new Promise((r) => setTimeout(r, 150))

    assert.ok(observed, 'core 应当观察到第二次读取失败')
    assert.ok(observed.readError instanceof Error, `read() 应以错误拒绝，实际 ${String(observed.readError)}`)
    assert.equal(observed.aborted, true, 'ctx.signal 必须已经中止')
    assert.ok(adapter.stats().clientCancelled >= 1, '断连应记为客户端取消')
  } finally {
    await close()
  }
})

/* ============================================================
 * 13. 响应体流式
 * ============================================================ */

test('13. 响应体流式：首块早于整体完成', async () => {
  /** @type {any[]} */
  const calls = []
  const core = async (ctx) => {
    calls.push(ctx)
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/plain' },
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(encoder.encode('first-'))
        },
        async pull(controller) {
          // 制造明显的「第二块比第一块晚」：如果实现是整读缓冲，
          // 客户端只会看到一次 data 事件，这里的时间差就测不出来
          await new Promise((r) => setTimeout(r, 200))
          controller.enqueue(encoder.encode('second'))
          controller.close()
        },
      }),
    }
  }
  const { port, close } = await startServer({ core })
  try {
    const result = await new Promise((resolve, reject) => {
      /** @type {{ at: number, text: string }[]} */
      const events = []
      let endedAt = 0
      const req = http.request(
        { host: '127.0.0.1', port, path: 'http://upstream.test/stream', headers: AUTH },
        (res) => {
          res.on('data', (c) => events.push({ at: Date.now(), text: c.toString() }))
          res.on('end', () => {
            endedAt = Date.now()
            resolve({ events, endedAt, status: res.statusCode })
          })
          res.on('error', reject)
        },
      )
      req.on('error', reject)
      req.end()
    })

    assert.equal(result.status, 200)
    assert.equal(calls.length, 1)
    assert.equal(result.events.length, 2, '客户端应看到两次 data 事件（逐块到达）')
    assert.equal(
      result.events.map((e) => e.text).join(''),
      'first-second',
      '字节完整性：两块拼起来必须等于 Core 给的全部内容',
    )
    assert.ok(
      result.events[1].at - result.events[0].at >= 100,
      `第二块应明显晚于首块到达（首块先行），实际间隔 ${result.events[1].at - result.events[0].at}ms`,
    )
    assert.ok(result.endedAt >= result.events[1].at)
  } finally {
    await close()
  }
})

/* ============================================================
 * 14-15. parseForwardRequest 纯函数
 * ============================================================ */

test('14. parseForwardRequest：合法 absolute-form 的解析结果', () => {
  const parsed = parseForwardRequest({
    method: 'get', // 小写也要规范化成大写
    url: 'http://UpStream.Test/Path?X=1',
    headers: { 'X-Custom': 'v', Connection: 'keep-alive' },
  })
  assert.equal(parsed.method, 'GET')
  assert.equal(parsed.url, 'http://UpStream.Test/Path?X=1', 'URL 字符串必须原样保留')
  assert.deepEqual(parsed.headers, { 'x-custom': 'v', connection: 'keep-alive' })
  assert.equal(parsed.body, null, '未声明请求体时 body 必须是 null')

  const emptyCl = parseForwardRequest({
    method: 'POST',
    url: 'http://h/p',
    headers: { 'content-length': '0' },
  })
  assert.equal(emptyCl.body, null, 'Content-Length: 0 视为无体')
})

test('15. parseForwardRequest：各拒绝形态与原因', () => {
  /** @type {[{ method?: string, url: string, headers?: object }, string][]} */
  const cases = [
    [{ method: 'GET', url: '/origin/path' }, 'origin_form'],
    [{ method: 'GET', url: 'upstream.test/x' }, 'not_absolute_form'],
    [{ method: 'GET', url: 'ftp://upstream.test/x' }, 'not_absolute_form'],
    [{ method: 'CONNECT', url: 'upstream.test:443' }, 'connect_not_supported'],
    [{ method: 'GET', url: 'http://user:pass@upstream.test/' }, 'userinfo'],
    [{ method: 'GET', url: 'http://upstream.test/p%zz' }, 'bad_percent_encoding'],
    [{ method: 'GET', url: 'http://upstream.test/p#frag' }, 'has_fragment'],
    [{ method: 'GET', url: 'http://upstream.test/p\u0001' }, 'control_chars'],
    // 最小等价对象声明了体但没有流可包 → 必须显式拒绝而不是包出假流
    [{ method: 'POST', url: 'http://h/p', headers: { 'content-length': '5' } }, 'body_requires_stream'],
  ]
  for (const [input, expectedReason] of cases) {
    try {
      parseForwardRequest(/** @type {any} */ (input))
      assert.fail(`应拒绝：${JSON.stringify(input)}`)
    } catch (err) {
      assert.ok(err instanceof TypeError, `${expectedReason} 应抛 TypeError`)
      assert.equal(/** @type {any} */ (err).forwardReject, true, `${expectedReason} 必须带 forwardReject 标记`)
      assert.equal(/** @type {any} */ (err).reason, expectedReason)
    }
  }
})

// decoder 留给后续断言扩展；避免 no-unused 变成噪音
void decoder


/* ============================================================
 * 请求体清理（独立审查发现的资源泄漏，2026-11-24）
 * ============================================================ */

/**
 * 认证失败时，请求体流必须被清理，不能让连接挂起等剩余 body。
 *
 * 为什么这条要单独测：`Readable.toWeb(req)` 不会主动消费 req。如果失败路径
 *（401 / 403 / Core 抛错）不 cancel 它，req 会一直是 paused，一个**不需要
 * 凭据**的客户端只要声明巨大的 Content-Length、只发一小段就开始等，就能让
 * 连接无法复用 —— 累积下去能压满连接池。
 *
 * 断言方式：发一个声明 1 MB 但只发 100 字节的请求，收到 401 之后 socket
 * 必须在短时间内关闭。修复前它会一直挂着等剩下 1 MB。
 */
test('认证失败后请求体被清理，连接不挂起等待剩余 body', async () => {
  const { port, close } = await startServer({
    core: makeEchoCore([]),
    auth: async () => { throw new ClientUnauthorized('拒绝', { reason: 'test_reject' }) },
  })

  try {
    const closed = await new Promise((resolve) => {
      const req = http.request({
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: 'http://upstream.test/upload',
        headers: { 'content-length': '1048576' },
      })

      let got401 = false
      req.on('response', (res) => {
        got401 = res.statusCode === 401
        res.resume()
      })
      // socket 关闭（正常结束或 RST 都算）说明请求体没被挂着等
      req.on('error', () => { /* 预期：服务端 destroy 会引起 ECONNRESET */ })
      req.on('close', () => resolve(got401))
      req.write('x'.repeat(100))

      // 兜底：超过 2 秒还没关就算失败
      setTimeout(() => resolve(false), 2000)
    })

    assert.equal(closed, true,
      '请求体未清理：连接挂着等待剩余 Content-Length，未认证客户端可借此耗尽连接池')
  } finally {
    await close()
  }
})
