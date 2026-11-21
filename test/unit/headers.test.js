/**
 * headers.test.js — 请求/响应 Header 边界（Issue #5）
 *
 * 验收重点（评审）：**不是**「把所有看起来特殊的 Header 都删掉」，
 * 而是遵守端到端字段与逐跳字段的边界（RFC 7230 §6.1）。
 *
 * 端到端要保留：content-encoding / content-type / authorization / accept-* / x-request-id
 * 逐跳必须剥离：connection / keep-alive / proxy-* / te / trailer / transfer-encoding / upgrade
 *              + Connection 头里动态列出的任意字段
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  connectionTokens, filterRequestHeaders, filterResponseHeaders,
  isEventStream, handleExpectContinue,
} from '../../lib/headers.mjs'

/* ============================================================
 * Connection 动态字段
 * ============================================================ */

test('Connection 头里动态列出的字段全部被识别', () => {
  assert.deepEqual(connectionTokens({ connection: 'keep-alive, X-Internal, X-Other' }),
    ['keep-alive', 'x-internal', 'x-other'])
  assert.deepEqual(connectionTokens({ connection: 'close' }), ['close'])
  assert.deepEqual(connectionTokens({}), [])
  assert.deepEqual(connectionTokens({ connection: '' }), [])
  // 多条、混空格、大小写
  assert.deepEqual(connectionTokens({ Connection: 'Te , X-A' }), ['te', 'x-a'])
})

test('Connection: X-Internal 时 X-Internal 也必须被过滤', () => {
  const out = filterRequestHeaders(
    { connection: 'X-Internal', 'x-internal': 'must-not-leak', 'x-keep': 'ok' },
    { targetHost: 'up.example' },
  )
  assert.equal(out['x-internal'], undefined, '动态声明的逐跳字段必须剥离')
  assert.equal(out['x-keep'], 'ok')
})

/* ============================================================
 * 请求头
 * ============================================================ */

test('请求：标准逐跳字段全部剥离', () => {
  const out = filterRequestHeaders({
    connection: 'keep-alive',
    'keep-alive': 'timeout=5',
    'proxy-authenticate': 'Basic',
    'proxy-authorization': 'Basic x',
    te: 'trailers',
    trailer: 'X-Sum',
    'transfer-encoding': 'chunked',
    upgrade: 'h2c',
    'content-length': '100',
  }, { targetHost: 'up.example' })

  for (const k of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
    assert.equal(out[k], undefined, `${k} 应被剥离`)
  }
  // transfer-encoding 剥离后，content-length 也不再可信（原来是 chunked 的伪装长度）
  assert.equal(out['content-length'], undefined)
})

test('请求：端到端字段必须保留', () => {
  const out = filterRequestHeaders({
    authorization: 'Bearer secret',
    'content-type': 'application/json',
    'content-encoding': 'gzip',
    accept: 'application/json',
    'accept-encoding': 'gzip, br',
    'x-request-id': 'abc-123',
    'user-agent': 'test/1.0',
  }, { targetHost: 'up.example' })

  for (const [k, v] of Object.entries({
    authorization: 'Bearer secret',
    'content-type': 'application/json',
    'content-encoding': 'gzip',
    accept: 'application/json',
    'accept-encoding': 'gzip, br',
    'x-request-id': 'abc-123',
    'user-agent': 'test/1.0',
  })) {
    assert.equal(out[k], v, `${k} 是端到端字段，必须保留`)
  }
})

test('请求：Host 被改写成上游域名', () => {
  const out = filterRequestHeaders({ host: '127.0.0.1:8787' }, { targetHost: 'api.example.com' })
  assert.equal(out.host, 'api.example.com')
})

test('请求：内部路由头按需剥离', () => {
  const out = filterRequestHeaders(
    { 'x-cf-target': 'a.com', 'x-other': 'v' },
    { targetHost: 'up.example', dropExtra: ['x-cf-target'] },
  )
  assert.equal(out['x-cf-target'], undefined)
  assert.equal(out['x-other'], 'v')
})

test('请求：纯 chunked 请求体（无 content-length）可以正常转发', () => {
  const out = filterRequestHeaders({ 'transfer-encoding': 'chunked' }, { targetHost: 'up.example' })
  assert.equal(out['transfer-encoding'], undefined, '逐跳字段剥离')
  assert.equal(out['content-length'], undefined, '不能凭空造长度')
})

/* ============================================================
 * 响应头
 * ============================================================ */

test('响应：逐跳剥离，但 content-encoding 等端到端保留', () => {
  const out = filterResponseHeaders({
    connection: 'close',
    'keep-alive': 'timeout=5',
    'transfer-encoding': 'chunked',
    'proxy-authenticate': 'Basic',
    'content-encoding': 'gzip',
    'content-type': 'application/json',
    'x-upstream-trace': 'xyz',
  })

  for (const k of ['connection', 'keep-alive', 'transfer-encoding', 'proxy-authenticate']) {
    assert.equal(out[k], undefined, `${k} 应被剥离`)
  }
  assert.equal(out['content-encoding'], 'gzip', 'gzip 是端到端字段，误删客户端就解不开')
  assert.equal(out['content-type'], 'application/json')
  assert.equal(out['x-upstream-trace'], 'xyz')
})

test('响应：SSE 相关头完整保留', () => {
  const out = filterResponseHeaders({
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
    'transfer-encoding': 'chunked',
  })
  assert.equal(out['content-type'], 'text/event-stream', 'SSE 必须保住类型')
  assert.equal(out['cache-control'], 'no-cache', '缓存控制语义要保住')
  assert.equal(out['transfer-encoding'], undefined, 'framing 交给 Node')
})

test('响应：非法 content-length 被丢弃，不伪造', () => {
  assert.equal(filterResponseHeaders({ 'content-length': 'abc' })['content-length'], undefined)
  assert.equal(filterResponseHeaders({ 'content-length': '1024' })['content-length'], '1024')
})

test('响应：Connection 动态字段同样剥离', () => {
  const out = filterResponseHeaders({ connection: 'X-Trace', 'x-trace': 'leak', 'x-ok': '1' })
  assert.equal(out['x-trace'], undefined)
  assert.equal(out['x-ok'], '1')
})

/* ============================================================
 * SSE 判定与 Expect
 * ============================================================ */

test('isEventStream 只认 text/event-stream', () => {
  assert.equal(isEventStream({ 'content-type': 'text/event-stream' }), true)
  assert.equal(isEventStream({ 'content-type': 'text/event-stream; charset=utf-8' }), true)
  assert.equal(isEventStream({ 'content-type': 'application/json' }), false)
  assert.equal(isEventStream({}), false)
})

test('Expect: 100-continue 明确不转发（保守策略，已记录理由）', () => {
  // 我们做流式 pipe，请求体立刻开始流动，中间没有「先验后发」的窗口。
  // 直接转发 Expect 是错的：客户端等的是上游响应，而中间多了一跳。
  const r = handleExpectContinue()
  assert.equal(r.forwardExpect, false)
})
