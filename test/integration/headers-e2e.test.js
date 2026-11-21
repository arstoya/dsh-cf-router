/**
 * headers-e2e.test.js — Header 过滤端到端（Issue #5）
 * 验证经过真实代理链路后：gzip 字节完整、chunked 请求体不截断、SSE 逐块到达。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import zlib from 'node:zlib'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'

async function boot(fixtureOpts = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
  const listenPort = await freePort()
  setupPlugin({
    targets: [HOST], listenHost: '127.0.0.1', listenPort,
    allowPrivateTargets: true, adminToken: 'e2e', adminRateLimit: 10000,
    probeSamples: 1, probeTimeoutMs: 2000, upstreamTimeoutMs: 20000,
  })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
  const server = api.createProxy()
  await new Promise((r) => server.once('listening', r))
  await api.refreshHost(HOST)
  return { up, port: server.address().port }
}

function req(port, { method = 'GET', path = '/x', headers = {}, chunks = null } = {}) {
  return new Promise((resolve, reject) => {
    const q = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const b = []
      res.on('data', (c) => b.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(b) }))
      res.on('error', reject)
    })
    q.on('error', reject)
    if (chunks) for (const c of chunks) q.write(c)
    q.end()
  })
}

async function shutdown(env) {
  try { api.closeProxy() } catch { /* ignore */ }
  await env.up.close()
  mod.__resetForTest()
}

test.afterEach(async () => { try { api.closeProxy() } catch { /* ignore */ } mod.__resetForTest() })

test('gzip 响应字节完整，可解压出原文', async () => {
  const payload = '{"t":"中文😀 abc 123","arr":[1,2,3]}'
  const env = await boot({ status: 200, body: payload, gzip: true })
  try {
    const r = await req(env.port, {})
    assert.equal(r.status, 200)
    assert.equal(r.headers['content-encoding'], 'gzip')
    assert.equal(zlib.gunzipSync(r.body).toString('utf8'), payload)
  } finally { await shutdown(env) }
})

test('chunked 请求体（无 content-length）分片写出后字节不差', async () => {
  const env = await boot({ status: 200, body: '{"ok":1}' })
  try {
    const chunks = ['{"a":', '"中文', '","b":[1', ',2]}']
    const r = await req(env.port, {
      method: 'POST', path: '/chunked',
      headers: { 'content-type': 'application/json' },
      chunks,
    })
    assert.equal(r.status, 200)
    assert.equal(env.up.requests.at(-1).body, chunks.join(''), '上游收到的请求体必须完整')
  } finally { await shutdown(env) }
})

test('SSE 逐块到达且 content-type 保留', async () => {
  const events = ['data: 1\n\n', 'data: 2\n\n', 'data: [DONE]\n\n']
  const env = await boot({ status: 200, sse: true, sseEvents: events, delayBodyMs: 60 })
  try {
    const arrivals = []
    await new Promise((resolve, reject) => {
      const q = http.request({ host: '127.0.0.1', port: env.port, path: '/sse', method: 'POST',
        headers: { 'content-type': 'application/json' } }, (res) => {
        assert.match(res.headers['content-type'], /text\/event-stream/)
        res.on('data', (c) => arrivals.push(c.toString()))
        res.on('end', resolve)
        res.on('error', reject)
      })
      q.on('error', reject)
      q.end('{}')
    })
    assert.ok(arrivals.length >= 2, `SSE 应分批到达，实际 ${arrivals.length} 批`)
    assert.match(arrivals.join(''), /\[DONE\]/)
  } finally { await shutdown(env) }
})

test('内部路由头不泄漏给上游', async () => {
  const env = await boot({ status: 200 })
  try {
    await req(env.port, { headers: { 'x-cf-target': HOST, 'x-request-id': 'rid-1' } })
    const seen = env.up.requests.at(-1)
    assert.equal(seen.headers['x-cf-target'], undefined)
    assert.equal(seen.headers['x-request-id'], 'rid-1', '端到端字段应保留')
  } finally { await shutdown(env) }
})
