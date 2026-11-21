/**
 * proxy.test.js — 代理转发路径
 *
 * 走真实监听端口：插件代理 ↔ 本地 HTTPS 上游。
 * 覆盖 GET / POST / JSON / SSE / gzip / 客户端中途断开 / 上游首字节超时 / 上游重置。
 *
 * 注意：代理只会用 https 连上游，所以 fixture 必须是 HTTPS 服务。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import zlib from 'node:zlib'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { freePort, waitFor } from '../helpers/deferred.mjs'
import { setupPlugin } from '../helpers/setup.mjs'

const api = mod.__testApi
const HOST = 'localhost'

/** 起上游 + 让插件的代理监听一个临时端口 */
async function boot(fixtureOpts = {}, cfgOverrides = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
  const listenPort = await freePort()

  // 顺序要紧：setupPlugin() 内部会 reset()，依赖注入必须放在它之后，
  // 否则刚注入的 upstreamPort / tlsOptions 会被复位成默认值。
  setupPlugin({
    targets: [HOST],
    listenHost: '127.0.0.1',
    listenPort,
    probeSamples: 1,
    probeTimeoutMs: 2000,
    upstreamTimeoutMs: 15000,
    ...cfgOverrides,
  })
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (host, cb) => cb(null, ['127.0.0.1'])

  const server = api.createProxy()
  await new Promise((resolve, reject) => {
    if (server.listening) return resolve()
    server.once('listening', resolve)
    server.once('error', reject)
  })

  // 先把当前 IP 定下来，免得首个请求走「探测未完成」分支
  await api.refreshHost(HOST)

  return { up, port: server.address().port, server }
}

function request(port, { method = 'GET', path = '/v1/chat/completions', headers = {}, body = null, onResponse } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = []
      if (onResponse) onResponse(res)
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
      }))
      res.on('error', reject)
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

async function shutdown(env) {
  try { api.closeProxy() } catch { /* ignore */ }
  await env.up.close()
  mod.__resetForTest()
}

test.afterEach(async () => {
  try { api.closeProxy() } catch { /* ignore */ }
  mod.__resetForTest()
})

test('GET 透传到上游，路径与 Host 正确', async () => {
  const env = await boot({ status: 200, body: '{"ok":1}' })
  try {
    const r = await request(env.port, { path: '/v1/models' })

    assert.equal(r.status, 200)
    assert.equal(JSON.parse(r.body.toString()).ok, 1)

    const seen = env.up.requests.at(-1)
    assert.equal(seen.method, 'GET')
    assert.equal(seen.url, '/v1/models')
    assert.equal(String(seen.headers.host).split(':')[0], HOST)
  } finally {
    await shutdown(env)
  }
})

test('POST + JSON 请求体完整透传', async () => {
  const payload = JSON.stringify({ model: 'x', messages: [{ role: 'user', content: '你好' }] })
  const env = await boot({ status: 200, body: '{"ok":1}' })
  try {
    const r = await request(env.port, {
      method: 'POST',
      path: '/v1/chat/completions',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
      body: payload,
    })

    assert.equal(r.status, 200)
    assert.equal(env.up.requests.at(-1).body, payload, '请求体必须一字节不差')
  } finally {
    await shutdown(env)
  }
})

test('Authorization 头透传（不被改写成小写以外的形态）', async () => {
  const env = await boot({ status: 200 })
  try {
    await request(env.port, { headers: { authorization: 'Bearer test-key-123' } })
    assert.equal(env.up.requests.at(-1).headers.authorization, 'Bearer test-key-123')
  } finally {
    await shutdown(env)
  }
})

test('x-cf-target 内部头不会转发给上游', async () => {
  const env = await boot({ status: 200 })
  try {
    await request(env.port, { headers: { 'x-cf-target': HOST } })
    const seen = env.up.requests.at(-1)
    assert.equal(seen.headers['x-cf-target'], undefined, '内部路由头必须剥掉')
  } finally {
    await shutdown(env)
  }
})

test('上游 401 原样返回（不吞成 502）', async () => {
  const env = await boot({ status: 401, body: '{code":"invalid_api_key"}' })
  try {
    const r = await request(env.port, { method: 'POST', body: '{}' })
    assert.equal(r.status, 401)
  } finally {
    await shutdown(env)
  }
})

test('上游 503 原样返回', async () => {
  const env = await boot({ status: 503, body: 'busy' })
  try {
    const r = await request(env.port, {})
    assert.equal(r.status, 503)
    assert.equal(r.body.toString(), 'busy')
  } finally {
    await shutdown(env)
  }
})

test('gzip 响应：content-encoding 保留，body 可解压', async () => {
  const env = await boot({ status: 200, body: '{"compressed":true}', gzip: true })
  try {
    const r = await request(env.port, {})
    assert.equal(r.headers['content-encoding'], 'gzip')
    const plain = zlib.gunzipSync(r.body).toString()
    assert.equal(JSON.parse(plain).compressed, true)
  } finally {
    await shutdown(env)
  }
})

test('SSE 流式：逐条到达，不缓冲到结束', async () => {
  const env = await boot({
    status: 200,
    sse: true,
    sseEvents: ['data: {"delta":"a"}\n\n', 'data: {"delta":"b"}\n\n', 'data: [DONE]\n\n'],
    delayBodyMs: 60,
  })
  try {
    const arrivals = []
    await new Promise((resolve, reject) => {
      const req = http.request(
        { host: '127.0.0.1', port: env.port, path: '/v1/chat/completions', method: 'POST', headers: { 'content-type': 'application/json' } },
        (res) => {
          assert.equal(res.headers['content-type'], 'text/event-stream')
          res.on('data', (c) => arrivals.push({ at: Date.now(), text: c.toString() }))
          res.on('end', resolve)
          res.on('error', reject)
        },
      )
      req.on('error', reject)
      req.write('{"stream":true}')
      req.end()
    })

    const text = arrivals.map((a) => a.text).join('')
    assert.match(text, /delta":"a"/)
    assert.match(text, /\[DONE\]/)
    // 分片到达：至少两个事件不是同一批来的
    assert.ok(arrivals.length >= 2, `SSE 应分批到达，实际 ${arrivals.length} 批`)
  } finally {
    await shutdown(env)
  }
})

test('客户端中途断开：上游连接被清理，不算 IP 失败', async () => {
  const env = await boot({ status: 200, sse: true, delayBodyMs: 100, sseEvents: Array(30).fill('data: x\n\n') })
  try {
    const before = api.statOf(HOST, '127.0.0.1').fail

    await new Promise((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port: env.port, path: '/sse', method: 'GET' },
        (res) => {
          res.once('data', () => {
            req.destroy()      // 模拟用户点了「停止生成」
            setTimeout(resolve, 250)
          })
        },
      )
      req.on('error', () => resolve())
      req.end()
    })

    assert.equal(api.statOf(HOST, '127.0.0.1').fail, before, '客户端取消不该计入 IP 失败')
  } finally {
    await shutdown(env)
  }
})

test('firstByteTimeoutMs 有 5000ms 下限：配 300 按 5000 执行，且状态接口可见', async () => {
  // Issue #17 最小修复后的语义：
  //   · 下限仍然存在（setInterval(0)/0ms 超时会打满事件循环，护栏必须留）
  //   · 但"配了 300 实际跑 5000"这件事不再静默 —— statusSnapshot().configEffective
  //     同时暴露 configured(300) 与 effective(5000)
  const env = await boot({ status: 200, delayFirstByteMs: 1200 }, { firstByteTimeoutMs: 300 })
  try {
    const r = await request(env.port, { method: 'POST', body: '{}' })
    assert.equal(r.status, 200, '5000ms 生效值意味着 1200ms 延迟不会被掐断')

    // 关键断言：接口必须说实话
    const eff = api.statusSnapshot().configEffective.firstByteTimeoutMs
    assert.equal(eff.configured, 300, '配置值应显示 300')
    assert.equal(eff.effective, 5000, '生效值必须显示 5000，不能显示 300')
  } finally {
    await shutdown(env)
  }
})

test('上游首字节超时：真实触发 502（受 5000ms 生效值约束，本用例约 5 秒）', async () => {
  // 这是「长时间无首字节」的真实路径覆盖：
  // firstByteTimeoutMs 的生效值是 max(5000, 配置)，所以必须让上游拖过 5 秒才能触发。
  // 配 5000 时生效值仍是 5000。用例慢，但它覆盖的是真实故障场景，
  // 不能为了跑得快就删掉。
  const env = await boot({ status: 200, delayFirstByteMs: 6500 }, { firstByteTimeoutMs: 5000 })
  try {
    // 上游 6.5 秒才回，探测本身也会超时拿不到候选 → 会走直连兜底、就没有 IP 可以罚。
    // 这里显式指定一条候选 IP，才能真正走到「转发超时 → noteFailure(ip)」这条路径。
    api.state().currentIp.set(HOST, '127.0.0.1')
    api.state().hosts.set(HOST, {
      ips: ['127.0.0.1'],
      results: [{ ip: '127.0.0.1', okCount: 3, samples: 3, median: 100, best: 100, colo: '', excluded: null }],
      lastProbeAt: api.deps.now(),
      error: null,
    })

    const started = Date.now()
    const r = await request(env.port, { method: 'POST', body: '{}' })
    const elapsed = Date.now() - started

    assert.equal(r.status, 502, '首字节超时应回 502')
    assert.match(r.body.toString(), /first_byte_timeout|upstream_error/)
    assert.ok(elapsed >= 4500, `应在 5 秒左右触发，实际 ${elapsed}ms`)
    await waitFor(() => api.statOf(HOST, '127.0.0.1').fail > 0, { timeoutMs: 2000, label: 'fail 计数' })
  } finally {
    await shutdown(env)
  }
})

test('上游连接重置：返回 502', async () => {
  const env = await boot({ resetConnection: true })
  try {
    const r = await request(env.port, { method: 'POST', body: '{}' })
    assert.equal(r.status, 502)
  } finally {
    await shutdown(env)
  }
})

test('Keep-Alive：连续两个请求复用同一条上游连接', async () => {
  const env = await boot({ status: 200 })
  try {
    // 注意：refreshHost() 的探测本身也会打一次上游（probePath），所以要算增量
    const before = env.up.requests.length
    await request(env.port, {})
    await request(env.port, {})

    assert.equal(env.up.requests.length - before, 2, '两次转发应产生两条上游请求')
    // 复用与否看连接数：两个转发请求应共用一条连接
    assert.ok(env.up.connections() <= 2, `上游连接数应被复用，实际 ${env.up.connections()}`)
  } finally {
    await shutdown(env)
  }
})

test('direct 模式：不钉 IP，仍能正常转发', async () => {
  const env = await boot({ status: 200, body: '{"mode":"direct"}' })
  try {
    api.setRoutingMode('direct')
    const r = await request(env.port, {})
    assert.equal(r.status, 200)
    assert.equal(JSON.parse(r.body.toString()).mode, 'direct')
    assert.equal(api.currentMode(), 'direct')
  } finally {
    await shutdown(env)
  }
})

test('客户端中途断开：上游确实观察到响应被中断（Issue #4 验收）', { skip: '#4 未实施：当前 aborted=0、上游把 8MB 写完了' }, async () => {
  // 评审指出的测试缺口：原用例只断言「没增加 IP 失败次数」，
  // 但上游可能还在照常跑 —— 那样断言照样通过。
  //
  // 关键在 payload 必须**大到会阻塞上游写**：几百字节会整个进内核缓冲，
  // 上游瞬间就「写完」了，测不出任何东西。用 8MB 让上游写到缓冲区满后卡住，
  // 此时：
  //   · 代理若取消上游 → 上游 socket 关闭，close 时 writableFinished=false → aborted
  //   · 代理若不取消   → 上游一直卡在写，close 不触发 → aborted 保持 0
  const env = await boot({ status: 200, body: 'x'.repeat(8 * 1024 * 1024) })
  try {
    const completedBefore = env.up.completedCount()

    await new Promise((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port: env.port, path: '/big', method: 'GET' },
        (res) => {
          res.once('data', () => {
            req.destroy()          // 模拟用户点了「停止生成」
            setTimeout(resolve, 200)
          })
        },
      )
      req.on('error', () => resolve())
      req.end()
    })

    await waitFor(() => env.up.abortedCount() > 0, {
      timeoutMs: 3000,
      label: 'upstream observed abort',
      describe: () => `aborted=${env.up.abortedCount()} completed=${env.up.completedCount()}`,
    })

    assert.ok(env.up.abortedCount() >= 1, '上游必须观察到响应中断')
    assert.equal(
      env.up.completedCount(),
      completedBefore,
      '这次请求不该在上游「正常写完」—— 说明客户端断开后上游没有被继续跑完',
    )
  } finally {
    await shutdown(env)
  }
})

test('控制端点 /__router/status 返回真实快照', async () => {
  const env = await boot({ status: 200 })
  try {
    const r = await request(env.port, { path: '/__router/status' })
    const snap = JSON.parse(r.body.toString())
    assert.equal(snap.ok, true)
    assert.equal(snap.routingMode, 'auto', '每个 test 都重新 configure，模式应回到 auto')
    assert.ok(Array.isArray(snap.hosts))
  } finally {
    await shutdown(env)
  }
})

test('无目标配置时返回 400 no_target', async () => {
  api.reset()
  const listenPort = await freePort()
  api.configure({ targets: [], listenHost: '127.0.0.1', listenPort })
  const server = api.createProxy()
  await new Promise((resolve) => server.once('listening', resolve))
  try {
    const r = await request(server.address().port, { path: '/v1/models' })
    assert.equal(r.status, 400)
    assert.match(r.body.toString(), /no_target/)
  } finally {
    api.closeProxy()
  }
})
