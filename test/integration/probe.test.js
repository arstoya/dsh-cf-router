/**
 * probe.test.js — 探测路径（DNS / TCP / TLS / HTTP 状态码）
 *
 * 全部对本地 HTTPS 服务跑：deps.resolve4 伪造 DNS、deps.upstreamPort 指向临时端口、
 * deps.tlsOptions 注入自签 CA。不碰真实 Cloudflare、真实 DNS。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
// 证书 SAN 只有 localhost / 127.0.0.1，所以测试域名用 localhost 才能过 TLS 校验
const HOST = 'localhost'

/** 起一个本地 HTTPS 上游，并把插件依赖指过去 */
async function withUpstream(fixtureOpts = {}, cfgOverrides = {}) {
  const up = await startHttpsUpstream(fixtureOpts)
  api.reset()
  api.deps.upstreamPort = up.port
  api.deps.tlsOptions = { ca: up.cert }
  api.deps.resolve4 = (host, cb) => cb(null, ['127.0.0.1'])
  api.configure({
    targets: [HOST],
    discoverEnabled: false,
    probeSamples: 1,
    probeTimeoutMs: 2000,
    probePath: '/probe',
    l1Concurrency: 1,
    l2TopN: 1,
    ...cfgOverrides,
  })
  return up
}

test.afterEach(() => mod.__resetForTest())

/* ---------- DNS ---------- */

test('DNS 成功：resolveIps 返回去重后的 IPv4 列表', async () => {
  api.reset()
  api.deps.resolve4 = (host, cb) => cb(null, ['203.0.113.1', '203.0.113.1', '203.0.113.2'])
  const ips = await api.resolveIps('x.test')
  assert.deepEqual(ips, ['203.0.113.1', '203.0.113.2'])
})

test('DNS 失败：返回空数组而不是抛错', async () => {
  api.reset()
  api.deps.resolve4 = (host, cb) => cb(new Error('ENOTFOUND'), null)
  assert.deepEqual(await api.resolveIps('x.test'), [])

  api.deps.resolve4 = (host, cb) => cb(null, [])
  assert.deepEqual(await api.resolveIps('x.test'), [])
})

test('DNS 全失败时 refreshHost 记录错误但不抛', async () => {
  api.reset()
  api.deps.resolve4 = (host, cb) => cb(null, [])
  api.configure({ targets: [HOST], discoverEnabled: false })
  const entry = await api.refreshHost(HOST)
  assert.equal(entry.error, 'DNS 无 A 记录')
  assert.deepEqual(entry.results, [])
})

/* ---------- TCP ---------- */

test('TCP 连接成功', async () => {
  const up = await withUpstream()
  try {
    const r = await api.tcpProbe('127.0.0.1', 2000)
    assert.equal(r.ok, true)
    assert.ok(Number.isFinite(r.ms))
  } finally {
    await up.close()
  }
})

test('TCP 连接失败（端口没人听）', async () => {
  api.reset()
  const dead = await freePort()   // 拿到就关掉，保证没人监听
  api.deps.upstreamPort = dead
  const r = await api.tcpProbe('127.0.0.1', 800)
  assert.equal(r.ok, false)
})

/* ---------- TLS / HTTP ---------- */

test('TLS 握手失败：证书不受信任时探测判失败', async () => {
  const up = await startHttpsUpstream({ status: 200 })
  try {
    api.reset()
    api.deps.upstreamPort = up.port
    api.deps.tlsOptions = {}          // 故意不给 CA
    api.deps.resolve4 = (host, cb) => cb(null, ['127.0.0.1'])
    api.configure({ targets: [HOST], discoverEnabled: false, probeSamples: 1, probeTimeoutMs: 2000 })

    const r = await api.probeOnce(HOST, '127.0.0.1', 2000, '/probe')
    assert.equal(r.ok, false, '证书校验失败应判失败')
  } finally {
    await up.close()
  }
})

for (const status of [200, 401, 404, 500, 503]) {
  test(`HTTP ${status}：都表示「网络可达」，探测算成功`, async () => {
    const up = await withUpstream({ status, body: '{"x":1}' })
    try {
      const r = await api.probeOnce(HOST, '127.0.0.1', 2000, '/probe')
      assert.equal(r.ok, true, `HTTP ${status} 不该被判成不可达`)
      assert.match(r.detail, new RegExp(`http ${status}`))
    } finally {
      await up.close()
    }
  })
}

test('探测在响应体结束时才收尾（当前实现，Issue #3 会拆出 TTFB）', async () => {
  // 现状：probeOnce 的 finish 在 res.end 之后，所以 ms 包含响应体下载时间。
  // 这里钉住行为，Issue #3 改计时边界时这条会改成断言「TTFB < total」。
  const up = await withUpstream({ status: 200, body: 'x'.repeat(200_000), delayBodyMs: 120 })
  try {
    const r = await api.probeOnce(HOST, '127.0.0.1', 3000, '/probe')
    assert.equal(r.ok, true)
    assert.ok(r.ms >= 100, `含响应体传输的耗时应在 100ms 以上，实测 ${r.ms}`)
  } finally {
    await up.close()
  }
})

test('请求超时：delayFirstByteMs 超过 probeTimeoutMs 时判失败', async () => {
  const up = await withUpstream({ status: 200, delayFirstByteMs: 800 }, { probeTimeoutMs: 200 })
  try {
    const r = await api.probeOnce(HOST, '127.0.0.1', 200, '/probe')
    assert.equal(r.ok, false)
    assert.equal(r.detail, 'timeout')
  } finally {
    await up.close()
  }
})

test('连接重置：判失败而不是挂住', async () => {
  const up = await withUpstream({ resetConnection: true }, { probeTimeoutMs: 1500 })
  try {
    const r = await api.probeOnce(HOST, '127.0.0.1', 1500, '/probe')
    assert.equal(r.ok, false)
  } finally {
    await up.close()
  }
})

/* ---------- 聚合 ---------- */

test('measureIp：样本取中位数，全部成功才算 okCount', async () => {
  const up = await withUpstream({ status: 200 })
  try {
    api.configure({ targets: [HOST], discoverEnabled: false, probeSamples: 3, probeTimeoutMs: 2000 })
    const r = await api.measureIp(HOST, '127.0.0.1', 3, 2000, '/probe')
    assert.equal(r.okCount, 3)
    assert.equal(r.samples, 3)
    assert.ok(Number.isFinite(r.median))
    assert.ok(r.best <= r.median, 'best 应不大于 median')
  } finally {
    await up.close()
  }
})

test('refreshHost：写入 hosts 并按延迟排序', async () => {
  const up = await withUpstream({ status: 200 })
  try {
    const entry = await api.refreshHost(HOST)
    assert.equal(entry.error, null)
    assert.equal(entry.results.length, 1)
    assert.equal(entry.results[0].ip, '127.0.0.1')
    assert.equal(api.state().currentIp.get(HOST), '127.0.0.1', '首次探测后应选定当前 IP')
    assert.equal(api.state().switches.at(-1).reason, 'initial')
  } finally {
    await up.close()
  }
})

test('coloAllow 过滤：colo 不匹配的候选被标记 excluded', async () => {
  const up = await withUpstream({ status: 200 })
  try {
    api.configure({ targets: [HOST], discoverEnabled: false, probeSamples: 1, coloAllow: ['SIN'] })
    const r = await api.measureIp(HOST, '127.0.0.1', 1, 2000, '/probe')
    // 本地服务没有 cf-ray，colo 为空 → 不在白名单 → 被排除
    assert.match(String(r.excluded), /colo/)
  } finally {
    await up.close()
  }
})
