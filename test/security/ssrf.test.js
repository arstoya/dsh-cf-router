/**
 * ssrf.test.js — 目标域名白名单与 SSRF 防护（Issue #6）
 *
 * 四层防护各有独立用例：
 *   1  Authority 解析与规范化
 *   2  配置授权（精确白名单）
 *   3  解析地址分类（回环/私网/链路本地/CGNAT/保留段）
 *   4  防 DNS rebinding
 *
 * 验收重点（评审要求）：安全测试必须断言「没有建立到被拒绝地址的 socket」，
 * 不能只断言返回 400/403。本文件最后两节就是这么做的。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import https from 'node:https'

import {
  normalizeAuthority, blockedIpv4, filterResolvedIps, normalizeAllowlist, isAllowedHost,
} from '../../lib/ssrf-guard.mjs'
import * as mod from '../../lib/index.js'
import { startHttpsUpstream } from '../fixtures/https-server.js'
import { setupPlugin, teardownPlugin } from '../helpers/setup.mjs'
import { freePort } from '../helpers/deferred.mjs'

const api = mod.__testApi
const HOST = 'localhost'

test.afterEach(() => teardownPlugin())

/* ============================================================
 * 第一层：Authority 解析与规范化
 * ============================================================ */

test('接受合法域名，统一小写并去掉末尾点', () => {
  for (const [input, want] of [
    ['api.example.com', 'api.example.com'],
    ['API.Example.COM', 'api.example.com'],
    ['api.example.com.', 'api.example.com'],
    ['a-b.example.co', 'a-b.example.co'],
    ['api.example.com:8443', 'api.example.com'],
  ]) {
    const r = normalizeAuthority(input)
    assert.equal(r.ok, true, `${input} 应被接受`)
    assert.equal(r.host, want)
  }
})

test('拒绝协议、路径、query、userinfo、IPv6 字面量', () => {
  const bad = [
    ['http://example.com', 'has_scheme'],
    ['example.com/path', 'has_path_or_query'],
    ['example.com?x=1', 'has_path_or_query'],
    ['user@example.com', 'has_userinfo'],
    ['[::1]', 'ipv6_literal'],
  ]
  for (const [input, reason] of bad) {
    const r = normalizeAuthority(input)
    assert.equal(r.ok, false, `${input} 应被拒绝`)
    assert.equal(r.reason, reason, `${input} 的拒绝理由`)
  }
})

test('拒绝 IP 字面量与其十进制/十六进制伪装', () => {
  for (const s of ['127.0.0.1', '10.0.0.1', '2130706433', '0x7f.0.0.1', '1.2.3']) {
    const r = normalizeAuthority(s)
    assert.equal(r.ok, false, `${s} 应被拒绝`)
  }
})

test('拒绝非法端口、多值 Host、控制字符', () => {
  for (const [s, reason] of [
    ['example.com:0', 'bad_port'],
    ['example.com:99999', 'bad_port'],
    ['example.com:abc', 'bad_port'],
    ['a.com,b.com', 'multiple_values'],
    ['example.com\u0000', 'control_or_space'],
    ['exa mple.com', 'control_or_space'],
    ['example.com:80:80', 'multiple_colons'],
  ]) {
    const r = normalizeAuthority(s)
    assert.equal(r.ok, false)
    assert.equal(r.reason, reason)
  }
})

test('单段主机名语法层放行（能否使用由白名单+地址层决定）', () => {
  const r = normalizeAuthority('localhost')
  assert.equal(r.ok, true)
  assert.equal(r.host, 'localhost')
})

/* ============================================================
 * 第二层：白名单精确匹配
 * ============================================================ */

test('白名单精确匹配，不做后缀/通配', () => {
  const { allowed } = normalizeAllowlist(['example.com', 'api.example.com'])

  assert.equal(isAllowedHost('example.com', allowed), true)
  assert.equal(isAllowedHost('api.example.com', allowed), true)
  assert.equal(isAllowedHost('evil-example.com', allowed), false, '后缀不算命中')
  assert.equal(isAllowedHost('example.com.evil.tld', allowed), false)
  assert.equal(isAllowedHost('www.example.com', allowed), false, '子域需显式配置')
})

test('非法 targets 条目被剔除并记录原因', () => {
  const { allowed, rejected } = normalizeAllowlist([
    'good.example.com',
    '127.0.0.1',
    'evil host',
    'http://x.com',
    'Bad_Host.com',
  ])
  assert.deepEqual([...allowed], ['good.example.com'])
  assert.equal(rejected.length, 4)
  assert.ok(rejected.every((r) => r.reason))
})

/* ============================================================
 * 第三层：地址分类
 * ============================================================ */

test('IPv4 受保护范围全部命中', () => {
  const cases = {
    '127.0.0.1': 'loopback',
    '127.255.255.254': 'loopback',
    '10.0.0.1': 'private_10',
    '172.16.0.1': 'private_172',
    '172.31.255.254': 'private_172',
    '192.168.1.1': 'private_192',
    '169.254.1.1': 'link_local',
    '169.254.169.254': 'link_local',
    '100.64.0.1': 'cgnat',
    '0.0.0.0': 'this_network',
    '224.0.0.1': 'multicast',
    '240.0.0.1': 'reserved',
    '198.18.0.1': 'benchmark',
  }
  for (const [ip, reason] of Object.entries(cases)) {
    assert.equal(blockedIpv4(ip), reason, `${ip}`)
  }
})

test('公网地址放行', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '104.16.0.1', '203.0.114.1']) {
    assert.equal(blockedIpv4(ip), null, `${ip} 应可用`)
  }
})

test('172.32 已不在私网范围内（边界值）', () => {
  assert.equal(blockedIpv4('172.32.0.1'), null, '172.32 是公网')
  assert.equal(blockedIpv4('172.15.0.1'), null, '172.15 是公网')
})

test('混合结果整体拒绝，不挑安全的用', () => {
  const r = filterResolvedIps(['8.8.8.8', '127.0.0.1'])
  assert.equal(r.ok, false)
  assert.match(r.hit, /127\.0\.0\.1/)

  const clean = filterResolvedIps(['8.8.8.8', '1.1.1.1'])
  assert.equal(clean.ok, true)
})

test('空结果不算通过', () => {
  assert.equal(filterResolvedIps([]).ok, false)
  assert.equal(filterResolvedIps(null).ok, false)
})

/* ============================================================
 * 端到端：被拒绝的目标不得建立 socket
 * ============================================================ */

/** 起一个代理，返回 {port, server}；不预设 hosts 状态 */
async function bootProxy(overrides = {}) {
  const listenPort = await freePort()
  setupPlugin({
    targets: [HOST],
    listenHost: '127.0.0.1',
    listenPort,
    allowPrivateTargets: true,
    ...overrides,
  })
  const server = api.createProxy()
  await new Promise((r) => server.once('listening', r))
  return { port: server.address().port, server }
}

function get(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'GET', headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }))
    })
    req.on('error', reject)
    req.end()
  })
}

test('未配置公网域名被拒绝，且不建立上游 socket', async () => {
  // 起一个真实上游，用它证明「没被连上」
  const up = await startHttpsUpstream({ status: 200 })
  let upstreamConnections = 0
  up.server.on('connection', () => { upstreamConnections += 1 })

  try {
    const env = await bootProxy({ allowPrivateTargets: true })
    api.deps.upstreamPort = up.port
    api.deps.tlsOptions = { ca: up.cert }
    api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])

    // x-cf-target 指向白名单外的域名
    const r = await get(env.port, '/v1/models', { 'x-cf-target': 'evil.example.com' })

    assert.equal(r.status, 403, '白名单外应 403')
    assert.match(r.body, /target_not_allowed/)
    assert.equal(up.requests.length, 0, '上游不该收到任何请求')
    assert.equal(upstreamConnections, 0, '不该建立任何上游 socket')
  } finally {
    try { api.closeProxy() } catch { /* ignore */ }
    await up.close()
  }
})

test('IP 字面量目标被拒绝，且不建立 socket', async () => {
  const up = await startHttpsUpstream({ status: 200 })
  let upstreamConnections = 0
  up.server.on('connection', () => { upstreamConnections += 1 })

  try {
    const env = await bootProxy({ allowPrivateTargets: true })
    api.deps.upstreamPort = up.port
    api.deps.tlsOptions = { ca: up.cert }

    for (const target of ['127.0.0.1', '169.254.169.254', '10.0.0.1', '2130706433']) {
      const r = await get(env.port, '/v1/models', { 'x-cf-target': target })
      assert.equal(r.status, 400, `${target} 应 400`)
      assert.match(r.body, /invalid_target/)
    }
    assert.equal(upstreamConnections, 0, '不该建立任何上游 socket')
  } finally {
    try { api.closeProxy() } catch { /* ignore */ }
    await up.close()
  }
})

test('白名单内域名解析到私网地址时拒绝（第三层）', async () => {
  const up = await startHttpsUpstream({ status: 200 })
  let upstreamConnections = 0
  up.server.on('connection', () => { upstreamConnections += 1 })

  try {
    // 注意这里 allowPrivateTargets=false，走真实的地址分类
    const env = await bootProxy({ allowPrivateTargets: false })
    api.deps.upstreamPort = up.port
    api.deps.tlsOptions = { ca: up.cert }
    // 白名单里的域名解析到回环地址
    api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])

    await api.refreshHost(HOST).catch(() => null)

    const entry = api.state().hosts.get(HOST)
    assert.ok(entry, 'hosts 应被写入')
    assert.equal(entry.ips.length, 0, '受保护地址不该进候选')
    assert.match(String(entry.error), /ssrf_blocked/, '应记录 ssrf_blocked')
    assert.equal(upstreamConnections, 0, '不该建立任何上游 socket')
  } finally {
    try { api.closeProxy() } catch { /* ignore */ }
    await up.close()
  }
})

test('host 与 x-cf-target 冲突时以显式目标为准，但必须过白名单', async () => {
  // 证书 SAN 只覆盖 localhost，所以白名单里放两个都能过 TLS 校验的名字会失真。
  // 这里改为验证**判定顺序**：Host 在白名单外、x-cf-target 在白名单内，
  // 应以显式目标为准并成功转发。
  const up = await startHttpsUpstream({ status: 200, body: '{"via":"explicit"}' })
  try {
    const env = await bootProxy({ targets: [HOST], allowPrivateTargets: true })
    api.deps.upstreamPort = up.port
    api.deps.tlsOptions = { ca: up.cert }
    api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
    api.state().hosts.set(HOST, {
      ips: ['127.0.0.1'],
      results: [{ ip: '127.0.0.1', okCount: 3, samples: 3, ttfbMedian: 50, ttfbBest: 50, totalMedian: 70, tcpMedian: 5, tlsMedian: 8, colo: 'HKG', excluded: null }],
      lastProbeAt: api.deps.now(),
      error: null,
    })
    api.state().currentIp.set(HOST, '127.0.0.1')

    // Host 指向白名单外的域名，但 x-cf-target 显式指定白名单内的 localhost
    const r = await get(env.port, '/v1/models', {
      'x-cf-target': HOST,
      host: 'evil.example.com',
    })
    assert.equal(r.status, 200, '显式且授权的目标应生效')
    assert.equal(JSON.parse(r.body).via, 'explicit')
    assert.equal(String(up.requests.at(-1).headers.host).split(':')[0], HOST)
  } finally {
    try { api.closeProxy() } catch { /* ignore */ }
    await up.close()
  }
})

/* ============================================================
 * 第四层：防 DNS rebinding
 * ============================================================ */

test('rebinding：首次公网、随后私网 —— 后续解析被拒，不复用旧候选', async () => {
  const up = await startHttpsUpstream({ status: 200 })
  try {
    const env = await bootProxy({
      allowPrivateTargets: false,
      probeTimeoutMs: 300,
      l1TimeoutMs: 200,
      l2TopN: 1,
      probeSamples: 1,
    })
    api.deps.upstreamPort = up.port
    api.deps.tlsOptions = { ca: up.cert }

    // 第一次：解析到公网
    api.deps.resolve4 = (h, cb) => cb(null, ['8.8.8.8'])
    await api.refreshHost(HOST).catch(() => null)
    assert.deepEqual(api.state().hosts.get(HOST).ips, ['8.8.8.8'], '首轮应接受公网地址')

    // 第二次：换成私网（模拟 TTL 过期后攻击者改了记录）
    api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
    await api.refreshHost(HOST).catch(() => null)

    const entry = api.state().hosts.get(HOST)
    assert.equal(entry.ips.length, 0, '新的私网解析必须被拒')
    assert.match(String(entry.error), /ssrf_blocked/)
  } finally {
    try { api.closeProxy() } catch { /* ignore */ }
    await up.close()
  }
})

/* ============================================================
 * 兼容：direct 模式不得绕过校验
 * ============================================================ */

test('direct 模式同样受白名单保护', async () => {
  const up = await startHttpsUpstream({ status: 200 })
  let upstreamConnections = 0
  up.server.on('connection', () => { upstreamConnections += 1 })

  try {
    const env = await bootProxy({ allowPrivateTargets: true, routingMode: 'direct' })
    api.deps.upstreamPort = up.port
    api.deps.tlsOptions = { ca: up.cert }
    api.deps.resolve4 = (h, cb) => cb(null, ['127.0.0.1'])
    assert.equal(api.currentMode(), 'direct')

    const r = await get(env.port, '/v1/models', { 'x-cf-target': 'evil.example.com' })
    assert.equal(r.status, 403, 'direct 不是绕过白名单的理由')
    assert.equal(upstreamConnections, 0)
  } finally {
    try { api.closeProxy() } catch { /* ignore */ }
    await up.close()
  }
})

/* ============================================================
 * 状态可观测
 * ============================================================ */

test('statusSnapshot 暴露允许的目标与被剔除的条目', () => {
  setupPlugin({
    targets: ['ok.example.com', '127.0.0.1', 'bad host'],
    discoverEnabled: false,
    allowPrivateTargets: true,
  })
  const snap = api.statusSnapshot()
  assert.deepEqual([...snap.allowedTargets], ['ok.example.com'])
  assert.equal(snap.rejectedTargets.length, 2)
})
