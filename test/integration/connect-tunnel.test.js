/**
 * connect-tunnel.test.js — HTTPS CONNECT 隧道（D2）
 *
 * 全部用真实 `http.createServer` + `server.on('connect')`，客户端用裸
 * net socket 发 CONNECT（能拿到**手写状态行原文**，这是 http.request 的
 * connect 事件给不了的判据）。上游是一台本地 TCP echo 服务器，不用真 TLS
 * —— 隧道对内容是盲的，echo 与 TLS 在隧道视角下没有区别。
 *
 * 判据都是可观测量：
 *   未建上游连接 = echo 服务器的连接计数仍为 0；
 *   不可达 = 状态行是 502 而不是 200；
 *   内容不落日志 = 日志样本里搜不到隧道载荷的标记串。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import http from 'node:http'
import crypto from 'node:crypto'

import { parseConnectTarget, createConnectTunnel } from '../../lib/connect-tunnel.mjs'
import { generateClientToken, hashClientToken } from '../../lib/client-auth.mjs'
import { TargetDenied } from '../../lib/contract/errors.mjs'
import { deferred, waitFor, sleep, freePort } from '../helpers/deferred.mjs'

/* ============================================================
 * 辅助
 * ============================================================ */

/** 客户端 Token + 服务端客户端表 */
function makeAuth() {
  const { token, authTokenHash } = generateClientToken()
  const clients = [
    { id: 'client-d2', name: '测试客户端', enabled: true, routeGroupId: 'group-d2', authTokenHash },
  ]
  return { token, clients }
}

const AUTH = makeAuth()
// client-auth 的 authenticateClient 只读 `Authorization`（与 D1 同一约定）
const AUTH_HEADER = `Authorization: Bearer ${AUTH.token}`

/**
 * echo 服务器：收到什么回什么；收到 FIN（半关闭）后先补一段「迟到数据」
 * 再关自己的写侧 —— 这是半关闭测试里「客户端仍能读」的判据来源。
 */
function startEchoServer() {
  const state = {
    connections: 0,
    closed: 0,
    bytesSeen: 0,
    lastReceived: '',
    /** @type {Set<import('node:net').Socket>} */
    sockets: new Set(),
  }
  const LATE = ' late-echo-fin'
  const server = net.createServer((sock) => {
    state.connections += 1
    state.sockets.add(sock)
    sock.on('data', (chunk) => {
      state.bytesSeen += chunk.length
      state.lastReceived += chunk.toString('utf8')
      if (state.lastReceived.length > 4096) state.lastReceived = state.lastReceived.slice(-4096)
      if (!sock.destroyed && !sock.writableEnded) sock.write(chunk)
    })
    sock.on('end', () => {
      // 半关闭传播：对端 FIN 后仍可写。先补写迟到数据，再关自己的写侧。
      if (!sock.destroyed && !sock.writableEnded) {
        sock.write(LATE)
        sock.end()
      }
    })
    sock.on('close', () => {
      state.closed += 1
      state.sockets.delete(sock)
    })
    sock.on('error', () => { /* RST 是测试流程的一部分 */ })
  })
  /** @type {Promise<number>} */
  const ready = new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(/** @type {import('node:net').AddressInfo} */ (server.address()).port))
  })
  return { server, state, ready, close: () => new Promise((r) => server.close(() => r())) }
}

/** 代理服务器：http.createServer + server.on('connect', tunnel.handle) */
function startProxyServer(tunnel) {
  const server = http.createServer(() => { /* 非 CONNECT 请求不归本测试管 */ })
  server.on('connect', (req, socket, head) => { tunnel.handle(req, socket, head) })
  /** @type {Promise<number>} */
  const ready = new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(/** @type {import('node:net').AddressInfo} */ (server.address()).port))
  })
  return { server, ready, close: () => new Promise((r) => server.close(() => r())) }
}

/**
 * 裸 socket 发 CONNECT，读回第一条状态行（直到 \r\n\r\n）。
 * 成功建立后 socket 直接可当隧道字节口用。
 */
async function openConnect(proxyPort, target, { extraHeaders = '', payload = '' } = {}) {
  const sock = net.connect({ host: '127.0.0.1', port: proxyPort })
  await waitFor(() => sock.readyState === 'open' || !sock.connecting, { label: 'proxy tcp connect' })
  sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${extraHeaders}\r\n${payload}`)
  const { statusLine, rest } = await readStatusLine(sock)
  return { sock, statusLine, rest }
}

/**
 * 读状态行 + 头块。返回 statusLine（如 'HTTP/1.1 403 Forbidden'）与
 * 头块之后残留的隧道字节（rest，Buffer）。
 */
function readStatusLine(sock) {
  return new Promise((resolve, reject) => {
    const chunks = []
    const done = deferred()
    const onErr = () => { cleanup(); reject(new Error('socket error while reading status line')) }
    function cleanup() {
      sock.removeListener('data', onData)
      sock.removeListener('error', onErr)
      sock.removeListener('close', onErr)
    }
    function onData(chunk) {
      chunks.push(chunk)
      const buf = Buffer.concat(chunks)
      const idx = buf.indexOf('\r\n\r\n')
      if (idx !== -1) {
        cleanup()
        const headerBlock = buf.slice(0, idx).toString('utf8')
        const rest = buf.slice(idx + 4)
        resolve({ statusLine: headerBlock.split('\r\n')[0], rest })
      }
    }
    sock.on('data', onData)
    sock.on('error', onErr)
    sock.on('close', onErr)
    void done
  })
}

/** 收集 socket 后续字节直到关闭 */
function collectUntilClose(sock, { maxBytes = 64 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    /** @type {Buffer[]} */
    const chunks = []
    let total = 0
    sock.on('data', (c) => {
      chunks.push(c)
      total += c.length
      if (total >= maxBytes) sock.destroy()
    })
    sock.on('close', () => resolve(Buffer.concat(chunks)))
    sock.on('error', () => { /* close 会跟着来 */ })
  })
}

/** 确认一个白名单目标：host 是 localhost，端口指向本机 echo */
/** 白名单 + 本机 echo 端口动态放行（allowedPorts 必须覆盖 CONNECT 的目标端口） */
function validatorOpts(extraPorts = []) {
  return {
    allowlist: ['localhost', 'refused.example'],
    allowedPorts: [80, 443, 8888, ...extraPorts],
    allowPrivate: true,
    resolve: RESOLVE_LOCAL,
  }
}

/** 把域名解析钉到 127.0.0.1（测试不查真 DNS） */
const RESOLVE_LOCAL = () => ['127.0.0.1']

/* ============================================================
 * 1. 白名单目标可建立隧道，双向传输字节
 * ============================================================ */
test('1. 白名单目标：CONNECT 建立，双向字节透传，状态行 200 Connection Established', async () => {
  const echo = startEchoServer()
  const echoPort = await echo.ready
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([echoPort]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      `localhost:${echoPort}`,
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 200 Connection Established')

    sock.write('ping-from-client')
    const first = await waitFor(() => echo.state.bytesSeen >= 'ping-from-client'.length
      ? 'ping-from-client'
      : null, { label: 'upstream received' })
    assert.equal(first, 'ping-from-client')

    // 上游 → 客户端：直接往 echo 的 socket 写，客户端应收到
    const echoSock = [...echo.state.sockets][0]
    const downstream = deferred()
    sock.on('data', (c) => {
      if (c.toString('utf8').includes('pong-from-upstream')) downstream.resolve(true)
    })
    echoSock.write('pong-from-upstream')
    assert.ok(await downstream.promise, '客户端应收到上游发来的字节')
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 2. 私网目标被拒（403），且未建立上游连接
 * ============================================================ */
test('2. 私网目标 403，echo 连接计数为 0（未建立上游连接）', async () => {
  const echo = startEchoServer()
  const echoPort = await echo.ready
  // 白名单不含 127.0.0.1：IP 字面量直接被 not_allowlisted 拒掉
  // （echoPort 放行，保证 403 来自 host 白名单而不是端口策略）
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: {
      allowlist: ['localhost'],
      allowedPorts: [80, 443, 8888, echoPort],
      allowPrivate: true,
      resolve: RESOLVE_LOCAL,
    },
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      `127.0.0.1:${echoPort}`,
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 403 Forbidden')
    // 连接计数器：echo 一条连接都没收到 —— 拒绝发生在拨号之前
    await sleep(100)
    assert.equal(echo.state.connections, 0)
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 3. 上游不可达：502，而不是先 200 再断
 * ============================================================ */
test('3. 上游不可达返回 502 Bad Gateway（状态行里没有 200）', async () => {
  const deadPort = await freePort() // 有端口、没监听者 → ECONNREFUSED
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: {
      allowlist: ['refused.example'],
      // deadPort 必须在白名单里，否则 403（port_not_allowed）先于拨号发生
      allowedPorts: [80, 443, 8888, deadPort],
      allowPrivate: true,
      resolve: RESOLVE_LOCAL,
    },
    connectTimeoutMs: 3000,
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      `refused.example:${deadPort}`,
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 502 Bad Gateway')
    assert.match(statusLine, /^HTTP\/1\.1 502 /)
    sock.destroy()
    // 关键断言：上游连接失败必须把 Session 收掉。
    //
    // 这里曾经漏了 —— 只断言 established/failed 看不出泄漏。原实现里
    // connectUpstream 拨号前就把 socket 赋给 session.upstream，失败时
    // 只 reject 不清空，maybeFinalize 的 `upstreamClosed || upstream === null`
    // 永不成立，session 永久留在 activeSessions，state.active 永不递减。
    // 反复连不通的上游就能把内存撑大（独立审查抓到的 blocker）。
    await waitFor(() => tunnel.stats().active === 0, { label: '502 后 session 已收尾' })
    const s = tunnel.stats()
    assert.equal(s.established, 0)
    assert.equal(s.failed, 1)
    assert.equal(s.active, 0, '上游连接失败后 active 必须归零，否则是 session 泄漏')
  } finally {
    await tunnel.close()
    await proxy.close()
  }
})

/* ============================================================
 * 4. 认证失败 → 407
 * ============================================================ */
test('4. 认证失败返回 407 Proxy Authentication Required（选 407 的理由：RFC 9110 为代理认证专设，客户端据以弹出代理凭据提示；403 留给目标策略否决）', async () => {
  const echo = startEchoServer()
  const echoPort = await echo.ready
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([echoPort]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(proxyPort, `localhost:${echoPort}`)
    assert.equal(statusLine, 'HTTP/1.1 407 Proxy Authentication Required')
    await sleep(50)
    assert.equal(echo.state.connections, 0)
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 5. authority-form 解析：IPv6 字面量
 * ============================================================ */
test('5. parseConnectTarget 正确处理 [::1]:443，不按冒号切碎', () => {
  const ok = parseConnectTarget('[::1]:443')
  assert.deepEqual(ok, { host: '[::1]', port: 443 })
  // 方括号内多冒号不碎：连 8888 端口一起解析
  const ok2 = parseConnectTarget('[2001:db8::1]:8888')
  assert.equal(ok2.port, 8888)
  assert.equal(ok2.host, '[2001:db8::1]')
  // 无端口的 IPv6 字面量：CONNECT 必须带端口
  assert.throws(() => parseConnectTarget('[::1]'), /missing_port/)
  // 验证层认方括号形态：validateAuthority 的 normalizeHost 会剥括号归一化
  assert.throws(() => parseConnectTarget('[::1]:443:extra'), /bad_authority|bad_port/)
})

/* ============================================================
 * 6. 非法端口被拒
 * ============================================================ */
test('6. 非法端口 0 / 65536 / 非数字 被拒（解析层抛、Adapter 层回 400）', async () => {
  assert.throws(() => parseConnectTarget('localhost:0'), /bad_port/)
  assert.throws(() => parseConnectTarget('localhost:65536'), /bad_port/)
  assert.throws(() => parseConnectTarget('localhost:abc'), /bad_port/)

  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([443]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      'localhost:0',
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 400 Bad Request')
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
  }
})

/* ============================================================
 * 7. 双向大流量（1 MB）字节完整性
 * ============================================================ */
test('7. 1 MB 双向流量字节完整性（echo 原样返回）', async () => {
  const echo = startEchoServer()
  const echoPort = await echo.ready
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([echoPort]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock } = await openConnect(
      proxyPort,
      `localhost:${echoPort}`,
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    const payload = crypto.randomBytes(1024 * 1024)
    // 分块灌入，让背压与 drain 真实运转
    const CHUNK = 32 * 1024
    for (let off = 0; off < payload.length; off += CHUNK) {
      if (!sock.write(payload.subarray(off, off + CHUNK))) {
        await new Promise((r) => sock.once('drain', r))
      }
    }
    const received = await collectUntilClose(sock, { maxBytes: payload.length })
    assert.equal(received.length, payload.length)
    assert.ok(received.equals(payload), '回读内容与发送内容逐字节一致')
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 8. 半关闭：客户端 shutdown write 后仍能读
 * ============================================================ */
test('8. 半关闭：客户端 end() 之后仍能收到上游数据（含 FIN 后的迟到字节）', async () => {
  const echo = startEchoServer()
  const echoPort = await echo.ready
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([echoPort]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock } = await openConnect(
      proxyPort,
      `localhost:${echoPort}`,
      { extraHeaders: `${AUTH_HEADER}\r\n`, payload: 'pre-fin-hello' },
    )
    // shutdown write（FIN），随后不再发送任何字节
    sock.end()
    const rest = await collectUntilClose(sock)
    const text = rest.toString('utf8')
    // 连接前捎带的 head 字节被转交上游并回显
    assert.ok(text.includes('pre-fin-hello'), `head 字节应回显，实际：${JSON.stringify(text)}`)
    // 客户端已 FIN，上游 FIN 后补写的迟到数据仍然送达 —— 半关闭的关键判据
    assert.ok(text.includes('late-echo-fin'), `迟到数据应送达，实际：${JSON.stringify(text)}`)
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 9. 客户端突然断开 → 上游连接被清理
 * ============================================================ */
test('9. 客户端突然断开：上游 socket 被销毁（echo 观察到 close）', async () => {
  const echo = startEchoServer()
  const echoPort = await echo.ready
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([echoPort]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock } = await openConnect(
      proxyPort,
      `localhost:${echoPort}`,
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    sock.write('some bytes')
    await waitFor(() => echo.state.connections === 1, { label: 'upstream connected' })
    sock.destroy() // 不 end、不 FIN，直接 RST
    // 上游连接必须被清理：echo 侧 socket 全部关闭
    await waitFor(() => echo.state.closed >= 1, { label: 'upstream cleaned up' })
    await waitFor(() => tunnel.stats().active === 0, { label: 'session finalized' })
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 10. 隧道内容不出现在任何日志里
 * ============================================================ */
test('10. 日志样本中搜不到隧道内容（只含 host/port/计量）', async () => {
  const logs = []
  const logger = {
    debug: (m) => logs.push(`[debug] ${m}`),
    info: (m) => logs.push(`[info] ${m}`),
    warn: (m) => logs.push(`[warn] ${m}`),
    error: (m) => logs.push(`[error] ${m}`),
  }
  const echo = startEchoServer()
  const echoPort = await echo.ready
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    logger,
    validatorOptions: validatorOpts([echoPort]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const secret = 'TOP-SECRET-TUNNEL-PAYLOAD-XYZ'
    const { sock } = await openConnect(
      proxyPort,
      `localhost:${echoPort}`,
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    sock.write(secret)
    await waitFor(() => echo.state.bytesSeen >= secret.length, { label: 'payload forwarded' })
    sock.destroy()
    await waitFor(() => tunnel.stats().active === 0, { label: 'session finalized' })

    // 正向对照：日志确实记录了隧道生命周期
    const joined = logs.join('\n')
    assert.ok(joined.includes('connect established'), '应有建立日志')
    assert.ok(joined.includes('localhost'), '应有 host 记录')
    // 隐私判据：内容与凭据都不出现
    assert.ok(!joined.includes(secret), '隧道内容不得入日志')
    assert.ok(!joined.includes(AUTH.token), '凭据不得入日志')
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 11. 并发多条隧道互不干扰
 * ============================================================ */
test('11. 并发 3 条隧道，各自的字节流互不串线', async () => {
  const echo = startEchoServer()
  const echoPort = await echo.ready
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([echoPort]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const sessions = []
    for (let i = 0; i < 3; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const opened = await openConnect(
        proxyPort,
        `localhost:${echoPort}`,
        { extraHeaders: `${AUTH_HEADER}\r\n` },
      )
      assert.equal(opened.statusLine, 'HTTP/1.1 200 Connection Established')
      const session = { sock: opened.sock, marker: `stream-${i}-`, got: '' }
      sessions.push(session)
      opened.sock.on('data', (c) => { session.got += c.toString('utf8') })
    }
    // 交错发送，让 echo 侧与隧道侧出现真实的并发交错
    for (let round = 0; round < 3; round += 1) {
      for (const s of sessions) s.sock.write(s.marker)
      // eslint-disable-next-line no-await-in-loop
      await sleep(10)
    }
    // 每条隧道应完整收到自己的 3 轮标记
    await waitFor(() => sessions.every((s) => (s.got.match(new RegExp(s.marker, 'g')) ?? []).length >= 3), {
      label: 'each tunnel echoed its own markers',
    })
    for (const s of sessions) {
      for (let i = 0; i < 3; i += 1) {
        const other = `stream-${i}-`
        if (other !== s.marker) {
          assert.ok(!s.got.includes(other), `隧道 ${s.marker} 不应收到别人的标记 ${other}`)
        }
      }
    }
    for (const s of sessions) s.sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 12. 隧道建立耗时、上下行字节数统计正确
 * ============================================================ */
test('12. records 记录 connectMs / durationMs / bytesUp / bytesDown', async () => {
  const echo = startEchoServer()
  const echoPort = await echo.ready
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([echoPort]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock } = await openConnect(
      proxyPort,
      `localhost:${echoPort}`,
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    sock.write('12345') // 5 字节上行
    // 等下行字节真正送回客户端（echo 原样回 5 字节），再 RST
    await sleep(100)
    // 显式 RST 而不是 destroy()：后者在无未读数据时走优雅关闭（FIN），
    // echo 收到 FIN 会补写迟到数据，字节数就不是可控的 5/5 了
    sock.resetAndDestroy()
    await waitFor(() => tunnel.stats().active === 0, { label: 'finalized' })
    const record = tunnel.stats().records.at(-1)
    assert.ok(record, '应有一条完成记录')
    assert.equal(record.host, 'localhost')
    assert.equal(record.port, echoPort)
    assert.ok(record.connectMs >= 0, `connectMs=${record.connectMs}`)
    assert.ok(record.durationMs >= 0, `durationMs=${record.durationMs}`)
    assert.ok(record.connectMs <= record.durationMs + 5, '建连耗时不超过总时长')
    assert.equal(record.bytesUp, 5)
    assert.equal(record.bytesDown, 5)
    const s = tunnel.stats()
    assert.equal(s.bytesUp, 5)
    assert.equal(s.bytesDown, 5)
  } finally {
    await tunnel.close()
    await proxy.close()
    await echo.close()
  }
})

/* ============================================================
 * 13. close() 幂等，且关闭后新隧道被拒
 * ============================================================ */
test('13. close() 幂等；关闭后新 CONNECT 收 503', async () => {
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([443]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    await tunnel.close()
    await tunnel.close() // 幂等：第二次直接返回同一个 Promise
    const { sock, statusLine } = await openConnect(
      proxyPort,
      'localhost:443',
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 503 Service Unavailable')
    sock.destroy()
  } finally {
    await proxy.close()
  }
})

/* ============================================================
 * 14. 空 target / 畸形 target 被拒
 * ============================================================ */
test('14. 空 / 畸形 target 被拒（解析层 400）', async () => {
  assert.throws(() => parseConnectTarget(''), /empty_authority/)
  assert.throws(() => parseConnectTarget(null), /authority_not_string/)
  assert.throws(() => parseConnectTarget('host with space:443'), /control_or_space/)
  assert.throws(() => parseConnectTarget('a:1:2:3'), /bad_authority/)
  assert.throws(() => parseConnectTarget(':443'), /empty_host/)
  assert.throws(() => parseConnectTarget('host:'), /missing_port/)
  assert.throws(() => parseConnectTarget('http://host:443'), /has_scheme/)

  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: validatorOpts([443]),
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      ':443',
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 400 Bad Request')
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
  }
})

/* ============================================================
 * 15. 目标验证抛错时的错误映射
 * ============================================================ */
test('15a. 验证抛 TargetDenied → 403', async () => {
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    targetValidator: async () => { throw new TargetDenied('目标被拒绝：not_allowlisted（x）', { host: 'x', reason: 'not_allowlisted' }) },
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      'anything.example:443',
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 403 Forbidden')
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
  }
})

test('15b. 验证抛非契约错误 → 500（不伪装成网关故障）', async () => {
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    targetValidator: async () => { throw new Error('boom-validator') },
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      'anything.example:443',
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 500 Internal Server Error')
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
  }
})

test('15c. 验证抛 UpstreamTimeout → 504（ProxyError 按码映射）', async () => {
  const { UpstreamTimeout } = await import('../../lib/contract/errors.mjs')
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    targetValidator: async () => { throw new UpstreamTimeout('验证层超时', { phase: 'validate' }) },
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      'anything.example:443',
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.equal(statusLine, 'HTTP/1.1 504 Gateway Timeout')
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
  }
})

/* ============================================================
 * 16. connectTimeoutMs：上游挂起时按 504 收场，而不是 502
 * ============================================================ */
test('16. 上游建连超时按 504 收场（黑洞目标；环境若立刻回 RST 则为 502 —— 两者都合法，唯独不能是 200）', async () => {
  // 黑洞地址：SYN 发出去没有回应。若本机网络栈立刻报 EHOSTUNREACH，
  // ConnectFailure → 502 同样是「没先发 200」的正确行为；只有真的挂到
  // connectTimeoutMs 才走 504 分支。判据放宽为「拒绝状态行，绝非 200」。
  const tunnel = createConnectTunnel({
    clients: AUTH.clients,
    validatorOptions: {
      allowlist: ['blackhole.example'],
      allowedPorts: [80, 443, 8888],
      allowPrivate: true,
      resolve: () => ['10.255.255.1'], // RFC1918 内的可路由黑洞（allowPrivate 已开）
    },
    connectTimeoutMs: 300,
  })
  const proxy = startProxyServer(tunnel)
  const proxyPort = await proxy.ready
  try {
    const { sock, statusLine } = await openConnect(
      proxyPort,
      'blackhole.example:8888',
      { extraHeaders: `${AUTH_HEADER}\r\n` },
    )
    assert.match(statusLine, /^HTTP\/1\.1 (502|504) /)
    assert.equal(tunnel.stats().established, 0)
    sock.destroy()
  } finally {
    await tunnel.close()
    await proxy.close()
  }
})
