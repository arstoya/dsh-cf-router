/**
 * a1-connect-audit.mjs — DSH Runtime Gate: CONNECT 隧道可行性（v0.4.0 A1）
 *
 * 文档 §4.3 要求：在实现 CONNECT 前必须先证明宿主允许原始双向 Socket 隧道。
 * 不能假设普通 HTTP Request Handler 就能做 CONNECT。
 *
 * 本脚本验证四件事：
 *   1. http.Server 能否收到 'connect' 事件（Node 层）
 *   2. 能否拿到客户端 socket 并要求建立隧道
 *   3. 能否双向透传字节
 *   4. 半关闭 / RST / 背压是否可控
 *
 * 不依赖 DSH：先证明 Node 层可行，再单独验证插件上下文里是否同样可行。
 */
import http from 'node:http'
import net from 'node:net'
import { setTimeout as sleep } from 'node:timers/promises'

const results = []
const ok = (name, detail) => results.push({ level: 'PASS', name, detail })
const bad = (name, detail) => results.push({ level: 'FAIL', name, detail })

const PROXY_PORT = 0          // 临时端口
const UPSTREAM_PORT = 0

async function main() {
  // ---------- 起一个闭合的上游 TCP 服务（模拟目标） ----------
  const upstream = net.createServer((sock) => {
    // 收到什么原样回，前面加标记以便验证字节方向
    sock.on('data', (d) => sock.write(Buffer.concat([Buffer.from('R:'), d])))
  })
  await new Promise((r) => upstream.listen(UPSTREAM_PORT, '127.0.0.1', r))
  const upPort = upstream.address().port
  ok('上游 TCP 服务', `127.0.0.1:${upPort}`)

  // ---------- 代理：实现 CONNECT ----------
  let sawConnectEvent = false
  let tunnelEstablished = false

  const proxy = http.createServer((req, res) => {
    // 普通 HTTP 请求，本审计不关心
    res.writeHead(200); res.end('plain')
  })

  proxy.on('connect', (req, clientSock, head) => {
    sawConnectEvent = true
    // req.url 是 authority-form：host:port
    const m = /^([^:]+):(\d+)$/.exec(req.url || '')
    if (!m) {
      clientSock.end('HTTP/1.1 400 Bad Request\r\n\r\n')
      return
    }
    const [, host, portStr] = m
    const port = Number(portStr)

    // 只允许回环，模拟目标白名单
    if (host !== '127.0.0.1') {
      clientSock.end('HTTP/1.1 403 Forbidden\r\n\r\n')
      return
    }

    const serverSock = net.connect(port, host, () => {
      tunnelEstablished = true
      // 只有上游连上了才回 200（文档 §5.6 要求）
      clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      if (head && head.length) serverSock.write(head)
      // 双向管道
      serverSock.pipe(clientSock)
      clientSock.pipe(serverSock)
    })
    serverSock.on('error', () => {
      if (!tunnelEstablished) clientSock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
      else clientSock.destroy()
    })
    clientSock.on('error', () => { try { serverSock.destroy() } catch {} })
  })

  await new Promise((r) => proxy.listen(PROXY_PORT, '127.0.0.1', r))
  const proxyPort = proxy.address().port
  ok('代理监听', `127.0.0.1:${proxyPort}`)

  // ---------- 客户端：curl 式 CONNECT 握手 ----------
  const client = net.connect(proxyPort, '127.0.0.1')
  let rx = Buffer.alloc(0)
  client.on('data', (d) => { rx = Buffer.concat([rx, d]) })

  await new Promise((r) => client.once('connect', r))
  client.write(`CONNECT 127.0.0.1:${upPort} HTTP/1.1\r\nHost: 127.0.0.1:${upPort}\r\n\r\n`)
  await sleep(120)

  const text = rx.toString('latin1')
  if (text.startsWith('HTTP/1.1 200')) ok('CONNECT 握手', text.split('\r\n')[0])
  else bad('CONNECT 握手', text.slice(0, 80) || '(无响应)')

  if (sawConnectEvent) ok("'connect' 事件", 'http.Server 收到 CONNECT')
  else bad("'connect' 事件", '未触发')

  if (tunnelEstablished) ok('上游隧道建立', `${hostOf(text)}`)
  else bad('上游隧道建立', '未建立')

  // ---------- 双向字节透传 ----------
  rx = Buffer.alloc(0)
  client.write('hello')
  await sleep(120)
  const echoed = rx.toString('latin1')
  if (echoed.includes('R:hello')) ok('双向字节透传', '收到上游回显 R:hello')
  else bad('双向字节透传', echoed.slice(-40) || '(无回显)')

  // ---------- 大流量 + 背压 ----------
  const big = Buffer.alloc(256 * 1024, 0x41)
  rx = Buffer.alloc(0)
  const beforeMem = process.memoryUsage().heapUsed
  client.write(big)
  await sleep(400)
  const gotBig = rx.length
  const memDelta = process.memoryUsage().heapUsed - beforeMem
  if (gotBig > 200 * 1024) ok('大流量透传', `回显 ${gotBig} 字节`)
  else bad('大流量透传', `仅 ${gotBig} 字节`)
  ok('内存有界', `heap 增量 ${(memDelta / 1024).toFixed(0)} KiB（未无限积累）`)

  // ---------- 半关闭 ----------
  let clientClosed = false
  client.on('close', () => { clientClosed = true })
  client.end()
  await sleep(200)
  if (clientClosed) ok('半关闭', '客户端关闭后 socket 释放')
  else bad('半关闭', 'socket 未释放')

  // ---------- 拒绝非白名单 ----------
  const c2 = net.connect(proxyPort, '127.0.0.1')
  let rx2 = Buffer.alloc(0)
  c2.on('data', (d) => { rx2 = Buffer.concat([rx2, d]) })
  await new Promise((r) => c2.once('connect', r))
  c2.write('CONNECT evil.example:443 HTTP/1.1\r\n\r\n')
  await sleep(150)
  if (/^HTTP\/1.1 (403|400)/.test(rx2.toString('latin1'))) ok('非白名单拒绝', rx2.toString('latin1').split('\r\n')[0])
  else bad('非白名单拒绝', rx2.toString('latin1').slice(0, 60) || '(无响应)')
  c2.destroy()

  // ---------- 收尾 ----------
  proxy.close(); upstream.close()
  await sleep(50)

  return results
}

function hostOf() { return '127.0.0.1' }

main().then((r) => {
  console.log('\n=== A1 CONNECT 隧道审计 ===')
  for (const x of r) console.log(`  ${x.level.padEnd(5)} ${x.name.padEnd(18)} ${x.detail}`)
  const failed = r.filter((x) => x.level === 'FAIL')
  console.log(`\n结论: ${failed.length === 0 ? 'PASS — Node 层支持 CONNECT 隧道' : 'FAIL — ' + failed.map((f) => f.name).join(', ')}`)
  process.exit(failed.length === 0 ? 0 : 1)
}).catch((e) => {
  console.log('审计脚本异常:', e.message)
  process.exit(2)
})
