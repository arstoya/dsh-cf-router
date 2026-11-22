/**
 * a1-in-plugin.mjs —— 插件上下文内 CONNECT 可行性
 *
 * 目的：第一个脚本只证明了「Node 层」可行；这里验证
 * 「插件进程内」同样可行（宿主不额外限制 bind / socket）。
 */
import http from 'node:http'
import net from 'node:net'
import { setTimeout as sleep } from 'node:timers/promises'

const out = []
const ok = (n, d) => out.push(['PASS', n, d])
const bad = (n, d) => out.push(['FAIL', n, d])

const upstream = net.createServer((s) => {
  s.on('data', (d) => s.write(Buffer.concat([Buffer.from('R:'), d])))
})
await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
const upPort = upstream.address().port

const proxy = http.createServer((_q, s) => s.end('plain'))
proxy.on('connect', (req, cs, head) => {
  const m = /^([^:]+):(\d+)$/.exec(req.url || '')
  if (!m) return cs.end('HTTP/1.1 400 Bad Request\r\n\r\n')
  const [, h, p] = m
  if (h !== '127.0.0.1') return cs.end('HTTP/1.1 403 Forbidden\r\n\r\n')
  const ss = net.connect(Number(p), h, () => {
    cs.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    if (head && head.length) ss.write(head)
    ss.pipe(cs)
    cs.pipe(ss)
  })
  ss.on('error', () => cs.destroy())
  cs.on('error', () => { try { ss.destroy() } catch { /* ignore */ } })
})
await new Promise((r) => proxy.listen(0, '127.0.0.1', r))
const pPort = proxy.address().port
ok('插件进程内可监听', `127.0.0.1:${pPort}`)

const c = net.connect(pPort, '127.0.0.1')
let rx = Buffer.alloc(0)
c.on('data', (d) => { rx = Buffer.concat([rx, d]) })
await new Promise((r) => c.once('connect', r))
c.write(`CONNECT 127.0.0.1:${upPort} HTTP/1.1\r\n\r\n`)
await sleep(150)
if (/^HTTP\/1\.1 200/.test(rx.toString('latin1'))) ok('隧道建立', '200 Established')
else bad('隧道建立', rx.toString('latin1').slice(0, 50))

rx = Buffer.alloc(0)
c.write('ping')
await sleep(120)
if (rx.toString('latin1').includes('R:ping')) ok('双向透传', 'R:ping')
else bad('双向透传', '无回显')

c.end()
proxy.close()
upstream.close()
await sleep(50)

console.log('\n=== 插件上下文 CONNECT 审计 ===')
for (const [l, n, d] of out) console.log(`  ${l.padEnd(5)} ${n.padEnd(16)} ${d}`)
const f = out.filter((x) => x[0] === 'FAIL')
console.log(`\n结论: ${f.length ? 'FAIL — ' + f.map((x) => x[1]).join(',') : 'PASS'}`)
process.exit(f.length ? 1 : 0)
