/**
 * https-server.js — 本地 HTTPS 上游桩
 *
 * 插件只会用 https 连上游（生产固定 443），所以探测/转发的测试必须用 TLS 服务。
 * 证书是 test/fixtures/certificates/ 下的自签证书，测试里把该 CA 注入
 * deps.tlsOptions 即可让 https.request 通过校验。
 *
 * 用法：
 *   const up = await startHttpsUpstream({ status: 200, body: '...' })
 *   mod.__testApi.deps.tlsOptions = { ca: up.cert }
 *   mod.__testApi.deps.upstreamPort = up.port
 */
import https from 'node:https'
import zlib from 'node:zlib'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import { freePort } from '../helpers/deferred.mjs'
import { ensureTestCertificate } from './certificates/ensure-certificate.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))

/** 取测试证书。首次调用会用 openssl 现生成（不入库）。 */
export function loadTestCertificate() {
  return ensureTestCertificate()
}

/**
 * @param {object} opts 同 http-server，另有
 * @param {number} [opts.delayTlsMs=0] 握手后延迟（不好直接模拟，改用 delayFirstByteMs）
 */
export async function startHttpsUpstream(opts = {}) {
  const {
    status = 200,
    body = '{"ok":true}',
    headers = {},
    delayFirstByteMs = 0,
    delayBodyMs = 0,
    sse = false,
    sseEvents = ['data: {"delta":"a"}\n\n', 'data: [DONE]\n\n'],
    gzip = false,
    abortMidBody = false,
    resetConnection = false,
    port = 0,
    certPair,
  } = opts

  const { key, cert } = certPair || loadTestCertificate()
  const requests = []
  const sockets = new Set()
  /** 上游眼里「响应还没写完，客户端就断了」的次数（Issue #4 的验收依据） */
  const abortedResponses = []
  /** 上游眼里「响应正常写完」的次数 */
  let completedResponses = 0

  const server = https.createServer({ key, cert }, async (req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    const record = { method: req.method, url: req.url, headers: req.headers, body: null }
    requests.push(record)

    // res.writableFinished 为 false 就 close，说明客户端在上游写完前断开了。
    // 这是「代理有没有真的取消上游」的可观测证据：若代理没销毁上游请求，
    // 它会把响应读完，这里就不会记成 aborted。
    res.on('close', () => {
      if (res.writableFinished) {
        completedResponses += 1
      } else {
        abortedResponses.push({ url: req.url, at: Date.now() })
      }
    })

    await new Promise((r) => req.on('end', r).on('error', r))
    record.body = Buffer.concat(chunks).toString('utf8')

    if (resetConnection) {
      try { req.socket.destroy() } catch { /* ignore */ }
      return
    }
    if (delayFirstByteMs) await new Promise((r) => setTimeout(r, delayFirstByteMs))

    if (sse) {
      res.writeHead(status, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
        ...headers,
      })
      for (const ev of sseEvents) {
        if (res.writableEnded || res.destroyed) return
        res.write(ev)
        if (delayBodyMs) await new Promise((r) => setTimeout(r, delayBodyMs))
      }
      res.end()
      return
    }

    let payload = Buffer.isBuffer(body)
      ? body
      : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8')

    const outHeaders = { 'content-type': 'application/json', ...headers }
    if (gzip) {
      payload = zlib.gzipSync(payload)
      outHeaders['content-encoding'] = 'gzip'
    }
    outHeaders['content-length'] = String(payload.length)
    res.writeHead(status, outHeaders)

    if (abortMidBody) {
      res.write(payload.subarray(0, Math.max(1, Math.floor(payload.length / 3))))
      await new Promise((r) => setTimeout(r, delayBodyMs || 10))
      try { res.socket.destroy() } catch { /* ignore */ }
      return
    }
    if (delayBodyMs) {
      const half = Math.ceil(payload.length / 2)
      res.write(payload.subarray(0, half))
      await new Promise((r) => setTimeout(r, delayBodyMs))
      res.write(payload.subarray(half))
      res.end()
      return
    }
    res.end(payload)
  })

  server.on('connection', (s) => {
    sockets.add(s)
    s.on('close', () => sockets.delete(s))
  })

  const listenPort = port || (await freePort())
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(listenPort, '127.0.0.1', resolve)
  })

  return {
    server,
    port: server.address().port,
    url: `https://127.0.0.1:${server.address().port}`,
    cert,
    key,
    requests,
    connections: () => sockets.size,
    /** 客户端在上游写完前断开的次数（代理取消链路的可观测证据） */
    abortedCount: () => abortedResponses.length,
    completedCount: () => completedResponses,
    async close() {
      for (const s of sockets) { try { s.destroy() } catch { /* ignore */ } }
      await new Promise((r) => server.close(r))
    },
  }
}
