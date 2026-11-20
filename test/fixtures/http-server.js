/**
 * http-server.js — 本地 HTTP 上游桩
 *
 * 用来替代真实上游。可配置：状态码、响应体、SSE、gzip、
 * 延迟首字节、响应体传输中途断开、连接重置。
 *
 * 用法：
 *   const up = await startHttpUpstream({ status: 200, body: '{"ok":1}' })
 *   ... up.port, up.url, up.requests（收到的请求记录）, up.close()
 */
import http from 'node:http'
import zlib from 'node:zlib'
import { freePort } from '../helpers/deferred.mjs'

/**
 * @param {object} opts
 * @param {number} [opts.status=200]
 * @param {string|Buffer|object} [opts.body]  object 会被 JSON.stringify
 * @param {object} [opts.headers]
 * @param {number} [opts.delayFirstByteMs=0]   收到请求后延迟多久才开始回
 * @param {number} [opts.delayBodyMs=0]        首字节之后，响应体分片之间延迟
 * @param {boolean} [opts.sse=false]           按 SSE 逐条推送
 * @param {string[]} [opts.sseEvents]          自定义 SSE 事件内容
 * @param {boolean} [opts.gzip=false]          用 gzip 压缩响应体
 * @param {boolean} [opts.abortMidBody=false]  写了几个字节后直接 destroy socket
 * @param {boolean} [opts.resetConnection=false] 立刻 RST
 * @param {number} [opts.port=0]               0 = 自动选空闲端口
 */
export async function startHttpUpstream(opts = {}) {
  const {
    status = 200,
    body = '{"ok":true}',
    headers = {},
    delayFirstByteMs = 0,
    delayBodyMs = 0,
    sse = false,
    sseEvents = ['data: {"delta":"a"}\n\n', 'data: {"delta":"b"}\n\n', 'data: [DONE]\n\n'],
    gzip = false,
    abortMidBody = false,
    resetConnection = false,
    port = 0,
  } = opts

  const requests = []
  const sockets = new Set()

  const server = http.createServer(async (req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    const record = {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: null,
    }
    requests.push(record)

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
        connection: 'keep-alive',
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
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    connections: () => sockets.size,
    async close() {
      for (const s of sockets) { try { s.destroy() } catch { /* ignore */ } }
      await new Promise((r) => server.close(r))
    },
  }
}
