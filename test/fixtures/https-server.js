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
    chunkedWrite = 0,
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

    // 「上游有没有被取消」的判据（三次试错后的总结）：
    //   1. res.writableFinished —— 一次性 res.end(bigBuffer) 会立刻为 true，
    //      客户端之后再断开测不出来
    //   2. res.writableLength   —— 同样是瞬时的，8MB 一次写完立刻归零
    //   3. res.destroyed        —— 服务端视角，客户端断开时不一定会置位
    // 真正可靠的信号是**连接是否被对端关闭**：
    //   客户端读完之前断开 → socket 会 close，且此时请求还没走完
    let finishedNormally = false
    res.on('finish', () => { finishedNormally = true })

    res.on('close', () => {
      // 服务端还没 finish 连接就被关了 = 客户端中途断开
      if (finishedNormally) completedResponses += 1
      else abortedResponses.push({ url: req.url, at: Date.now() })
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

    // chunkedWrite：把响应体拆成 N 块，每块之间等 drain。
    // 这样在客户端断开时**一定还有未 flush 的数据**，才测得出取消。
    // 一次性 res.end(8MB) 会被内核瞬间收下，之后再断开就无从观测。
    if (chunkedWrite) {
      const total = payload.length
      const chunkSize = Math.max(64 * 1024, Math.ceil(total / chunkedWrite))
      let offset = 0
      while (offset < total) {
        if (res.destroyed) return
        const slice = payload.subarray(offset, offset + chunkSize)
        offset += slice.length
        const ok = res.write(slice)
        // 等缓冲区腾出空间再继续 —— 这正是客户端断开时会被打断的地方
        if (!ok) {
          await new Promise((r) => { res.once('drain', r); res.once('close', r) })
        }
      }
      if (!res.destroyed) res.end()
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
