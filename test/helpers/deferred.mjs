/**
 * deferred.mjs / 等待工具
 *
 * 测试里到处是「等某个事件发生」。统一用这两种原语：
 *   - deferred()：手动 resolve/reject，用来把异步流程卡在指定点
 *   - waitFor(pred, opts)：轮询直到条件成立，超时抛错（比固定 sleep 稳）
 */

export function deferred() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

/** 轮询直到 pred() 为真；超时抛错并带上最后一次取值 */
export async function waitFor(pred, { timeoutMs = 3000, intervalMs = 10, label = 'condition', describe } = {}) {
  const started = Date.now()
  for (;;) {
    const value = await pred()
    if (value) return value
    if (Date.now() - started > timeoutMs) {
      const extra = describe ? describe() : ''
      throw new Error(`waitFor(${label}) 超时 ${timeoutMs}ms${extra ? ' — ' + extra : ''}`)
    }
    await sleep(intervalMs)
  }
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

/** 拿一个当前空闲的本地端口 */
export async function freePort() {
  const net = await import('node:net')
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}
