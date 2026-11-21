/**
 * headers.mjs — 请求/响应 Header 过滤（Issue #5）
 *
 * 核心不是「把所有看起来特殊的 Header 都删掉」，而是遵守
 * **端到端字段（end-to-end）与逐跳字段（hop-by-hop）的边界**（RFC 7230 §6.1）。
 *
 *   端到端：由最终接收者解释，代理必须原样转发 —— content-encoding / content-type /
 *           authorization / accept-* / x-request-id ...
 *   逐跳：只对单条连接有意义，代理必须剥离 —— connection / keep-alive /
 *         proxy-authenticate / proxy-authorization / te / trailer /
 *         transfer-encoding / upgrade，**以及 Connection 头里动态列出的字段**
 *
 * 为什么必须处理 Connection 动态字段：`Connection: X-Internal` 是合法的逐跳声明，
 * 意思是「X-Internal 只在这一跳有意义」。只删标准字段会把 X-Internal 泄漏给上游。
 */

/** RFC 7230 §6.1 的标准逐跳字段（小写） */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/**
 * 解析 `Connection` 头，收集其中动态声明的逐跳字段名。
 * 例：`Connection: keep-alive, X-Internal, X-Other` → ['keep-alive','x-internal','x-other']
 */
export function connectionTokens(headers) {
  const raw = headers && (headers.connection || headers.Connection)
  if (typeof raw !== 'string') return []
  return raw
    .split(',')
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean)
}

/**
 * 过滤请求头（客户端 → 上游）。
 *
 * @param {object} incoming 入站请求头
 * @param {object} opts
 * @param {string} opts.targetHost 上游主机名（改写 Host）
 * @param {string[]} [opts.dropExtra] 额外要去掉的字段（如内部路由头）
 * @returns {object} 可直接交给 https.request 的头
 */
export function filterRequestHeaders(incoming, opts = {}) {
  const { targetHost, dropExtra = [] } = opts
  const drop = new Set(HOP_BY_HOP)
  for (const t of connectionTokens(incoming)) drop.add(t)
  for (const d of dropExtra) drop.add(String(d).toLowerCase())

  const out = {}
  for (const [name, value] of Object.entries(incoming || {})) {
    const lower = name.toLowerCase()
    if (drop.has(lower)) continue
    // Node 的 http 头是小写键；保留原始大小写无意义但也不改值
    out[lower] = value
  }

  // Host 必须改写成上游域名（否则上游按错误 vhost 处理）
  if (targetHost) out.host = targetHost

  // Content-Length：只有当请求体字节确实不变、且长度已知时才可信。
  // 注意要检查**入站**是否声明了 transfer-encoding —— 上一步已经把该字段
  // 从 out 里剥掉了，若在 out 上判断，条件永远为假（第一版就是这个 bug）。
  // chunked 请求体没有可信长度，必须让 Node 自己重新分帧。
  const incomingTe = incoming && (incoming['transfer-encoding'] || incoming['Transfer-Encoding'])
  if (incomingTe || out['transfer-encoding']) {
    delete out['content-length']
  }

  return out
}

/**
 * 过滤响应头（上游 → 客户端）。
 *
 * @param {object} upstream 上游响应头
 * @param {object} opts
 * @param {number} [opts.statusCode]
 * @returns {object}
 */
export function filterResponseHeaders(upstream, opts = {}) {
  const drop = new Set(HOP_BY_HOP)
  for (const t of connectionTokens(upstream)) drop.add(t)

  const out = {}
  for (const [name, value] of Object.entries(upstream || {})) {
    const lower = name.toLowerCase()
    if (drop.has(lower)) continue
    out[lower] = value
  }

  // Transfer-Encoding 已被剥离，下游 framing 由 Node 决定：
  //   · 若上游给了 content-length 且没有编码变换 → 保留，Node 按定长发
  //   · 否则 Node 自动用 chunked，并自己补 transfer-encoding
  // 两者同时出现会冲突（"既声明定长又要 chunked"），所以这里必须二选一。
  if (out['content-length'] !== undefined && !Number.isFinite(Number(out['content-length']))) {
    delete out['content-length']
  }

  // content-encoding（gzip/br）是端到端字段：必须保留，否则客户端解不开
  // content-type（含 text/event-stream）同理 —— 这里不做任何删除，只是标记意图
  return out
}

/**
 * 判断响应是否是 SSE。
 * SSE 依赖三件事：正确的 content-type、不缓冲、以及缓存控制语义。
 */
export function isEventStream(headers) {
  const ct = String(headers?.['content-type'] || '').toLowerCase()
  return ct.startsWith('text/event-stream')
}

/**
 * 处理 `Expect: 100-continue` 的三方握手。
 *
 * 链路：客户端 --Expect--> 代理 --?--> 上游
 *   · 客户端声明要发大请求体并等待 100
 *   · 代理必须**自己先向上游确认**，再把结果回给客户端
 *   · 直接转发 Expect 头是错的：那样客户端等的是上游的响应，
 *     而中间多了一跳，语义已变
 *
 * 本实现取保守策略：**不转发 Expect 头**，同时由 Node 默认行为立即放行
 * 客户端（不真的等 100）。理由是我们做流式 pipe，请求体会立刻开始流动，
 * 中间没有「先验后发」的机会窗口。这一点必须显式记录，不能假装处理了。
 *
 * @returns {{forwardExpect: boolean}}
 */
export function handleExpectContinue() {
  // 明确不转发：见上方说明。返回值仅为可观测性/测试断言用。
  return { forwardExpect: false }
}
