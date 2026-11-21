/**
 * error-classifier.mjs — 统一错误分类器（Issue #9 阶段 1）
 *
 * **纯函数，无状态。** 只回答三件事：
 *   1. 这是什么错误（category / phase / reason）
 *   2. 是否允许重试（retryable）
 *   3. 是否该计入 IP 惩罚、权重多少（penalizeIp / failureWeight）
 *
 * 它不修改任何统计、不做状态转换、不碰路由 —— 那些是健康管理器的事。
 *
 * 分类原则（方案 §3.3）：
 *   · 优先用稳定的错误码（err.code）与明确上下文，**不靠消息文本模糊匹配**改变性质
 *   · 未知错误保留惩罚（宁可错杀不可放过尚未覆盖的网络错误）
 *   · HTTP 业务状态码（401/403/429/500/502/503）默认不惩罚 IP
 */

/** 明确的网络层错误码 → 分类与阶段 */
const NETWORK_CODES = {
  ECONNREFUSED: { category: 'network', phase: 'connect' },
  ECONNRESET: { category: 'network', phase: 'transfer' },
  EHOSTUNREACH: { category: 'network', phase: 'connect' },
  ENETUNREACH: { category: 'network', phase: 'connect' },
  EPIPE: { category: 'network', phase: 'transfer' },
  ETIMEDOUT: { category: 'timeout', phase: 'unknown' },
  // TLS 层
  ERR_TLS_CERT_ALTNAME_INVALID: { category: 'protocol', phase: 'tls' },
  ERR_TLS_HANDSHAKE_TIMEOUT: { category: 'timeout', phase: 'tls' },
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: { category: 'protocol', phase: 'tls' },
  CERT_HAS_EXPIRED: { category: 'protocol', phase: 'tls' },
  DEPTH_ZERO_SELF_SIGNED_CERT: { category: 'protocol', phase: 'tls' },
  SELF_SIGNED_CERT_IN_CHAIN: { category: 'protocol', phase: 'tls' },
}

/** 网关自己抛出的超时（不是 Node 的错误码，用 message 精确匹配） */
const PROXY_TIMEOUTS = {
  first_byte_timeout: { category: 'timeout', phase: 'first_byte', failureWeight: 0.5 },
  upstream_timeout: { category: 'timeout', phase: 'transfer', failureWeight: 1 },
  client_aborted: { category: 'client_abort', phase: 'unknown', failureWeight: 0 },
}

const ZERO = { penalizeIp: false, failureWeight: 0 }

/**
 * @param {Error|object|null} err
 * @param {object} [context]
 * @param {boolean} [context.clientAborted] 客户端是否已断开（优先于一切）
 * @param {number}  [context.statusCode]    上游 HTTP 状态码（若已收到响应头）
 * @param {boolean} [context.headersReceived] 是否已收到响应头
 * @returns {{category:string, phase:string, reason:string, retryable:boolean, penalizeIp:boolean, failureWeight:number}}
 */
export function classifyError(err, context = {}) {
  const { clientAborted = false, statusCode = null } = context

  // 1. 客户端取消优先于一切 —— 它绝不是 IP 的问题
  if (clientAborted) {
    return {
      category: 'client_abort',
      phase: 'unknown',
      reason: 'client_aborted',
      retryable: false,
      ...ZERO,
    }
  }

  const code = err && typeof err === 'object' ? String(err.code || '') : ''
  const message = err && typeof err === 'object' ? String(err.message || '') : String(err || '')

  // 2. 网关自抛的超时：用精确 key 匹配，不做 includes 模糊判断
  for (const [key, spec] of Object.entries(PROXY_TIMEOUTS)) {
    if (message === key) {
      return {
        category: spec.category,
        phase: spec.phase,
        reason: key,
        retryable: spec.category === 'timeout',
        penalizeIp: spec.failureWeight > 0,
        failureWeight: spec.failureWeight,
      }
    }
  }

  // 3. 明确的网络/TLS 错误码
  if (code && NETWORK_CODES[code]) {
    const spec = NETWORK_CODES[code]
    return {
      category: spec.category,
      phase: spec.phase,
      reason: code,
      retryable: spec.category !== 'protocol' || true,
      penalizeIp: true,
      failureWeight: 1,
    }
  }

  // 4. HTTP 业务状态码：不计入 IP 惩罚（方案 §3.3）
  //
  //    注意：当前代理**从不**把状态码送进这个路径（失败只在 up.on('error') 记录），
  //    这里显式处理是为了让契约完整——将来若有人接入，分类器会替他把住。
  if (Number.isFinite(statusCode)) {
    const s = Number(statusCode)
    if (s === 401 || s === 403) {
      return { category: 'auth', phase: 'unknown', reason: `http_${s}`, retryable: false, ...ZERO }
    }
    if (s === 429) {
      return { category: 'rate_limit', phase: 'unknown', reason: 'http_429', retryable: true, ...ZERO }
    }
    if (s >= 500 && s <= 599) {
      return {
        category: 'upstream', phase: 'unknown', reason: `http_${s}`, retryable: true, ...ZERO,
      }
    }
  }

  // 5. 未知错误：保留惩罚，避免漏掉尚未覆盖的网络错误
  return {
    category: 'unknown',
    phase: 'unknown',
    reason: code || (message ? message.slice(0, 60) : 'unknown'),
    retryable: true,
    penalizeIp: true,
    failureWeight: 1,
  }
}
