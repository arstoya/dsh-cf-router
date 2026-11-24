/**
 * errors.mjs — 统一错误类型（Issue #26 / A2）
 *
 * v0.4.0 的两种入口（Forward / Reverse）共用同一套错误语义。
 * 这里定义 9 个具名类型，C3（重试决策）将按类型分支而不是按字符串。
 *
 * ## 为什么用 class 而不是普通对象
 *
 * 现有 `lib/index.js` 的错误是 `{ error: 'target_not_allowed', message }`。
 * 新架构改用 class，理由只有一条：**C3 需要可靠的分支判断**。
 *
 *   err instanceof ClientCancelled   // 取消，永不可重试
 *   err.code === 'client_cancelled'  // 字符串，拼错不报错
 *
 * 第一种在重构时会被编辑器/类型检查盯住，第二种不会。
 *
 * ## 一条硬约束
 *
 * `details` **不得**包含 Token / Authorization / Cookie / 完整敏感 URL。
 * 有测试断言 `JSON.stringify(err)` 不匹配这些模式。
 *
 * @module contract/errors
 */

/**
 * 所有代理错误的基类。
 *
 * @extends Error
 */
export class ProxyError extends Error {
  /**
   * @param {string} code 稳定标识，与类一一对应
   * @param {string} message 人类可读描述，**不含敏感值**
   * @param {Record<string, unknown>} [details] 结构化附加信息，同样不含敏感值
   */
  constructor(code, message, details = {}) {
    super(message)
    this.name = 'ProxyError'
    /** @type {string} */
    this.code = code
    /** @type {Record<string, unknown>} */
    this.details = details
  }

  /**
   * 序列化。刻意只输出 code / message / details —
   * 不含 stack，因为 stack 可能带文件路径与内部结构。
   *
   * @returns {{ code: string, message: string } & Record<string, unknown>}
   */
  toJSON() {
    return { code: this.code, message: this.message, ...this.details }
  }
}

/** 目标不在白名单、或解析到受保护地址 */
export class TargetDenied extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('target_denied', message, details)
    this.name = 'TargetDenied'
  }
}

/** 客户端未通过认证，或凭据无效 */
export class ClientUnauthorized extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('client_unauthorized', message, details)
    this.name = 'ClientUnauthorized'
  }
}

/** DNS 解析失败，或解析结果全部被拒 */
export class DnsFailure extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('dns_failure', message, details)
    this.name = 'DnsFailure'
  }
}

/** TCP 连接建立失败 */
export class ConnectFailure extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('connect_failure', message, details)
    this.name = 'ConnectFailure'
  }
}

/**
 * TLS 握手失败或证书校验失败。
 *
 * **注意**：证书安全错误不应被静默吞掉（方案 §5.5）——
 * 它可能意味着中间人或配置错误，不是「重试一次就好」。
 */
export class TlsFailure extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('tls_failure', message, details)
    this.name = 'TlsFailure'
  }
}

/** 上游在任一阶段超时（DNS / connect / first byte / stream idle / total） */
export class UpstreamTimeout extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('upstream_timeout', message, details)
    this.name = 'UpstreamTimeout'
  }
}

/**
 * 客户端主动取消。
 *
 * **永不重试、永不惩罚上游**（方案 §5.5）。C3 必须把它排在最前面判断。
 */
export class ClientCancelled extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('client_cancelled', message, details)
    this.name = 'ClientCancelled'
  }
}

/** 响应体传输中断（对端断开、分块错误等） */
export class StreamFailure extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('stream_failure', message, details)
    this.name = 'StreamFailure'
  }
}

/**
 * 不允许重试。
 *
 * 与「可重试但失败了」不同：这个错误表示**判定阶段就否决了重试**，
 * 通常因为响应已提交给客户端、请求体不可重放、或方法非幂等。
 */
export class RetryNotAllowed extends ProxyError {
  /** @param {string} message @param {Record<string, unknown>} [details] */
  constructor(message, details) {
    super('retry_not_allowed', message, details)
    this.name = 'RetryNotAllowed'
  }
}

/** code → 构造函数，供反序列化与测试用 */
const REGISTRY = Object.freeze({
  target_denied: TargetDenied,
  client_unauthorized: ClientUnauthorized,
  dns_failure: DnsFailure,
  connect_failure: ConnectFailure,
  tls_failure: TlsFailure,
  upstream_timeout: UpstreamTimeout,
  client_cancelled: ClientCancelled,
  stream_failure: StreamFailure,
  retry_not_allowed: RetryNotAllowed,
})

/** 全部合法 code */
export const ERROR_CODES = Object.freeze(Object.keys(REGISTRY))

/**
 * 由 code 构造对应的错误实例。
 *
 * 未知 code 返回 `null` 而不是抛错 —— 调用方通常在处理已经出错的情况，
 * 再加一个异常只会把原始错误盖掉。
 *
 * @param {string} code
 * @param {string} [message]
 * @param {Record<string, unknown>} [details]
 * @returns {ProxyError|null}
 */
export function errorFromCode(code, message, details) {
  const Ctor = REGISTRY[code]
  if (!Ctor) return null
  return new Ctor(message ?? code, details)
}

/**
 * 判断某个值是否属于本模块定义的错误类型。
 *
 * 不直接用 `instanceof ProxyError`：插件可能被加载两次（不同模块实例），
 * 那时 `instanceof` 会因构造函数不同而失败。这里按 code 判断更稳。
 *
 * @param {unknown} err
 * @returns {boolean}
 */
export function isProxyError(err) {
  if (err instanceof ProxyError) return true
  return Boolean(
    err
    && typeof err === 'object'
    && typeof (/** @type {{code?: unknown}} */ (err)).code === 'string'
    && ERROR_CODES.includes(/** @type {{code: string}} */ (err).code),
  )
}
