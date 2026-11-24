/**
 * request-context.mjs — 统一请求上下文（Issue #26 / A2）
 *
 * 两种入口（Forward / Reverse）都产出这一个结构，Core 只认它，
 * 不认 `req` / `res` / `socket` 这类入口专有对象。
 *
 * ## 两条刻意的设计决定
 *
 * **1. `clientId` / `routeGroupId` 不允许为空，工厂直接拒绝。**
 *
 * 这两个字段是**授权决定的结果**，不是请求输入。B2 明确：
 * 客户端自报的身份 Header 必须被忽略，身份由服务端认证结果确定。
 *
 * 如果工厂允许传 `''`，下游某处就可能把它当成「未认证」而走另一条分支 ——
 * 那种「半认证」状态正是要消灭的。空值应该在**调用工厂之前**就被拒绝
 * （认证失败 → 抛 `ClientUnauthorized`）。
 *
 * **2. 返回 `Object.freeze` 的对象。**
 *
 * Core 的各个阶段（验证 → 路由 → 传输 → 记录）都读同一个 context。
 * 任何一处就地改写，后面的阶段就会看到被篡改的输入，而这类 bug
 * 在日志里几乎不可能看出来。
 *
 * @module contract/request-context
 */

import { randomUUID } from 'node:crypto'

/** 合法入口类型 */
export const REQUEST_MODES = Object.freeze(['forward', 'reverse'])

/**
 * @typedef {object} RequestContext
 * @property {string} requestId 唯一标识，用于日志关联
 * @property {string} clientId 由服务端认证确定，**不来自请求头**
 * @property {string} routeGroupId 由服务端绑定关系确定
 * @property {'forward'|'reverse'} mode 入口类型
 * @property {string} method 已规范化为大写
 * @property {string} originalUrl 原始 URL（Forward 为 absolute-form）
 * @property {Record<string, string|string[]>} headers 键已规范化为小写
 * @property {ReadableStream<Uint8Array>|null} body 流式请求体，无体为 null
 * @property {AbortSignal} signal 客户端取消信号
 * @property {number} startedAt 毫秒时间戳
 */

/**
 * 把 header 名规范化为小写键。
 *
 * 不做 trim、不改值 —— 值里的空格可能是签名的一部分。
 *
 * @param {Record<string, string|string[]>} [headers]
 * @returns {Record<string, string|string[]>}
 */
function normalizeHeaders(headers) {
  /** @type {Record<string, string|string[]>} */
  const out = {}
  for (const [k, v] of Object.entries(headers || {})) {
    if (k === '') continue
    out[k.toLowerCase()] = v
  }
  return out
}

/**
 * 构造并校验请求上下文。
 *
 * @param {object} input
 * @param {string} [input.requestId] 省略则生成 UUID
 * @param {string} input.clientId 必填、非空
 * @param {string} input.routeGroupId 必填、非空
 * @param {'forward'|'reverse'} input.mode 必填
 * @param {string} input.method 必填，自动大写
 * @param {string} input.originalUrl 必填
 * @param {Record<string, string|string[]>} [input.headers] 自动小写化
 * @param {ReadableStream<Uint8Array>|null} [input.body]
 * @param {AbortSignal} [input.signal] 省略则新建一个永不取消的 signal
 * @param {number} [input.startedAt] 省略则用当前时间
 * @returns {RequestContext}
 * @throws {TypeError} 任必填字段不合法
 */
export function makeRequestContext(input) {
  if (input == null || typeof input !== 'object') {
    throw new TypeError('makeRequestContext: 需要对象参数')
  }

  const requestId = input.requestId == null ? randomUUID() : input.requestId
  if (typeof requestId !== 'string' || requestId === '') {
    throw new TypeError('makeRequestContext: requestId 必须是非空字符串')
  }

  // 身份字段：不允许空值，理由见文件头
  for (const key of ['clientId', 'routeGroupId']) {
    const v = input[key]
    if (typeof v !== 'string' || v === '') {
      throw new TypeError(
        `makeRequestContext: ${key} 必须是非空字符串（身份由服务端认证结果决定，` +
        '空值应在调用本函数前就拒绝）',
      )
    }
  }

  if (!REQUEST_MODES.includes(input.mode)) {
    throw new TypeError(
      `makeRequestContext: mode 必须是 ${REQUEST_MODES.join(' 或 ')}，实际 ${JSON.stringify(input.mode)}`,
    )
  }

  const method = typeof input.method === 'string' ? input.method.trim() : ''
  if (method === '') {
    throw new TypeError('makeRequestContext: method 必须是非空字符串')
  }

  if (typeof input.originalUrl !== 'string' || input.originalUrl === '') {
    throw new TypeError('makeRequestContext: originalUrl 必须是非空字符串')
  }

  const signal = input.signal == null ? new AbortController().signal : input.signal
  if (!signal || typeof signal.aborted !== 'boolean') {
    throw new TypeError('makeRequestContext: signal 必须是 AbortSignal')
  }

  const startedAt = input.startedAt == null ? Date.now() : input.startedAt
  if (!Number.isFinite(startedAt)) {
    throw new TypeError('makeRequestContext: startedAt 必须是有限数字')
  }

  const body = input.body == null ? null : input.body
  if (body !== null && typeof body !== 'object') {
    throw new TypeError('makeRequestContext: body 必须是 ReadableStream 或 null')
  }

  return Object.freeze({
    requestId,
    clientId: input.clientId,
    routeGroupId: input.routeGroupId,
    mode: input.mode,
    method: method.toUpperCase(),
    originalUrl: input.originalUrl,
    headers: normalizeHeaders(input.headers),
    body,
    signal,
    startedAt,
  })
}

/**
 * 判断某个值是否是合法的 RequestContext 结构。
 *
 * 用于跨信任边界的地方（例如 Core 收到一个来路不明的对象时先验一下）。
 * 不做深度校验（headers 的值类型、body 的流状态），那属于调用方的责任。
 *
 * @param {unknown} v
 * @returns {boolean}
 */
export function isRequestContext(v) {
  if (v == null || typeof v !== 'object') return false
  const c = /** @type {Record<string, unknown>} */ (v)
  return (
    typeof c.requestId === 'string' && c.requestId !== ''
    && typeof c.clientId === 'string' && c.clientId !== ''
    && typeof c.routeGroupId === 'string' && c.routeGroupId !== ''
    && REQUEST_MODES.includes(/** @type {any} */ (c.mode))
    && typeof c.method === 'string' && c.method !== ''
    && typeof c.originalUrl === 'string'
    && c.headers != null && typeof c.headers === 'object'
    && typeof c.startedAt === 'number'
    && c.signal != null && typeof (/** @type {any} */ (c.signal)).aborted === 'boolean'
  )
}
