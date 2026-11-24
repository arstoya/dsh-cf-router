/**
 * upstream.mjs — 上游、分组与客户端身份（Issue #26 / A2）
 *
 * 三类配置对象共用一个模式：工厂函数做校验 + 填默认 + freeze，
 * 不引入 schema 库（现有 schemastery 用于插件配置面，这里是内部契约）。
 *
 * ## 三条硬约束及其理由
 *
 * **1. `protocol` 只接受 `'https'`**
 * 方案 §1.2 明确「不做明文 HTTP 到上游」。允许 `http` 会让人以为
 * 「本地测试用一下」是可以的，而实际上那会把凭据以明文发出去。
 * 需要明文调试时应该走 `routingMode: 'direct'`，不经过代理。
 *
 * **2. `authTokenHash` 拒绝明文 Token**
 * 只做**启发式**检查（长度与常见前缀），不是密码学保证。
 * 目的是防手滑 —— 有人把 `sk-xxxx` 直接贴进配置时立刻报错，
 * 而不是等到日志/状态快照里出现明文才发现。
 *
 * **3. `retryOn` 是 code 白名单，不是布尔开关**
 * C3 的结论：重试资格由上下文决定（失败阶段、Body 可重放性、
 * 响应是否已提交）。策略层只声明「哪些错误类别原则上可重试」。
 *
 * @module contract/upstream
 */

import { ERROR_CODES } from './errors.mjs'

/** 允许的上游协议。只支持 https，理由见文件头。 */
export const UPSTREAM_PROTOCOLS = Object.freeze(['https'])

/** 合法路由模式 */
export const ROUTING_MODES = Object.freeze(['auto', 'direct'])

/**
 * 明文 Token 的启发式特征。
 *
 * **这不是安全边界**，是「手滑检测」。真正的防护是永远不读明文 Token
 * （见 B2）。命中这些模式时直接拒绝，让配置阶段就暴露问题。
 */
const PLAINTEXT_TOKEN_PATTERNS = Object.freeze([
  /^sk-[A-Za-z0-9_-]{8,}$/,          // OpenAI 风格
  /^ghp_[A-Za-z0-9]{8,}$/,           // GitHub PAT (classic)
  /^github_pat_/,                     // GitHub PAT (fine-grained)
  /^Bearer\s+/i,                      // 把整个 header 贴进来了
  // 长 base64，通常是 key 本体。
  // **必须要求含 base64 特征字符**（+ / =）——否则 sha256 的 64 位十六进制
  // 会被这条误伤。实测踩到过。
  /^[A-Za-z0-9+/]{40,}={0,2}$/,
])

/**
 * 合法摘要的形态：纯十六进制，长度 32（md5）到 128（sha512）。
 *
 * 先认这个再跑明文检测，因为 sha256 hex 是 64 位字母数字，
 * 与「长 token」在朴素正则下无法区分。
 */
const HEX_DIGEST = /^[0-9a-f]{32,128}$/i

/**
 * @typedef {object} Upstream
 * @property {string} id 全局唯一（Registry 主键）
 * @property {string} name
 * @property {string} hostname
 * @property {number} port 1..65535
 * @property {'https'} protocol
 * @property {boolean} enabled
 * @property {number} priority 越小越优先
 * @property {number} weight 加权用，>= 0
 * @property {number|null} timeoutMs 覆盖 Transport 默认超时
 */

/**
 * @typedef {object} RetryPolicy
 * @property {number} maxAttempts 含首次，>= 1
 * @property {number} totalBudgetMs 整次请求（含重试）的时间上限
 * @property {number} baseDelayMs 退避基数
 * @property {number} maxDelayMs 退避上限
 * @property {ReadonlyArray<string>} retryOn 允许重试的错误 code 白名单（frozen）
 */

/**
 * @typedef {object} UpstreamGroup
 * @property {string} id
 * @property {string} name
 * @property {ReadonlyArray<string>} upstreamIds 引用 Upstream.id，已去重（frozen）
 * @property {'auto'|'direct'} routingMode
 * @property {RetryPolicy} retryPolicy
 */

/**
 * @typedef {object} ProxyClient
 * @property {string} id
 * @property {string} name
 * @property {boolean} enabled
 * @property {string} routeGroupId 绑定关系
 * @property {string} authTokenHash 只存哈希
 */

/**
 * 非空字符串判断。
 *
 * **必须写成类型守卫**：否则 `nonEmpty(input.name) ? input.name : input.id`
 * 在 strictNullChecks 下会被推成 `string | undefined`（tsc 不知道三元分支里
 * 已经把 undefined 排除掉了）。
 *
 * @param {unknown} v
 * @returns {v is string}
 */
const nonEmpty = (v) => typeof v === 'string' && v.trim() !== ''

/**
 * 构造上游。`enabled` 默认 true，`priority` 默认 100，`weight` 默认 1。
 *
 * @param {object} input
 * @param {string} input.id
 * @param {string} [input.name] 省略则用 id
 * @param {string} input.hostname
 * @param {number} [input.port] 默认 443
 * @param {'https'} [input.protocol] 默认 'https'
 * @param {boolean} [input.enabled]
 * @param {number} [input.priority]
 * @param {number} [input.weight]
 * @param {number|null} [input.timeoutMs]
 * @returns {Upstream}
 * @throws {TypeError}
 */
export function makeUpstream(input) {
  if (input == null || typeof input !== 'object') {
    throw new TypeError('makeUpstream: 需要对象参数')
  }
  if (!nonEmpty(input.id)) {
    throw new TypeError('makeUpstream: id 必须是非空字符串')
  }
  if (!nonEmpty(input.hostname)) {
    throw new TypeError('makeUpstream: hostname 必须是非空字符串')
  }

  const port = input.port == null ? 443 : input.port
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError(`makeUpstream: port 必须是 1..65535 的整数，实际 ${JSON.stringify(input.port)}`)
  }

  const protocol = input.protocol == null ? 'https' : input.protocol
  if (!UPSTREAM_PROTOCOLS.includes(protocol)) {
    throw new TypeError(
      `makeUpstream: protocol 只支持 ${UPSTREAM_PROTOCOLS.join('/')}，实际 ${JSON.stringify(protocol)}。` +
      '明文 HTTP 会把凭据以明文发出；需要明文调试请用 routingMode: direct。',
    )
  }

  const priority = input.priority == null ? 100 : input.priority
  if (!Number.isFinite(priority)) {
    throw new TypeError('makeUpstream: priority 必须是有限数字')
  }

  const weight = input.weight == null ? 1 : input.weight
  if (!Number.isFinite(weight) || weight < 0) {
    throw new TypeError('makeUpstream: weight 必须是 >= 0 的有限数字')
  }

  const timeoutMs = input.timeoutMs == null ? null : input.timeoutMs
  if (timeoutMs !== null && (!Number.isFinite(timeoutMs) || timeoutMs <= 0)) {
    throw new TypeError('makeUpstream: timeoutMs 必须是正数或 null')
  }

  return Object.freeze({
    id: input.id,
    name: nonEmpty(input.name) ? input.name : input.id,
    hostname: input.hostname,
    port,
    protocol,
    enabled: input.enabled !== false,
    priority,
    weight,
    timeoutMs,
  })
}

/**
 * 构造重试策略。
 *
 * 默认值刻意保守：1 次尝试（等于不重试）、5 秒预算、只对网络层错误开放。
 * 想开重试必须显式写，不能靠默认。
 *
 * @param {object} [input]
 * @param {number} [input.maxAttempts] 默认 1
 * @param {number} [input.totalBudgetMs] 默认 5000
 * @param {number} [input.baseDelayMs] 默认 100
 * @param {number} [input.maxDelayMs] 默认 1000
 * @param {string[]} [input.retryOn] 默认 ['connect_failure','dns_failure']
 * @returns {RetryPolicy}
 * @throws {TypeError}
 */
export function makeRetryPolicy(input = {}) {
  if (input == null || typeof input !== 'object') {
    throw new TypeError('makeRetryPolicy: 需要对象参数')
  }

  const maxAttempts = input.maxAttempts == null ? 1 : input.maxAttempts
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new TypeError('makeRetryPolicy: maxAttempts 必须是 >= 1 的整数')
  }

  const totalBudgetMs = input.totalBudgetMs == null ? 5000 : input.totalBudgetMs
  if (!Number.isFinite(totalBudgetMs) || totalBudgetMs <= 0) {
    throw new TypeError('makeRetryPolicy: totalBudgetMs 必须是正数')
  }

  const baseDelayMs = input.baseDelayMs == null ? 100 : input.baseDelayMs
  const maxDelayMs = input.maxDelayMs == null ? 1000 : input.maxDelayMs
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0) {
    throw new TypeError('makeRetryPolicy: baseDelayMs 必须是 >= 0 的有限数字')
  }
  if (!Number.isFinite(maxDelayMs) || maxDelayMs < baseDelayMs) {
    throw new TypeError('makeRetryPolicy: maxDelayMs 必须 >= baseDelayMs')
  }

  const retryOn = input.retryOn == null
    ? ['connect_failure', 'dns_failure']
    : input.retryOn
  if (!Array.isArray(retryOn)) {
    throw new TypeError('makeRetryPolicy: retryOn 必须是数组')
  }
  for (const code of retryOn) {
    if (!ERROR_CODES.includes(code)) {
      throw new TypeError(`makeRetryPolicy: retryOn 含未知错误码 ${JSON.stringify(code)}`)
    }
  }

  // client_cancelled 绝不可重试 —— 允许它进来是配置错误，不是策略选择
  if (retryOn.includes('client_cancelled')) {
    throw new TypeError(
      'makeRetryPolicy: retryOn 不能包含 client_cancelled（客户端取消永不重试，见方案 §5.5）',
    )
  }

  return Object.freeze({
    maxAttempts,
    totalBudgetMs,
    baseDelayMs,
    maxDelayMs,
    retryOn: Object.freeze([...new Set(retryOn)]),
  })
}

/**
 * 构造上游分组。
 *
 * @param {object} input
 * @param {string} input.id
 * @param {string} [input.name]
 * @param {string[]} [input.upstreamIds]
 * @param {'auto'|'direct'} [input.routingMode] 默认 'auto'
 * @param {object|RetryPolicy} [input.retryPolicy]
 * @returns {UpstreamGroup}
 * @throws {TypeError}
 */
export function makeUpstreamGroup(input) {
  if (input == null || typeof input !== 'object') {
    throw new TypeError('makeUpstreamGroup: 需要对象参数')
  }
  if (!nonEmpty(input.id)) {
    throw new TypeError('makeUpstreamGroup: id 必须是非空字符串')
  }

  const ids = input.upstreamIds == null ? [] : input.upstreamIds
  if (!Array.isArray(ids)) {
    throw new TypeError('makeUpstreamGroup: upstreamIds 必须是数组')
  }
  for (const id of ids) {
    if (!nonEmpty(id)) {
      throw new TypeError('makeUpstreamGroup: upstreamIds 里每项都必须是非空字符串')
    }
  }

  const routingMode = input.routingMode == null ? 'auto' : input.routingMode
  if (!ROUTING_MODES.includes(routingMode)) {
    throw new TypeError(
      `makeUpstreamGroup: routingMode 必须是 ${ROUTING_MODES.join(' 或 ')}，实际 ${JSON.stringify(routingMode)}`,
    )
  }

  const retryPolicy = input.retryPolicy == null
    ? makeRetryPolicy()
    : (Object.isFrozen(input.retryPolicy) ? input.retryPolicy : makeRetryPolicy(input.retryPolicy))

  return Object.freeze({
    id: input.id,
    name: nonEmpty(input.name) ? input.name : input.id,
    upstreamIds: Object.freeze([...new Set(ids)]),
    routingMode,
    retryPolicy,
  })
}

/**
 * 构造代理客户端。
 *
 * `authTokenHash` 必须是哈希（或至少不是明文 Token）。检查是启发式的，
 * 理由是让「贴错东西」在配置阶段就报错，而不是等日志里出现明文才发现。
 *
 * @param {object} input
 * @param {string} input.id
 * @param {string} [input.name]
 * @param {boolean} [input.enabled]
 * @param {string} input.routeGroupId
 * @param {string} input.authTokenHash
 * @returns {ProxyClient}
 * @throws {TypeError}
 */
export function makeProxyClient(input) {
  if (input == null || typeof input !== 'object') {
    throw new TypeError('makeProxyClient: 需要对象参数')
  }
  if (!nonEmpty(input.id)) {
    throw new TypeError('makeProxyClient: id 必须是非空字符串')
  }
  if (!nonEmpty(input.routeGroupId)) {
    throw new TypeError('makeProxyClient: routeGroupId 必须是非空字符串')
  }
  if (!nonEmpty(input.authTokenHash)) {
    throw new TypeError('makeProxyClient: authTokenHash 必须是非空字符串')
  }

  const hash = input.authTokenHash.trim()

  if (hash.length < 32) {
    throw new TypeError(
      `makeProxyClient: authTokenHash 长度 ${hash.length} 过短，看起来不是哈希。` +
      '只接受 sha256 十六进制或等价的摘要。',
    )
  }

  // 纯十六进制摘要直接放行：sha256 hex 与「长 token」在朴素正则下无法区分，
  // 必须先认形态，否则每次正常配置都会误报。
  if (!HEX_DIGEST.test(hash)) {
    for (const pat of PLAINTEXT_TOKEN_PATTERNS) {
      if (pat.test(hash)) {
        throw new TypeError(
          'makeProxyClient: authTokenHash 看起来是明文 Token（命中已知前缀/形态）。' +
          '只存摘要，明文永远不写入配置。',
        )
      }
    }
  }

  return Object.freeze({
    id: input.id,
    name: nonEmpty(input.name) ? input.name : input.id,
    enabled: input.enabled !== false,
    routeGroupId: input.routeGroupId,
    authTokenHash: hash,
  })
}

/**
 * 校验一个分组的 upstreamIds 是否都能在给定上游集合里找到。
 *
 * F1（Registry）会用它做删除前的引用检查。放在 A2 是因为这是契约的一部分：
 * 分组可以引不存在的上游，但**不能带着悬空引用被启用**。
 *
 * @param {UpstreamGroup} group
 * @param {Map<string, Upstream>|Upstream[]} upstreams
 * @returns {{ ok: boolean, missing: string[] }}
 */
export function validateGroupReferences(group, upstreams) {
  const known = upstreams instanceof Map
    ? new Set(upstreams.keys())
    : new Set((upstreams || []).map((u) => u.id))
  const missing = group.upstreamIds.filter((id) => !known.has(id))
  return { ok: missing.length === 0, missing }
}
