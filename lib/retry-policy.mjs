/**
 * retry-policy.mjs — 重试与故障切换安全决策（v0.4.0 / C3）
 *
 * **纯决策逻辑：不建连、不发请求、不改任何统计。** 输入一份失败现场描述，
 * 输出「要不要再试一次、等多久、为什么」。
 *
 * ## 为什么需要这一层（方案 §5.5）
 *
 * 旧实现的 `retryable` 是 `classifyError()` 返回的布尔常量 ——
 * 它只看错误类别，不看现场。同一类错误在不同现场结论相反：
 *
 *   ECONNREFUSED 发生在「连接都没建立」→ 非幂等 POST 重试是安全的；
 *   ECONNRESET 发生在「请求体已发出」 → 重试可能把一次转账做两遍。
 *
 * 所以判断必须同时看五件事：**失败阶段、HTTP 语义、请求体可重放性、
 * 幂等性、客户端是否已收到响应字节**。缺任何一项都会给出错误的答案。
 *
 * ## 「重试」与「换上游」是两件事
 *
 * 这个名字容易混。本模块只回答第一个问题：**这次失败值不值得再发一次**。
 * 至于「再发到哪里」，是第二个问题，且答案有两种：
 *
 *   1. **同一个上游**（瞬时故障）：DNS 抖动、边缘节点瞬时 5xx、TLS 握手被中断。
 *      这类故障与「哪条线路」无关，换线路反而把请求推给一个没测过的候选。
 *   2. **另一个候选**（线路故障）：连接被拒、路由黑洞、持续超时。
 *      这时重试到原上游只是重复失败，必须换目标。
 *
 * 本模块**只输出 retry 与 delayMs，不选择目标**。调用方（Core）必须自己决定
 * 是原地重试还是换候选，并且 —— 这一条是硬要求 ——
 * **每次换候选都要重新走一遍 target validation 与健康过滤**：
 *
 *   · 重跑 `lib/target-validator.mjs`：新候选可能解析到受保护地址
 *     （内网、元数据端点、回环），上次校验通过的结论不能复用到新 IP；
 *   · 重跑健康/冷却过滤：上次请求进行期间该候选可能已被打入 cooling；
 *   · 重新建立连接与超时计时：旧的 socket 与 deadline 属于上一个候选，
 *     复用它们会把「上一个目标的耗时」算到新目标头上；
 *   · 重新计量：失败计数与权重归到实际失败的那条线路上，不要记成新候选的。
 *
 * 这些属于 Core（F* 系列）。C3 不实现，但接口措辞必须让调用方无法误解：
 * `decideRetry()` 的返回值里没有 target 字段，就是为了逼调用方显式做这件事。
 *
 * ## reason 为什么用 ASCII token
 *
 * 决策原因是**日志聚合键**（按 reason 统计「为什么没重试」），中文串在重构和
 * 翻译时会漂移，token 不会。中文含义见 `RETRY_REASONS` 的逐项注释。
 * 真正的「出错信息」（抛出的 TypeError）用中文。
 *
 * @module retry-policy
 */

import { ERROR_CODES } from './contract/errors.mjs'

/**
 * 失败阶段。
 *
 * 阶段是这份决策里信息量最大的字段：它直接区分「副作用是否可能已发生」。
 *
 * @typedef {'dns'|'connect'|'tls'|'first_byte'|'stream_idle'|'total'|'request_body'|'response_body'} FailurePhase
 */

/**
 * 全部合法阶段（运行时校验用，与上面的联合类型必须一致）。
 *
 * @type {readonly FailurePhase[]}
 */
export const FAILURE_PHASES = Object.freeze([
  'dns',
  'connect',
  'tls',
  'first_byte',
  'stream_idle',
  'total',
  'request_body',
  'response_body',
])

/**
 * 重试策略形状。
 *
 * 与 `lib/contract/upstream.mjs` 的 `makeRetryPolicy()` 返回值**结构一致**，
 * 这里重新声明是为了让本模块不依赖契约层的类型导出（契约层的 typedef 未导出，
 * 无法通过 import() 取得）。字段语义与默认值以契约为准，本模块不重复定义默认值。
 *
 * @typedef {object} RetryPolicy
 * @property {number} maxAttempts 含首次尝试，>= 1
 * @property {number} totalBudgetMs 整次请求（含所有重试与等待）的时间上限
 * @property {number} baseDelayMs 退避基数
 * @property {number} maxDelayMs 退避上限
 * @property {ReadonlyArray<string>} retryOn 允许重试的错误 code 白名单
 */

/**
 * 决策输入：一次失败现场的完整描述。
 *
 * `statusCode` 与 `retryAfterMs` 是可选的，因为连接类失败根本到不了 HTTP 层。
 *
 * @typedef {object} RetryDecisionInput
 * @property {string} method HTTP 方法（保留原始大小写；用于日志与幂等性交叉校验）
 * @property {string} errorCode `ProxyError.code`，必须是 `contract/errors.mjs` 定义的 9 类之一
 * @property {FailurePhase} failurePhase 失败发生在哪一阶段
 * @property {boolean} bodyReplayable 请求体是否可以原样再发一次（false = 已消费/已流式发送）
 * @property {boolean} idempotent 该方法在本语义下是否幂等（由调用方判定，可能比 HTTP 更严）
 * @property {boolean} responseCommitted 是否已向客户端发出过任何响应字节（含响应头）
 * @property {boolean} clientCancelled 客户端是否已断开
 * @property {number} attemptIndex 当前是第几次尝试，从 1 开始
 * @property {number} elapsedMs 本次请求（含之前所有尝试）已耗时
 * @property {number} [statusCode] 上游 HTTP 状态码（已收到响应头时才有）
 * @property {number} [retryAfterMs] 解析后的 Retry-After（毫秒），仅配合 statusCode 使用
 */

/**
 * 决策结果。
 *
 * 刻意**不含 target**：本模块不做目标选择，见文件头「重试与换上游是两件事」。
 *
 * @typedef {object} RetryDecision
 * @property {boolean} retry 是否允许再发一次
 * @property {string} reason 决策原因 token，取值为 `RETRY_REASONS` 里的某一项
 * @property {number} [delayMs] 仅 retry=true 时给出：本次重试前应等待的毫秒数
 */

/**
 * 状态码可重试性判断的可选项。
 *
 * @typedef {object} RetriableStatusOptions
 * @property {boolean} [idempotent] 缺省按 false 处理（保守：不假设幂等）
 * @property {number} [retryAfterMs] 解析后的 Retry-After（毫秒）
 */

/**
 * 决策原因 token。
 *
 * 按「可协商程度」从硬到软排列，与 `decideRetry()` 的判断顺序一致：
 * 越靠前的理由越接近「语义上禁止重试」，越靠后的越接近「策略或容量不允许」。
 */
export const RETRY_REASONS = Object.freeze({
  /** 客户端已取消：连日志都不该按失败上报，重试等于把用户放弃的请求再跑一遍 */
  CLIENT_CANCELLED: 'client_cancelled',
  /**
   * 响应已提交给客户端：字节已经出去了，重发会在客户端侧拼出两份响应体
   * （或一份被截断后接上另一份），这是不可修复的协议损坏
   */
  RESPONSE_COMMITTED: 'response_committed',
  /** 尝试次数已用尽（含首次） */
  ATTEMPTS_EXHAUSTED: 'attempts_exhausted',
  /** 预算不够：已耗时 + 本次应等待时长 会超出 totalBudgetMs */
  BUDGET_EXHAUSTED: 'budget_exhausted',
  /** 错误类别不在策略白名单里（策略层声明「这类错误原则上不重试」） */
  ERROR_NOT_RETRYABLE: 'error_not_retryable',
  /** 请求体已发送且不可重放：重发可能让副作用执行第二次 */
  BODY_NOT_REPLAYABLE: 'body_not_replayable',
  /**
   * 非幂等且失败阶段证明「操作可能已执行」：
   * 只有 dns / connect 两个阶段能保证请求一个字节都没到上游
   */
  NON_IDEMPOTENT: 'non_idempotent',
  /** HTTP 语义不允许：4xx（客户端错误重试无用）或 Retry-After 超出可接受等待 */
  STATUS_NOT_RETRIABLE: 'status_not_retriable',
  /** 允许重试 */
  RETRY: 'retry',
})

/**
 * Retry-After 的可接受上限。
 *
 * 默认 `totalBudgetMs` 只有 5 秒；30 秒已经远超一次代理请求能占用的时间。
 * 服务端要求等待超过这个值时，重试只会把连接和预算一起占住而不产生价值 ——
 * 此时「不重试」比「等 5 分钟后重试」更接近客户端想要的。
 */
export const RETRY_AFTER_CAP_MS = 30_000

/**
 * 能保证「请求尚未落地到上游」的阶段。
 *
 * dns：域名还没解析出来，没有连接，更没有字节；
 * connect：TCP 三次握手未完成，HTTP 请求一个字节都没发出去。
 *
 * tls **不在**这里：握手失败前客户端可能已经在 TLS 通道里送出应用数据
 * （TLS 1.3 的 early data / 0-RTT），而且我们无法从错误码分辨是哪个方向失败。
 * 把 tls 放进来会让非幂等请求获得一次「可能重复执行」的机会，代价太大。
 */
const CONNECTION_SETUP_PHASES = new Set(['dns', 'connect'])

/**
 * HTTP 语义上幂等的方法（RFC 9110 §9.2.2）。
 *
 * 只在调用方要求「按方法推导 idempotent」时使用；`decideRetry()` 永远以
 * 调用方显式传入的 `idempotent` 为准 —— 业务层可能比 HTTP 更严格
 * （例如 PUT 一个计费资源）。
 */
const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'])

/**
 * 按 RFC 9110 判断方法是否幂等。
 *
 * @param {string} method HTTP 方法，大小写不敏感
 * @returns {boolean}
 */
export function isIdempotentMethod(method) {
  if (typeof method !== 'string') return false
  return IDEMPOTENT_METHODS.has(method.trim().toUpperCase())
}

/**
 * 构造拒绝结果。
 *
 * @param {string} reason
 * @returns {RetryDecision}
 */
const deny = (reason) => ({ retry: false, reason })

/**
 * 校验策略对象。
 *
 * 这里重复了 `makeRetryPolicy()` 的一部分校验：本模块是纯函数，
 * 可能被直接喂一个手写对象（测试、外部调用方），不能让非法值进到决策里 ——
 * 例如 `maxAttempts: NaN` 会让 `attemptIndex >= maxAttempts` 恒为 false，
 * 重试次数变成无限。
 *
 * @param {RetryPolicy} policy
 * @returns {void}
 * @throws {TypeError}
 */
function assertPolicy(policy) {
  if (policy == null || typeof policy !== 'object') {
    throw new TypeError(
      'decideRetry: 第二个参数必须是 RetryPolicy 对象'
      + '（建议用 contract/upstream.mjs 的 makeRetryPolicy 构造）',
    )
  }
  const { maxAttempts, totalBudgetMs, baseDelayMs, maxDelayMs, retryOn } = policy
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new TypeError(`retry-policy: policy.maxAttempts 必须是 >= 1 的整数，实际 ${JSON.stringify(maxAttempts)}`)
  }
  if (!Number.isFinite(totalBudgetMs) || totalBudgetMs <= 0) {
    throw new TypeError(`retry-policy: policy.totalBudgetMs 必须是正数，实际 ${JSON.stringify(totalBudgetMs)}`)
  }
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0) {
    throw new TypeError(`retry-policy: policy.baseDelayMs 必须是 >= 0 的有限数字，实际 ${JSON.stringify(baseDelayMs)}`)
  }
  if (!Number.isFinite(maxDelayMs) || maxDelayMs < baseDelayMs) {
    throw new TypeError(
      `retry-policy: policy.maxDelayMs 必须 >= baseDelayMs 且有限，实际 ${JSON.stringify(maxDelayMs)}`,
    )
  }
  if (!Array.isArray(retryOn)) {
    throw new TypeError('retry-policy: policy.retryOn 必须是字符串数组')
  }
  for (const code of retryOn) {
    if (typeof code !== 'string') {
      throw new TypeError(`retry-policy: policy.retryOn 里每项都必须是字符串，实际 ${JSON.stringify(code)}`)
    }
  }
}

/**
 * 校验决策输入。
 *
 * 四个布尔字段单独检查，因为「把 undefined 当 false 用」在本模块是危险的：
 * `bodyReplayable: undefined` 会被后面的 `!bodyReplayable` 当成「不可重放」，
 * 看似安全；但 `clientCancelled: undefined` 会被当成「未取消」，
 * 方向正好相反。宁可在这里崩，也不要在重试时崩。
 *
 * @param {RetryDecisionInput} input
 * @returns {void}
 * @throws {TypeError}
 */
function assertDecisionInput(input) {
  if (input == null || typeof input !== 'object') {
    throw new TypeError('decideRetry: 第一个参数必须是 RetryDecisionInput 对象')
  }
  if (typeof input.method !== 'string' || input.method.trim() === '') {
    throw new TypeError('decideRetry: method 必须是非空字符串')
  }
  if (typeof input.errorCode !== 'string' || !ERROR_CODES.includes(input.errorCode)) {
    throw new TypeError(
      `decideRetry: errorCode 必须是 contract/errors.mjs 定义的错误类型，实际 ${JSON.stringify(input.errorCode)}。`
      + '不要用自定义字符串描述上游失败 —— 分类会因此漂移。',
    )
  }
  if (!FAILURE_PHASES.includes(input.failurePhase)) {
    throw new TypeError(
      `decideRetry: failurePhase 不合法，实际 ${JSON.stringify(input.failurePhase)}，`
      + `合法值：${FAILURE_PHASES.join(' / ')}`,
    )
  }

  const flagNames = /** @type {const} */ ([
    'bodyReplayable',
    'idempotent',
    'responseCommitted',
    'clientCancelled',
  ])
  const raw = /** @type {Record<string, unknown>} */ (input)
  for (const name of flagNames) {
    if (typeof raw[name] !== 'boolean') {
      throw new TypeError(`decideRetry: ${name} 必须是布尔值，实际 ${JSON.stringify(raw[name])}`)
    }
  }

  if (!Number.isInteger(input.attemptIndex) || input.attemptIndex < 1) {
    throw new TypeError(`decideRetry: attemptIndex 必须是 >= 1 的整数（从 1 开始），实际 ${JSON.stringify(input.attemptIndex)}`)
  }
  if (!Number.isFinite(input.elapsedMs) || input.elapsedMs < 0) {
    throw new TypeError(`decideRetry: elapsedMs 必须是 >= 0 的有限数字，实际 ${JSON.stringify(input.elapsedMs)}`)
  }
  if (input.statusCode !== undefined
    && (!Number.isInteger(input.statusCode) || input.statusCode < 100 || input.statusCode > 599)) {
    throw new TypeError(`decideRetry: statusCode 若提供，必须是 100..599 的整数，实际 ${JSON.stringify(input.statusCode)}`)
  }
}

/**
 * 计算第 N 次重试前的退避时长：`baseDelayMs * 2^(N-1)`，钳到 `maxDelayMs`。
 *
 * 为什么从 attemptIndex=1 开始就是 baseDelayMs 而不是 0：
 * 第一次重试也需要让出一小段时间。立刻重打在一个瞬时抖动的线路上，
 * 命中同一个故障窗口的概率很高，退避基数就是为这个窗口准备的。
 *
 * @param {RetryPolicy} policy
 * @param {number} attemptIndex 已完成的那次尝试序号（从 1 开始）
 * @returns {number} 毫秒
 */
export function computeBackoffMs(policy, attemptIndex) {
  const n = Number.isFinite(attemptIndex) ? Math.max(1, Math.floor(attemptIndex)) : 1
  const raw = policy.baseDelayMs * 2 ** (n - 1)
  // 指数在 n 很大时会溢出成 Infinity；此时直接取上限，
  // 而不是让 Infinity 一路传进预算比较（那是永远为真的拒绝）。
  if (!Number.isFinite(raw)) return policy.maxDelayMs
  return Math.min(Math.max(raw, 0), policy.maxDelayMs)
}

/**
 * 判断 HTTP 状态码是否值得重试。
 *
 * 规则来自方案 §5.5 的 HTTP 语义部分：
 *
 *   · 429 / 502 / 503 / 504 → 可重试，但必须尊重 Retry-After
 *   · 500 → 只在幂等方法上可重试（非幂等请求重打一个「服务器内部错误」
 *     可能让已部分执行的写操作执行第二次）
 *   · 其它 4xx → 不可重试（客户端错误，重发同样的请求只会得到同样的答案）
 *   · 其它 5xx → 可重试（按方案字面语义；501 Not Implemented 也被包含在内，
 *     调用方若认为它属于永久错误，应在策略层用 retryOn 收紧，而不是改这里）
 *
 * 「尊重 Retry-After」在这里的具体含义：服务端要求的等待超过 `RETRY_AFTER_CAP_MS`
 * 时判为不可重试 —— 等不起就别答应当场重试，让客户端自己决定。
 * 上限之内的等待由调用方把 `retryAfterMs` 作为 delayMs 使用，而不是用自家退避。
 *
 * @param {number} statusCode
 * @param {RetriableStatusOptions} [options]
 * @returns {boolean}
 */
export function isRetriableStatus(statusCode, options = {}) {
  // 非整数 / 超出 HTTP 范围：不是可判断的状态码，保守拒绝
  if (!Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) return false

  const idempotent = options.idempotent === true
  const retryAfterMs = options.retryAfterMs

  // Retry-After 超上限：任何状态码都等不起。
  // 放在最前面是为了让「尊重 Retry-After」对所有分支一致生效，
  // 而不是只在 429 上生效（503 + Retry-After: 600 是真实存在的组合）。
  if (typeof retryAfterMs === 'number'
    && Number.isFinite(retryAfterMs)
    && retryAfterMs > RETRY_AFTER_CAP_MS) {
    return false
  }

  // 429：限流是明确可恢复的，前提是等得起
  if (statusCode === 429) return true
  // 502/503/504：网关/上游临时不可用，与是否幂等无关
  if (statusCode === 502 || statusCode === 503 || statusCode === 504) return true
  // 500：可能是「执行到一半炸了」，只有幂等方法能安全重打
  if (statusCode === 500) return idempotent
  // 其它 5xx：按方案字面语义可重试
  if (statusCode >= 500 && statusCode <= 599) return true
  // 其余（含所有 4xx）不可重试
  return false
}

/**
 * 重试决策主函数。
 *
 * **判断顺序就是语义优先级，不能重排。** 越靠前的拒绝理由越不可协商：
 *
 *   1. 客户端取消 —— 用户不要了，重试是纯粹的资源浪费
 *   2. 响应已提交 —— 字节已出，重放会损坏已发出的响应
 *   3. 尝试次数用尽 —— 容量边界
 *   4. 预算不足 —— 时间边界（需要先算出 delay 才能判断）
 *   5. 错误类别不在白名单 —— 策略声明
 *   6. 请求体不可重放 —— 副作用可能已发生
 *   7. 非幂等且阶段无法证明「未落地」 —— 副作用可能已发生
 *   8. （附加闸门）HTTP 语义不允许 —— 见 `isRetriableStatus`
 *
 * 第 8 条是方案 §5.5 主干八条之后的**收紧项**：它只会在主干全部放行之后
 * 进一步否决，因此不会改变前七条的结论。放在最后而不是插在中间，
 * 是为了让 `error_not_retryable` 这类「策略可调」的原因排在任何状态码判断之前 ——
 * 调策略比调状态码语义更常见。
 *
 * @param {RetryDecisionInput} input
 * @param {RetryPolicy} policy
 * @returns {RetryDecision}
 * @throws {TypeError} 输入或策略不合法时抛出（中文描述）
 */
export function decideRetry(input, policy) {
  assertDecisionInput(input)
  assertPolicy(policy)

  // 1. 客户端取消：最高优先级。它甚至不算「失败」，
  //    重试会把一个已经放弃的请求重新发到上游，是纯粹的资源浪费。
  if (input.clientCancelled) {
    return deny(RETRY_REASONS.CLIENT_CANCELLED)
  }

  // 2. 响应已提交：客户端已经收到过字节（哪怕只是一个响应头），
  //    再发一次会在客户端侧拼出两份响应。这条没有例外，不看幂等、不看预算。
  if (input.responseCommitted) {
    return deny(RETRY_REASONS.RESPONSE_COMMITTED)
  }

  // 3. 尝试次数：maxAttempts 含首次，所以 attemptIndex == maxAttempts 时已无余量
  if (input.attemptIndex >= policy.maxAttempts) {
    return deny(RETRY_REASONS.ATTEMPTS_EXHAUSTED)
  }

  // 4. 预算：必须先把 delay 算出来才能判断「等完还来不来得及」。
  //    这一步只是计算，不改变任何状态，所以放在第 3 条之后不会影响前面结论。
  const delayMs = computeBackoffMs(policy, input.attemptIndex)
  if (input.elapsedMs + delayMs > policy.totalBudgetMs) {
    return deny(RETRY_REASONS.BUDGET_EXHAUSTED)
  }

  // 5. 策略白名单：只给「原则上可重试」的错误类别发通行证
  if (!policy.retryOn.includes(input.errorCode)) {
    return deny(RETRY_REASONS.ERROR_NOT_RETRYABLE)
  }

  // 6. 请求体：已发送（bodyReplayable=false）就是不可重放。
  //    注意这条不区分幂等性 —— 请求体被消费掉之后，连「幂等」这个前提都不成立了。
  if (input.failurePhase === 'request_body' && !input.bodyReplayable) {
    return deny(RETRY_REASONS.BODY_NOT_REPLAYABLE)
  }

  // 7. 幂等性：只有 dns / connect 能证明「上游一个字节都没收到」。
  //    其它阶段（tls / first_byte / stream_idle / total / response_body）都可能
  //    意味着请求已落地，非幂等操作重试就是重复执行。
  if (!input.idempotent && !CONNECTION_SETUP_PHASES.has(input.failurePhase)) {
    return deny(RETRY_REASONS.NON_IDEMPOTENT)
  }

  // 8. 附加闸门：HTTP 语义。主干八条里没有单列它，是因为状态码的可重试性
  //    另有独立函数（isRetriableStatus）承载，且需要 idempotent / Retry-After 共同判断。
  if (input.statusCode !== undefined) {
    const statusOptions = /** @type {RetriableStatusOptions} */ ({
      idempotent: input.idempotent,
      ...(input.retryAfterMs === undefined ? {} : { retryAfterMs: input.retryAfterMs }),
    })
    if (!isRetriableStatus(input.statusCode, statusOptions)) {
      return deny(RETRY_REASONS.STATUS_NOT_RETRIABLE)
    }
  }

  return { retry: true, reason: RETRY_REASONS.RETRY, delayMs }
}

/**
 * 跨多次调用保持的重试预算。
 *
 * 为什么需要它：`decideRetry()` 是无状态的纯函数，每次调用都要调用方
 * 自己算 `attemptIndex` 与 `elapsedMs`。真实现场里这两个数最容易算错 ——
 * 忘了把上一次的等待时间计入 elapsed，或者忘了自增 attemptIndex，
 * 都会让重试次数或总耗时突破上限。把状态收进一个对象里，只暴露
 * 「还能不能试」「记一笔」「还剩多少」三个动作。
 *
 * `attemptsLeft` 是**剩余重试次数**（不含首次），与 `maxAttempts` 的语义配套。
 *
 * @typedef {object} RetryBudget
 * @property {(input?: { attemptIndex?: number, elapsedMs?: number, delayMs?: number }) => boolean} canRetry
 *   还能不能发起下一次尝试。`input` 用于临时覆盖：不传则用内部状态；
 *   `attemptIndex` 缺省为「已记录次数 + 1」，`delayMs` 缺省按退避公式算。
 * @property {(attempt: number | { attemptIndex?: number, elapsedMs?: number }) => void} record
 *   记录一次**已完成**的尝试。传数字时视为该次尝试的耗时（毫秒）。
 * @property {() => { attemptsLeft: number, timeLeftMs: number, usedAttempts: number, spentMs: number, maxAttempts: number, totalBudgetMs: number }} remaining
 *   只读快照，不改变状态。
 */

/**
 * 构造一个重试预算。
 *
 * @param {RetryPolicy} policy
 * @param {{ elapsedMs?: number }} [options] `elapsedMs` 是构造前已经消耗的时间（例如入口层花掉的部分）
 * @returns {RetryBudget}
 * @throws {TypeError} 策略不合法时抛出
 */
export function createRetryBudget(policy, options = {}) {
  assertPolicy(policy)

  const initialElapsed = options.elapsedMs ?? 0
  if (!Number.isFinite(initialElapsed) || initialElapsed < 0) {
    throw new TypeError(`createRetryBudget: elapsedMs 必须是 >= 0 的有限数字，实际 ${JSON.stringify(options.elapsedMs)}`)
  }

  // 唯一可变状态：已记录的尝试次数与已消耗时间。
  let usedAttempts = 0
  let spentMs = initialElapsed

  /**
   * @param {{ attemptIndex?: number, elapsedMs?: number, delayMs?: number }} [input]
   * @returns {boolean}
   */
  const canRetry = (input = {}) => {
    const nextAttempt = input.attemptIndex ?? (usedAttempts + 1)
    if (!Number.isInteger(nextAttempt) || nextAttempt < 1) return false
    // 下一次尝试的序号达到上限 → 没有余量（与 decideRetry 第 3 条同一判据）
    if (nextAttempt >= policy.maxAttempts) return false

    const elapsed = spentMs + (input.elapsedMs ?? 0)
    const delay = input.delayMs ?? computeBackoffMs(policy, nextAttempt)
    // 与 decideRetry 第 4 条保持同一边界：恰好用满预算视为允许
    return elapsed + delay <= policy.totalBudgetMs
  }

  /**
   * @param {number | { attemptIndex?: number, elapsedMs?: number }} attempt
   * @returns {void}
   */
  const record = (attempt) => {
    if (typeof attempt === 'number') {
      if (!Number.isFinite(attempt) || attempt < 0) {
        throw new TypeError(`createRetryBudget: record(耗时) 必须是 >= 0 的有限数字，实际 ${JSON.stringify(attempt)}`)
      }
      spentMs += attempt
      usedAttempts += 1
      return
    }
    if (attempt == null || typeof attempt !== 'object') {
      throw new TypeError('createRetryBudget: record 需要数字耗时或 { attemptIndex, elapsedMs } 对象')
    }
    const idx = attempt.attemptIndex
    const cost = attempt.elapsedMs ?? 0
    if (!Number.isFinite(cost) || cost < 0) {
      throw new TypeError(`createRetryBudget: record 的 elapsedMs 必须是 >= 0 的有限数字，实际 ${JSON.stringify(attempt.elapsedMs)}`)
    }
    // attemptIndex 由调用方给出时以它为准（可能跳号），否则按顺序累加。
    // 取 max 而不是直接赋值：跳号记录不应该让已用次数倒退。
    usedAttempts = Math.max(
      usedAttempts + 1,
      Number.isInteger(idx) && Number(idx) >= 1 ? Number(idx) : 0,
    )
    spentMs += cost
  }

  /**
   * @returns {{ attemptsLeft: number, timeLeftMs: number, usedAttempts: number, spentMs: number, maxAttempts: number, totalBudgetMs: number }}
   */
  const remaining = () => ({
    // maxAttempts 含首次，所以剩余重试次数要减掉那次
    attemptsLeft: Math.max(0, policy.maxAttempts - 1 - usedAttempts),
    timeLeftMs: Math.max(0, policy.totalBudgetMs - spentMs),
    usedAttempts,
    spentMs,
    maxAttempts: policy.maxAttempts,
    totalBudgetMs: policy.totalBudgetMs,
  })

  return { canRetry, record, remaining }
}
