/**
 * retry-policy.test.js — 重试决策（v0.4.0 / C3）
 *
 * 纯函数测试，不起网络。核心是两个维度的矩阵：
 *
 *   · 方案 §5.5 的八种失败场景（阶段 × 副作用可能性）
 *   · 判断顺序（同时满足多个拒绝条件时，只能返回最高优先级的 reason）
 *
 * 策略对象全部用 `makeRetryPolicy()` 真实构造，而不是手写字面量 ——
 * 这样契约形状一旦漂移，本测试会跟着红，而不是两边各说各话。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  decideRetry,
  isRetriableStatus,
  createRetryBudget,
  computeBackoffMs,
  isIdempotentMethod,
  FAILURE_PHASES,
  RETRY_REASONS,
  RETRY_AFTER_CAP_MS,
} from '../../lib/retry-policy.mjs'
import { makeRetryPolicy } from '../../lib/contract/upstream.mjs'

/** 主力策略：3 次尝试、5 秒预算、100→1000ms 退避、网络与传输类错误全开 */
const POLICY = makeRetryPolicy({
  maxAttempts: 3,
  totalBudgetMs: 5000,
  baseDelayMs: 100,
  maxDelayMs: 1000,
  retryOn: [
    'dns_failure',
    'connect_failure',
    'tls_failure',
    'upstream_timeout',
    'stream_failure',
  ],
})

/** 更宽的策略：只为了让 attemptIndex 能走到 3 以上而不触发次数上限 */
const WIDE = makeRetryPolicy({
  maxAttempts: 5,
  totalBudgetMs: 5000,
  baseDelayMs: 100,
  maxDelayMs: 1000,
  retryOn: POLICY.retryOn,
})

/** 契约默认策略：maxAttempts = 1，等于不重试 */
const DEFAULT_POLICY = makeRetryPolicy()

/**
 * 基线输入：一次「一切都允许重试」的失败现场。
 * 每条用例只覆盖它需要改变的字段，避免出现「不知道是哪个字段否决的」。
 */
const base = (over = {}) => ({
  method: 'GET',
  errorCode: 'connect_failure',
  failurePhase: 'connect',
  bodyReplayable: true,
  idempotent: true,
  responseCommitted: false,
  clientCancelled: false,
  attemptIndex: 1,
  elapsedMs: 0,
  ...over,
})

/* ============================================================
 * 场景矩阵（方案 §5.5 八条）
 * ============================================================ */

test('场景 1 · DNS 失败：可切候选', () => {
  const r = decideRetry(base({ errorCode: 'dns_failure', failurePhase: 'dns' }), POLICY)
  assert.equal(r.retry, true)
  assert.equal(r.reason, RETRY_REASONS.RETRY)
  assert.equal(r.delayMs, 100, '首次重试的等待就是退避基数')
})

test('场景 1 · DNS 失败：非幂等 POST 也可切（域名都没解析出来，请求不可能落地）', () => {
  const r = decideRetry(
    base({ method: 'POST', idempotent: false, errorCode: 'dns_failure', failurePhase: 'dns' }),
    POLICY,
  )
  assert.equal(r.retry, true, 'dns 阶段是第 7 条的例外：没有任何副作用可能发生')
})

test('场景 1 · DNS 失败但策略未开放该错误类别 → 不重试', () => {
  const narrow = makeRetryPolicy({ maxAttempts: 3, retryOn: ['connect_failure'] })
  const r = decideRetry(base({ errorCode: 'dns_failure', failurePhase: 'dns' }), narrow)
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.ERROR_NOT_RETRYABLE)
})

test('场景 2 · TCP 连接建立前失败：幂等方法满足策略即可切', () => {
  const r = decideRetry(base({ errorCode: 'connect_failure', failurePhase: 'connect' }), POLICY)
  assert.equal(r.retry, true)
  assert.equal(r.delayMs, 100)
})

test('场景 2 · connect 失败但已无尝试次数 → 不重试', () => {
  const r = decideRetry(
    base({ errorCode: 'connect_failure', failurePhase: 'connect', attemptIndex: 3 }),
    POLICY,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.ATTEMPTS_EXHAUSTED)
})

test('场景 3 · TLS 失败：默认策略不开放 → 不重试（证书错误不被静默吞掉）', () => {
  const r = decideRetry(
    base({ errorCode: 'tls_failure', failurePhase: 'tls' }),
    DEFAULT_POLICY,
  )
  assert.equal(r.retry, false, '默认策略只开 dns/connect，TLS 类失败必须原样暴露')
  assert.equal(r.reason, RETRY_REASONS.ATTEMPTS_EXHAUSTED, '默认 maxAttempts=1，先撞次数上限')
})

test('场景 3 · TLS 失败：策略显式放开 + 幂等 → 可按错误类别重试', () => {
  const r = decideRetry(base({ errorCode: 'tls_failure', failurePhase: 'tls' }), POLICY)
  assert.equal(r.retry, true)
  assert.equal(r.reason, RETRY_REASONS.RETRY)
})

test('场景 3 · TLS 失败 + 非幂等 → 不重试（TLS 阶段无法证明请求未落地）', () => {
  const r = decideRetry(
    base({ method: 'POST', idempotent: false, errorCode: 'tls_failure', failurePhase: 'tls' }),
    POLICY,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.NON_IDEMPOTENT, 'tls 不在「保证未落地」的阶段集合里')
})

test('场景 4 · 请求体尚未发送（可重放）+ 策略允许 + 幂等 → 可切', () => {
  const r = decideRetry(
    base({ errorCode: 'stream_failure', failurePhase: 'request_body', bodyReplayable: true }),
    POLICY,
  )
  assert.equal(r.retry, true)
})

test('场景 4 · 请求体可重放但方法非幂等 → 仍不切', () => {
  const r = decideRetry(
    base({
      method: 'POST', idempotent: false, errorCode: 'stream_failure',
      failurePhase: 'request_body', bodyReplayable: true,
    }),
    POLICY,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.NON_IDEMPOTENT, '可重放不等于可以重复执行副作用')
})

test('场景 5 · 请求体已发送（不可重放）→ 默认不可重试，即使方法幂等', () => {
  const r = decideRetry(
    base({ errorCode: 'stream_failure', failurePhase: 'request_body', bodyReplayable: false }),
    POLICY,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.BODY_NOT_REPLAYABLE)
})

test('场景 5 · 请求体已发送 + 非幂等 → reason 仍是请求体（第 6 条先于第 7 条）', () => {
  const r = decideRetry(
    base({
      method: 'POST', idempotent: false, errorCode: 'stream_failure',
      failurePhase: 'request_body', bodyReplayable: false,
    }),
    POLICY,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.BODY_NOT_REPLAYABLE)
})

test('场景 6 · 响应已开始发给客户端 → 禁止重试，无例外', () => {
  const r = decideRetry(base({ responseCommitted: true }), POLICY)
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.RESPONSE_COMMITTED)
})

test('场景 6 · 响应已提交时忽略「一切都允许」的现场（幂等、预算充足、错误类别开放）', () => {
  const r = decideRetry(
    base({
      responseCommitted: true, idempotent: true, attemptIndex: 1,
      elapsedMs: 0, errorCode: 'connect_failure', failurePhase: 'connect',
    }),
    WIDE,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.RESPONSE_COMMITTED)
})

test('场景 7 · 客户端取消 → 立即取消，不重试', () => {
  const r = decideRetry(base({ clientCancelled: true }), POLICY)
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.CLIENT_CANCELLED)
})

test('场景 7 · 客户端取消时连 delayMs 都不给', () => {
  const r = decideRetry(base({ clientCancelled: true }), POLICY)
  assert.equal('delayMs' in r, false, '取消场景不该让调用方以为还有什么可以等待')
})

test('场景 8 · 429/503：状态码可重试且其它闸门放行 → 重试', () => {
  for (const status of [429, 502, 503, 504]) {
    const r = decideRetry(
      base({ errorCode: 'upstream_timeout', failurePhase: 'first_byte', statusCode: status }),
      POLICY,
    )
    assert.equal(r.retry, true, `${status} 应可重试`)
  }
})

test('场景 8 · 500 只在幂等方法上可重试', () => {
  const idem = decideRetry(
    base({ method: 'PUT', errorCode: 'upstream_timeout', failurePhase: 'first_byte', statusCode: 500 }),
    POLICY,
  )
  assert.equal(idem.retry, true)
  const nonIdem = decideRetry(
    base({
      method: 'POST', idempotent: false, errorCode: 'upstream_timeout',
      failurePhase: 'first_byte', statusCode: 500,
    }),
    POLICY,
  )
  assert.equal(nonIdem.retry, false)
})

test('场景 8 · 4xx（非 429）→ 不重试', () => {
  for (const status of [400, 401, 403, 404, 409, 499]) {
    const r = decideRetry(
      base({ errorCode: 'upstream_timeout', failurePhase: 'first_byte', statusCode: status }),
      POLICY,
    )
    assert.equal(r.retry, false, `${status} 不该重试`)
    assert.equal(r.reason, RETRY_REASONS.STATUS_NOT_RETRIABLE)
  }
})

test('场景 8 · 429 + Retry-After 超出可接受等待 → 不重试', () => {
  const r = decideRetry(
    base({
      errorCode: 'upstream_timeout', failurePhase: 'first_byte',
      statusCode: 429, retryAfterMs: RETRY_AFTER_CAP_MS + 1,
    }),
    POLICY,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.STATUS_NOT_RETRIABLE)
})

test('场景 8 · 429 + Retry-After 在上限内 → 重试', () => {
  const r = decideRetry(
    base({
      errorCode: 'upstream_timeout', failurePhase: 'first_byte',
      statusCode: 429, retryAfterMs: 500,
    }),
    POLICY,
  )
  assert.equal(r.retry, true)
})

/* ============================================================
 * 优先级（顺序即语义，不能重排）
 * ============================================================ */

test('优先级 1：clientCancelled 压过响应已提交、次数用尽、预算超限、错误类别、请求体、幂等、状态码', () => {
  const r = decideRetry(
    base({
      clientCancelled: true,
      responseCommitted: true,
      attemptIndex: 9,
      elapsedMs: 999_999,
      errorCode: 'target_denied',
      failurePhase: 'request_body',
      bodyReplayable: false,
      idempotent: false,
      statusCode: 404,
    }),
    POLICY,
  )
  assert.equal(r.reason, RETRY_REASONS.CLIENT_CANCELLED)
})

test('优先级 2：responseCommitted 压过次数、预算、错误类别、请求体、幂等、状态码', () => {
  const r = decideRetry(
    base({
      responseCommitted: true,
      attemptIndex: 9,
      elapsedMs: 999_999,
      errorCode: 'target_denied',
      failurePhase: 'request_body',
      bodyReplayable: false,
      idempotent: false,
      statusCode: 404,
    }),
    POLICY,
  )
  assert.equal(r.reason, RETRY_REASONS.RESPONSE_COMMITTED)
})

test('优先级 3：次数用尽压过预算、错误类别、请求体、幂等', () => {
  const r = decideRetry(
    base({
      attemptIndex: 3,
      elapsedMs: 999_999,
      errorCode: 'target_denied',
      failurePhase: 'request_body',
      bodyReplayable: false,
      idempotent: false,
    }),
    POLICY,
  )
  assert.equal(r.reason, RETRY_REASONS.ATTEMPTS_EXHAUSTED)
})

test('优先级 4：预算不足压过错误类别、请求体、幂等', () => {
  const r = decideRetry(
    base({
      attemptIndex: 2,
      elapsedMs: 4999,
      errorCode: 'target_denied',
      failurePhase: 'request_body',
      bodyReplayable: false,
      idempotent: false,
    }),
    POLICY,
  )
  assert.equal(r.reason, RETRY_REASONS.BUDGET_EXHAUSTED, 'attempt 2 的退避是 200ms，4999+200 超预算')
})

test('优先级 5：错误类别不在白名单压过请求体与幂等', () => {
  const r = decideRetry(
    base({
      errorCode: 'target_denied',
      failurePhase: 'request_body',
      bodyReplayable: false,
      idempotent: false,
    }),
    POLICY,
  )
  assert.equal(r.reason, RETRY_REASONS.ERROR_NOT_RETRYABLE)
})

test('优先级 6：请求体不可重放压过非幂等', () => {
  const r = decideRetry(
    base({
      method: 'POST', idempotent: false, errorCode: 'stream_failure',
      failurePhase: 'request_body', bodyReplayable: false,
    }),
    POLICY,
  )
  assert.equal(r.reason, RETRY_REASONS.BODY_NOT_REPLAYABLE)
})

test('优先级 7：非幂等压过状态码闸门', () => {
  const r = decideRetry(
    base({
      method: 'POST', idempotent: false, errorCode: 'upstream_timeout',
      failurePhase: 'first_byte', statusCode: 404,
    }),
    POLICY,
  )
  assert.equal(r.reason, RETRY_REASONS.NON_IDEMPOTENT, '主干第 7 条先于附加的状态码闸门')
})

test('优先级：未提交 + 未取消 + 有余量 时，允许路径给出 reason=retry', () => {
  assert.equal(decideRetry(base(), POLICY).reason, RETRY_REASONS.RETRY)
})

/* ============================================================
 * 关键反例：非幂等方法在 connect 阶段失败「可以」重试
 * ============================================================ */

test('反例：非幂等 POST 在 connect 阶段失败可以重试（连接没建立，副作用不可能发生）', () => {
  const r = decideRetry(
    base({ method: 'POST', idempotent: false, errorCode: 'connect_failure', failurePhase: 'connect' }),
    POLICY,
  )
  assert.equal(r.retry, true, '把 connect 排除在例外之外会让所有 POST 都无法从线路故障中恢复')
  assert.ok(r.delayMs > 0)
})

test('反例：同一份 POST 在 first_byte 阶段失败就不能重试', () => {
  const r = decideRetry(
    base({ method: 'POST', idempotent: false, errorCode: 'stream_failure', failurePhase: 'first_byte' }),
    POLICY,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.NON_IDEMPOTENT, '请求已发出去了，这已经不是「有没有落地」的问题')
})

/* ============================================================
 * 退避计算
 * ============================================================ */

test('退避：按 2 的幂增长并钳到 maxDelayMs', () => {
  assert.equal(computeBackoffMs(POLICY, 1), 100)
  assert.equal(computeBackoffMs(POLICY, 2), 200)
  assert.equal(computeBackoffMs(POLICY, 3), 400)
  assert.equal(computeBackoffMs(POLICY, 4), 800)
  assert.equal(computeBackoffMs(POLICY, 5), 1000, '1600 被钳到 1000')
  assert.equal(computeBackoffMs(POLICY, 12), 1000)
})

test('退避：baseDelayMs 为 0 时永远是 0（等于不等待）', () => {
  const p = makeRetryPolicy({ maxAttempts: 5, baseDelayMs: 0, maxDelayMs: 0 })
  assert.equal(computeBackoffMs(p, 1), 0)
  assert.equal(computeBackoffMs(p, 5), 0)
})

test('退避：指数溢出时不返回 Infinity，直接取上限', () => {
  const p = makeRetryPolicy({ maxAttempts: 3, baseDelayMs: 1e300, maxDelayMs: 1e300 })
  const d = computeBackoffMs(p, 2000)
  assert.equal(Number.isFinite(d), true)
  assert.equal(d, 1e300)
})

test('退避：attemptIndex 非法输入按 1 处理，不抛错（纯计算函数）', () => {
  assert.equal(computeBackoffMs(POLICY, 0), 100)
  assert.equal(computeBackoffMs(POLICY, -5), 100)
  assert.equal(computeBackoffMs(POLICY, Number.NaN), 100)
})

test('decideRetry 给出的 delayMs 与退避公式一致', () => {
  for (const attemptIndex of [1, 2, 3]) {
    const r = decideRetry(base({ attemptIndex }), WIDE)
    assert.equal(r.retry, true)
    assert.equal(r.delayMs, computeBackoffMs(WIDE, attemptIndex))
  }
})

/* ============================================================
 * 预算边界
 * ============================================================ */

test('预算：恰好用满视为允许（严格大于才拒绝）', () => {
  const exact = decideRetry(base({ attemptIndex: 3, elapsedMs: 4600 }), WIDE)
  assert.equal(exact.retry, true, '4600 + 400 = 5000，等于预算上限仍然可重试')

  const over = decideRetry(base({ attemptIndex: 3, elapsedMs: 4601 }), WIDE)
  assert.equal(over.retry, false)
  assert.equal(over.reason, RETRY_REASONS.BUDGET_EXHAUSTED)
})

test('预算：首次尝试就已超预算 → 不重试', () => {
  const r = decideRetry(base({ attemptIndex: 1, elapsedMs: 5000 }), POLICY)
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.BUDGET_EXHAUSTED)
})

/* ============================================================
 * createRetryBudget
 * ============================================================ */

test('预算对象：次数用满后 canRetry 为 false', () => {
  const b = createRetryBudget(POLICY) // maxAttempts = 3
  assert.equal(b.canRetry(), true, '第 1 次尝试后仍有余量')
  b.record(100)
  assert.equal(b.canRetry(), true, '第 2 次尝试后还剩一次')
  b.record({ elapsedMs: 100 })
  assert.equal(b.canRetry(), false, 'usedAttempts=2，下一次就是第 3 次 = 上限')
})

test('预算对象：remaining 是只读快照', () => {
  const b = createRetryBudget(POLICY, { elapsedMs: 500 })
  b.record({ attemptIndex: 1, elapsedMs: 1000 })
  const snapshot = b.remaining()
  assert.deepEqual(snapshot, {
    attemptsLeft: 1,
    timeLeftMs: 3500,
    usedAttempts: 1,
    spentMs: 1500,
    maxAttempts: 3,
    totalBudgetMs: 5000,
  })
  assert.deepEqual(b.remaining(), snapshot, '连续两次读取必须一致')
})

test('预算对象：时间耗尽后 canRetry 为 false', () => {
  const b = createRetryBudget(POLICY)
  b.record(4900)
  // 下一次是第 2 次尝试，退避 200ms：4900 + 200 > 5000
  assert.equal(b.canRetry(), false)
  assert.equal(b.remaining().timeLeftMs, 100)
})

test('预算对象：input 可临时覆盖 elapsedMs / delayMs（调用方补充最近一次耗时）', () => {
  const b = createRetryBudget(POLICY)
  assert.equal(b.canRetry({ attemptIndex: 1, delayMs: 900, elapsedMs: 4200 }), false, '4200+900 超预算')
  assert.equal(b.canRetry({ attemptIndex: 1, delayMs: 100, elapsedMs: 4900 }), true, '4900+100 恰好用满')
})

test('预算对象：record 传数字视为该次尝试耗时', () => {
  const b = createRetryBudget(POLICY)
  b.record(250)
  assert.equal(b.remaining().spentMs, 250)
  assert.equal(b.remaining().usedAttempts, 1)
})

test('预算对象：跳号记录不让已用次数倒退', () => {
  const b = createRetryBudget(WIDE)
  b.record({ attemptIndex: 3, elapsedMs: 10 })
  assert.equal(b.remaining().usedAttempts, 3)
  b.record({ attemptIndex: 1, elapsedMs: 10 })
  assert.equal(b.remaining().usedAttempts, 4, '取 max(累加, 跳号)')
})

test('预算对象：非法 record 参数抛中文 TypeError', () => {
  const b = createRetryBudget(POLICY)
  assert.throws(() => b.record(-1), (e) => e instanceof TypeError && /耗时/.test(e.message))
  assert.throws(() => b.record({ elapsedMs: -1 }), (e) => e instanceof TypeError)
})

test('预算对象：非法 policy 抛 TypeError', () => {
  assert.throws(() => createRetryBudget({}), (e) => e instanceof TypeError && /maxAttempts/.test(e.message))
})

test('预算对象：入口层已消耗的时间计入初始预算', () => {
  const b = createRetryBudget(POLICY, { elapsedMs: 4800 })
  assert.equal(b.remaining().timeLeftMs, 200)
  assert.equal(b.canRetry(), true, '剩余 200ms 够第 1 次退避（100ms）')

  const tight = createRetryBudget(POLICY, { elapsedMs: 4950 })
  assert.equal(tight.canRetry(), false, '剩余 50ms 不够第 1 次退避（100ms）')
})

/* ============================================================
 * isRetriableStatus 边界
 * ============================================================ */

const STATUS_CASES = /** @type {const} */ ([
  // [statusCode, options, expected, note]
  [200, {}, false, '成功码不该进重试路径'],
  [301, {}, false, '重定向不是失败'],
  [400, {}, false, '客户端错误'],
  [401, {}, false, '认证失败重试无用'],
  [403, {}, false, '权限失败重试无用'],
  [404, {}, false, '资源不存在'],
  [409, {}, false, '冲突'],
  [429, {}, true, '限流可重试'],
  [429, { idempotent: false }, true, '限流与幂等无关'],
  [429, { retryAfterMs: 500 }, true, '等得起'],
  [429, { retryAfterMs: RETRY_AFTER_CAP_MS }, true, '恰好等于上限，允许'],
  [429, { retryAfterMs: RETRY_AFTER_CAP_MS + 1 }, false, '等不起就别答应'],
  [499, {}, false, '客户端主动断开'],
  [500, {}, false, '非幂等不给 500 重试机会'],
  [500, { idempotent: true }, true, '幂等 GET/PUT 可重试'],
  [500, { idempotent: true, retryAfterMs: RETRY_AFTER_CAP_MS + 1 }, false, 'Retry-After 上限压过幂等'],
  [501, {}, true, '按方案「其它 5xx 可重试」的字面语义'],
  [502, {}, true],
  [503, {}, true],
  [504, {}, true],
  [503, { retryAfterMs: RETRY_AFTER_CAP_MS + 1 }, false, '503 带超长 Retry-After 同样等不起'],
  [599, {}, true, '其它 5xx'],
  [600, {}, false, '超出 HTTP 范围'],
  [99, {}, false, '超出 HTTP 范围'],
  [Number.NaN, {}, false, 'NaN 不是状态码'],
  [/** @type {any} */ ('503'), {}, false, '字符串不被静默转成数字'],
])

for (const [status, options, expected, note] of STATUS_CASES) {
  test(`isRetriableStatus(${String(status)}, ${JSON.stringify(options)}) === ${expected} — ${note}`, () => {
    assert.equal(isRetriableStatus(status, options), expected)
  })
}

/* ============================================================
 * isIdempotentMethod
 * ============================================================ */

test('isIdempotentMethod：按 RFC 9110 判定，大小写不敏感', () => {
  for (const m of ['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE']) {
    assert.equal(isIdempotentMethod(m), true, `${m} 应幂等`)
    assert.equal(isIdempotentMethod(m.toLowerCase()), true)
    assert.equal(isIdempotentMethod(`  ${m}  `), true)
  }
  for (const m of ['POST', 'PATCH', 'CONNECT', '']) {
    assert.equal(isIdempotentMethod(m), false, `${m} 不该被判为幂等`)
  }
})

/* ============================================================
 * 输入校验（宁可在决策前崩，也不要在重试后崩）
 * ============================================================ */

test('校验：input 为 null 抛中文 TypeError', () => {
  assert.throws(
    () => decideRetry(/** @type {any} */ (null), POLICY),
    (e) => e instanceof TypeError && /RetryDecisionInput/.test(e.message),
  )
})

test('校验：未知 errorCode 抛错（不许用自定义字符串描述上游失败）', () => {
  assert.throws(
    () => decideRetry(base({ errorCode: 'made_up' }), POLICY),
    (e) => e instanceof TypeError && /errorCode/.test(e.message),
  )
})

test('校验：非法 failurePhase 抛错并列出合法值', () => {
  assert.throws(
    () => decideRetry(base({ failurePhase: /** @type {any} */ ('weird') }), POLICY),
    (e) => e instanceof TypeError && /failurePhase/.test(e.message) && /request_body/.test(e.message),
  )
})

test('校验：attemptIndex 从 1 开始，0 抛错', () => {
  assert.throws(() => decideRetry(base({ attemptIndex: 0 }), POLICY), (e) => e instanceof TypeError)
})

test('校验：elapsedMs 不得为负', () => {
  assert.throws(() => decideRetry(base({ elapsedMs: -1 }), POLICY), (e) => e instanceof TypeError)
})

test('校验：布尔字段缺省为 undefined 也抛错（不能让 undefined 被当成 false 用）', () => {
  for (const field of ['bodyReplayable', 'idempotent', 'responseCommitted', 'clientCancelled']) {
    assert.throws(
      () => decideRetry(base({ [field]: /** @type {any} */ (undefined) }), POLICY),
      (e) => e instanceof TypeError && new RegExp(field).test(e.message),
      `${field} 缺失必须报错`,
    )
  }
})

test('校验：method 必须非空', () => {
  assert.throws(() => decideRetry(base({ method: '  ' }), POLICY), (e) => e instanceof TypeError)
})

test('校验：policy 非法（maxAttempts=NaN）抛错，否则重试次数会变成无限', () => {
  const bad = /** @type {any} */ ({ ...POLICY, maxAttempts: Number.NaN })
  assert.throws(() => decideRetry(base(), bad), (e) => e instanceof TypeError && /maxAttempts/.test(e.message))
})

test('决策函数不修改输入与策略', () => {
  const input = base({ statusCode: 503, retryAfterMs: 10 })
  const before = JSON.stringify(input)
  const policyBefore = JSON.stringify(POLICY)
  decideRetry(input, POLICY)
  assert.equal(JSON.stringify(input), before)
  assert.equal(JSON.stringify(POLICY), policyBefore)
})

/* ============================================================
 * 契约联动
 * ============================================================ */

test('默认策略 maxAttempts=1：任何失败都不重试（默认必须是关闭的）', () => {
  const r = decideRetry(base(), DEFAULT_POLICY)
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.ATTEMPTS_EXHAUSTED)
})

test('client_cancelled 作为 errorCode 传入也不会重试（策略层不允许它进 retryOn）', () => {
  const r = decideRetry(
    base({ errorCode: 'client_cancelled', failurePhase: 'connect' }),
    POLICY,
  )
  assert.equal(r.retry, false)
  assert.equal(r.reason, RETRY_REASONS.ERROR_NOT_RETRYABLE)
})

test('FAILURE_PHASES 覆盖方案列出的全部阶段且不可变', () => {
  assert.deepEqual(
    [...FAILURE_PHASES],
    ['dns', 'connect', 'tls', 'first_byte', 'stream_idle', 'total', 'request_body', 'response_body'],
  )
  assert.equal(Object.isFrozen(FAILURE_PHASES), true)
})
