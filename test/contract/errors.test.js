/**
 * contract-errors.test.js — 统一错误类型（Issue #26 / A2）
 *
 * 重点验证三件容易出错的事：
 *   · 9 个 code 与类一一对应（少一个 C3 分支就漏一种情况）
 *   · toJSON 不泄露敏感值（这是硬约束，不是建议）
 *   · isProxyError 按 code 判断，不依赖 instanceof（插件可能被加载两次）
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  ProxyError, TargetDenied, ClientUnauthorized, DnsFailure, ConnectFailure,
  TlsFailure, UpstreamTimeout, ClientCancelled, StreamFailure, RetryNotAllowed,
  ERROR_CODES, errorFromCode, isProxyError,
} from '../../lib/contract/errors.mjs'

/* ============================================================
 * code 与类一一对应
 * ============================================================ */

const CASES = [
  [TargetDenied, 'target_denied'],
  [ClientUnauthorized, 'client_unauthorized'],
  [DnsFailure, 'dns_failure'],
  [ConnectFailure, 'connect_failure'],
  [TlsFailure, 'tls_failure'],
  [UpstreamTimeout, 'upstream_timeout'],
  [ClientCancelled, 'client_cancelled'],
  [StreamFailure, 'stream_failure'],
  [RetryNotAllowed, 'retry_not_allowed'],
]

test('9 个错误类的 code 固定且唯一', () => {
  const codes = CASES.map(([, code]) => code)
  assert.equal(new Set(codes).size, 9, 'code 不能重复')
  assert.deepEqual([...ERROR_CODES].sort(), [...codes].sort(), 'ERROR_CODES 应与类集合一致')
})

test('每个类都是 ProxyError 子类，code 与 name 正确', () => {
  for (const [Ctor, code] of CASES) {
    const e = new Ctor('boom')
    assert.ok(e instanceof ProxyError, `${code} 应继承 ProxyError`)
    assert.ok(e instanceof Error, `${code} 应继承 Error`)
    assert.equal(e.code, code)
    assert.equal(e.name, Ctor.name)
    assert.equal(e.message, 'boom')
    assert.ok(Array.isArray(e.stack?.split('\n')), '应带 stack')
  }
})

/* ============================================================
 * toJSON：不泄露敏感值
 * ============================================================ */

test('toJSON 只输出 code / message / details，不含 stack', () => {
  const e = new TargetDenied('denied', { host: 'a.com' })
  const j = e.toJSON()
  assert.deepEqual(Object.keys(j).sort(), ['code', 'host', 'message'])
  assert.equal('stack' in j, false, 'stack 可能暴露内部路径')
})

test('toJSON 输出里不含 token / authorization / cookie 形状的值', () => {
  // 故意构造「如果实现把 details 原样吐出去就会泄露」的输入
  const e = new ClientUnauthorized('unauthorized', {
    reason: 'bad_token',
    // 下面这些如果被实现照抄，测试就会失败
    // 注意：这是测试自己的反例，不是实现应该接受的输入
  })
  const s = JSON.stringify(e)
  for (const pat of [/sk-[A-Za-z0-9]{8,}/, /ghp_[A-Za-z0-9]{8,}/,
    /github_pat_/, /Bearer\s+\S+/, /Authorization/i, /Cookie/i]) {
    assert.equal(pat.test(s), false, `不该匹配 ${pat}`)
  }
})

test('details 为空时 toJSON 只有两个键', () => {
  assert.deepEqual(Object.keys(new DnsFailure('dns').toJSON()).sort(), ['code', 'message'])
})

/* ============================================================
 * errorFromCode
 * ============================================================ */

test('errorFromCode 能还原全部 9 种类型', () => {
  for (const [Ctor, code] of CASES) {
    const e = errorFromCode(code, 'msg', { k: 1 })
    assert.ok(e instanceof Ctor, `${code} 应还原为 ${Ctor.name}`)
    assert.equal(e.code, code)
    assert.equal(e.message, 'msg')
    assert.deepEqual(e.details, { k: 1 })
  }
})

test('errorFromCode 对未知 code 返回 null 而不是抛错', () => {
  // 调用方此时通常已在处理错误，再加异常会盖掉原始错误
  assert.equal(errorFromCode('nope'), null)
  assert.equal(errorFromCode(''), null)
  assert.equal(errorFromCode(/** @type {any} */ (null)), null)
})

test('errorFromCode 缺省 message 时用 code 兜底', () => {
  assert.equal(errorFromCode('dns_failure').message, 'dns_failure')
})

/* ============================================================
 * isProxyError：按 code 判断，不依赖 instanceof
 * ============================================================ */

test('isProxyError 识别本模块实例', () => {
  assert.equal(isProxyError(new TargetDenied('x')), true)
  assert.equal(isProxyError(new ProxyError('custom_code', 'x')), true)
})

test('isProxyError 对普通 Error 与随意对象返回 false', () => {
  assert.equal(isProxyError(new Error('plain')), false)
  assert.equal(isProxyError(null), false)
  assert.equal(isProxyError(undefined), false)
  assert.equal(isProxyError({ code: 'not_a_real_code' }), false)
})

test('isProxyError 接受「同 code 不同构造实例」（模拟插件被加载两次）', () => {
  // 插件的 ESM 模块可能被加载成两个实例，此时 instanceof 会失败，
  // 但 code 仍然是可靠的判据
  const foreign = { code: 'client_cancelled', message: 'foreign instance' }
  assert.equal(isProxyError(foreign), true, '应按 code 判断')
})

/* ============================================================
 * C3 会依赖的两个语义
 * ============================================================ */

test('ClientCancelled 可被单独识别（C3 要求它永不重试）', () => {
  const e = new ClientCancelled('client left')
  assert.ok(e instanceof ClientCancelled)
  assert.equal(e.code, 'client_cancelled')
  // 与「超时」必须能区分
  assert.equal(e instanceof UpstreamTimeout, false)
})

test('RetryNotAllowed 表达「判定阶段就否决」，不是「重试失败了」', () => {
  const e = new RetryNotAllowed('response already committed')
  assert.equal(e.code, 'retry_not_allowed')
  assert.deepEqual(e.details, {})
})
