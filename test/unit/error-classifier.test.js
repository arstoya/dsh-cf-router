/**
 * error-classifier.test.js — 统一错误分类器（Issue #9 阶段 1）
 *
 * 分类器是纯函数：只回答「这是什么错误 / 能不能重试 / 该不该惩罚 IP」，
 * 不改统计、不转状态、不碰路由。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { classifyError } from '../../lib/error-classifier.mjs'

const classify = (err, ctx) => classifyError(err, ctx)
const mkErr = (code, message) => {
  const e = new Error(message || code || 'err')
  if (code) e.code = code
  return e
}

/* ============================================================
 * 网络层错误码
 * ============================================================ */

test('TCP 建连失败 → network/connect，权重 1', () => {
  for (const code of ['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH']) {
    const r = classify(mkErr(code))
    assert.equal(r.category, 'network', code)
    assert.equal(r.phase, 'connect', code)
    assert.equal(r.reason, code)
    assert.equal(r.penalizeIp, true)
    assert.equal(r.failureWeight, 1)
    assert.equal(r.retryable, true)
  }
})

test('连接重置 → network/transfer', () => {
  const r = classify(mkErr('ECONNRESET'))
  assert.equal(r.category, 'network')
  assert.equal(r.phase, 'transfer', '重置发生在传输阶段，不是建连')
  assert.equal(r.failureWeight, 1)
})

test('TLS 协议错误 → protocol/tls，可重试', () => {
  const r = classify(mkErr('ERR_TLS_CERT_ALTNAME_INVALID'))
  assert.equal(r.category, 'protocol')
  assert.equal(r.phase, 'tls')
  assert.equal(r.penalizeIp, true)
})

test('TLS 握手超时 → timeout/tls', () => {
  const r = classify(mkErr('ERR_TLS_HANDSHAKE_TIMEOUT'))
  assert.equal(r.category, 'timeout')
  assert.equal(r.phase, 'tls')
})

/* ============================================================
 * 超时：三个阶段必须区分
 * ============================================================ */

test('首字节超时 → timeout/first_byte，权重 0.5（可能是模型 prefill）', () => {
  const r = classify(new Error('first_byte_timeout'))
  assert.equal(r.category, 'timeout')
  assert.equal(r.phase, 'first_byte', '首字节与建连超时必须能分辨')
  assert.equal(r.failureWeight, 0.5, '首字节超时惩罚应低于真连接超时')
  assert.equal(r.penalizeIp, true, '仍要惩罚，否则真卡死也漏掉')
})

test('上游整体超时 → timeout/transfer，权重 1', () => {
  const r = classify(new Error('upstream_timeout'))
  assert.equal(r.category, 'timeout')
  assert.equal(r.phase, 'transfer')
  assert.equal(r.failureWeight, 1)
})

test('ETIMEDOUT → timeout/unknown，权重 1', () => {
  const r = classify(mkErr('ETIMEDOUT'))
  assert.equal(r.category, 'timeout')
  assert.equal(r.phase, 'unknown')
  assert.equal(r.failureWeight, 1)
})

test('首字节与建连超时不会被混为一类', () => {
  const a = classify(new Error('first_byte_timeout'))
  const b = classify(mkErr('ECONNREFUSED'))
  assert.notEqual(a.phase, b.phase, 'phase 必须不同')
  assert.notEqual(a.failureWeight, b.failureWeight, '权重必须不同')
})

/* ============================================================
 * HTTP 业务状态码：不惩罚 IP
 * ============================================================ */

test('HTTP 401 / 403 → auth，不惩罚 IP', () => {
  for (const s of [401, 403]) {
    const r = classify(null, { statusCode: s })
    assert.equal(r.category, 'auth')
    assert.equal(r.penalizeIp, false)
    assert.equal(r.failureWeight, 0)
    assert.equal(r.retryable, false)
  }
})

test('HTTP 429 → rate_limit，不惩罚 IP', () => {
  const r = classify(null, { statusCode: 429 })
  assert.equal(r.category, 'rate_limit')
  assert.equal(r.penalizeIp, false)
  assert.equal(r.failureWeight, 0)
  assert.equal(r.retryable, true, '限流可以重试')
})

test('HTTP 500/502/503 → upstream，不直接惩罚 IP', () => {
  for (const s of [500, 502, 503]) {
    const r = classify(null, { statusCode: s })
    assert.equal(r.category, 'upstream')
    assert.equal(r.penalizeIp, false, `${s} 不该仅凭状态码认定 IP 故障`)
    assert.equal(r.failureWeight, 0)
  }
})

/* ============================================================
 * 客户端取消
 * ============================================================ */

test('客户端取消 → client_abort，权重 0，优先于一切', () => {
  // 即使同时带了看起来很糟的错误码，取消仍是取消
  const r = classify(mkErr('ECONNRESET'), { clientAborted: true })
  assert.equal(r.category, 'client_abort')
  assert.equal(r.penalizeIp, false)
  assert.equal(r.failureWeight, 0)
})

test('client_aborted 这个网关错误同样归为取消', () => {
  const r = classify(new Error('client_aborted'))
  assert.equal(r.category, 'client_abort')
  assert.equal(r.failureWeight, 0)
})

/* ============================================================
 * 未知与边界
 * ============================================================ */

test('未知错误保留惩罚（不放过未覆盖的网络错误）', () => {
  const r = classify(mkErr('ESOMETHING_NEW'))
  assert.equal(r.category, 'unknown')
  assert.equal(r.penalizeIp, true)
  assert.equal(r.failureWeight, 1)
  assert.equal(r.reason, 'ESOMETHING_NEW')
})

test('null / undefined / 字符串都能安全处理', () => {
  for (const x of [null, undefined, 'boom']) {
    const r = classify(x)
    assert.ok(['unknown', 'protocol', 'network', 'timeout'].includes(r.category))
    assert.equal(typeof r.failureWeight, 'number')
  }
})

test('不靠模糊文本改变性质：消息里含 timeout 但不是精确 key 时归为未知', () => {
  // 这是方案 §3.3 的明确要求：优先用稳定错误码，不做 includes 匹配
  const r = classify(mkErr('EWHATEVER', 'connection timeout while doing x'))
  assert.equal(r.category, 'unknown', '不能因为消息里有 timeout 就判成超时')
  assert.equal(r.reason, 'EWHATEVER')
})

test('所有分类结果结构完整', () => {
  const samples = [
    classify(mkErr('ECONNREFUSED')),
    classify(new Error('first_byte_timeout')),
    classify(mkErr('ECONNRESET'), { clientAborted: true }),
    classify(null, { statusCode: 429 }),
    classify(null),
  ]
  for (const r of samples) {
    for (const k of ['category', 'phase', 'reason', 'retryable', 'penalizeIp', 'failureWeight']) {
      assert.ok(k in r, `缺字段 ${k}`)
    }
    assert.equal(typeof r.failureWeight, 'number')
    assert.ok(r.failureWeight >= 0 && r.failureWeight <= 1)
  }
})
