/**
 * contract-upstream.test.js — 上游 / 分组 / 客户端（Issue #26 / A2）
 *
 * 三条硬约束各有专门用例：
 *   · protocol 只接受 https（明文 HTTP 会把凭据泄出去）
 *   · authTokenHash 拒绝明文 Token（手滑检测，不是安全边界）
 *   · retryOn 是 code 白名单，且 client_cancelled 永不可重试
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import {
  makeUpstream, makeUpstreamGroup, makeProxyClient, makeRetryPolicy,
  validateGroupReferences, UPSTREAM_PROTOCOLS, ROUTING_MODES,
} from '../../lib/contract/upstream.mjs'

const sha256 = (s) => createHash('sha256').update(s).digest('hex')

/* ============================================================
 * makeUpstream
 * ============================================================ */

test('最小输入：端口默认 443、protocol 默认 https、enabled 默认 true', () => {
  const u = makeUpstream({ id: 'cf', hostname: 'api.example.com' })
  assert.equal(u.port, 443)
  assert.equal(u.protocol, 'https')
  assert.equal(u.enabled, true)
  assert.equal(u.priority, 100)
  assert.equal(u.weight, 1)
  assert.equal(u.timeoutMs, null)
  assert.equal(u.name, 'cf', '未给 name 时用 id')
})

test('显式 enabled: false 被保留', () => {
  assert.equal(makeUpstream({ id: 'a', hostname: 'h', enabled: false }).enabled, false)
})

test('id / hostname 不接受空值', () => {
  assert.throws(() => makeUpstream({ id: '', hostname: 'h' }), TypeError)
  assert.throws(() => makeUpstream({ id: '   ', hostname: 'h' }), TypeError)
  assert.throws(() => makeUpstream({ id: 'a', hostname: '' }), TypeError)
  assert.throws(() => makeUpstream({ id: 'a' }), TypeError)
})

test('port 必须是 1..65535 的整数', () => {
  assert.equal(makeUpstream({ id: 'a', hostname: 'h', port: 8443 }).port, 8443)
  for (const bad of [0, -1, 65536, 1.5, '443', NaN, Infinity]) {
    assert.throws(() => makeUpstream({ id: 'a', hostname: 'h', port: bad }), TypeError, `port=${bad}`)
  }
})

test('protocol 只接受 https，http 被拒并说明原因', () => {
  assert.deepEqual([...UPSTREAM_PROTOCOLS], ['https'])
  try {
    makeUpstream({ id: 'a', hostname: 'h', protocol: 'http' })
    assert.fail('应该抛错')
  } catch (e) {
    assert.match(e.message, /明文/)
    assert.match(e.message, /direct/, '应指出替代方案')
  }
  assert.throws(() => makeUpstream({ id: 'a', hostname: 'h', protocol: 'ftp' }), TypeError)
})

test('weight 必须 >= 0；priority 必须是有限数', () => {
  assert.equal(makeUpstream({ id: 'a', hostname: 'h', weight: 0 }).weight, 0)
  assert.throws(() => makeUpstream({ id: 'a', hostname: 'h', weight: -1 }), TypeError)
  assert.throws(() => makeUpstream({ id: 'a', hostname: 'h', priority: NaN }), TypeError)
})

test('timeoutMs 只接受正数或 null', () => {
  assert.equal(makeUpstream({ id: 'a', hostname: 'h', timeoutMs: 1000 }).timeoutMs, 1000)
  assert.equal(makeUpstream({ id: 'a', hostname: 'h', timeoutMs: null }).timeoutMs, null)
  for (const bad of [0, -5, '1000', NaN]) {
    assert.throws(() => makeUpstream({ id: 'a', hostname: 'h', timeoutMs: bad }), TypeError)
  }
})

test('Upstream 是 frozen 的', () => {
  const u = makeUpstream({ id: 'a', hostname: 'h' })
  assert.equal(Object.isFrozen(u), true)
})

/* ============================================================
 * makeRetryPolicy
 * ============================================================ */

test('默认策略刻意保守：1 次尝试（等于不重试）', () => {
  const p = makeRetryPolicy()
  assert.equal(p.maxAttempts, 1)
  assert.equal(p.totalBudgetMs, 5000)
  assert.deepEqual([...p.retryOn], ['connect_failure', 'dns_failure'])
})

test('maxAttempts 必须 >= 1', () => {
  assert.equal(makeRetryPolicy({ maxAttempts: 3 }).maxAttempts, 3)
  for (const bad of [0, -1, 1.5]) {
    assert.throws(() => makeRetryPolicy({ maxAttempts: bad }), TypeError)
  }
})

test('maxDelayMs 必须 >= baseDelayMs', () => {
  assert.throws(() => makeRetryPolicy({ baseDelayMs: 500, maxDelayMs: 100 }), TypeError)
})

test('retryOn 只接受已知错误码', () => {
  assert.deepEqual([...makeRetryPolicy({ retryOn: ['tls_failure'] }).retryOn], ['tls_failure'])
  assert.throws(() => makeRetryPolicy({ retryOn: ['not_a_code'] }), TypeError)
})

test('retryOn 不能包含 client_cancelled', () => {
  try {
    makeRetryPolicy({ retryOn: ['client_cancelled'] })
    assert.fail('应该抛错')
  } catch (e) {
    assert.match(e.message, /client_cancelled/)
    assert.match(e.message, /永不重试/)
  }
})

test('retryOn 去重', () => {
  const p = makeRetryPolicy({ retryOn: ['dns_failure', 'dns_failure', 'connect_failure'] })
  assert.deepEqual([...p.retryOn], ['dns_failure', 'connect_failure'])
})

/* ============================================================
 * makeUpstreamGroup
 * ============================================================ */

test('分组默认 routingMode auto，并自带默认重试策略', () => {
  const g = makeUpstreamGroup({ id: 'g1' })
  assert.equal(g.routingMode, 'auto')
  assert.equal(g.name, 'g1')
  assert.deepEqual([...g.upstreamIds], [])
  assert.equal(g.retryPolicy.maxAttempts, 1, '默认不重试')
})

test('routingMode 只接受 auto / direct', () => {
  assert.deepEqual([...ROUTING_MODES], ['auto', 'direct'])
  assert.equal(makeUpstreamGroup({ id: 'g', routingMode: 'direct' }).routingMode, 'direct')
  for (const bad of ['Auto', 'proxy', '']) {
    assert.throws(() => makeUpstreamGroup({ id: 'g', routingMode: bad }), TypeError)
  }
})

test('upstreamIds 去重且保持顺序', () => {
  const g = makeUpstreamGroup({ id: 'g', upstreamIds: ['b', 'a', 'b', 'c'] })
  assert.deepEqual([...g.upstreamIds], ['b', 'a', 'c'])
})

test('upstreamIds 里不允许空字符串', () => {
  assert.throws(() => makeUpstreamGroup({ id: 'g', upstreamIds: ['a', ''] }), TypeError)
})

test('传入普通对象作为 retryPolicy 会被构造并校验', () => {
  const g = makeUpstreamGroup({ id: 'g', retryPolicy: { maxAttempts: 2 } })
  assert.equal(g.retryPolicy.maxAttempts, 2)
  assert.equal(Object.isFrozen(g.retryPolicy), true)
  assert.throws(() => makeUpstreamGroup({ id: 'g', retryPolicy: { maxAttempts: 0 } }), TypeError)
})

/* ============================================================
 * makeProxyClient：明文 Token 检测
 * ============================================================ */

test('合法哈希可以构造', () => {
  const h = sha256('some-secret')
  const c = makeProxyClient({ id: 'c1', routeGroupId: 'g1', authTokenHash: h })
  assert.equal(c.authTokenHash, h)
  assert.equal(c.enabled, true)
  assert.equal(c.name, 'c1')
})

test('过短的 hash 被拒', () => {
  assert.throws(() => makeProxyClient({ id: 'c', routeGroupId: 'g', authTokenHash: 'abc' }), {
    name: 'TypeError',
    message: /过短/,
  })
})

test('明文 Token 按已知前缀被拒', () => {
  const cases = [
    'sk-' + 'a'.repeat(40),
    'ghp_' + 'b'.repeat(36),
    'github_pat_' + 'c'.repeat(30),
    'Bearer ' + 'd'.repeat(40),
  ]
  for (const token of cases) {
    assert.throws(
      () => makeProxyClient({ id: 'c', routeGroupId: 'g', authTokenHash: token }),
      TypeError,
      `应拒 ${token.slice(0, 12)}...`,
    )
  }
})

test('长 base64 形态被拒（可能是 key 本体）', () => {
  const b64 = Buffer.from('x'.repeat(40)).toString('base64')
  assert.throws(
    () => makeProxyClient({ id: 'c', routeGroupId: 'g', authTokenHash: b64 }),
    TypeError,
  )
})

test('这是启发式而非安全边界 —— sha256 十六进制能通过', () => {
  // sha256 hex 是 64 位小写字母数字，长度够且不命中任何前缀
  const h = sha256('anything')
  assert.equal(h.length, 64)
  assert.doesNotThrow(() => makeProxyClient({ id: 'c', routeGroupId: 'g', authTokenHash: h }))
})

test('routeGroupId 不接受空值', () => {
  assert.throws(
    () => makeProxyClient({ id: 'c', routeGroupId: '', authTokenHash: sha256('x') }),
    TypeError,
  )
})

/* ============================================================
 * validateGroupReferences（F1 会用它做删除前检查）
 * ============================================================ */

test('引用全部存在时 ok', () => {
  const ups = [
    makeUpstream({ id: 'a', hostname: 'h1' }),
    makeUpstream({ id: 'b', hostname: 'h2' }),
  ]
  const g = makeUpstreamGroup({ id: 'g', upstreamIds: ['a', 'b'] })
  assert.deepEqual(validateGroupReferences(g, ups), { ok: true, missing: [] })
})

test('悬空引用被列出', () => {
  const ups = [makeUpstream({ id: 'a', hostname: 'h' })]
  const g = makeUpstreamGroup({ id: 'g', upstreamIds: ['a', 'ghost'] })
  assert.deepEqual(validateGroupReferences(g, ups), { ok: false, missing: ['ghost'] })
})

test('也接受 Map 形式的上游集合', () => {
  const m = new Map([['a', makeUpstream({ id: 'a', hostname: 'h' })]])
  const g = makeUpstreamGroup({ id: 'g', upstreamIds: ['a'] })
  assert.equal(validateGroupReferences(g, m).ok, true)
})
